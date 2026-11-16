#!/usr/bin/env python3
"""Read-only homepage availability sampling for every published Seiryn extension.

This is not a chapter parser, authenticated session, or Cloudflare bypass.
"""
import argparse
import datetime as dt
import ipaddress
import json
from pathlib import Path
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from audit_extension_apks import checked_catalog


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not public_https(newurl):
            raise ValueError("Unsafe redirect target")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def public_https(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return False
    host = parsed.hostname
    if host in ("localhost",) or host.endswith((".local", ".internal")):
        return False
    try:
        if not all(ipaddress.ip_address(x[4][0]).is_global for x in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)):
            return False
    except (socket.gaierror, ValueError):
        return False
    return True


FUNCTIONAL_STAGES = ("discovery", "manga_details", "chapter_list", "chapter_images", "download")

def classify_response(status, headers=None, body=b""):
    """Classify HTTP signals; do not infer that Kotlin extension parsing works."""
    headers = headers or {}
    header_values = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    sample = body[:4096].lower()
    if (b"cf-chl-" in sample or b"just a moment" in sample or
        b"checking your browser" in sample or
        header_values.get("cf-mitigated") == "challenge"):
        return {"status": "DEGRADED", "category": "POSSIBLE_CLOUDFLARE_CHALLENGE", "detail": f"HTTP {status}"}
    if status in (401, 403, 429):
        return {"status": "DEGRADED", "category": "ACCESS_RESTRICTED", "detail": f"HTTP {status}"}
    if status == 404:
        return {"status": "DEGRADED", "category": "HOMEPAGE_NOT_FOUND", "detail": "HTTP 404"}
    if status >= 500:
        return {"status": "ERROR", "category": "SERVER_ERROR", "detail": f"HTTP {status}"}
    if 200 <= status < 400:
        return {"status": "OK", "category": "HOMEPAGE_REACHABLE", "detail": f"HTTP {status}"}
    return {"status": "DEGRADED", "category": "HTTP_ERROR", "detail": f"HTTP {status}"}


def probe(url, opener):
    if not public_https(url):
        return {"status": "ERROR", "category": "UNSAFE_URL", "detail": "Invalid or non-public HTTPS origin"}
    request = Request(url, headers={"User-Agent": "SeirynExtensionHealth/1.0 (read-only; GitHub Actions)", "Accept": "text/html,application/xhtml+xml,*/*;q=0.5"})
    try:
        with opener.open(request, timeout=12) as response:
            return classify_response(response.status, response.headers, response.read(4096))
    except HTTPError as exc:
        try:
            body = exc.read(4096)
        except OSError:
            body = b""
        return classify_response(exc.code, exc.headers, body)
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return {"status": "ERROR", "category": "NETWORK_ERROR", "detail": type(exc).__name__}

def audit(catalog, delay=1.5, probe_fn=None):
    pairs = checked_catalog(catalog)
    opener = build_opener(HTTPSHandler(), SafeRedirect())
    probe_fn = probe_fn or (lambda url: probe(url, opener))
    cached = {}
    results = []
    for spec, row in pairs:
        origins = sorted({source["homeUrl"].rstrip("/") for source in row["sources"]})
        samples = []
        for url in origins:
            if url not in cached:
                if cached:
                    time.sleep(delay)
                cached[url] = probe_fn(url)
            samples.append({"url": url, **cached[url]})
        status = "ERROR" if any(s["status"] == "ERROR" for s in samples) else (
            "DEGRADED" if any(s["status"] == "DEGRADED" for s in samples) else "OK"
        )
        results.append({"name": spec["name"], "package": spec["package"], "status": status, "samples": samples,
                        "functionalChecks": {stage: "NOT_TESTED" for stage in FUNCTIONAL_STAGES},
                        "sourceCount": len(row["sources"])})
    return {"checkedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "extensionCount": len(results),
            "sourceIdentityCount": sum(r["sourceCount"] for r in results),
            "uniqueOriginsProbed": len(cached), "extensions": results,
            "limitations": "Homepage sampling only. No chapter, image, login, Cloudflare bypass or extension runtime checks. HTTP 403/429 can be bot protection, not an extension defect."}


def markdown(report):
    counts = {s: sum(x["status"] == s for x in report["extensions"]) for s in ("OK", "DEGRADED", "ERROR")}
    lines = ["# Seiryn extension availability report", "",
             f"Checked {report['extensionCount']} extensions / {report['sourceIdentityCount']} source identities; {report['uniqueOriginsProbed']} distinct HTTPS homepages.",
             f"**OK:** {counts['OK']} · **Degraded:** {counts['DEGRADED']} · **Error:** {counts['ERROR']}", "",
             "**Functional checks (discovery, manga details, chapter list, images, downloads): NOT TESTED; Kotlin runtime execution is required.**", "",
             "| Extension | Result | Homepage observations |", "|---|---|---|"]
    for item in report["extensions"]:
        details = "; ".join(f"{s['url']} ({s.get('category', 'HTTP')}: {s['detail']})" for s in item["samples"])
        lines.append(f"| {item['name'].replace('|', '/')} | {item['status']} | {details.replace('|', '/')} |")
    lines.extend(["", "**Limitations:** " + report["limitations"], "",
                  "No APKs, source IDs, credentials, library data or extension configurations were changed."])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    try:
        report = audit(json.loads(args.catalog.read_text(encoding="utf-8")))
    except (ValueError, KeyError, TypeError) as exc:
        report = {"error": str(exc), "extensions": []}
    (args.output_dir / "health.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = markdown(report) if "error" not in report else "# Seiryn extension health check failed\n\nCatalog validation: " + report["error"] + "\n"
    (args.output_dir / "health.md").write_text(summary, encoding="utf-8")
    print(summary)
    return 1 if "error" in report else 0


if __name__ == "__main__":
    raise SystemExit(main())
