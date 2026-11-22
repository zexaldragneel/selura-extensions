#!/usr/bin/env python3
"""Read-only homepage and supported provider sampling for published extensions."""
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
from functional_extension_health import (
    ASURA, MANGADEX, PUBLIC_SERIES, STAGES, check_asura, check_mangadex, check_public_series,
)


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not public_https(newurl):
            raise ValueError("Unsafe redirect target")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def public_https(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
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
    if 300 <= status < 400:
        return {"status": "DEGRADED", "category": "REDIRECT", "detail": f"HTTP {status}"}
    if 200 <= status < 300:
        return {"status": "OK", "category": "HOMEPAGE_REACHABLE", "detail": f"HTTP {status}"}
    return {"status": "DEGRADED", "category": "HTTP_ERROR", "detail": f"HTTP {status}"}


def fetch(url, opener, limit=4096, accept="text/html,application/xhtml+xml,*/*;q=0.5"):
    empty = ({}, b"")
    if not public_https(url):
        return {"status": "ERROR", "category": "UNSAFE_URL", "detail": "Invalid or non-public HTTPS origin"}, *empty
    request = Request(url, headers={"User-Agent": "SeirynExtensionHealth/1.0 (read-only; GitHub Actions)", "Accept": accept})
    started = time.monotonic()
    try:
        with opener.open(request, timeout=12) as response:
            body = response.read(limit)
            observation = classify_response(response.status, response.headers, body)
            observation["elapsedMs"] = round((time.monotonic() - started) * 1000)
            return observation, response.headers, body
    except HTTPError as exc:
        try:
            body = exc.read(4096)
        except OSError:
            body = b""
        exc.close()
        return classify_response(exc.code, exc.headers, body), *empty
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return {"status": "ERROR", "category": "NETWORK_ERROR", "detail": type(exc).__name__}, *empty

def audit(catalog, delay=1.5, probe_fn=None, functional_fetch=None):
    pairs = checked_catalog(catalog)
    opener = build_opener(HTTPSHandler(), SafeRedirect())
    html_origins = {"asurascans.com", "cdn.asurascans.com"}
    for origin, _, _, _, image_origin in PUBLIC_SERIES.values():
        html_origins.update((urlparse(origin).hostname, urlparse(image_origin).hostname))
    html_opener = build_opener(HTTPSHandler(), NoRedirect())

    def provider_fetch(url, limit, accept):
        time.sleep(delay)
        return fetch(url, html_opener if urlparse(url).hostname in html_origins else opener, limit, accept)

    probe_fn = probe_fn or (lambda url: fetch(url, opener)[0])
    functional_fetch = functional_fetch or provider_fetch
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
        functional = {stage: {"status": "NOT_TESTED", "reason": "NO_PROVIDER_ADAPTER"} for stage in STAGES}
        if spec["package"] == MANGADEX:
            functional = check_mangadex(functional_fetch)
        elif spec["package"] == ASURA:
            functional = {stage: {"status": "NOT_TESTED"} for stage in STAGES}
            if status == "OK":
                functional = check_asura(functional_fetch)
            else:
                functional["discovery"] = {"status": "UNKNOWN", "reason": samples[0].get("category", "HOMEPAGE_UNAVAILABLE")}
                functional["download"]["reason"] = "OUT_OF_SCOPE"
        elif spec["package"] in PUBLIC_SERIES:
            if status == "OK":
                functional = check_public_series(functional_fetch, spec["package"])
            else:
                functional["manga_details"] = {"status": "UNKNOWN", "reason": samples[0]["category"]}
        if status == "OK" and any(stage["status"] in {"FAIL", "UNKNOWN", "SLOW"} for stage in functional.values()):
            status = "DEGRADED"
        results.append({"name": spec["name"], "package": spec["package"], "status": status, "samples": samples,
                        "functionalChecks": functional,
                        "sourceCount": len(row["sources"])})
    return {"checkedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "extensionCount": len(results),
            "sourceIdentityCount": sum(r["sourceCount"] for r in results),
            "uniqueOriginsProbed": len(cached), "extensions": results,
            "limitations": "All extensions have homepage sampling. MangaDex has one English sample via the MangaDex public API (https://api.mangadex.org/docs/). Asura Scans, Hiperdex and Toonily sample public HTML and one reader image when access and recognized markup permit. Image timing covers the first 4 KiB at most, and samples taking 4 seconds or longer are flagged. Android extension parsing requires runtime tests. Access restrictions describe the CI request."}


def markdown(report):
    counts = {s: sum(x["status"] == s for x in report["extensions"]) for s in ("OK", "DEGRADED", "ERROR")}
    lines = ["# Seiryn extension availability report", "",
             f"Checked {report['extensionCount']} extensions / {report['sourceIdentityCount']} source identities; {report['uniqueOriginsProbed']} distinct HTTPS homepages.",
             f"**OK:** {counts['OK']} · **Degraded:** {counts['DEGRADED']} · **Error:** {counts['ERROR']}", "",
             "| Extension | Result | Homepage observations | Functional stages (discovery, details, chapters, images, download) |", "|---|---|---|---|"]
    for item in report["extensions"]:
        details = "; ".join(f"{s['url']} ({s.get('category', 'HTTP')}: {s['detail']})" for s in item["samples"])
        stages = ", ".join(
            result["status"] + (f" ({result['reason']})" if "reason" in result else "")
            + (f" [{result['elapsedMs']} ms]" if "elapsedMs" in result else "")
            for result in item["functionalChecks"].values()
        )
        lines.append(f"| {item['name'].replace('|', '/')} | {item['status']} | {details.replace('|', '/')} | {stages} |")
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
