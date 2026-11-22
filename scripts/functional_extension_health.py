"""Bounded, anonymous smoke checks for explicitly supported public providers."""
import json
import re
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.robotparser import RobotFileParser
from uuid import UUID

SLOW_IMAGE_MS = 4000
STAGES = ("discovery", "manga_details", "chapter_list", "chapter_images", "download")
MANGADEX = "eu.kanade.tachiyomi.extension.all.seluramangadex"
API = "https://api.mangadex.org"
ASURA = "eu.kanade.tachiyomi.extension.en.seluraasurascans"
ASURA_ORIGIN = "https://asurascans.com"
ASURA_CDN = "https://cdn.asurascans.com"


class ProbeStopped(Exception):
    def __init__(self, outcome):
        self.outcome = outcome


def entity_id(entity, kind):
    if entity["type"] != kind:
        raise ValueError("Unexpected entity type")
    return str(UUID(entity["id"]))


def image_signature(body):
    return (body.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a"))
            or body.startswith(b"RIFF") and body[8:12] == b"WEBP")


def checked_fetch(fetch, url, limit, accept):
    observation, headers, data = fetch(url, limit, accept)
    if observation["status"] != "OK":
        category = observation["category"]
        raise ProbeStopped({
            "status": "UNKNOWN" if category in {
                "ACCESS_RESTRICTED", "POSSIBLE_CLOUDFLARE_CHALLENGE", "NETWORK_ERROR", "REDIRECT",
            } else "FAIL",
            "reason": category,
        })
    return headers, data


def sample_image(fetch, url):
    def measured_fetch(url, limit, accept):
        nonlocal elapsed_ms
        observation, headers, body = fetch(url, limit, accept)
        elapsed_ms = observation.get("elapsedMs")
        return observation, headers, body

    elapsed_ms = None
    headers, body = checked_fetch(measured_fetch, url, 4096, "image/*")
    if not headers.get("Content-Type", "").lower().startswith("image/") or not image_signature(body):
        raise ValueError("Expected page image bytes")
    result = {"status": "PASS", "reason": "SAMPLED_ONE_PAGE"}
    if elapsed_ms is not None:
        result["elapsedMs"] = elapsed_ms
        if elapsed_ms >= SLOW_IMAGE_MS:
            result.update(status="SLOW", reason="SLOW_IMAGE_SAMPLE")
    return result



def check_mangadex(fetch):
    results = {name: {"status": "NOT_TESTED"} for name in STAGES}
    stage = "discovery"

    def api(path, **query):
        url = API + path + ("?" + urlencode(query) if query else "")
        _, body = checked_fetch(fetch, url, 256 * 1024, "application/json")
        document = json.loads(body)
        if document["result"] != "ok":
            raise ValueError("API response was unsuccessful")
        return document

    try:
        catalog = api("/manga", limit=1, hasAvailableChapters="true", **{
            "contentRating[]": "safe", "availableTranslatedLanguage[]": "en",
            "order[latestUploadedChapter]": "desc",
        })
        manga = entity_id(catalog["data"][0], "manga")
        results[stage] = {"status": "PASS"}

        stage = "manga_details"
        details = api("/manga/" + manga)["data"]
        titles = details["attributes"]["title"]
        if entity_id(details, "manga") != manga or not any(
            isinstance(title, str) and title.strip() for title in titles.values()
        ):
            raise ValueError("Missing manga details")
        results[stage] = {"status": "PASS"}

        stage = "chapter_list"
        chapters = api("/manga/" + manga + "/feed", limit=10, **{
            "translatedLanguage[]": "en", "contentRating[]": "safe",
            "includeExternalUrl": 0, "order[publishAt]": "desc",
        })["data"]
        if not chapters:
            raise ProbeStopped({"status": "FAIL", "reason": "EMPTY_CHAPTER_LIST"})
        results[stage] = {"status": "PASS"}
        stage = "chapter_images"
        sample = next((entry for entry in chapters if entry["attributes"]["pages"] > 0
                       and not entry["attributes"].get("externalUrl")), None)
        if sample is None:
            raise ProbeStopped({"status": "UNKNOWN", "reason": "NO_HOSTED_SAMPLE"})
        manifest = api("/at-home/server/" + entity_id(sample, "chapter"), forcePort443="true")
        base = urlsplit(manifest["baseUrl"])
        chapter_hash = manifest["chapter"]["hash"]
        filename = manifest["chapter"]["data"][0]
        if (base.scheme != "https" or not base.hostname or base.username or base.password
                or base.port not in (None, 443) or base.path not in ("", "/")
                or base.query or base.fragment
                or not re.fullmatch(r"[a-f0-9]{16,128}", chapter_hash)
                or not re.fullmatch(r"[A-Za-z0-9_-]+\.(?:jpg|jpeg|png|gif|webp)", filename, re.I)):
            raise ValueError("Invalid page URL")
        results[stage] = sample_image(fetch, f"https://{base.netloc}/data/{chapter_hash}/{filename}")
    except ProbeStopped as exc:
        results[stage] = exc.outcome
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        results[stage] = {"status": "FAIL", "reason": "EMPTY_OR_INVALID_RESPONSE"}
    results["download"] = {"status": "NOT_TESTED", "reason": "ANDROID_DOWNLOADER_REQUIRED"}
    return results


class AsuraPage(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.tags = []
        self.feed(body.decode("utf-8", errors="replace"))

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def check_asura(fetch):
    results = {stage: {"status": "NOT_TESTED"} for stage in STAGES}
    results["download"] = {"status": "NOT_TESTED", "reason": "OUT_OF_SCOPE"}
    rules_by_origin = {}
    stage = "discovery"

    def allowed_fetch(url, limit, accept):
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in {ASURA_ORIGIN, ASURA_CDN}:
            raise ValueError("Unexpected Asura host")
        if origin not in rules_by_origin:
            observation, _, body = fetch(origin + "/robots.txt", 64 * 1024, "text/plain")
            rules = RobotFileParser()
            if observation["status"] == "OK" and len(body) < 64 * 1024 and not body.lstrip().startswith(b"<"):
                rules.parse(body.decode("utf-8", errors="replace").splitlines())
            elif observation["category"] == "HOMEPAGE_NOT_FOUND":
                rules.allow_all = True
            else:
                reason = observation["category"] if observation["status"] != "OK" else "INVALID_ROBOTS"
                raise ProbeStopped({"status": "UNKNOWN", "reason": reason})
            rules_by_origin[origin] = rules
        if not rules_by_origin[origin].can_fetch("SeirynExtensionHealth", url):
            raise ProbeStopped({"status": "UNKNOWN", "reason": "ROBOTS_DISALLOWED"})
        return fetch(url, limit, accept)

    def page(url):
        headers, body = checked_fetch(allowed_fetch, url, 2 * 1024 * 1024, "text/html")
        if not headers.get("Content-Type", "").lower().startswith("text/html"):
            raise ValueError("Expected an HTML page")
        return AsuraPage(body)

    def links(document, pattern):
        for tag, attrs in document.tags:
            if tag != "a" or not attrs.get("href"):
                continue
            url = urlsplit(urljoin(ASURA_ORIGIN, attrs["href"]))
            if (url.scheme == "https" and url.netloc == "asurascans.com"
                    and not url.query and not url.fragment and re.fullmatch(pattern, url.path)):
                yield url.path

    try:
        series = next(links(page(ASURA_ORIGIN + "/"), r"/comics/[a-z0-9-]+"))
        results[stage] = {"status": "PASS"}
        stage = "manga_details"
        details = page(ASURA_ORIGIN + series)
        if not any(tag == "h1" for tag, _ in details.tags):
            raise ValueError("No series title")
        results[stage] = {"status": "PASS"}
        stage = "chapter_list"
        chapters = set(links(details, re.escape(series) + r"/chapter/[0-9]+(?:\.[0-9]+)?"))
        if not chapters:
            raise ProbeStopped({"status": "FAIL", "reason": "EMPTY_CHAPTER_LIST"})
        results[stage] = {"status": "PASS"}
        stage = "chapter_images"
        chapter = min(chapters, key=lambda path: (float(path.rsplit("/", 1)[-1]), path))
        reader = page(ASURA_ORIGIN + chapter)
        image = next(attrs["src"] for tag, attrs in reader.tags
                     if tag == "img" and attrs.get("src", "").startswith(ASURA_CDN + "/")
                     and re.match(r"Page 1 - Chapter ", attrs.get("alt") or ""))
        results[stage] = sample_image(allowed_fetch, image)
    except ProbeStopped as exc:
        results[stage] = exc.outcome
    except (StopIteration, ValueError):
        results[stage] = {"status": "FAIL", "reason": "MISSING_OR_INVALID_" + stage.upper()}
    return results
