"""Bounded, anonymous smoke checks for explicitly supported public provider APIs."""
import json
import re
from urllib.parse import urlencode, urlsplit
from uuid import UUID

STAGES = ("discovery", "manga_details", "chapter_list", "chapter_images", "download")
MANGADEX = "eu.kanade.tachiyomi.extension.all.seluramangadex"
API = "https://api.mangadex.org"


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


def check_mangadex(fetch):
    results = {name: {"status": "NOT_TESTED"} for name in STAGES}
    stage = "discovery"

    def get(url, limit, accept):
        observation, headers, data = fetch(url, limit, accept)
        if observation["status"] != "OK":
            category = observation["category"]
            raise ProbeStopped({
                "status": "UNKNOWN" if category in {
                    "ACCESS_RESTRICTED", "POSSIBLE_CLOUDFLARE_CHALLENGE", "NETWORK_ERROR",
                } else "FAIL",
                "reason": category,
            })
        return headers, data

    def api(path, **query):
        url = API + path + ("?" + urlencode(query) if query else "")
        _, body = get(url, 256 * 1024, "application/json")
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
            raise ValueError("Empty chapter list")
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
        headers, body = get(f"https://{base.netloc}/data/{chapter_hash}/{filename}", 4096, "image/*")
        if not headers.get("Content-Type", "").lower().startswith("image/") or not image_signature(body):
            raise ValueError("Page response did not contain image bytes")
        results[stage] = {"status": "PASS", "reason": "SAMPLED_ONE_PAGE"}
    except ProbeStopped as exc:
        results[stage] = exc.outcome
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        results[stage] = {"status": "FAIL", "reason": "EMPTY_OR_INVALID_RESPONSE"}
    results["download"] = {"status": "NOT_TESTED", "reason": "ANDROID_DOWNLOADER_REQUIRED"}
    return results
