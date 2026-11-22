import json
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_extension_health as health
import functional_extension_health as functional


class HealthTests(unittest.TestCase):
    def test_rejects_insecure_and_local_urls(self):
        self.assertFalse(health.public_https("http://example.com"))
        self.assertFalse(health.public_https("https://localhost"))
        self.assertFalse(health.public_https("https://127.0.0.1"))
        self.assertFalse(health.public_https("https://user:pass@example.com"))

    def test_reports_all_extensions_and_deduplicates_homepages(self):
        rows = [
            ({"name": "Alpha", "package": "a"}, {"sources": [{"homeUrl": "https://example.org", "id": 1}]}),
            ({"name": "Beta", "package": "b"}, {"sources": [{"homeUrl": "https://example.org", "id": 2},
                                                           {"homeUrl": "https://example.net", "id": 3}]}),
        ]
        visited = []
        def fake(url):
            visited.append(url)
            return {"status": "DEGRADED" if url.endswith(".net") else "OK", "detail": "HTTP 403" if url.endswith(".net") else "HTTP 200"}
        with patch.object(health, "checked_catalog", return_value=rows), patch.object(health.time, "sleep"):
            report = health.audit({}, probe_fn=fake)
        self.assertEqual(report["extensionCount"], 2)
        self.assertEqual(report["sourceIdentityCount"], 3)
        self.assertEqual(report["uniqueOriginsProbed"], 2)
        self.assertEqual(len(visited), 2)
        self.assertEqual([x["status"] for x in report["extensions"]], ["OK", "DEGRADED"])
        self.assertIn("Beta", health.markdown(report))

    def test_cloudflare_challenge_signals(self):
        self.assertEqual(health.classify_response(403, {"cf-mitigated": "challenge"})["category"], "POSSIBLE_CLOUDFLARE_CHALLENGE")
        self.assertEqual(health.classify_response(200, {}, b"<title>Just a moment...</title>")["status"], "DEGRADED")
        self.assertEqual(health.classify_response(503)["category"], "SERVER_ERROR")
        self.assertEqual(health.classify_response(403)["category"], "ACCESS_RESTRICTED")
        self.assertEqual(health.classify_response(200)["category"], "HOMEPAGE_REACHABLE")

    def test_functional_checks_are_not_claimed_without_runtime(self):
        with patch.object(health, "checked_catalog", return_value=[
            ({"name": "Alpha", "package": "a"}, {"sources": [{"homeUrl": "https://example.org", "id": 1}]})
        ]):
            report = health.audit({}, probe_fn=lambda _: {"status": "OK", "detail": "HTTP 200"})
        self.assertEqual({stage["status"] for stage in report["extensions"][0]["functionalChecks"].values()}, {"NOT_TESTED"})

    def test_mangadex_provider_path_checks_images_and_leaves_android_download_untested(self):
        identifier = "00000000-0000-4000-8000-000000000001"
        manga = {"type": "manga", "id": identifier, "attributes": {"title": {"en": "Sample"}}}
        chapter = {"type": "chapter", "id": identifier, "attributes": {"pages": 2}}
        manifest = {
            "baseUrl": "https://example.org",
            "chapter": {"hash": "a" * 32, "data": ["1.jpg", "2.jpg"]},
        }
        documents = iter([{"data": [manga]}, {"data": manga}, {"data": [chapter]}, manifest])
        visited = []

        def fetch(url, limit, accept):
            visited.append(url)
            if accept == "image/*":
                return {"status": "OK"}, {"Content-Type": "image/jpeg"}, b"\xff\xd8\xff"
            return {"status": "OK"}, {}, json.dumps({"result": "ok", **next(documents)}).encode()

        result = functional.check_mangadex(fetch)
        self.assertEqual([r["status"] for r in result.values()], ["PASS"] * 4 + ["NOT_TESTED"])
        self.assertEqual(len(visited), 5)
        self.assertEqual(visited[-1], "https://example.org/data/" + "a" * 32 + "/1.jpg")

    def test_mangadex_access_restriction_stops_downstream_requests(self):
        for category in ("ACCESS_RESTRICTED", "POSSIBLE_CLOUDFLARE_CHALLENGE", "NETWORK_ERROR"):
            with self.subTest(category=category):
                def fetch(url, limit, accept):
                    self.assertIn("/manga?", url)
                    return {"status": "DEGRADED", "category": category}, {}, b""

                result = functional.check_mangadex(fetch)
                self.assertEqual(result["discovery"], {"status": "UNKNOWN", "reason": category})
                self.assertEqual(result["chapter_list"]["status"], "NOT_TESTED")

    def test_asura_checks_public_reading_and_skips_downloads(self):
        responses = iter([
            ("text/plain", b"User-agent: *\nDisallow: /api/"),
            ("text/html", b'<a href="/comics/example">Example</a>'),
            ("text/html", b'<h1>Example</h1><a href="/comics/example/chapter/1">Read</a>'),
            ("text/html", b'<img src="https://cdn.asurascans.com/page.webp" alt="Page 1 - Chapter 1">'),
            ("text/plain", b"User-agent: *\nAllow: /"),
            ("image/webp", b"RIFF....WEBP"),
        ])
        urls = []

        def fetch(url, limit, accept):
            urls.append(url)
            mime, body = next(responses)
            return {"status": "OK"}, {"Content-Type": mime}, body

        stages = functional.check_asura(fetch)
        self.assertEqual([result["status"] for result in stages.values()], ["PASS"] * 4 + ["NOT_TESTED"])
        self.assertEqual(urls[-2:], [
            "https://cdn.asurascans.com/robots.txt", "https://cdn.asurascans.com/page.webp",
        ])

    def test_asura_robots_denial_stops_before_discovery(self):
        def fetch(url, limit, accept):
            self.assertEqual(url, "https://asurascans.com/robots.txt")
            return {"status": "OK"}, {}, b"User-agent: *\nDisallow: /"

        stages = functional.check_asura(fetch)
        self.assertEqual(stages["discovery"], {"status": "UNKNOWN", "reason": "ROBOTS_DISALLOWED"})
        self.assertEqual(stages["chapter_images"]["status"], "NOT_TESTED")

    def test_slow_image_sample_is_reported(self):
        def fetch(url, limit, accept):
            self.assertEqual(limit, 4096)
            return {"status": "OK", "elapsedMs": 4100}, {"Content-Type": "image/jpeg"}, b"\xff\xd8\xff"

        self.assertEqual(functional.sample_image(fetch, "https://example.org/page.jpg"), {
            "status": "SLOW", "reason": "SLOW_IMAGE_SAMPLE", "elapsedMs": 4100,
        })

    def test_asura_empty_chapter_list_is_reported(self):
        responses = iter([
            ("text/plain", b"User-agent: *\nAllow: /"),
            ("text/html", b'<a href="/comics/example">Example</a>'),
            ("text/html", b'<h1>Example</h1>'),
        ])

        def fetch(url, limit, accept):
            mime, body = next(responses)
            return {"status": "OK"}, {"Content-Type": mime}, body

        stages = functional.check_asura(fetch)
        self.assertEqual(stages["chapter_list"], {"status": "FAIL", "reason": "EMPTY_CHAPTER_LIST"})
        self.assertEqual(stages["chapter_images"]["status"], "NOT_TESTED")

    def test_image_signatures_distinguish_html_and_images(self):
        self.assertFalse(functional.image_signature(b"<html>Access denied</html>"))
        self.assertTrue(functional.image_signature(b"RIFF....WEBP"))


if __name__ == "__main__":
    unittest.main()
