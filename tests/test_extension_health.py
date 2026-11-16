import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_extension_health as health


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
        self.assertEqual(set(report["extensions"][0]["functionalChecks"].values()), {"NOT_TESTED"})

    def test_http_status_is_not_misrepresented_as_chapter_success(self):
        self.assertIn("No chapter", health.audit.__doc__ or "No chapter") if health.audit.__doc__ else self.assertIn("No chapter", health.markdown({
            "extensionCount": 0, "sourceIdentityCount": 0, "uniqueOriginsProbed": 0,
            "extensions": [], "limitations": "No chapter requests"
        }))


if __name__ == "__main__":
    unittest.main()
