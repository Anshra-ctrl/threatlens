"""Automated tests for ThreatLens (run with: python -m unittest -v)."""

import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from app import Handler
from detector import analyze, generate_sample, parse_log

FAIL_LINE = (
    "2026-10-08 10:00:{sec:02d} web-01 sshd[1]: "
    "Failed password for {user} from {ip} port 22 ssh2"
)
OK_LINE = (
    "2026-10-08 10:00:{sec:02d} web-01 sshd[1]: "
    "Accepted password for {user} from {ip} port 22 ssh2"
)


def find(report, kind, ip=None):
    """Return the alerts of one type, optionally only for one IP."""
    return [
        a
        for a in report["alerts"]
        if a["type"] == kind and (ip is None or a["ip"] == ip)
    ]


def make_log(template, count, user="bob", ip="1.2.3.4"):
    """Build `count` log lines, one second apart, from a line template."""
    return "\n".join(template.format(sec=i, user=user, ip=ip) for i in range(count))


class DetectorTests(unittest.TestCase):
    """Checks every detection rule against the built-in sample logs."""

    def setUp(self):
        """Analyze the sample once per test."""
        self.report = analyze(generate_sample())

    def test_brute_force_detected(self):
        """The root brute-forcer is flagged as high severity."""
        alerts = find(self.report, "Brute-force attack", "185.220.101.4")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["user"], "root")
        self.assertEqual(alerts[0]["severity"], "high")

    def test_password_spraying_detected(self):
        """The IP that tried 12 different accounts is flagged."""
        alerts = find(self.report, "Password spraying", "45.155.205.9")
        self.assertEqual(len(alerts), 1)
        self.assertIn("12 different accounts", alerts[0]["detail"])

    def test_compromise_detected_and_critical(self):
        """A success right after failures is critical and listed first."""
        alerts = find(self.report, "Possible account compromise", "91.240.118.77")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "critical")
        self.assertEqual(alerts[0]["user"], "deploy")
        self.assertEqual(self.report["alerts"][0]["severity"], "critical")

    def test_off_hours_login_detected(self):
        """The 03:12 login from a new address is flagged."""
        alerts = find(self.report, "Off-hours login", "203.0.113.50")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["user"], "bob")

    def test_normal_staff_never_flagged(self):
        """Normal staff traffic (with a few typos) raises no alerts."""
        flagged = {a["ip"] for a in self.report["alerts"]}
        for ip in ("10.0.0.21", "10.0.0.34", "10.0.0.58"):
            self.assertNotIn(ip, flagged)

    def test_summary_numbers_add_up(self):
        """Totals, risk level and timeline all agree with each other."""
        s = self.report["summary"]
        self.assertEqual(s["events"], s["failed"] + s["accepted"])
        self.assertEqual(s["skipped"], 0)
        self.assertEqual(s["risk_level"], "Critical")
        self.assertLessEqual(s["risk_score"], 100)
        points = self.report["timeline"]["points"]
        self.assertEqual(sum(p["failed"] + p["accepted"] for p in points), s["events"])

    def test_top_source_is_the_brute_forcer(self):
        """The IP with the most failures is listed first."""
        self.assertEqual(self.report["top_sources"][0]["ip"], "185.220.101.4")

    def test_sample_is_deterministic(self):
        """The demo logs are identical every time."""
        self.assertEqual(generate_sample(), generate_sample())

    def test_report_is_json_serializable(self):
        """The report can be sent to the browser as JSON."""
        json.dumps(self.report)


class RootLoginTests(unittest.TestCase):
    """Checks the direct root login rule."""

    def test_root_login_raises_high_alert(self):
        """One successful root login gives one high-severity alert."""
        report = analyze(make_log(OK_LINE, 1, user="root"))
        alerts = find(report, "Root login")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(alerts[0]["user"], "root")
        self.assertEqual(alerts[0]["mitre_id"], "T1078")

    def test_normal_user_login_is_not_flagged(self):
        """A daytime login by a normal account raises nothing."""
        report = analyze(make_log(OK_LINE, 1, user="alice"))
        self.assertEqual(report["alerts"], [])

    def test_failed_root_attempts_are_not_a_root_login(self):
        """Failed attempts as root are not a successful root login."""
        report = analyze(make_log(FAIL_LINE, 2, user="root"))
        self.assertEqual(find(report, "Root login"), [])

    def test_many_root_logins_give_one_alert_per_ip(self):
        """Ten root logins from one IP are reported once, with the count."""
        report = analyze(make_log(OK_LINE, 10, user="root"))
        alerts = find(report, "Root login")
        self.assertEqual(len(alerts), 1)
        self.assertIn("10 successful logins", alerts[0]["detail"])

    def test_root_login_adds_a_recommendation(self):
        """The next-steps list mentions disabling root SSH login."""
        report = analyze(make_log(OK_LINE, 1, user="root"))
        self.assertTrue(any("root" in r.lower() for r in report["recommendations"]))


class EdgeCaseTests(unittest.TestCase):
    """Checks unusual or broken input."""

    def test_empty_input(self):
        """Empty input gives an empty report, not an error."""
        report = analyze("")
        self.assertEqual(report["summary"]["events"], 0)
        self.assertEqual(report["summary"]["risk_level"], "No data")
        self.assertEqual(report["alerts"], [])

    def test_garbage_lines_are_skipped_and_counted(self):
        """Lines in the wrong format are skipped and counted."""
        report = analyze("hello world\nnot a log line\n")
        self.assertEqual(report["summary"]["events"], 0)
        self.assertEqual(report["summary"]["skipped"], 2)

    def test_invalid_ip_is_skipped(self):
        """An IP like 999.1.1.1 is rejected."""
        line = FAIL_LINE.format(sec=0, user="bob", ip="999.1.1.1")
        events, skipped = parse_log(line)
        self.assertEqual((len(events), skipped), (0, 1))

    def test_invalid_date_is_skipped(self):
        """A date like 2026-13-45 is rejected."""
        line = (
            "2026-13-45 10:00:00 web-01 sshd[1]: "
            "Failed password for bob from 1.2.3.4 port 22 ssh2"
        )
        events, skipped = parse_log(line)
        self.assertEqual((len(events), skipped), (0, 1))

    def test_few_failures_do_not_alert(self):
        """Four failures stay below the brute-force threshold."""
        self.assertEqual(analyze(make_log(FAIL_LINE, 4))["alerts"], [])

    def test_five_failures_in_window_alert(self):
        """Five quick failures against one account trigger an alert."""
        alerts = analyze(make_log(FAIL_LINE, 5))["alerts"]
        self.assertEqual([a["type"] for a in alerts], ["Brute-force attack"])

    def test_slow_failures_outside_window_do_not_alert(self):
        """Failures spread over hours are not a brute-force burst."""
        lines = [
            f"2026-10-08 1{i}:00:00 web-01 sshd[1]: "
            "Failed password for bob from 1.2.3.4 port 22 ssh2"
            for i in range(6)
        ]
        self.assertEqual(analyze("\n".join(lines))["alerts"], [])

    def test_log_spanning_weeks_uses_daily_buckets(self):
        """A log longer than a week is charted by day."""
        text = (
            "2026-09-01 10:00:00 h sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2\n"
            "2026-10-08 10:00:00 h sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2\n"
        )
        self.assertEqual(analyze(text)["timeline"]["bucket"], "day")

    def test_windows_line_endings(self):
        """Windows-style line endings (CRLF) are handled."""
        text = "2026-10-08 10:00:00 h sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2\r\n"
        self.assertEqual(analyze(text)["summary"]["events"], 1)


class ServerTests(unittest.TestCase):
    """Starts the real server on a free port and calls it."""

    @classmethod
    def setUpClass(cls):
        """Start the server in a background thread."""
        cls.server = ThreadingHTTPServer(  # pylint: disable=consider-using-with
            ("127.0.0.1", 0), Handler
        )
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        """Stop the server."""
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None):
        """Call the test server and return (status code, response bytes)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_index_served(self):
        """The dashboard page loads."""
        status, data = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"ThreatLens", data)

    def test_sample_then_analyze(self):
        """Sample logs can be fetched and analyzed end to end."""
        status, sample = self.request("GET", "/api/sample")
        self.assertEqual(status, 200)
        status, data = self.request("POST", "/api/analyze", body=sample)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["summary"]["risk_level"], "Critical")

    def test_empty_body_rejected(self):
        """An empty request body gets a 400 error."""
        status, _ = self.request("POST", "/api/analyze", body=b"")
        self.assertEqual(status, 400)

    def test_unknown_path_404(self):
        """An unknown path gets a 404 error."""
        status, _ = self.request("GET", "/nope")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
