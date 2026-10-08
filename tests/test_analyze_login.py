import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from analyze_login import (
    count_failed_attempts,
    extract_failed_ip,
    find_suspicious_ips,
    main,
    render_report,
)


class LogParsingTests(unittest.TestCase):
    def test_extracts_ipv4_from_failed_password_line(self):
        line = (
            "Jan 10 12:34:56 server sshd[123]: "
            "Failed password for invalid user admin from 192.0.2.10 port 22 ssh2"
        )
        self.assertEqual(extract_failed_ip(line), "192.0.2.10")

    def test_extracts_ipv6_from_failed_password_line(self):
        line = (
            "Jan 10 12:34:56 server sshd[123]: "
            "Failed password for root from 2001:db8::1 port 22 ssh2"
        )
        self.assertEqual(extract_failed_ip(line), "2001:db8::1")

    def test_ignores_success_unrelated_and_invalid_lines(self):
        lines = [
            "Jan 10 sshd: Accepted password for admin from 192.0.2.10 port 22 ssh2",
            "Jan 10 cron: Failed password check for backup",
            "Jan 10 sshd: Failed password for root from not-an-ip port 22 ssh2",
            "Jan 10 sshd: Failed password for root from 999.999.999.999 port 22 ssh2",
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertIsNone(extract_failed_ip(line))

    def test_counts_failed_attempts_by_ip(self):
        lines = [
            "sshd: Failed password for root from 192.0.2.10 port 22 ssh2",
            "sshd: Failed password for admin from 192.0.2.10 port 22 ssh2",
            "sshd: Failed password for root from 2001:db8::1 port 22 ssh2",
        ]
        self.assertEqual(
            count_failed_attempts(lines),
            {"192.0.2.10": 2, "2001:db8::1": 1},
        )

    def test_finds_threshold_and_sorts_results(self):
        counts = {
            "192.0.2.20": 5,
            "192.0.2.10": 7,
            "192.0.2.30": 4,
            "192.0.2.11": 7,
        }
        self.assertEqual(
            find_suspicious_ips(counts),
            [("192.0.2.10", 7), ("192.0.2.11", 7), ("192.0.2.20", 5)],
        )

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            find_suspicious_ips({}, threshold=0)


class ReportTests(unittest.TestCase):
    def test_render_report_has_structured_plain_text_findings(self):
        report = render_report(
            "/var/log/auth.log",
            [("192.0.2.10", 7)],
            color=False,
        )
        self.assertIn("SSH LOGIN SECURITY ANALYSIS", report)
        self.assertIn("Source : /var/log/auth.log", report)
        self.assertIn("failed authentication attempts >= 5", report)
        self.assertIn("IP ADDRESS", report)
        self.assertIn("FAILED ATTEMPTS", report)
        self.assertIn("192.0.2.10", report)
        self.assertIn("7", report)
        self.assertIn("1 IP address", report)
        self.assertNotIn("\x1b[", report)

    def test_render_report_has_no_findings_summary(self):
        report = render_report("empty.log", [], color=False)
        self.assertIn("No suspicious IP addresses found", report)
        self.assertNotIn("\x1b[", report)

    def test_render_report_supports_ascii_fallback(self):
        report = render_report(
            "auth.log",
            [("192.0.2.10", 5)],
            color=False,
            unicode_output=False,
        )
        self.assertIn("+", report)
        self.assertIn("! 1 IP address", report)
        self.assertNotIn("╔", report)


class CliTests(unittest.TestCase):
    def test_missing_argument_returns_usage_error(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            exit_code = main([])
        self.assertEqual(exit_code, 2)
        self.assertIn("usage:", stderr.getvalue())

    def test_missing_file_returns_concise_error_without_traceback(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            exit_code = main(["does-not-exist.auth.log"])
        self.assertEqual(exit_code, 1)
        self.assertIn("Error:", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_reports_suspicious_ip(self):
        line = "sshd: Failed password for root from 192.0.2.10 port 22 ssh2\n"
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "auth.log"
            log_path.write_text(line * 5, encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main([str(log_path)])
        self.assertEqual(exit_code, 0)
        self.assertIn("192.0.2.10", stdout.getvalue())
        self.assertIn("5", stdout.getvalue())
        self.assertNotIn("\x1b[", stdout.getvalue())

    def test_cli_handles_invalid_utf8_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "auth.log"
            log_path.write_bytes(b"sshd: Failed password \xff\n")
            with redirect_stdout(io.StringIO()):
                exit_code = main([str(log_path)])
        self.assertEqual(exit_code, 0)

    def test_cli_uses_ascii_when_stdout_encoding_cannot_encode_unicode(self):
        line = "sshd: Failed password for root from 192.0.2.10 port 22 ssh2\n"
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "auth.log"
            log_path.write_text(line * 5, encoding="utf-8")
            stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
            with patch("sys.stdout", stdout):
                exit_code = main([str(log_path)])
            stdout.flush()
            output = stdout.detach().getvalue().decode("cp1252")
        self.assertEqual(exit_code, 0)
        self.assertIn("+", output)
        self.assertIn("192.0.2.10", output)


if __name__ == "__main__":
    unittest.main()
