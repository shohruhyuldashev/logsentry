import tempfile
import unittest
from pathlib import Path

from logsentry import analyze_users, detect_anomalies, parse_file, parse_line


class ParseLineTests(unittest.TestCase):
    def test_project_format_discovers_any_username(self):
        entry = parse_line(
            "2025-01-15 10:24:02 sshd[1234]: Accepted password "
            "for user new_employee from 10.20.30.40"
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry["user"], "new_employee")
        self.assertEqual(entry["status"], "SUCCESS")

    def test_common_syslog_failed_password(self):
        entry = parse_line(
            "Jan 15 10:23:45 server-01 sshd[1234]: Failed password "
            "for root from 203.0.113.7 port 443 ssh2"
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry["host"], "server-01")
        self.assertEqual(entry["user"], "root")
        self.assertEqual(entry["status"], "FAILED")

    def test_publickey_and_ipv6_are_supported(self):
        entry = parse_line(
            "2025-01-15 10:24:02 sshd[22]: Accepted publickey "
            "for dev.ops from 2001:db8::8 port 22 ssh2"
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry["method"], "publickey")
        self.assertEqual(entry["ip"], "2001:db8::8")

    def test_invalid_user_is_a_failed_attempt(self):
        entry = parse_line(
            "Jan 15 10:23:45 host sshd[1234]: Invalid user intruder from 198.51.100.9"
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry["user"], "intruder")
        self.assertEqual(entry["status"], "FAILED")

    def test_malformed_or_invalid_ip_is_skipped(self):
        self.assertIsNone(parse_line("this is garbage"))
        self.assertIsNone(parse_line(
            "2025-01-15 10:23:45 sshd[1]: Failed password for alice from 999.1.1.1"
        ))
        self.assertIsNone(parse_line(
            "2025-99-15 10:23:45 sshd[1]: Failed password for alice from 10.0.0.1"
        ))

    def test_parse_file_counts_skipped_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            logfile = Path(directory) / "auth.log"
            logfile.write_text(
                "2025-01-15 10:23:45 sshd[1]: Failed password for alice from 10.0.0.1\n"
                "bad input\n",
                encoding="utf-8",
            )
            entries, skipped = parse_file(logfile)
        self.assertEqual(len(entries), 1)
        self.assertEqual(skipped, 1)


class UserAnalysisTests(unittest.TestCase):
    def test_aggregates_discovered_users(self):
        entries = [
            {"timestamp": "t1", "user": "sam", "ip": "10.0.0.1", "status": "FAILED"},
            {"timestamp": "t2", "user": "sam", "ip": "10.0.0.2", "status": "SUCCESS"},
            {"timestamp": "t3", "user": "lee", "ip": "10.0.0.1", "status": "FAILED"},
        ]
        report = analyze_users(entries)
        sam = next(item for item in report if item["user"] == "sam")
        self.assertEqual(sam["total"], 2)
        self.assertEqual(sam["unique_ips"], 2)
        self.assertEqual(sam["success_rate"], 50.0)


class AnomalyDetectionTests(unittest.TestCase):
    @staticmethod
    def entry(second, user, ip, status="FAILED", event_type="login"):
        return {
            "timestamp": f"2025-01-15 10:00:{second:02d}",
            "user": user,
            "ip": ip,
            "status": status,
            "event_type": event_type,
        }

    def test_detects_brute_force_and_success_after_failures(self):
        entries = [self.entry(second, "admin", "10.0.0.9") for second in range(8)]
        entries.append(self.entry(9, "admin", "10.0.0.9", "SUCCESS"))
        alert_types = {
            alert["type"] for alert in detect_anomalies(
                entries, brute_force_threshold=8, compromise_threshold=3
            )
        }
        self.assertIn("BRUTE_FORCE", alert_types)
        self.assertIn("SUCCESS_AFTER_FAILURES", alert_types)

    def test_detects_spray_distributed_and_enumeration(self):
        spray_entries = [
            self.entry(second, f"user{second}", "10.0.0.9")
            for second in range(6)
        ]
        distributed_entries = [
            self.entry(second + 10, "target", f"10.0.1.{second}")
            for second in range(6)
        ]
        enum_entries = [
            self.entry(second + 20, f"missing{second}", "10.0.2.9", event_type="invalid_user")
            for second in range(5)
        ]
        alert_types = {
            alert["type"]
            for alert in detect_anomalies(spray_entries + distributed_entries + enum_entries)
        }
        self.assertTrue({"PASSWORD_SPRAY", "DISTRIBUTED_ATTACK", "USERNAME_ENUMERATION"} <= alert_types)


if __name__ == "__main__":
    unittest.main()
