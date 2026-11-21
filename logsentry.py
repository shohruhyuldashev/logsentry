#!/usr/bin/env python3
"""LogSentry: safe, streaming SSH authentication-log analysis.

Analyse only logs you own or are authorized to review.  Detection uses bounded
sliding windows, so each parsed event enters and leaves a queue once: O(n)
amortized time for n log lines.
"""

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple


ISO_TIMESTAMP = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<rest>.+)$"
)
SYSLOG_TIMESTAMP = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<rest>.+)$"
)
SSHD_MESSAGE = re.compile(
    r"^(?:(?P<host>\S+)\s+)?sshd(?:\[\d+\])?:\s*(?P<event>.+)$"
)
LOGIN_EVENT = re.compile(
    r"\b(?P<result>Accepted|Failed)\s+"
    r"(?P<method>password|publickey|keyboard-interactive(?:/pam)?)\s+"
    r"for\s+(?:invalid\s+)?(?:user\s+)?(?P<username>[^\s]+)\s+"
    r"from\s+(?P<ip>[^\s]+)",
    re.IGNORECASE,
)
INVALID_USER_EVENT = re.compile(
    r"\bInvalid user\s+(?P<username>[^\s]+)\s+from\s+(?P<ip>[^\s]+)",
    re.IGNORECASE,
)


class Colors:
    """Small ANSI formatter with no third-party dependency."""

    CODES = {
        "reset": "\033[0m", "bold": "\033[1m", "cyan": "\033[36m",
        "green": "\033[32m", "yellow": "\033[33m", "red": "\033[31m",
        "magenta": "\033[35m", "dim": "\033[2m",
    }

    def __init__(self, mode: str) -> None:
        self.enabled = mode == "always" or (mode == "auto" and sys.stdout.isatty())

    def paint(self, value: object, *styles: str) -> str:
        text = str(value)
        if not self.enabled or not styles:
            return text
        return "".join(self.CODES[style] for style in styles) + text + self.CODES["reset"]


def valid_ip(address: str) -> bool:
    """Return whether *address* is a syntactically valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(address.strip("[]"))
    except ValueError:
        return False
    return True


def _split_log_line(line: str) -> Optional[Dict[str, str]]:
    """Extract timestamp, optional host and sshd event text from one line."""
    timestamp_match = ISO_TIMESTAMP.match(line.strip()) or SYSLOG_TIMESTAMP.match(line.strip())
    if not timestamp_match:
        return None
    message_match = SSHD_MESSAGE.match(timestamp_match.group("rest"))
    if not message_match:
        return None
    return {
        "timestamp": timestamp_match.group("timestamp"),
        "host": message_match.group("host") or "-",
        "event": message_match.group("event"),
    }


def parse_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a supported SSH authentication event, or return ``None``.

    Username and IP are discovered from the input; there is no hard-coded
    account list or private-network-only restriction.
    """
    parts = _split_log_line(line)
    if parts is None:
        return None
    try:
        _event_seconds(parts["timestamp"])
    except ValueError:
        # A syntactically timestamp-like but impossible date must not later
        # crash the streaming detector.
        return None

    event_match = LOGIN_EVENT.search(parts["event"])
    if event_match:
        fields = event_match.groupdict()
        status = "SUCCESS" if fields["result"].lower() == "accepted" else "FAILED"
        method = fields["method"].lower()
        event_type = "login"
    else:
        invalid_match = INVALID_USER_EVENT.search(parts["event"])
        if not invalid_match:
            return None
        fields = invalid_match.groupdict()
        status, method, event_type = "FAILED", "unknown", "invalid_user"

    address = fields["ip"].strip("[]")
    if not fields["username"] or not valid_ip(address):
        return None
    return {
        "timestamp": parts["timestamp"], "host": parts["host"],
        "user": fields["username"], "ip": address, "status": status,
        "method": method, "event_type": event_type,
    }


def parse_file(path: Path, verbose: bool = False) -> Tuple[List[Dict[str, str]], int]:
    """Read *path* line-by-line and return parsed entries plus skipped count."""
    entries: List[Dict[str, str]] = []
    skipped = 0
    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            entry = parse_line(line)
            if entry is None:
                skipped += 1
                if verbose:
                    print(f"SKIPPED line {line_number}: {line.rstrip() or '<blank line>'}")
                continue
            entries.append(entry)
            if verbose:
                print(
                    f"PARSED line {line_number}: {entry['timestamp']} "
                    f"user={entry['user']} ip={entry['ip']} status={entry['status']}"
                )
    return entries, skipped


def _event_seconds(timestamp: str) -> int:
    """Convert a supported timestamp into a comparable value for windows."""
    try:
        if timestamp[0].isdigit():
            value = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        else:
            # Syslog omits the year.  A fixed leap-free year is sufficient for
            # intervals inside one ordered log file and avoids timezone effects.
            value = datetime.strptime(f"2025 {timestamp}", "%Y %b %d %H:%M:%S")
    except ValueError as error:
        raise ValueError(f"Unsupported timestamp: {timestamp}") from error
    return value.toordinal() * 86_400 + value.hour * 3_600 + value.minute * 60 + value.second


def _trim_times(window: Deque[int], now: int, window_seconds: int) -> None:
    """Discard expired timestamps. Each timestamp is discarded at most once."""
    while window and now - window[0] > window_seconds:
        window.popleft()


def _add_distinct(
    windows: Dict[str, Deque[Tuple[int, str]]],
    counters: Dict[str, Counter[str]],
    key: str,
    value: str,
    now: int,
    window_seconds: int,
) -> int:
    """Add one value and return distinct values in its sliding time window."""
    window = windows[key]
    counter = counters[key]
    while window and now - window[0][0] > window_seconds:
        _, expired_value = window.popleft()
        counter[expired_value] -= 1
        if counter[expired_value] == 0:
            del counter[expired_value]
    window.append((now, value))
    counter[value] += 1
    return len(counter)


def _alert(
    kind: str, severity: str, timestamp: str, ip: str, user: str,
    count: int, window_minutes: int, detail: str,
) -> Dict[str, Any]:
    return {
        "type": kind, "severity": severity, "timestamp": timestamp,
        "ip": ip, "user": user, "count": count,
        "window_minutes": window_minutes, "detail": detail,
    }


def detect_anomalies(
    entries: Iterable[Dict[str, str]],
    window_minutes: int = 15,
    brute_force_threshold: int = 8,
    spray_threshold: int = 6,
    distributed_threshold: int = 6,
    enumeration_threshold: int = 5,
    compromise_threshold: int = 3,
) -> List[Dict[str, Any]]:
    """Detect common SSH attack patterns in chronological input in O(n) time.

    The input must be chronological, as authentication logs normally are.  The
    state stores only events inside the selected window; operations on queues
    are amortized O(1), and all distinct counts use incrementally maintained
    ``Counter`` objects rather than rescanning past events.
    """
    seconds = window_minutes * 60
    pair_failures: Dict[Tuple[str, str], Deque[int]] = defaultdict(deque)
    ip_user_windows: Dict[str, Deque[Tuple[int, str]]] = defaultdict(deque)
    ip_user_counts: Dict[str, Counter[str]] = defaultdict(Counter)
    user_ip_windows: Dict[str, Deque[Tuple[int, str]]] = defaultdict(deque)
    user_ip_counts: Dict[str, Counter[str]] = defaultdict(Counter)
    enum_windows: Dict[str, Deque[Tuple[int, str]]] = defaultdict(deque)
    enum_counts: Dict[str, Counter[str]] = defaultdict(Counter)

    # A profile is reported once per run.  This prevents a long noisy log from
    # repeating the same IP/account incident on every later window crossing.
    brute_reported, spray_reported, distributed_reported, enum_reported = set(), set(), set(), set()
    compromise_seen: set[Tuple[str, str]] = set()
    alerts: List[Dict[str, Any]] = []

    for entry in entries:
        now = _event_seconds(entry["timestamp"])
        ip, user = entry["ip"], entry["user"]
        pair = (ip, user)
        failures = pair_failures[pair]
        _trim_times(failures, now, seconds)

        if entry["status"] == "SUCCESS":
            if len(failures) >= compromise_threshold and pair not in compromise_seen:
                compromise_seen.add(pair)
                alerts.append(_alert(
                    "SUCCESS_AFTER_FAILURES", "HIGH", entry["timestamp"], ip, user,
                    len(failures), window_minutes,
                    "Successful login followed repeated failures for the same account and source IP.",
                ))
            continue

        # Failed event: all four detection families update in O(1) amortized time.
        failures.append(now)
        if len(failures) >= brute_force_threshold and pair not in brute_reported:
            brute_reported.add(pair)
            alerts.append(_alert(
                "BRUTE_FORCE", "CRITICAL", entry["timestamp"], ip, user,
                len(failures), window_minutes,
                "Repeated failures against one account from one source IP.",
            ))

        distinct_users = _add_distinct(
            ip_user_windows, ip_user_counts, ip, user, now, seconds
        )
        if distinct_users >= spray_threshold and ip not in spray_reported:
            spray_reported.add(ip)
            alerts.append(_alert(
                "PASSWORD_SPRAY", "HIGH", entry["timestamp"], ip, "*",
                distinct_users, window_minutes,
                "One source IP failed against many different accounts.",
            ))

        distinct_ips = _add_distinct(
            user_ip_windows, user_ip_counts, user, ip, now, seconds
        )
        if distinct_ips >= distributed_threshold and user not in distributed_reported:
            distributed_reported.add(user)
            alerts.append(_alert(
                "DISTRIBUTED_ATTACK", "HIGH", entry["timestamp"], "*", user,
                distinct_ips, window_minutes,
                "One account received failures from many different source IPs.",
            ))

        if entry["event_type"] == "invalid_user":
            invalid_names = _add_distinct(
                enum_windows, enum_counts, ip, user, now, seconds
            )
            if invalid_names >= enumeration_threshold and ip not in enum_reported:
                enum_reported.add(ip)
                alerts.append(_alert(
                    "USERNAME_ENUMERATION", "MEDIUM", entry["timestamp"], ip, "*",
                    invalid_names, window_minutes,
                    "One source IP attempted many nonexistent usernames.",
                ))
    return alerts


def analyze_users(entries: Iterable[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Return per-account login totals and source-IP diversity."""
    stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"user": "", "total": 0, "successful": 0, "failed": 0,
                 "ips": set(), "first_seen": "", "last_seen": ""}
    )
    for entry in entries:
        item = stats[entry["user"]]
        item["user"] = entry["user"]
        item["total"] += 1
        item["successful" if entry["status"] == "SUCCESS" else "failed"] += 1
        item["ips"].add(entry["ip"])
        if not item["first_seen"]:
            item["first_seen"] = entry["timestamp"]
        item["last_seen"] = entry["timestamp"]
    report = []
    for item in stats.values():
        report.append({
            "user": item["user"], "total": item["total"],
            "successful": item["successful"], "failed": item["failed"],
            "success_rate": round(item["successful"] / item["total"] * 100, 1),
            "unique_ips": len(item["ips"]), "first_seen": item["first_seen"],
            "last_seen": item["last_seen"],
        })
    return sorted(report, key=lambda row: (-row["failed"], -row["total"], row["user"]))


def print_preview(entries: List[Dict[str, str]], colors: Colors) -> None:
    """Print a five-line colored preview."""
    print("\n" + colors.paint("Preview (first 5 parsed entries)", "bold", "cyan"))
    if not entries:
        print(colors.paint("No supported SSH authentication entries.", "yellow"))
        return
    for entry in entries[:5]:
        status_style = "green" if entry["status"] == "SUCCESS" else "red"
        status = colors.paint(entry["status"], "bold", status_style)
        print(f"{entry['timestamp']}  user={entry['user']:<16} ip={entry['ip']:<39} status={status}")


def print_user_report(report: List[Dict[str, Any]], colors: Colors) -> None:
    """Print concise account activity table."""
    print("\n" + colors.paint("User analysis", "bold", "cyan"))
    if not report:
        print(colors.paint("No matching users found.", "yellow"))
        return
    print(f"{'User':<18} {'Total':>5} {'OK':>5} {'Fail':>5} {'Rate':>7} {'IPs':>4}")
    print(colors.paint("-" * 55, "dim"))
    for item in report:
        failures = colors.paint(f"{item['failed']:>5}", "red") if item["failed"] else f"{0:>5}"
        successful = colors.paint(f"{item['successful']:>5}", "green") if item["successful"] else f"{0:>5}"
        print(f"{item['user']:<18} {item['total']:>5} {successful} {failures} {item['success_rate']:>6.1f}% {item['unique_ips']:>4}")


def print_alert_report(alerts: List[Dict[str, Any]], colors: Colors) -> None:
    """Print actionable anomalies with severity-specific terminal colors."""
    print("\n" + colors.paint("Security anomaly alerts", "bold", "magenta"))
    if not alerts:
        print(colors.paint("No configured anomaly threshold was reached.", "green"))
        return
    color_by_severity = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan"}
    for alert in alerts:
        label = colors.paint(alert["severity"], "bold", color_by_severity[alert["severity"]])
        target = f"ip={alert['ip']} user={alert['user']}"
        print(f"[{label}] {alert['type']}  {target}")
        print(f"  {alert['timestamp']} | {alert['count']} signal(s) in {alert['window_minutes']} min — {alert['detail']}")


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Analyze SSH logs with O(n) sliding-window anomaly detection."
    )
    parser.add_argument("logfile", nargs="?", type=Path, default=Path(__file__).with_name("sample_auth.log"), help="Log file to parse (default: sample_auth.log)")
    parser.add_argument("--verbose", action="store_true", help="Print parsed and skipped lines")
    parser.add_argument("--user", action="append", metavar="USERNAME", help="Show only this user (repeatable)")
    parser.add_argument("--window-minutes", type=int, default=15, metavar="MINUTES", help="Detection time window (default: 15)")
    parser.add_argument("--brute-force-threshold", "--min-failures", dest="brute_force_threshold", type=int, default=8, metavar="COUNT", help="Failures for same IP + user (default: 8)")
    parser.add_argument("--spray-threshold", type=int, default=6, metavar="COUNT", help="Distinct users failed by one IP (default: 6)")
    parser.add_argument("--distributed-threshold", type=int, default=6, metavar="COUNT", help="Distinct IPs failing one user (default: 6)")
    parser.add_argument("--enumeration-threshold", type=int, default=5, metavar="COUNT", help="Invalid usernames tried by one IP (default: 5)")
    parser.add_argument("--compromise-threshold", type=int, default=3, metavar="COUNT", help="Failures before later success alert (default: 3)")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="ANSI color mode (default: auto)")
    parser.add_argument("--no-user-report", action="store_true", help="Hide the per-user table")
    parser.add_argument("--no-alerts", action="store_true", help="Hide anomaly alerts")
    parser.add_argument("--json", action="store_true", help="Print the complete report as JSON")
    return parser


def _validate_thresholds(args: argparse.Namespace) -> Optional[str]:
    values = (args.window_minutes, args.brute_force_threshold, args.spray_threshold,
              args.distributed_threshold, args.enumeration_threshold, args.compromise_threshold)
    return "All window and threshold values must be at least 1." if any(value < 1 for value in values) else None


def main() -> int:
    """Run parsing, O(n) detection and selected terminal/JSON reporting."""
    args = build_parser().parse_args()
    validation_error = _validate_thresholds(args)
    if validation_error:
        print(f"Error: {validation_error}", file=sys.stderr)
        return 2
    if not args.logfile.is_file():
        print(f"Error: file not found or not a regular file: {args.logfile}", file=sys.stderr)
        return 1
    try:
        entries, skipped = parse_file(args.logfile, args.verbose and not args.json)
    except OSError as error:
        print(f"Error: could not read {args.logfile}: {error}", file=sys.stderr)
        return 1

    alerts = detect_anomalies(
        entries, args.window_minutes, args.brute_force_threshold, args.spray_threshold,
        args.distributed_threshold, args.enumeration_threshold, args.compromise_threshold,
    )
    summary = {
        "total_lines": len(entries) + skipped, "parsed_entries": len(entries),
        "successful_logins": sum(row["status"] == "SUCCESS" for row in entries),
        "failed_logins": sum(row["status"] == "FAILED" for row in entries),
        "invalid_user_events": sum(row["event_type"] == "invalid_user" for row in entries),
        "skipped_lines": skipped,
    }
    report = analyze_users(entries)
    selected_report = report if not args.user else [row for row in report if row["user"] in set(args.user)]
    if args.json:
        print(json.dumps({"summary": summary, "users": selected_report, "alerts": alerts}, indent=2))
        return 0

    colors = Colors(args.color)
    print_preview(entries, colors)
    print("\n" + colors.paint("Summary", "bold", "cyan"))
    print(f"Total lines read: {summary['total_lines']}")
    print(f"Parsed successfully: {summary['parsed_entries']}")
    print(f"Successful logins: {colors.paint(summary['successful_logins'], 'green')}")
    print(f"Failed logins: {colors.paint(summary['failed_logins'], 'red')}")
    print(f"Invalid-user events: {colors.paint(summary['invalid_user_events'], 'yellow')}")
    print(f"Skipped / unsupported lines: {summary['skipped_lines']}")
    print(f"Check: {len(entries)} parsed + {skipped} skipped = {summary['total_lines']} total")
    if not args.no_user_report:
        print_user_report(selected_report, colors)
    if not args.no_alerts:
        print_alert_report(alerts, colors)
    return 0


if __name__ == "__main__":
    sys.exit(main())
