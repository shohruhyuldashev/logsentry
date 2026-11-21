#!/usr/bin/env python3
"""Generate a reproducible 1000-line sample authentication log."""

import random
from datetime import datetime, timedelta
from pathlib import Path


SEED = 2025
VALID_LINE_COUNT = 996
TOTAL_LINE_COUNT = 1000
USERNAMES = ("alice", "bob", "carol", "dave", "admin", "test_user", "guest")


def generate_line(timestamp: datetime, pid: int, username: str,
                  ip: int, status: str) -> str:
    """Create one line in the sample authentication log format."""
    result = "Accepted" if status == "SUCCESS" else "Failed"
    password = "password" if status == "SUCCESS" else "password"
    return (
        f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} sshd[{pid}]: "
        f"{result} {password} for user {username} from 192.168.1.{ip}"
    )


def main() -> None:
    random.seed(SEED)
    start = datetime(2025, 1, 15, 10, 0, 0)
    current = start
    pid = 1234
    valid_lines = []
    target_ip = 15

    for index in range(VALID_LINE_COUNT):
        if 400 <= index < 408:
            current += timedelta(seconds=random.randint(15, 60))
            pid = random.randint(1200, 1299)
            valid_lines.append(
                generate_line(current, pid, "admin", target_ip, "FAILED")
            )
            continue

        current += timedelta(seconds=random.randint(15, 60))
        pid = random.randint(1200, 1299)
        username = random.choice(USERNAMES)
        ip = random.randint(10, 250)
        status = "SUCCESS" if random.random() < 0.35 else "FAILED"
        valid_lines.append(generate_line(current, pid, username, ip, status))

    malformed = (
        "",
        "this is not an authentication log line",
        "2025/01/15 10:23:45 wrong date format",
        "sshd[1234]: Failed password for user",
    )

    lines = []
    valid_index = 0
    malformed_index = 0
    malformed_positions = {250, 500, 750, 996}
    for position in range(TOTAL_LINE_COUNT):
        if position in malformed_positions:
            lines.append(malformed[malformed_index])
            malformed_index += 1
        else:
            lines.append(valid_lines[valid_index])
            valid_index += 1

    output = Path(__file__).with_name("sample_auth.log")
    with output.open("w", encoding="utf-8") as log_file:
        log_file.write("\n".join(lines))
        log_file.write("\n")

    print(f"Generated {TOTAL_LINE_COUNT} lines in {output}")


if __name__ == "__main__":
    main()
