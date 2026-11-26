# LogSentry — SSH Login Log Analyzer

LogSentry is a Python command-line tool that reads SSH authentication logs,
summarises login activity, and detects suspicious patterns with sliding time
windows. It was extended for **SkillMe Cybersecurity Virtual Internship — Week
2: Detecting Repeated Failed Logins**.

The project uses only Python's standard library. No installation or external
packages are required.

> **Ethical use:** analyse only logs you own or are explicitly authorised to
> review. The included sample contains fictional accounts and private IP
> addresses.

## Week 2 result

The included sample log deliberately contains eight failed logins against
`admin` from `192.168.1.15` within 105 seconds. With the setting below, the
fifth failure raises a `BRUTE_FORCE` alert:

```bash
python3 logsentry.py sample_auth.log \
  --window-minutes 2 \
  --brute-force-threshold 5 \
  --spray-threshold 8 \
  --distributed-threshold 8 \
  --enumeration-threshold 4
```

Expected alert (time may be shown from the fifth event):

```text
[CRITICAL] BRUTE_FORCE  ip=192.168.1.15 user=admin
  ... | 5 signal(s) in 2 min — Repeated failures against one account from one source IP.
```

This demonstrates the core rule: **flag an IP/account pair after 5 failed
logins inside a 2-minute window.** The threshold and time window are command
line options, so they can be changed without editing source code.

## Features

- Parses the supplied ISO-style format and common Linux `sshd`/syslog entries.
- Supports successful and failed password, public-key, and keyboard-interactive
  logins; accepts IPv4 and IPv6 addresses.
- Safely skips malformed or unsupported lines and reports how many were
  skipped.
- Shows login totals, success rate, and unique source IPs per user.
- Shows the top five source IPs by failed-login count (configurable).
- Finds brute force, password spray, distributed attacks, username enumeration,
  and success-after-failures signals.
- Prints JSON or saves a complete JSON/CSV report for further analysis.
- Uses bounded sliding-window queues: each event enters and leaves a queue once,
  giving amortized **O(n)** detection for chronological logs.

## Quick start

```bash
cd ~/SkillMe/logsentry
python3 logsentry.py
```

Running without a log-file argument reads `sample_auth.log`. To analyse another
authorised log:

```bash
python3 logsentry.py /path/to/auth.log
```

## Sample log and test scenario

Recreate the deterministic sample any time with:

```bash
python3 generate_sample_log.py
```

It generates 1,000 lines: 996 valid SSH events and four intentionally malformed
lines. Inside it, the generator adds this controlled attack pattern:

| Item | Value |
| --- | --- |
| Source IP | `192.168.1.15` |
| Target account | `admin` |
| Failed attempts in the burst | 8 |
| Time span | 105 seconds |
| Week 2 detection setting | 5 failures in 2 minutes (triggers on attempt 5) |

The rest of the generated traffic is normal-looking, mixed successful and
failed authentication activity. This makes the alert easy to demonstrate while
avoiding a sample that consists only of attack data.

## Command-line options

Run `python3 logsentry.py --help` to see the built-in help. The following table
explains every option.

| Option | What it does | Example |
| --- | --- | --- |
| `logfile` | Optional path to the log file. If omitted, uses `sample_auth.log`. | `python3 logsentry.py /var/log/auth.log` |
| `--verbose` | Prints each parsed line and each skipped line; useful while checking parser support. | `--verbose` |
| `--user USERNAME` | Limits the per-user table to one chosen user. It may be repeated for multiple users. Detection still examines the complete log. | `--user alice --user admin` |
| `--window-minutes MINUTES` | Sets the sliding time window used by all attack detectors. Default: `15`. | `--window-minutes 2` |
| `--brute-force-threshold COUNT` | Flags repeated failures from the **same IP against the same account**. Default: `8`. The older alias `--min-failures` means the same thing. | `--brute-force-threshold 5` |
| `--spray-threshold COUNT` | Flags an IP that fails against this many **different accounts** within the window. Default: `6`. | `--spray-threshold 8` |
| `--distributed-threshold COUNT` | Flags an account that receives failures from this many **different IPs** within the window. Default: `6`. | `--distributed-threshold 8` |
| `--enumeration-threshold COUNT` | Flags an IP attempting this many different nonexistent usernames within the window. Default: `5`. | `--enumeration-threshold 4` |
| `--compromise-threshold COUNT` | Flags a later successful login after this many failures from the same IP/account pair in the window. Default: `3`. | `--compromise-threshold 3` |
| `--top-ips COUNT` | Chooses how many IPs to display in the failed-login ranking. Default: `5`. | `--top-ips 10` |
| `--no-ip-report` | Hides the failed-IP ranking table. | `--no-ip-report` |
| `--no-user-report` | Hides the per-user summary table. | `--no-user-report` |
| `--no-alerts` | Hides the alert section but still performs analysis and export. | `--no-alerts` |
| `--color auto\|always\|never` | Controls ANSI terminal colours. Default: `auto`. JSON never includes colour codes. | `--color never` |
| `--json` | Prints the full structured result as JSON instead of the human-readable terminal report. | `--json` |
| `--output FILE` | Saves the structured result to a file. The type is inferred from `.json` or `.csv`, unless `--format` is supplied. | `--output reports/week2.json` |
| `--format json\|csv` | Explicitly selects output format, needed when the filename has no recognised extension. | `--output report --format csv` |

All thresholds, the window, and `--top-ips` must be positive integers.

## Detection rules

| Alert | Trigger | Why it matters |
| --- | --- | --- |
| `BRUTE_FORCE` | Repeated failed attempts from one IP against one account. | Often indicates credential guessing. |
| `PASSWORD_SPRAY` | One IP fails against many distinct accounts. | Often indicates testing a common password across many users. |
| `DISTRIBUTED_ATTACK` | One account receives failures from many distinct IPs. | Can indicate a distributed guessing attempt. |
| `USERNAME_ENUMERATION` | One IP tries many invalid usernames. | May indicate account discovery before an attack. |
| `SUCCESS_AFTER_FAILURES` | A successful login follows repeated failures for the same IP/account pair. | Worth prompt investigation for possible account compromise. |

Each unique attack profile is reported once per run to keep the report useful
instead of repeating the same alert for every subsequent matching line.

## Useful commands

Analyse only selected users:

```bash
python3 logsentry.py sample_auth.log --user alice --user admin
```

Show the top 10 failed-login IPs and turn off colours for a clean screenshot:

```bash
python3 logsentry.py sample_auth.log --top-ips 10 --color never
```

Write JSON for another tool:

```bash
python3 logsentry.py sample_auth.log --output reports/week2-report.json
```

Write spreadsheet-friendly CSV:

```bash
python3 logsentry.py sample_auth.log --output reports/week2-report.csv
```

CSV rows have a `record_type` of `summary`, `user`, `failed_ip`, or `alert`, so
one file can retain all report sections. Missing output folders are created
automatically.

## Input formats

Project sample format:

```text
2025-01-15 10:23:45 sshd[1234]: Failed password for user alice from 192.168.1.15
2025-01-15 10:24:02 sshd[1234]: Accepted password for user bob from 192.168.1.20
```

Common Linux syslog format:

```text
Jan 15 10:23:45 server-01 sshd[1234]: Failed password for root from 203.0.113.7 port 443 ssh2
```

Unsupported or malformed lines do not stop processing. They are counted as
skipped, which makes parser limitations visible in the report.

## Tests

Run the test suite with Python's built-in `unittest`:

```bash
python3 -m unittest -v
```

The tests cover parsing, malformed inputs, IPv6, invalid users, user and IP
aggregation, report exports, every detection type, and the two key Week 2 cases:

1. Five failures within two minutes are flagged as brute force.
2. Five failures spread across an hour are **not** flagged with a two-minute
   window.

## Suggested Week 2 demo checklist

1. Run the Week 2 command from the top of this README.
2. Capture the `Top 5 source IPs by failed logins` table and `BRUTE_FORCE`
   alert in a screenshot, or record a 30–60 second terminal demo.
3. Run `python3 -m unittest -v` and capture the passing tests.
4. Push the project to GitHub, include its link in a LinkedIn post, tag
   `@SkillMe`, and submit the LinkedIn post URL on the internship dashboard.
