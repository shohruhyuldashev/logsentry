# LogSentry: SSH Login Log Analyzer

LogSentry reads SSH authentication logs and turns raw login messages into a
clear per-user security report. It is a Week 1 cybersecurity internship project
that uses generated data by default, but it can also read compatible SSH logs
that you are authorized to analyse.

## Legal & Ethical Note

Scanning or attacking systems you do not own or do not have written permission
to test is illegal. Analyse only logs you own or have permission to review.
The included `sample_auth.log` contains fictional users and private IP
addresses only.

## What it does

- Reads the input file one line at a time.
- Extracts timestamp, hostname (when present), username, IP, authentication
  method and login status with regular expressions.
- Discovers usernames from the log itself; it does **not** use a fixed list of
  accounts or restrict addresses to a single private subnet.
- Supports the project format and common Linux `sshd` lines, including failed
  passwords, accepted password/public-key logins, invalid users, IPv4 and IPv6.
- Safely skips malformed or unsupported lines instead of crashing.
- Reports total, success, failure, success rate, unique source IPs, first seen
  and last seen for every discovered account.
- Highlights accounts whose failed-logins reach the selected threshold.
- Can return a machine-readable JSON report.

## Security anomaly detection

For chronological log files, LogSentry uses sliding-window queues and
incrementally maintained counters. Every event is added once and removed once,
so detection is **O(n) amortized time** for `n` parsed records; it does not
rescan the file for each username or IP.

It detects these high-value authentication signals:

- **Brute force:** repeated failures from one IP against one account.
- **Password spray:** one IP fails against many accounts.
- **Distributed attack:** many IPs fail against one account.
- **Username enumeration:** one IP probes many invalid usernames.
- **Success after failures:** a successful login follows repeated failures for
  the same IP/account pair, which merits investigation.

One profile is shown once per run, avoiding repeated alert spam from a long log.
The default window is 15 minutes and every threshold is configurable.

## Included sample format

```text
2025-01-15 10:23:45 sshd[1234]: Failed password for user alice from 192.168.1.15
2025-01-15 10:24:02 sshd[1234]: Accepted password for user bob from 192.168.1.20
```

Linux-style entries work as well:

```text
Jan 15 10:23:45 server-01 sshd[1234]: Failed password for root from 203.0.113.7 port 443 ssh2
```

## Run it

```bash
cd ~/SkillMe/logsentry
python3 logsentry.py                         # analyse sample_auth.log
python3 logsentry.py /path/to/auth.log       # analyse another authorised log
python3 logsentry.py --user alice            # report one discovered account
python3 logsentry.py --min-failures 10       # set the alert threshold
python3 logsentry.py --json                  # JSON for another tool/script
python3 logsentry.py --verbose               # show parsed and skipped lines
python3 logsentry.py --color always           # force terminal colors
python3 logsentry.py --output report.json     # save full report as JSON
python3 logsentry.py --output report.csv      # save full report as CSV
```

`--user` may be repeated, for example:

```bash
python3 logsentry.py auth.log --user alice --user root
```

Tune the anomaly detector when your normal traffic differs from the sample:

```bash
python3 logsentry.py auth.log \
  --window-minutes 10 \
  --brute-force-threshold 5 \
  --spray-threshold 8 \
  --distributed-threshold 8 \
  --enumeration-threshold 4
```

Use `--color auto` (default), `--color always`, or `--color never`. JSON output
contains `summary`, `users`, and structured `alerts`; it never includes ANSI
color codes.

## Save a report file

Use `--output` to save the complete analysis instead of copying terminal text.
The format is inferred from the filename extension:

```bash
python3 logsentry.py auth.log --output reports/auth-report.json
python3 logsentry.py auth.log --output reports/auth-report.csv
```

If the filename has no `.json` or `.csv` extension, select the format directly:

```bash
python3 logsentry.py auth.log --output reports/week1-result --format json
python3 logsentry.py auth.log --output reports/week1-result --format csv
```

JSON preserves the nested `summary`, `users`, and `alerts` structure. CSV is
spreadsheet-friendly: its `record_type` column identifies each row as
`summary`, `user`, or `alert`. Missing output folders are created automatically.

## Example report

```text
Summary
Total lines read: 1000
Parsed successfully: 996
Successful logins: 357
Failed logins: 639
Skipped / unsupported lines: 4

User analysis
User               Total    OK  Fail    Rate  IPs
-------------------------------------------------------
alice                164    64   100   39.0%  122
```

The full JSON output also includes `first_seen` and `last_seen` for every
account. The console table is deliberately compact for an easy demo video.

## Generate the sample data

```bash
python3 generate_sample_log.py
```

The generator is deterministic (`seed = 2025`) and creates 1,000 lines: 996
valid entries and 4 intentionally malformed lines.

## Test

```bash
python3 -m unittest -v
```

The tests cover unknown usernames, Linux syslog entries, IPv6, invalid-user
attempts, malformed records, file-level skipped-line counting, per-user
aggregation, brute force, password spray, distributed attacks, username
enumeration and success-after-failures detection.
