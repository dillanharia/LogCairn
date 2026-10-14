# imports
import re
import argparse
from datetime import datetime

# initialisation + counters

failed_count = 0
successful_count = 0
unmatched_count = 0

failures_by_ip = {}
failure_times_by_ip = {}
pending_failures_by_ip = {}

alerts = []
active_failure_alerts_by_ip = {}

# regex
auth_pattern = re.compile(
    r"(?P<outcome>Failed|Accepted) password for "
    r"(?:invalid user )?"
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\S+) port \d+ ssh2"
)

# main

## argparse

parser = argparse.ArgumentParser(
    description="Analyse SSH password authentication logs"
)

parser.add_argument("log_file", help="Path to the log file to analyse")

parser.add_argument(
    "--threshold",
    type=int,
    default=3,
    help="Number of failed attempts required to trigger an alert"
)

parser.add_argument(
    "--window",
    type=int,
    default=60,
    help="Time window in seconds for detecting repeated failures"
)
args = parser.parse_args()
if args.threshold < 1:
    parser.error("--threshold must be a positive integer")

if args.window < 1:
    parser.error("--window must be a positive integer")

## main loop

with open(args.log_file, "r", encoding="utf-8") as log_file:
    for line in log_file:
        match = auth_pattern.search(line)

        if match is None:
            unmatched_count += 1
            continue

        timestamp_text = line[:15]

        timestamp = datetime.strptime(
            timestamp_text,
            "%b %d %H:%M:%S"
        )

        username = match.group("username")
        source_ip = match.group("source_ip")
        outcome = match.group("outcome")

        if outcome == "Failed":
            failed_count += 1

            if source_ip not in failures_by_ip:
                failures_by_ip[source_ip] = 0

            failures_by_ip[source_ip] += 1

            if source_ip not in pending_failures_by_ip:
                pending_failures_by_ip[source_ip] = []

            pending_failures_by_ip[source_ip].append(line.strip())

            if source_ip not in failure_times_by_ip:
                failure_times_by_ip[source_ip] = []

            failure_times_by_ip[source_ip].append(timestamp)

            while (
                failure_times_by_ip[source_ip]
                and (timestamp - failure_times_by_ip[source_ip][0]).total_seconds() > args.window
            ):
                failure_times_by_ip[source_ip].pop(0)
                pending_failures_by_ip[source_ip].pop(0)

            current_failures = pending_failures_by_ip[source_ip]

            if len(current_failures) < args.threshold:
                active_failure_alerts_by_ip.pop(source_ip, None)

            else:
                alert_lines = [
                    f"ALERT: Repeated failed logins from {source_ip}",
                    "Suspicious log entries:"
                ]

                for failed_line in current_failures:
                    alert_lines.append(f"   [FAILED] {failed_line}")

                failure_alert = "\n".join(alert_lines)

                if source_ip in active_failure_alerts_by_ip:
                    index = active_failure_alerts_by_ip[source_ip]
                    alerts[index] = failure_alert

                else:
                    active_failure_alerts_by_ip[source_ip] = len(alerts)
                    alerts.append(failure_alert)

        elif outcome == "Accepted":
            successful_count += 1

            pending_failures = pending_failures_by_ip.get(source_ip, [])

            pending_times = failure_times_by_ip.get(source_ip, [])

            while (
                pending_times
                and (timestamp - pending_times[0]).total_seconds() > args.window
            ):
                pending_times.pop(0)
                pending_failures.pop(0)

            if len(pending_failures) >= args.threshold:
                alert_lines = [
                        f"ALERT: Suspicious successful login from {source_ip}",
                        "Suspicious log entries:"
                ]

                for failed_line in pending_failures:
                    alert_lines.append(f"   [FAILED] {failed_line}")

                alert_lines.append(f"   [ACCEPTED] {line.strip()}")

                success_alert = "\n".join(alert_lines)

                if source_ip in active_failure_alerts_by_ip:
                    index = active_failure_alerts_by_ip[source_ip]
                    alerts[index] = success_alert
                else:
                    alerts.append(success_alert)

            pending_failures_by_ip.pop(source_ip, None)
            failure_times_by_ip.pop(source_ip, None)
            active_failure_alerts_by_ip.pop(source_ip, None)

print("\n========== LOGCAIRN SUMMARY ==========")

print(f"Failed password attempts: {failed_count}")
print(f"Successful password attempts: {successful_count}")
print(f"Unmatched lines: {unmatched_count}")
print(f"Alert threshold: {args.threshold}")
print(f"Detection window: {args.window} seconds")

print("\nFailures by IP:")

for ip, count in failures_by_ip.items():
    print(f"  {ip}: {count} failed attempts")

print("\n========== SECURITY ALERTS ==========")

if alerts:
    for alert in alerts:
        print(f"\n{alert}")
else:
    print("No security alerts detected.")