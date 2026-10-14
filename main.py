# imports
import re
import argparse


# initialisation + counters

failed_count = 0
successful_count = 0
unmatched_count = 0

failures_by_ip = {}
pending_failures_by_ip = {}

alerts = []

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
args = parser.parse_args()
if args.threshold < 1:
    parser.error("--threshold must be a positive integer")


## main loop

with open(args.log_file, "r", encoding="utf-8") as log_file:
    for line in log_file:
        match = auth_pattern.search(line)

        if match is None:
            unmatched_count += 1
            continue

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

        elif outcome == "Accepted":
            successful_count += 1

            pending_failures = pending_failures_by_ip.get(source_ip, [])

            if len(pending_failures) >= args.threshold:
                alert_lines = [
                        f"ALERT: Suspicious successful login from {source_ip}",
                        "Suspicious log entries:"
                ]

                for failed_line in pending_failures:
                    alert_lines.append(f"   [FAILED] {failed_line}")

                alert_lines.append(f"   [ACCEPTED] {line.strip()}")

                alerts.append("\n".join(alert_lines))

            pending_failures_by_ip.pop(source_ip, None)

print("\n========== LOGCAIRN SUMMARY ==========")

print(f"Failed password attempts: {failed_count}")
print(f"Successful password attempts: {successful_count}")
print(f"Unmatched lines: {unmatched_count}")

print("\nFailures by IP:")

failure_threshold = args.threshold

for ip, count in failures_by_ip.items():
    print(f"  {ip}: {count} failed attempts")

for ip, failed_lines in pending_failures_by_ip.items():
    if len(failed_lines) >= args.threshold:
        alert_lines = [
            f"ALERT: Repeated failed logins from {ip}",
            "Suspicious log entries:"
        ]


        for failed_line in failed_lines:
            alert_lines.append(f"   [FAILED] {failed_line}")

        alerts.append("\n".join(alert_lines))

print("\n========== SECURITY ALERTS ==========")

if alerts:
    for alert in alerts:
        print(f"\n{alert}")
else:
    print("No security alerts detected.")