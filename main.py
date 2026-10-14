# imports
import re
import argparse


# initialisation + counters

failed_count = 0
successful_count = 0
unmatched_count = 0

failures_by_ip = {}

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
        
        print(f"User: {username} | Source IP: {source_ip} | Outcome: {outcome}")
        
        if outcome == "Failed":
            failed_count += 1
            
            if source_ip not in failures_by_ip:
                failures_by_ip[source_ip] = 0
                
            failures_by_ip[source_ip] += 1
            
        elif outcome == "Accepted":
            successful_count += 1

print(f"Failed password attempts: {failed_count}")
print(f"Successful password attempts: {successful_count}")
print(f"Failures by IP: {failures_by_ip}")
print(f"Unmatched lines: {unmatched_count}")

failure_threshold = args.threshold

for ip, count in failures_by_ip.items():
    if count >= failure_threshold:
        print(f"ALERT: {ip} recorded {count} failed password attempts.")

