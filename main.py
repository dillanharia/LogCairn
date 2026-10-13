# imports
import re


# initialisation
failed_count = 0
successful_count = 0

failures_by_ip = {}

# regex
auth_pattern = re.compile(
    r"(?P<outcome>Failed|Accepted) password for "
    r"(?:invalid user )?"
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\S+) port \d+ ssh2"
)


# main 

with open("samples/ssh_sample.txt", "r", encoding="utf-8") as log_file:
    for line in log_file:
        match = auth_pattern.search(line)
        
        if match is None:
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

failure_threshold = 3

for ip, count in failures_by_ip.items():
    if count >= failure_threshold:
        print(f"ALERT: {ip} recorded {count} failed password attempts.")

