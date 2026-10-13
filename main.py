failed_count = 0
successful_count = 0

failures_by_ip = {}

with open("samples/ssh_sample.txt", "r", encoding="utf-8") as log_file:
    for line in log_file:
        
        parts = line.split()
        
        username = parts[8]
        source_ip = parts[10]
        timestamp = parts[2]
        print(f"User: {username} | Source IP: {source_ip} | Time: {timestamp}")
        
        if "Failed password" in line:
            failed_count += 1
            
            if source_ip not in failures_by_ip:
                failures_by_ip[source_ip] = 0
            
            failures_by_ip[source_ip] += 1
        
        elif "Accepted password" in line:
            successful_count += 1

print(f"Failed password attempts: {failed_count}")
print(f"Successful password attempts: {successful_count}")
print(f"Failures by IP: {failures_by_ip}")

failure_threshold = 3

for ip, count in failures_by_ip.items():
    if count >= failure_threshold:
        print(f"ALERT: {ip} recorded {count} failed password attempts.")

