failed_count = 0
successful_count = 0

with open("samples/ssh_sample.txt", "r", encoding="utf-8") as log_file:
    for line in log_file:
        
        parts = line.split()
        
        username = parts[8]
        source_ip = parts[10]
        timestamp = parts[2]
        print(f"User: {username} | Source IP: {source_ip} | Time: {timestamp}")
        
        if "Failed password" in line:
            failed_count += 1
        
        elif "Accepted password" in line:
            successful_count += 1

print(f"Failed password attempts: {failed_count}")
print(f"Successful password attempts: {successful_count}")

