failed_count = 0
successful_count = 0

with open("samples/ssh_sample.txt", "r", encoding="utf-8") as log_file:
    for line in log_file:
        if "Failed password" in line:
            failed_count += 1
        
        elif "Accepted password" in line:
            successful_count += 1

print(f"Failed password attempts: {failed_count}")
print(f"Successful password attempts: {successful_count}")