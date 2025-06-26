import re

# Define the path of the log file
log_file_path = '/var/log/messages'

messages_log_regex = r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*(FINAL_REJECT|filter_IN_public_REJECT).*SRC=(?P<ip>\d+\.\d+\.\d+\.\d+)" 



def parse_messages_log(file_path):
    # Open the log file for reading
    with open(file_path, 'r') as file:
        print(f"Parsing {file_path}...")
        # Loop through each line in the file
        for line in file:
            # Use regex to find matches for the SRC IPs
            matches = re.findall(messages_log_regex, line)
            if matches:
                # Print each matched IP
                for ip in matches:
                    print(f"Timestamp: {line.split()[0]} {line.split()[1]} - IP Address: {ip}")

# Call the function to parse the log file
parse_messages_log(log_file_path)

