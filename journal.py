import datetime






def parse_audit_log(line):
    # Updated regex to avoid capturing "type=USER_LOGIN msg=audit(...)" and exclude entries with "success"
    audit_log_regex = r"(?P<timestamp>\b\w{3}\s+\d+\s+\d+:\d+:\d+\b).*?exe=\"/usr/sbin/sshd\".*?addr=(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b).*?res=failed"
    match = re.search(audit_log_regex, line)
    
    if match:
        timestamp = match.group("timestamp")  # Extract the human-readable timestamp
        ip = match.group("ip")  # Extract the IP address

        print(f"Timestamp: {timestamp} - IP Address: {ip}")
