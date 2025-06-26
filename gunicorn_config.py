# gunicorn_config.py

import os
from utils import init_database, run_historical_parsing, start_watchdog_monitoring, LOG_AUDIT, LOG_SECURE, LOG_MESSAGE, LOG_FIREWALLD, LOG_NGINX, LOG_NGINX_ERROR, parse_audit_log, parse_secure_log, parse_messages_log, parse_firewalld_log, parse_nginx_log, parse_nginx_log_error

# Specify the bind address and port
bind = "0.0.0.0:5000"

# Number of worker processes
workers = 4

# SSL configuration
certfile = "/etc/ssl/certs/fullchain.pem"
keyfile = "/etc/ssl/private/privkey.pem"

# Define log files and their respective parsing functions
log_file_parsers = {
    LOG_AUDIT: parse_audit_log,
    LOG_SECURE: parse_secure_log,
    LOG_MESSAGE: parse_messages_log,
    LOG_FIREWALLD: parse_firewalld_log,
    LOG_NGINX: parse_nginx_log,
    LOG_NGINX_ERROR: parse_nginx_log_error,
}

# Define on_starting hook for Gunicorn
def on_starting(server):
    print("Starting up Gunicorn, initializing database and running historical log parsing...")
    init_database()
    run_historical_parsing()
    print("Historical parsing complete. Setting up real-time monitoring...")

    # Start monitoring for each log file
    for log_file, parse_function in log_file_parsers.items():
        print(f"Setting up Watchdog monitoring for {log_file}")
        start_watchdog_monitoring(log_file, parse_function)

    print("Monitoring setup complete.")

