#!/bin/bash

# Run historical parse for each log file from the beginning
python3 -c "
from utils import parse_log_file_once, parse_audit_log, parse_messages_log, parse_secure_log, parse_nginx_log
LOG_AUDIT = '/var/log/audit/audit.log'
LOG_MESSAGE = '/var/log/messages'
LOG_SECURE = '/var/log/secure'
LOG_NGINX = '/var/log/nginx/access.log'

parse_log_file_once(LOG_AUDIT, parse_audit_log)
parse_log_file_once(LOG_MESSAGE, parse_messages_log)
parse_log_file_once(LOG_SECURE, parse_secure_log)
parse_log_file_once(LOG_NGINX, parse_nginx_log)
"