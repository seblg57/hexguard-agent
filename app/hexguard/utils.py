# HexGuard Core - Proprietary License
# © 2024 Hexguard Inc. All rights reserved.
# This software is licensed, not sold, under the HexGuard Core License Agreement.
# Unauthorized copying, modification, or distribution of this file, via any medium, is strictly prohibited.

import os
import re
import sqlite3
import time
import ipaddress
import glob
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

DB_FILE = "/opt/hexguard-agent/hexguard/suspicious_ips.db"
LOG_AUDIT = '/var/log/audit/audit.log'
LOG_SECURE = '/var/log/secure'
LOG_MESSAGE = '/var/log/messages'
LOG_FIREWALLD = '/var/log/messages'
LOG_NGINX = '/var/log/nginx/access.log'
LOG_NGINX_ERROR = '/var/log/nginx/error.log'

audit_log_regex = r"exe=\"/usr/sbin/sshd\".*?addr=(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b).*?res=failed"
messages_log_regex = r"(?:failed|invalid|unauthorized).*?(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"
secure_log_regex = r"sshd.*?(?:Failed password for|Connection closed by).*?from (?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"
firewalld_log_regex = r"(FINAL_REJECT|filter_IN_public_REJECT).*SRC=(?P<ip>\d+\.\d+\.\d+\.\d+)"
nginx_log_regex = r'(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b) - - \[(?P<timestamp>.*?)\] \"(?P<method>\S+) (?P<url>\S+) HTTP/\d\.\d\" (?P<status_code>\d{3}) \d+ \"[^"]*\" \"(?P<user_agent>[^"]*)\"'
nginx_error_log_regex = r"\[crit\].*? (SSL_read|SSL_do_handshake)\(\) failed.*client: (?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"

bot_indicators = [
    "bot", "crawl", "spider", "Googlebot", "bingbot", "Slurp", "AhrefsBot",
    "python-requests", "Wget", "curl", "MJ12bot", "SemrushBot", "DuckDuckBot",
]

def init_database():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='suspicious_ips';")
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE suspicious_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    source TEXT NOT NULL
                )
            """)
            print("suspicious_ips table created and initialized.")
        else:
            print("suspicious_ips table already exists.")

def is_docker_ip(ip):
    docker_networks = [
        ipaddress.IPv4Network("172.17.0.0/16"),
        ipaddress.IPv4Network("172.18.0.0/16"),
        ipaddress.IPv4Network("172.19.0.0/16")
    ]
    return any(ipaddress.IPv4Address(ip) in network for network in docker_networks)

def insert_into_db(ip, timestamp, reason, category, severity, source):
    if ip == "0.0.0.0" or is_docker_ip(ip):
        return
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM suspicious_ips WHERE ip = ?", (ip,))
        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO suspicious_ips (ip, timestamp, reason, category, severity, source)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ip, timestamp, reason, category, severity, source))
            conn.commit()
            print(f"[+] New IOC: {ip} ({reason})")

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, parse_function, log_file_path):
        self.parse_function = parse_function
        self.log_file_path = log_file_path
        self._open_log_file()
        self.last_heartbeat = time.time()

    def _open_log_file(self):
        self.file = open(self.log_file_path, 'r')
        self.file.seek(0, 2)

    def on_modified(self, event):
        if event.src_path == self.log_file_path:
            for line in self.file:
                self.parse_function(line)

    def __del__(self):
        self.file.close()

logged_ips = set()

def parse_audit_log(line):
    match = re.search(audit_log_regex, line)
    if match:
        insert_into_db(match.group('ip'), datetime.now().strftime("%b %d %H:%M:%S"),
                       "Unauthorized", "SSH Login", 2, "Audit Log")

def parse_messages_log(line):
    match = re.search(messages_log_regex, line)
    if match:
        insert_into_db(match.group('ip'), datetime.now().strftime("%b %d %H:%M:%S"),
                       "Scan Attempt", "Suspicious", 1, "Messages")

def parse_secure_log(line):
    match = re.search(secure_log_regex, line)
    if match:
        ip = match.group('ip')
        if ip not in logged_ips:
            print(f"Found match with IP: {ip}")
            logged_ips.add(ip)
        reason = "SSH brute force" if "Failed password" in line else "SSH connection closed"
        severity = 3 if "Failed password" in line else 2
        insert_into_db(ip, datetime.now().strftime("%b %d %H:%M:%S"),
                       reason, "SSH", severity, "Secure")

def parse_firewalld_log(line):
    match = re.search(firewalld_log_regex, line)
    if match:
        insert_into_db(match.group('ip'), datetime.now().strftime("%b %d %H:%M:%S"),
                       "Firewall reject", "Firewall", 2, "Firewalld")

def parse_nginx_log(line):
    match = re.search(nginx_log_regex, line)
    if match:
        ip = match.group('ip')
        ua = match.group('user_agent')
        if any(bot in ua for bot in bot_indicators):
            insert_into_db(ip, match.group('timestamp'), "Bot activity", "Bots", 1, "Nginx")
        elif match.group('status_code').startswith('4') or match.group('status_code').startswith('5'):
            insert_into_db(ip, match.group('timestamp'), "Unauthorized access", "Web Access", 2, "Nginx")

def parse_nginx_log_error(line):
    match = re.search(nginx_error_log_regex, line)
    if match:
        insert_into_db(match.group('ip'), datetime.now().strftime("%b %d %H:%M:%S"),
                       "SSL handshake failed", "Web Access", 3, "Nginx Error")

def run_historical_parsing():
    parsed_files = set()

    def safe_parse_all_logs(glob_path, parser):
        for file_path in glob.glob(glob_path):
            if file_path in parsed_files:
                continue
            parsed_files.add(file_path)
            print(f"Parsing file: {file_path}")
            with open(file_path, 'r') as file:
                for line in file:
                    parser(line)

    safe_parse_all_logs('/var/log/audit/audit*', parse_audit_log)
    safe_parse_all_logs('/var/log/secure*', parse_secure_log)
    safe_parse_all_logs('/var/log/messages*', parse_messages_log)
    safe_parse_all_logs('/var/log/messages*', parse_firewalld_log)
    safe_parse_all_logs('/var/log/nginx/access.log*', parse_nginx_log)
    safe_parse_all_logs('/var/log/nginx/error.log*', parse_nginx_log_error)

    print("✅ Historical log parsing complete.")

def start_watchdog_monitoring(log_file, parse_function):
    if not os.path.exists(log_file):
        print(f"⚠️ File not found: {log_file} — skipping.")
        return None
    observer = Observer()
    event_handler = LogFileHandler(parse_function, log_file)
    observer.schedule(event_handler, path=os.path.dirname(log_file), recursive=False)
    observer.start()
    print(f"👁️ Started watchdog on: {log_file}")
    return observer

def start_monitoring():
    logs_and_parsers = [
        (LOG_AUDIT, parse_audit_log),
        (LOG_SECURE, parse_secure_log),
        (LOG_MESSAGE, parse_messages_log),
        (LOG_FIREWALLD, parse_firewalld_log),
        (LOG_NGINX, parse_nginx_log),
        (LOG_NGINX_ERROR, parse_nginx_log_error),
    ]

    observers = []
    for log_path, parser in logs_and_parsers:
        print(f"Setting up Watchdog monitoring for {log_path}")
        observer = start_watchdog_monitoring(log_path, parser)
        if observer:
            observers.append(observer)

    print("Monitoring setup complete.")
    return observers

