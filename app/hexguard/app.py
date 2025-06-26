# HexGuard Core - Proprietary License
# © 2024 [Your Company/Your Name]. All rights reserved.

import sqlite3
from flask import Flask, jsonify
from threading import Thread
from utils import (
    start_monitoring,  # Use the watchdog-based monitoring function
    DB_FILE,
)

app = Flask(__name__)

@app.route('/suspicious_ips/list', methods=['GET'])
def get_suspicious_ips_list():
    """Endpoint to retrieve the list of suspicious IPs from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM suspicious_ips")
    rows = cursor.fetchall()
    conn.close()

    indicators = [
        {
            "id": row[0],
            "ip": row[1],
            "timestamp": row[2],
            "reason": row[3],
            "category": row[4],
            "severity": row[5],
            "source": row[6],
        }
        for row in rows
    ]

    return jsonify(indicators)

if __name__ == "__main__":
    # Start the log monitoring in a separate thread
    Thread(target=start_monitoring).start()  # This calls the function in utils.py

    # Start the Flask application
    app.run(host="0.0.0.0", port=5000, ssl_context=("/etc/ssl/certs/fullchain.pem", "/etc/ssl/private/privkey.pem"))

