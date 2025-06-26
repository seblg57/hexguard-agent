# HexGuard Agent

**HexGuard Agent** is a lightweight threat intelligence sensor designed to passively collect IOCs (Indicators of Compromise) from honeypots and external sources. It is intended to run on hosts like **TARentula** and send enriched data to **DeathWeb** or other threat analysis platforms.





![Screenshot_1116](https://github.com/user-attachments/assets/443d5beb-a1dd-49c4-86f9-a662d3a5d1be)


---

## ⚙️ Features

- Passive IOC collection from honeypots and system logs
- Modular architecture for adding new data sources
- Output in JSON or database-ready format
- Optional integration with DeathWeb’s enrichment pipeline

---

## ⚙️ Features

- Passive IOC collection from honeypots and system logs
- Modular architecture for adding new data sources
- Output in JSON or database-ready format
- Optional integration with DeathWeb’s enrichment pipeline

---

## 📁 Project Structure

hexguard-agent/
├── agent.py # Main agent script (entry point)
├── config.yaml # Configuration file
├── collector/ # Source-specific collectors
├── output/ # Output logic (file, API, DB, etc.)
└── README.md # You're reading it


## Customize config
Edit config.yaml to specify:

Collection interval

Output method (JSON, API, DB)

Log level, etc.

📌 Roadmap
 Add syslog/snort/suricata integration

 Implement REST API push to DeathWeb

 Dockerize the agent

 Unit test coverage

🤝 Integration
HexGuard Agent is designed to feed data into the DeathWeb framework.

📄 License
This project is currently private. License to be defined.
