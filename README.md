# 🕵️ Stealthy Sniffer — Network Packet Sniffer with Encryption Detection

**Author:** Sameer Shaikh  
**Project:** 1-month Penetration Tester Internship — Deltaware Solutions Pvt. Ltd.  
**Date:** 2025-09-13

---

## 📌 Project Summary
**Stealthy Sniffer** is a lightweight Python/Scapy tool designed for lab-based penetration testing and learning.  
It captures TCP traffic, classifies sessions as **Encrypted ✅**, **Plaintext ❌**, or **Unclassified (Port X)**, extracts credentials from plaintext HTTP POSTs, and detects simple suspicious patterns (brute-force and DoS) using sliding time windows. Results are logged to CSV and can be analyzed to produce graphs and a short report.

> **Important:** This project is for educational and authorized-lab use only. Do **not** run this on networks you do not own or have explicit permission to monitor.

---

## ✨ Key Features
- Capture traffic on multiple interfaces (default: `lo`, `eth0`).
- Port- and payload-aware encryption classification (Encrypted / Plaintext / Unclassified).
- Extract HTTP POST credentials (username/password) from plaintext traffic for demonstration.
- Sliding-window detection:
  - Brute-force detection: `N` login attempts within `T` seconds triggers an alert.
  - DoS detection: `M` packets within `T` seconds triggers an alert.
- Structured CSV logging for evidence and analysis.
- Simple report generator to create visualization images (bar/pie charts).
- Minimal dependencies; easy to run in a controlled lab.

---

## 🗂 Repository Structure

Stealthy-Sniffer/
├── sniff.py # Main sniffer (sliding-window detection)
├── test_http.py # Flask demo server (HTTP login form)
├── analyze_report.py # Reads CSV and creates graphs
├── captured_traffic_sample.csv # Sanitized sample CSV (safe to commit)
├── encryption_stats.png # Example output graph (optional)
├── suspicious_stats.png # Example output graph (optional)
├── project_report.md # Full project write-up (export to PDF)
├── poc/ # PoC materials: script, screenshots
│ ├── PoC_script.txt
│ └── screenshots/
├── requirements.txt
├── README.md
└── .gitignore


---

## ⚙️ Requirements
- Python 3.8+ (3.13 recommended)
- Libraries:
  ```text
  scapy
  flask
  pandas
  matplotlib

    Install quickly with:

    pip install -r requirements.txt

requirements.txt example:

scapy
flask
pandas
matplotlib

🧭 Quick Start (lab/demo)

    Note: Run the sniffer in a controlled environment (your VM / local machine). Use captured_traffic_sample.csv for examples — never commit real captured credentials.

    Start demo HTTP server (in terminal A):

python3 test_http.py

Open http://127.0.0.1:8080 and you will see a simple login form.

Run the sniffer (in terminal B — requires root to capture packets):

sudo python3 sniff.py

    Default listens on ["lo", "eth0"]. If your interface has another name (e.g., ens33, wlan0), edit sniff.py accordingly.

Generate demo traffic (in terminal C or browser):

    Single POST:

curl -s -X POST -d "username=demo&password=one" http://127.0.0.1:8080/login

Brute-force demo (5 quick wrong logins):

for i in 1 2 3 4 5; do curl -s -X POST -d "username=tester&password=wrong$i" http://127.0.0.1:8080/login >/dev/null; done

DoS demo (lab-only; causes many quick requests):

for i in {1..150}; do curl -s http://127.0.0.1:8080/ >/dev/null & done; wait

HTTPS metadata (no credentials):

    curl -sI https://example.com >/dev/null

Stop sniffer with Ctrl+C if it runs indefinitely.

Analyze results:

    python3 analyze_report.py

    This script reads captured_traffic.csv and produces encryption_stats.png and suspicious_stats.png.

🔍 Example Output (what to expect)

    Console (sniffer):

[!] Credential Captured: demo:one  (127.0.0.1 -> 127.0.0.1:8080)
2025-09-12 19:11:06 127.0.0.1 -> 127.0.0.1:8080 [Plaintext ❌] Possible Brute Force 🚨; High Traffic (DoS?) ⚠️ has-payload;

CSV (sample):

    Timestamp,SrcIP,DstIP,DstPort,Encryption,Username,Password,Suspicious,Notes
    2025-09-12 19:10:50,10.0.2.15,10.0.2.15,8080,Plaintext ❌,demo_user,demo_pass,,
    2025-09-12 19:11:06,10.0.2.15,10.0.2.15,8080,Plaintext ❌,tester,wrong1,Possible Brute Force 🚨,credentials-found;bf-window-triggered;

    Graphs:

        encryption_stats.png — shows distribution of Encrypted vs Plaintext vs Unclassified traffic.

        suspicious_stats.png — shows count of suspicious events (Brute Force / DoS).

🛡 Safety & Privacy (must read)

    Never commit actual captured_traffic.csv containing real credentials. Use captured_traffic_sample.csv for examples.

    Only sniff networks you own or where you have explicit permission.

    For submission, store recordings and reports on Google Drive and set sharing to “Anyone with the link” (as required by Deltaware).

🧩 How It Works (brief technical notes)

    Capture: Scapy sniff() listens on configured interfaces and invokes a callback per packet.

    Classification: Basic port lists mark common encrypted/plaintext services. TLS handshake detection can be added for better accuracy.

    Credential extraction: The script looks for HTTP POST payloads and extracts fields like username, user, email, password, pass, pwd using regex.

    Sliding windows: Per-IP deque of timestamps is used to detect N events within T seconds for brute-force and DoS detection to avoid cumulative false positives.

    Logging: Each relevant packet is appended to a CSV with timestamp, IPs, port, encryption label, credentials (if found), and suspicious notes.

🛠 Tuning & Improvements (future work)

    Add TLS ClientHello detection to identify TLS on non-standard ports.

    Expand credential field detection (e.g., email, login, token).

    Export alerts to external systems (Slack / Email) for real-time notifications.

    Implement log rotation and persistent storage (Elasticsearch / SQLite).

    Containerize tool and add command-line arguments (--iface, --duration, --bf-thresh).

