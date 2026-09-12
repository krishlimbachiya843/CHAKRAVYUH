# ⚔ CHAKRAVYUH

### *The Trap That Never Releases*

A multi-protocol honeypot system for real-time attack detection and threat intelligence.

---

## 🎯 Features

- **Multi-Protocol** — HTTP, FTP, SSH honeypots
- **Real-Time Logging** — SQLite database
- **Pattern Recognition** — Detects 20+ hacking tools
- **IP Geolocation** — Country, city, ISP
- **Live Dashboard** — Cyberpunk-style UI
- **Thread-Safe** — Handles concurrent attacks

---

## 🚀 Installation

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py

Open browser: http://127.0.0.1:5000

🎮 Usage
Click START on each honeypot card
Simulate attacks
Watch attacks appear in real-time

Test Attacks
# HTTP
curl -A "sqlmap/1.7" http://127.0.0.1:8080/

# FTP
python attack_ftp.py

# SSH
ssh -p 2222 root@127.0.0.1

📁 Project Structure

CHAKRAVYUH/
├── app.py                  # Main Flask server
├── requirements.txt        # Dependencies
├── attack_ftp.py          # FTP test script
├── core/
│   ├── logger.py          # Attack logging
│   ├── manager.py         # Service manager
│   ├── geoip.py           # Geolocation
│   └── patterns.py        # Pattern recognition
├── listeners/
│   ├── http_listener.py   # HTTP honeypot
│   ├── ftp_listener.py    # FTP honeypot
│   └── ssh_listener.py    # SSH honeypot
└── templates/
    └── dashboard.html     # Web UI

🛠️ Tech Stack
Component	Technology
Backend	Python, Flask
SSH	Paramiko
Database	SQLite
Frontend	HTML, CSS, JS
Concurrency	Threading

🧠 Detected Tools
sqlmap, Metasploit, Hydra, Nikto, Nmap, Nessus, Gobuster, Burp Suite, OWASP ZAP, and more.

🔒 Legal
For educational and authorized security testing only. Deploy only on networks you own or have permission to monitor.

👨‍💻 Author
krish limbachiya
Sankalchand Patel University (SPU)
krishlimbachiya843@gmail.com
