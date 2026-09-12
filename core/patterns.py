"""
CHAKRAVYUH - Attack Pattern Recognition
=======================================

Signature-based engine that identifies common attack tools and
techniques from honeypot telemetry.

Detection Sources:
    - HTTP User-Agent headers
    - FTP/SSH usernames and passwords (brute-force indicators)
    - Raw request payloads

The engine returns a structured assessment including:
    - Attack type (e.g., "SQL Injection Scanner")
    - Identified tool (e.g., "sqlmap")
    - Severity level (LOW / MEDIUM / HIGH / CRITICAL)
    - List of human-readable indicators
"""

# ---------------------------------------------------------------------------
# Signature Database
# ---------------------------------------------------------------------------
# Maps substrings found in telemetry to attack metadata.

SIGNATURES = {
    # Web scanners / exploit frameworks
    "sqlmap":      {"type": "SQL Injection Scanner",       "severity": "HIGH",     "tool": "sqlmap"},
    "nikto":       {"type": "Web Vulnerability Scanner",   "severity": "HIGH",     "tool": "Nikto"},
    "nmap":        {"type": "Port Scanner",                "severity": "MEDIUM",   "tool": "Nmap"},
    "masscan":     {"type": "Port Scanner",                "severity": "MEDIUM",   "tool": "Masscan"},
    "acunetix":    {"type": "Web Vulnerability Scanner",   "severity": "HIGH",     "tool": "Acunetix"},
    "nessus":      {"type": "Vulnerability Scanner",       "severity": "HIGH",     "tool": "Nessus"},
    "openvas":     {"type": "Vulnerability Scanner",       "severity": "HIGH",     "tool": "OpenVAS"},
    "metasploit":  {"type": "Exploit Framework",           "severity": "CRITICAL", "tool": "Metasploit"},
    "hydra":       {"type": "Brute Force Tool",            "severity": "CRITICAL", "tool": "Hydra"},
    "medusa":      {"type": "Brute Force Tool",            "severity": "CRITICAL", "tool": "Medusa"},
    "patator":     {"type": "Brute Force Tool",            "severity": "CRITICAL", "tool": "Patator"},
    "gobuster":    {"type": "Directory Bruteforcer",       "severity": "HIGH",     "tool": "Gobuster"},
    "dirb":        {"type": "Directory Bruteforcer",       "severity": "HIGH",     "tool": "Dirb"},
    "wfuzz":       {"type": "Web Fuzzer",                  "severity": "HIGH",     "tool": "WFuzz"},
    "burp":        {"type": "Burp Suite",                  "severity": "HIGH",     "tool": "Burp Suite"},
    "zaproxy":     {"type": "OWASP ZAP",                   "severity": "HIGH",     "tool": "ZAP"},
    "zgrab":       {"type": "Network Scanner",             "severity": "MEDIUM",   "tool": "ZGrab"},
    # Common legitimate clients (useful as baseline)
    "python-requests": {"type": "Scripted Attack",         "severity": "LOW",      "tool": "Python Requests"},
    "curl":        {"type": "Manual Probe",                "severity": "LOW",      "tool": "curl"},
    "wget":        {"type": "Manual Probe",                "severity": "LOW",      "tool": "wget"},
    "go-http-client": {"type": "Automated Scanner",        "severity": "MEDIUM",   "tool": "Go HTTP Client"},
}

WEAK_PASSWORDS = {
    "admin", "admin123", "password", "123456", "root", "toor",
    "1234", "qwerty", "letmein", "welcome", "pass", "test",
    "guest", "user", "default", "12345", "12345678", "abc123",
    "adminadmin", "root123"
}

COMMON_USERNAMES = {
    "root", "admin", "administrator", "test", "user", "guest",
    "oracle", "postgres", "mysql", "ubuntu", "pi", "vagrant",
    "support", "www", "ftp"
}


# ---------------------------------------------------------------------------
# Analysis Engine
# ---------------------------------------------------------------------------

def analyze_attack_pattern(protocol: str = "",
                           user_agent: str = "",
                           username: str = "",
                           password: str = "",
                           raw_data: str = "") -> dict:
    """
    Analyze attack telemetry and return a structured assessment.

    Parameters
    ----------
    protocol : str
        Protocol name (e.g., "HTTP", "FTP", "SSH").
    user_agent : str
        HTTP User-Agent header, if applicable.
    username : str
        Username submitted by the attacker.
    password : str
        Password submitted by the attacker.
    raw_data : str
        Full raw request/command payload.

    Returns
    -------
    dict
        Keys: detected, tool, type, severity, indicators.
    """
    result = {
        "detected": False,
        "tool": "Unknown",
        "type": "Unknown Activity",
        "severity": "LOW",
        "indicators": []
    }

    combined = f"{user_agent} {username} {password} {raw_data}".lower()

    # 1. Signature-based detection
    for signature, meta in SIGNATURES.items():
        if signature in combined:
            result["detected"] = True
            result["tool"] = meta["tool"]
            result["type"] = meta["type"]
            result["severity"] = meta["severity"]
            result["indicators"].append(f"Signature match: {signature}")
            break

    # 2. Weak password detection (brute-force indicator)
    if password and password.lower() in WEAK_PASSWORDS:
        result["detected"] = True
        result["indicators"].append(f"Weak password attempt: {password}")
        if result["severity"] == "LOW":
            result["severity"] = "MEDIUM"
        if result["type"] == "Unknown Activity":
            result["type"] = "Credential Attack"

    # 3. Common username detection
    if username and username.lower() in COMMON_USERNAMES:
        result["indicators"].append(f"Common username: {username}")

    # 4. Protocol-specific escalation
    if protocol == "SSH" and username and password:
        result["detected"] = True
        if result["severity"] in ("LOW", "MEDIUM"):
            result["severity"] = "HIGH"
        if result["type"] == "Unknown Activity":
            result["type"] = "SSH Brute Force Attempt"

    return result