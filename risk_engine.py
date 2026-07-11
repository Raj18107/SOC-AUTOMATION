# risk_engine.py
# Member 2 — Dynamic Risk Scoring Engine

from config import WAZUH_MANAGER_IP, UBUNTU_TARGET_IP, WINDOWS_ANALYST_IP


def classify_group(alert):
    rule_id = int(alert.get("rule", {}).get("id", "0"))
    desc = alert.get("rule", {}).get("description", "").lower()
    groups_str = " ".join(alert.get("rule", {}).get("groups", [])).lower()

    # A — Authentication Attacks
    if 5500 <= rule_id <= 5799:
        return "A"
    if any(w in desc for w in ["ssh","authentication failed","brute","invalid user","login failure"]):
        return "A"
    if any(w in groups_str for w in ["authentication","sshd","pam"]):
        return "A"

    # B — Network Reconnaissance
    if 40100 <= rule_id <= 40200:
        return "B"
    if any(w in desc for w in ["scan","nmap","recon","sweep","probe","port scan"]):
        return "B"
    if any(w in groups_str for w in ["ids","scan","network"]):
        return "B"

    # E — Denial of Service
    if any(w in desc for w in ["syn flood","dos attack","ddos","denial of service","flood detected"]):
        return "E"

    # F — Lateral Movement
    if any(w in desc for w in ["lateral movement","smb","pass-the-hash","psexec","wmi exec","remote exec"]):
        return "F"

    # G — Privilege Escalation
    if any(w in desc for w in ["privilege escalation","sudo","setuid","root access","elevation of privilege"]):
        return "G"

    # H — Web Application Attacks
    if any(w in desc for w in ["sql injection","xss","cross-site","web attack","sqli","command injection"]):
        return "H"

    # J — Rootkit / Persistence (checked before C: more specific than generic malware terms)
    if any(w in desc for w in ["rootkit","hidden process","hidden file","ld.so.preload","kernel module","backdoor"]):
        return "J"
    if any(w in desc for w in ["cron persistence","unauthorized startup","unauthorized cron"]):
        return "J"

    # C — Malware / Malicious Processes
    if any(w in desc for w in ["malware","trojan","exploit","payload","ransomware","cryptominer","xmrig","miner","c2","command and control","reverse shell","bind shell","botnet","malicious process"]):
        return "C"

    # D — File Integrity Violations
    if 550 <= rule_id <= 599:
        return "D"
    if any(w in desc for w in ["file","integrity","syscheck","modified","deleted"]):
        return "D"

    # I — Data Exfiltration
    if any(w in desc for w in ["exfiltration","data transfer","bulk upload","large transfer","unusual upload"]):
        return "I"

    return "B"


ASSET_IMPORTANCE = {
    WAZUH_MANAGER_IP:   10,
    UBUNTU_TARGET_IP:    7,
    WINDOWS_ANALYST_IP:  3,
    "192.168.56.30":  2,
    "unknown":           5,
}


def get_asset_importance(alert):
    agent_ip = alert.get("agent", {}).get("ip", "unknown")
    if agent_ip in ASSET_IMPORTANCE:
        return ASSET_IMPORTANCE[agent_ip]
    for known_ip, score in ASSET_IMPORTANCE.items():
        if known_ip != "unknown" and agent_ip.split(".")[:3] == known_ip.split(".")[:3]:
            return score
    return ASSET_IMPORTANCE["unknown"]


def get_context_score(alert):
    level = alert.get("rule", {}).get("level", 1)
    if level >= 13: return 10
    if level >= 10: return 8
    if level >= 7:  return 6
    if level >= 4:  return 3
    return 1


def get_risk_label(score):
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"


def get_confidence(severity, importance, context):
    signals = 0
    if severity >= 7:   signals += 1
    if importance >= 7: signals += 1
    if context >= 6:    signals += 1
    if signals >= 3:    return "HIGH"
    if signals >= 2:    return "MEDIUM"
    return "LOW"


def calculate_risk(alert):
    severity   = min(10, int(alert.get("rule", {}).get("level", 1)))
    importance = get_asset_importance(alert)
    context    = get_context_score(alert)
    group      = classify_group(alert)
    raw_score  = severity * importance * context
    score      = min(100, round(raw_score / 10))
    label      = get_risk_label(score)
    confidence = get_confidence(severity, importance, context)

    return {
        "score":      score,
        "label":      label,
        "confidence": confidence,
        "group":      group,
        "severity":   severity,
        "importance": importance,
        "context":    context,
        "raw":        raw_score,
    }


GROUP_NAMES = {
    "A": "Authentication Attack",
    "B": "Network Reconnaissance",
    "C": "Malware / Process",
    "D": "File Integrity Violation",
    "E": "Denial of Service",
    "F": "Lateral Movement",
    "G": "Privilege Escalation",
    "H": "Web Application Attack",
    "I": "Data Exfiltration",
    "J": "Rootkit / Persistence",
}


if __name__ == "__main__":
    print("=" * 65)
    print("Testing risk_engine.py")
    print("=" * 65)
    tests = [
        {
            "label": "1. SSH brute-force on Ubuntu Target -> expect Group A, score ~56",
            "alert": {
                "rule": {"id": "5712","level":10,"description":"sshd: brute force","groups":["authentication","sshd"]},
                "agent": {"ip": "192.168.56.102"},
            }
        },
        {
            "label": "2. SSH brute-force on Wazuh Manager -> expect Group A, score ~80",
            "alert": {
                "rule": {"id": "5712","level":10,"description":"sshd: brute force","groups":["authentication","sshd"]},
                "agent": {"ip": "192.168.56.101"},
            }
        },
        {
            "label": "3. Nmap scan -> expect Group B",
            "alert": {
                "rule": {"id": "40101","level":8,"description":"nmap port scan detected","groups":["ids","scan"]},
                "agent": {"ip": "192.168.56.102"},
            }
        },
        {
            "label": "4. Cryptominer -> expect Group C",
            "alert": {
                "rule": {"id": "100200","level":12,"description":"Cryptominer xmrig detected running","groups":[]},
                "agent": {"ip": "192.168.56.102"},
            }
        },
        {
            "label": "5. SYN flood -> expect Group E",
            "alert": {
                "rule": {"id": "100300","level":10,"description":"SYN flood attack detected","groups":[]},
                "agent": {"ip": "192.168.56.102"},
            }
        },
        {
            "label": "6. Rootkit -> expect Group J",
            "alert": {
                "rule": {"id": "100800","level":13,"description":"Rootkit detected hidden process ld.so.preload modified","groups":[]},
                "agent": {"ip": "192.168.56.102"},
            }
        },
    ]
    for tc in tests:
        r = calculate_risk(tc["alert"])
        print(f"  {tc['label']}")
        print(f"    Group={r['group']}  Score={r['score']:3d}/100  Label={r['label']}  Confidence={r['confidence']}")
        print()
