# SOC-AUTOMATION

**An automated Wazuh-powered SOC pipeline — from raw alert to verified remediation, with a live dashboard.**

---

## Project Summary

I designed and built the automated response core of this SOC homelab as part of a four-person team project at Offenso Hackers Academy. My work covers the system's risk logic and remediation engine: a custom risk engine that scores Wazuh alerts from 0–100 and classifies them into ten attack categories, ten response playbooks that route each category to the correct remediation, an SSH-based action engine that executes and verifies those remediations on a target host, and a human-approval workflow that pauses high-risk actions for analyst review before anything destructive runs. I also handled the Wazuh deployment and REST API integration, and used Kali Linux to simulate real attacks — SSH brute-force, file integrity violations — to test and validate the entire pipeline end-to-end.

---

## My Contributions

This was a four-person team project. Here's the breakdown of what I personally designed and built, versus work done by teammates — included so the README accurately reflects individual ownership.

**Designed and implemented by me** (Python implementation built with AI-assisted development; design, integration, testing, and debugging done by me):
- Wazuh deployment and Manager/Agent integration
- Wazuh REST API integration (`wazuh_api.py`) — alert retrieval, authentication, pagination
- Pipeline orchestration (`main_pipeline.py`)
- Risk scoring engine (`risk_engine.py`) — weighted 0–100 scoring, 10-category classification
- Response playbooks for Groups A–J (`playbook_groupA.py`, `playbook_groupB.py`, `playbook_groupCDEFGHIJ.py`)
- Action engine (`action_engine.py`) — SSH-based remote command execution via Paramiko
- Post-fix verification logic (`post_fix_checks.py`)
- Attack simulation, testing, and troubleshooting (Kali Linux against the Ubuntu target)

**Built by teammates:**
- Streamlit dashboard (`dashboard.py`)
- SQLite database design and `DatabaseManager` class (`database.py`)

The full project is included here for context and to show how my components fit into the larger system — but the breakdown above is the accurate picture of individual ownership.

---

## Overview

SOC-AUTOMATION is an end-to-end Security Operations Center (SOC) automation platform built around Wazuh. It continuously ingests security alerts, scores them by risk, classifies them into attack categories, runs an automated (or human-approved) response playbook, verifies that the fix actually worked, and displays the whole incident lifecycle on a live dashboard.

It was built as a hands-on demonstration of how a modern SOC pipeline goes from **detection → decision → action → verification**, rather than stopping at alerting.

**Stack:** Wazuh Manager · Wazuh Agent · Wazuh API · Wazuh Indexer (OpenSearch) · Filebeat · Python · SQLite · Streamlit

---

## Architecture

```
Attacker (Kali)
      │
      ▼
Ubuntu Target (Wazuh Agent)
      │
      ▼
Wazuh Manager → Filebeat → Wazuh Indexer (OpenSearch)
      │
      ▼
Wazuh API
      │
      ▼
Python SOC Pipeline → Risk Engine → Playbooks (A–J) → Action Engine → Post-Fix Verification
      │
      ▼
SQLite  →  Streamlit Dashboard
```

---

## Key Features

**Security Monitoring**
- Authentication monitoring, file integrity monitoring, privilege escalation and network activity detection via Wazuh Agent

**Dynamic Risk Scoring**
- Every alert is scored using severity, asset importance, and context, then bucketed into `INFO → LOW → MEDIUM → HIGH → CRITICAL`

**Attack Classification (Groups A–J)**
- Authentication Attacks, Reconnaissance, Malware, File Integrity Violations, Denial of Service, Lateral Movement, Privilege Escalation, Web Attacks, Data Exfiltration, Persistence/Rootkits

**Automated Response**
- Block attacker IP, rate-limit suspicious traffic, isolate compromised hosts, kill malicious processes, raise SOC alerts

**Human-in-the-Loop Approval**
- High-risk actions can be paused, approved, or rejected before they're executed — nothing destructive happens silently

**Post-Fix Verification**
- Confirms the remediation actually took effect: checks `iptables` rules, `fail2ban` bans, killed processes, sudo policy

**Live Dashboard (Streamlit)**
- Real-time incidents, risk scores, alert history, the approval queue, and incident reporting

---
<img width="1081" height="610" alt="Screenshot 2026-06-20 170353" src="https://github.com/user-attachments/assets/74ddf6a7-1c53-4b64-afc3-b60605d72540" />
<img width="1112" height="617" alt="Screenshot 2026-06-20 171104" src="https://github.com/user-attachments/assets/9709764e-8e79-4602-a29d-42029bb8a72c" />
<img width="1206" height="608" alt="Screenshot 2026-06-20 171334" src="https://github.com/user-attachments/assets/dffa6d16-684c-4c44-a2d7-794bb4380b35" />
<img width="1092" height="611" alt="Screenshot 2026-06-20 171423" src="https://github.com/user-attachments/assets/cc7eeaa9-61e8-40c7-a6ad-03a12c0ac641" />

<img width="1087" height="603" alt="Screenshot 2026-06-20 171448" src="https://github.com/user-attachments/assets/4c9dc46c-4fdf-49d0-a43a-338f74d56f21" />
<img width="1421" height="637" alt="Screenshot 2026-06-20 171549" src="https://github.com/user-attachments/assets/be66b14c-7518-464f-ae62-ba3718eb6f6d" />


## Skills Demonstrated

- **SIEM Integration** — Wazuh deployment, Manager/Agent configuration, REST API consumption
- **Risk-Based Alert Prioritization** — custom weighted scoring algorithm, threat classification taxonomy
- **Automated Incident Response (SOAR-style)** — playbook design across 10 attack categories
- **Remote Systems Automation** — SSH command execution and key-based authentication via Paramiko
- **Post-Remediation Verification** — confirming automated fixes actually took effect, not just assuming success
- **Security Governance** — human-approval workflow gating high-risk automated actions
- **Offensive Security Testing** — attack simulation with Kali Linux (SSH brute force, file integrity violations) to validate detection and response
- **Linux Administration** — `iptables`, `fail2ban`, and process management on the target host

---

## Prerequisites

- Python 3.10+
- A working Wazuh deployment: Manager + Agent (tested on the Wazuh OVA, Ubuntu-based)
- Wazuh Indexer (OpenSearch) reachable on port `9200`
- Filebeat configured to ship Manager logs to the Indexer
- pip dependencies listed in `requirements.txt`

## Installation

```bash
git clone <your-repo-url>
cd SOC-AUTOMATION
pip install -r requirements.txt
```

Create a `.env` file in the project root — **never commit this file**:

```env
WAZUH_URL=https://<manager-ip>:55000
WAZUH_USER=<username>
WAZUH_PASS=<password>

INDEXER_URL=https://<indexer-ip>:9200
INDEXER_USER=<username>
INDEXER_PASS=<password>
```

Copy the config template and fill in your own lab IPs — **`config.py` is also gitignored, never committed**:

```bash
cp config.example.py config.py      # Mac/Linux
copy config.example.py config.py    # Windows CMD
```

Then edit `config.py` with your own `WAZUH_MANAGER_IP`, `UBUNTU_TARGET_IP`, and `WINDOWS_ANALYST_IP`.

---

## Usage

Run the pipeline and the dashboard from two separate terminals:

```bash
# Terminal 1 — the SOC pipeline (pulls alerts, scores, runs playbooks)
python main_pipeline.py

# Terminal 2 — the live dashboard
python -m streamlit run dashboard.py
```

**Example end-to-end flow:**

1. An attacker runs an SSH brute-force attempt against the monitored Ubuntu target.
2. The Wazuh Agent forwards the relevant logs to the Manager.
3. The Manager generates an alert.
4. The pipeline retrieves the alert via the Wazuh API.
5. The Risk Engine scores it and classifies it (e.g. Group A — Authentication Attack).
6. The matching playbook is selected and the response action is executed.
7. Post-fix verification confirms the action actually worked.
8. The incident is stored in SQLite and instantly appears on the Streamlit dashboard.

---

## Validation & Testing

The system was validated through structured attack simulations using Kali Linux against the Ubuntu target VM, plus a self-test suite covering the classification and response logic.

**Live-tested in the homelab:**
- SSH brute-force attempts (Group A — Authentication)
- Network scans via Nmap (Group B — Reconnaissance)
- File integrity violations, e.g. modifying `/etc/passwd` (Group D — File Integrity)
- Average detection latency: ~8 seconds from attack initiation to dashboard display

**Risk scoring is asset-aware, not flat per attack type.** The same SSH brute-force attempt scores differently depending on what it hits — 56 (MEDIUM) against the Ubuntu target versus 80 (CRITICAL) against the Wazuh Manager itself — because the engine weighs target importance alongside attack severity, not just the attack type in isolation. Legitimate failed logins from trusted IPs consistently scored below 30 (INFO/LOW), confirming the engine reduces noise rather than flagging everything equally.

**Classification logic verified for all 10 attack categories (A–J)** via the module's self-test suite — authentication attacks, reconnaissance, malware, file integrity, denial of service, lateral movement, privilege escalation, web attacks, data exfiltration, and rootkits/persistence. The human-approval workflow correctly pauses incidents scoring above the 60 threshold for analyst review, and post-fix verification confirms remediation actions (iptables rules, killed processes) actually took effect before incidents are marked resolved.

---

## Contributing

This was built as an academic team project and personal portfolio piece rather than an actively maintained open-source project. That said, feedback and questions are always welcome — feel free to open an issue.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Contact

amaldileef25@gmail.com
www.linkedin.com/in/amal-dileef
