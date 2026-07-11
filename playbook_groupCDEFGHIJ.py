# playbook_groupCDEFGHIJ.py  —  Member 2
# Response Playbooks: Groups C, D, E, F, G, H, I, J
# Each run_playbook_X(alerts) function follows the same tiered pattern:
#   Priority 1 = Immediate containment
#   Priority 2 = High-urgency response
#   Priority 3 = Investigation / logging
#   Priority 4 = Remediation
#   Priority 5 = Long-term hardening

from risk_engine import calculate_risk, get_risk_label

from config import PROTECTED_IPS
WHITELIST = PROTECTED_IPS

# ===========================================================================
# GROUP C — Malware / Malicious Processes
# Covers: ransomware, cryptominers, trojans, reverse shells, C2 beacons,
#         botnet callbacks, bind shells, payload execution
# ===========================================================================
def run_playbook_C(alerts):
    if isinstance(alerts, dict):
        alerts = [alerts]
    actions = []

    for alert in alerts:
        risk  = calculate_risk(alert)
        if risk["group"] != "C":
            continue

        agent = alert.get("agent", {}).get("ip", "unknown")
        desc  = alert.get("rule", {}).get("description", "").lower()
        score = risk["score"]
        label = get_risk_label(score)
        src   = alert.get("data", {}).get("srcip", "")

        print(f"  [C] {label:8} score={score:3d}  agent={agent}  {alert['rule']['description'][:55]}")

        is_ransomware  = "ransomware" in desc
        is_miner       = "cryptominer" in desc or "miner" in desc or "xmrig" in desc
        is_c2          = "c2" in desc or "command and control" in desc or "reverse shell" in desc or "bind shell" in desc
        is_botnet      = "botnet" in desc

        # ── Immediate Isolation (all malware) ─────────────────────────────
        actions.append({
            "fix_type": "isolate",
            "command":  f"isolate_host --ip {agent} --reason malware_detected",
            "priority": 1,
            "reason":   f"Isolate {agent} — malware confirmed"
        })
        actions.append({
            "fix_type": "kill_process",
            "command":  f"ssh root@{agent} 'ps aux | grep -E \"xmrig|miner|shell|payload\" | awk {{print $2}} | xargs kill -9'",
            "priority": 1,
            "reason":   "Kill malicious processes immediately"
        })

        # ── Ransomware-specific ───────────────────────────────────────────
        if is_ransomware:
            actions.append({
                "fix_type": "isolate",
                "command":  f"network_block --host {agent} --all-interfaces",
                "priority": 1,
                "reason":   "Full network block — prevent ransomware spread"
            })
            actions.append({
                "fix_type": "snapshot",
                "command":  f"take_snapshot --host {agent} --label pre_ransomware_recovery",
                "priority": 1,
                "reason":   "Snapshot for forensics before encryption spreads"
            })
            actions.append({
                "fix_type": "backup",
                "command":  f"trigger_emergency_backup --host {agent} --dest /backups/emergency/",
                "priority": 1,
                "reason":   "Emergency backup of unencrypted data"
            })
            actions.append({
                "fix_type": "alert",
                "command":  f"send_soc_alert --level CRITICAL --msg 'RANSOMWARE on {agent}' --page-oncall",
                "priority": 1,
                "reason":   "Page on-call security team"
            })

        # ── C2 / Reverse shell ────────────────────────────────────────────
        if is_c2:
            if src and src not in WHITELIST:
                actions.append({
                    "fix_type": "block_ip",
                    "command":  f"iptables -I OUTPUT -d {src} -j DROP",
                    "priority": 1,
                    "reason":   f"Block outbound C2 callback to {src}"
                })
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I OUTPUT -s {agent} -j DROP",
                "priority": 1,
                "reason":   "Block all outbound from compromised host"
            })

        # ── Cryptominer-specific ──────────────────────────────────────────
        if is_miner:
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I OUTPUT -d 0.0.0.0/0 -p tcp --dport 3333 -j DROP",
                "priority": 2,
                "reason":   "Block common mining pool port 3333"
            })
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I OUTPUT -d 0.0.0.0/0 -p tcp --dport 4444 -j DROP",
                "priority": 2,
                "reason":   "Block mining pool port 4444"
            })

        # ── Forensics ─────────────────────────────────────────────────────
        actions.append({
            "fix_type": "forensics",
            "command":  f"collect_forensics --host {agent} --memory-dump --process-list --network-connections",
            "priority": 3,
            "reason":   "Collect forensic evidence before remediation"
        })
        actions.append({
            "fix_type": "scan",
            "command":  f"run_av_scan --host {agent} --full --quarantine",
            "priority": 3,
            "reason":   "Full antivirus/antimalware scan"
        })

        # ── Remediation ───────────────────────────────────────────────────
        actions.append({
            "fix_type": "remediate",
            "command":  f"restore_from_backup --host {agent} --latest-clean",
            "priority": 4,
            "reason":   "Restore system from last known-good backup"
        })
        actions.append({
            "fix_type": "hardened",
            "command":  f"apply_application_whitelist --host {agent}",
            "priority": 5,
            "reason":   "Enforce application whitelisting to prevent re-infection"
        })

    actions.sort(key=lambda x: x["priority"])
    return actions


# ===========================================================================
# GROUP D — File Integrity Violations
# Covers: /etc/passwd, /etc/shadow, /etc/sudoers, SSH keys, cron jobs,
#         startup scripts, web root files, binary replacements
# ===========================================================================
def run_playbook_D(alerts):
    if isinstance(alerts, dict):
        alerts = [alerts]
    actions = []

    for alert in alerts:
        risk  = calculate_risk(alert)
        if risk["group"] != "D":
            continue

        agent = alert.get("agent", {}).get("ip", "unknown")
        desc  = alert.get("rule", {}).get("description", "").lower()
        score = risk["score"]
        label = get_risk_label(score)

        print(f"  [D] {label:8} score={score:3d}  agent={agent}  {alert['rule']['description'][:55]}")

        is_critical_file = any(f in desc for f in [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "authorized_keys", "cron", "startup", "bashrc", "profile",
            "/bin/", "/usr/bin/", "/sbin/"
        ])
        is_web_root = any(f in desc for f in ["/var/www", "/html", "webroot", ".php"])

        # ── Alert + Log ───────────────────────────────────────────────────
        actions.append({
            "fix_type": "alert",
            "command":  f"send_soc_alert --level {'CRITICAL' if score >= 70 else 'HIGH'} "
                        f"--msg 'File integrity violation on {agent}: {desc[:50]}'",
            "priority": 1 if score >= 70 else 2,
            "reason":   "Notify SOC of integrity violation"
        })

        # ── Critical system files ─────────────────────────────────────────
        if is_critical_file and score >= 60:
            actions.append({
                "fix_type": "isolate",
                "command":  f"isolate_host --ip {agent} --reason critical_file_modified",
                "priority": 1,
                "reason":   f"Isolate {agent} — critical file changed"
            })
            actions.append({
                "fix_type": "forensics",
                "command":  f"collect_forensics --host {agent} --file-audit --changed-files",
                "priority": 2,
                "reason":   "Collect audit trail of changed files"
            })
            actions.append({
                "fix_type": "remediate",
                "command":  f"restore_file --host {agent} --from-backup --verify-hash",
                "priority": 3,
                "reason":   "Restore tampered file from trusted backup"
            })

        # ── SSH key changes ────────────────────────────────────────────────
        if "authorized_keys" in desc or "ssh" in desc:
            actions.append({
                "fix_type": "remediate",
                "command":  f"audit_ssh_keys --host {agent} --remove-unauthorized",
                "priority": 2,
                "reason":   "Audit and remove unauthorised SSH keys"
            })

        # ── Cron / startup persistence ─────────────────────────────────────
        if "cron" in desc or "startup" in desc or "profile" in desc:
            actions.append({
                "fix_type": "remediate",
                "command":  f"audit_cron --host {agent} --remove-unknown-entries",
                "priority": 2,
                "reason":   "Audit cron for persistence mechanisms"
            })

        # ── Web root changes ───────────────────────────────────────────────
        if is_web_root:
            actions.append({
                "fix_type": "scan",
                "command":  f"scan_webroot --host {agent} --check-webshells",
                "priority": 2,
                "reason":   "Scan web root for shells or backdoors"
            })

        # ── Hardening ─────────────────────────────────────────────────────
        actions.append({
            "fix_type": "hardened",
            "command":  f"enable_fim --host {agent} --realtime --alert-on-change",
            "priority": 5,
            "reason":   "Enable real-time file integrity monitoring"
        })
        actions.append({
            "fix_type": "hardened",
            "command":  f"set_immutable --host {agent} --files /etc/passwd,/etc/shadow,/etc/sudoers",
            "priority": 5,
            "reason":   "Set chattr +i on critical system files"
        })

    actions.sort(key=lambda x: x["priority"])
    return actions


# ===========================================================================
# GROUP E — Denial of Service
# Covers: SYN flood, UDP flood, ICMP flood, Slowloris, HTTP flood,
#         amplification attacks, connection exhaustion, DDoS
# ===========================================================================
def run_playbook_E(alerts):
    if isinstance(alerts, dict):
        alerts = [alerts]
    actions = []

    for alert in alerts:
        risk  = calculate_risk(alert)
        if risk["group"] != "E":
            continue

        agent = alert.get("agent", {}).get("ip", "unknown")
        src   = alert.get("data", {}).get("srcip", "")
        desc  = alert.get("rule", {}).get("description", "").lower()
        score = risk["score"]
        label = get_risk_label(score)

        print(f"  [E] {label:8} score={score:3d}  src={src or 'N/A':15}  {alert['rule']['description'][:50]}")

        is_syn      = "syn flood" in desc
        is_udp      = "udp flood" in desc
        is_icmp     = "icmp flood" in desc or "ping of death" in desc
        is_slowloris= "slowloris" in desc
        is_http     = "http" in desc or "connection limit" in desc

        # ── Immediate mitigation ──────────────────────────────────────────
        if src and src not in WHITELIST:
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I INPUT -s {src} -j DROP",
                "priority": 1,
                "reason":   f"Drop all packets from DoS source {src}"
            })

        # ── SYN flood ─────────────────────────────────────────────────────
        if is_syn:
            actions.append({
                "fix_type": "mitigate",
                "command":  "sysctl -w net.ipv4.tcp_syncookies=1",
                "priority": 1,
                "reason":   "Enable SYN cookies to mitigate SYN flood"
            })
            actions.append({
                "fix_type": "mitigate",
                "command":  "sysctl -w net.ipv4.tcp_max_syn_backlog=2048",
                "priority": 1,
                "reason":   "Increase SYN backlog queue"
            })

        # ── UDP flood ─────────────────────────────────────────────────────
        if is_udp:
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I INPUT -p udp -s {src} -j DROP",
                "priority": 1,
                "reason":   "Block UDP flood packets"
            })

        # ── ICMP flood ────────────────────────────────────────────────────
        if is_icmp:
            actions.append({
                "fix_type": "block_ip",
                "command":  "iptables -I INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT",
                "priority": 1,
                "reason":   "Rate-limit ICMP echo requests"
            })

        # ── Slowloris / HTTP ──────────────────────────────────────────────
        if is_slowloris or is_http:
            actions.append({
                "fix_type": "mitigate",
                "command":  f"configure_web_server --host {agent} --timeout 30 --max-connections 100",
                "priority": 2,
                "reason":   "Reduce HTTP timeout and max connections"
            })
            actions.append({
                "fix_type": "mitigate",
                "command":  f"enable_mod_reqtimeout --host {agent}",
                "priority": 2,
                "reason":   "Enable Apache mod_reqtimeout against Slowloris"
            })

        actions.append({
            "fix_type": "alert",
            "command":  f"send_soc_alert --level CRITICAL --msg 'DoS attack on {agent} from {src}'",
            "priority": 1,
            "reason":   "Notify SOC and upstream ISP for null-routing"
        })
        actions.append({
            "fix_type": "mitigate",
            "command":  f"contact_isp --request-nullroute --src {src}",
            "priority": 2,
            "reason":   "Request upstream null-route from ISP for DDoS"
        })
        actions.append({
            "fix_type": "hardened",
            "command":  "enable_ddos_protection --provider cloudflare --scrubbing-center",
            "priority": 5,
            "reason":   "Route traffic through DDoS scrubbing centre"
        })

    actions.sort(key=lambda x: x["priority"])
    return actions


# ===========================================================================
# GROUP F — Lateral Movement
# Covers: pass-the-hash, pass-the-ticket, PSExec, Mimikatz,
#         SMB lateral movement, WMI remote execution, RDP pivoting
# ===========================================================================
def run_playbook_F(alerts):
    if isinstance(alerts, dict):
        alerts = [alerts]
    actions = []

    for alert in alerts:
        risk  = calculate_risk(alert)
        if risk["group"] != "F":
            continue

        agent = alert.get("agent", {}).get("ip", "unknown")
        src   = alert.get("data", {}).get("srcip", "")
        desc  = alert.get("rule", {}).get("description", "").lower()
        score = risk["score"]
        label = get_risk_label(score)

        print(f"  [F] {label:8} score={score:3d}  src={src or 'N/A':15}  {alert['rule']['description'][:50]}")

        is_pth      = "pass the hash" in desc or "pass the ticket" in desc
        is_mimikatz = "mimikatz" in desc or "credential dump" in desc
        is_psexec   = "psexec" in desc or "remote exec" in desc
        is_smb      = "smb" in desc
        is_wmi      = "wmi" in desc

        # ── Isolate both source and destination ───────────────────────────
        actions.append({
            "fix_type": "isolate",
            "command":  f"isolate_host --ip {agent} --reason lateral_movement_target",
            "priority": 1,
            "reason":   f"Isolate target host {agent}"
        })
        if src and src not in WHITELIST:
            actions.append({
                "fix_type": "isolate",
                "command":  f"isolate_host --ip {src} --reason lateral_movement_source",
                "priority": 1,
                "reason":   f"Isolate source host {src} (lateral movement origin)"
            })
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I INPUT -s {src} -j DROP",
                "priority": 1,
                "reason":   f"Block all traffic from lateral movement source {src}"
            })

        # ── SMB-specific ──────────────────────────────────────────────────
        if is_smb:
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I INPUT -p tcp --dport 445 -s {src} -j DROP",
                "priority": 1,
                "reason":   "Block SMB port 445 from lateral movement source"
            })

        # ── Pass-the-hash / Pass-the-ticket ───────────────────────────────
        if is_pth:
            actions.append({
                "fix_type": "remediate",
                "command":  "force_password_reset --all-domain-accounts --reason pth_detected",
                "priority": 2,
                "reason":   "Force domain-wide password reset after PtH attack"
            })
            actions.append({
                "fix_type": "remediate",
                "command":  "invalidate_kerberos_tickets --all",
                "priority": 2,
                "reason":   "Invalidate all Kerberos tickets (krbtgt rotation)"
            })

        # ── Mimikatz / credential dump ─────────────────────────────────────
        if is_mimikatz:
            actions.append({
                "fix_type": "remediate",
                "command":  f"enable_credential_guard --host {agent}",
                "priority": 2,
                "reason":   "Enable Windows Credential Guard to prevent future dumps"
            })
            actions.append({
                "fix_type": "forensics",
                "command":  f"collect_forensics --host {agent} --lsass-dump --event-logs",
                "priority": 2,
                "reason":   "Collect LSASS and event logs for forensics"
            })

        # ── PSExec / WMI ──────────────────────────────────────────────────
        if is_psexec or is_wmi:
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I INPUT -p tcp --dport 135 -s {src} -j DROP",
                "priority": 2,
                "reason":   "Block WMI/RPC port 135 used by PSExec/WMI"
            })

        actions.append({
            "fix_type": "alert",
            "command":  f"send_soc_alert --level CRITICAL --msg 'Lateral movement {src}->{agent}'",
            "priority": 1,
            "reason":   "Notify SOC — attacker is spreading"
        })
        actions.append({
            "fix_type": "hardened",
            "command":  "segment_network --add-micro-segmentation --block-east-west",
            "priority": 5,
            "reason":   "Implement network micro-segmentation to limit lateral movement"
        })

    actions.sort(key=lambda x: x["priority"])
    return actions


# ===========================================================================
# GROUP G — Privilege Escalation
# Covers: sudo abuse, SUID exploitation, su root, sudoers modification,
#         token impersonation, UAC bypass, kernel exploits for root
# ===========================================================================
def run_playbook_G(alerts):
    if isinstance(alerts, dict):
        alerts = [alerts]
    actions = []

    for alert in alerts:
        risk  = calculate_risk(alert)
        if risk["group"] != "G":
            continue

        agent = alert.get("agent", {}).get("ip", "unknown")
        desc  = alert.get("rule", {}).get("description", "").lower()
        score = risk["score"]
        label = get_risk_label(score)

        print(f"  [G] {label:8} score={score:3d}  agent={agent}  {alert['rule']['description'][:55]}")

        is_sudo     = "sudo" in desc or "sudoers" in desc
        is_suid     = "setuid" in desc or "setgid" in desc or "suid" in desc
        is_root     = "root shell" in desc or "su root" in desc or "unauthorized root" in desc

        # ── Immediate response ────────────────────────────────────────────
        actions.append({
            "fix_type": "alert",
            "command":  f"send_soc_alert --level CRITICAL --msg 'Privilege escalation on {agent}'",
            "priority": 1,
            "reason":   "Immediate SOC notification"
        })
        if score >= 70:
            actions.append({
                "fix_type": "isolate",
                "command":  f"isolate_host --ip {agent} --reason privilege_escalation",
                "priority": 1,
                "reason":   f"Isolate {agent} — privilege escalation confirmed"
            })

        # ── Sudo-specific ─────────────────────────────────────────────────
        if is_sudo:
            actions.append({
                "fix_type": "remediate",
                "command":  f"restore_file --host {agent} --file /etc/sudoers --from-backup",
                "priority": 2,
                "reason":   "Restore /etc/sudoers from trusted backup"
            })
            actions.append({
                "fix_type": "remediate",
                "command":  f"audit_sudo_rules --host {agent} --remove-nopasswd",
                "priority": 2,
                "reason":   "Remove NOPASSWD entries from sudoers"
            })

        # ── SUID binary exploitation ───────────────────────────────────────
        if is_suid:
            actions.append({
                "fix_type": "remediate",
                "command":  f"find_suid_binaries --host {agent} --remove-unexpected",
                "priority": 2,
                "reason":   "Audit and remove unexpected SUID binaries"
            })

        # ── Root shell obtained ───────────────────────────────────────────
        if is_root:
            actions.append({
                "fix_type": "forensics",
                "command":  f"collect_forensics --host {agent} --root-activity --shell-history",
                "priority": 2,
                "reason":   "Capture root shell activity and command history"
            })
            actions.append({
                "fix_type": "remediate",
                "command":  f"revoke_root_sessions --host {agent}",
                "priority": 1,
                "reason":   "Terminate all active root sessions"
            })

        # ── Hardening ─────────────────────────────────────────────────────
        actions.append({
            "fix_type": "hardened",
            "command":  f"configure_sudo --host {agent} --require-tty --log-all-commands",
            "priority": 5,
            "reason":   "Require TTY and log all sudo commands"
        })
        actions.append({
            "fix_type": "hardened",
            "command":  f"enable_pam_tally --host {agent} --lock-after 3",
            "priority": 5,
            "reason":   "Lock account after 3 failed sudo attempts"
        })

    actions.sort(key=lambda x: x["priority"])
    return actions


# ===========================================================================
# GROUP H — Web Application Attacks
# Covers: SQL injection, XSS, CSRF, directory traversal, LFI, RFI,
#         web shells, Shellshock, Log4j, command injection, HTTP floods
# ===========================================================================
def run_playbook_H(alerts):
    if isinstance(alerts, dict):
        alerts = [alerts]
    actions = []

    for alert in alerts:
        risk  = calculate_risk(alert)
        if risk["group"] != "H":
            continue

        agent = alert.get("agent", {}).get("ip", "unknown")
        src   = alert.get("data", {}).get("srcip", "")
        desc  = alert.get("rule", {}).get("description", "").lower()
        score = risk["score"]
        label = get_risk_label(score)

        print(f"  [H] {label:8} score={score:3d}  src={src or 'N/A':15}  {alert['rule']['description'][:50]}")

        is_sqli      = "sql injection" in desc
        is_xss       = "xss" in desc or "cross-site" in desc
        is_traversal = "traversal" in desc or "path traversal" in desc or "lfi" in desc
        is_webshell  = "web shell" in desc
        is_log4j     = "log4j" in desc or "cve-2021" in desc
        is_cmd_inj   = "command injection" in desc

        # ── Block attacker ────────────────────────────────────────────────
        if src and src not in WHITELIST:
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I INPUT -s {src} -p tcp --dport 80 -j DROP",
                "priority": 1,
                "reason":   f"Block web attacker {src} on port 80"
            })
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I INPUT -s {src} -p tcp --dport 443 -j DROP",
                "priority": 1,
                "reason":   f"Block web attacker {src} on port 443"
            })
            actions.append({
                "fix_type": "block_ip",
                "command":  f"add_waf_rule --block-ip {src} --duration 3600",
                "priority": 1,
                "reason":   "Add attacker IP to WAF blocklist for 1 hour"
            })

        actions.append({
            "fix_type": "alert",
            "command":  f"send_soc_alert --level HIGH --msg 'Web attack on {agent} from {src}'",
            "priority": 2,
            "reason":   "Notify SOC of web application attack"
        })

        # ── SQL Injection ─────────────────────────────────────────────────
        if is_sqli:
            actions.append({
                "fix_type": "waf_rule",
                "command":  "add_waf_rule --type sqli --pattern \"union|select|drop|insert|delete|'--\"",
                "priority": 2,
                "reason":   "Add WAF rule to block SQL injection patterns"
            })
            actions.append({
                "fix_type": "forensics",
                "command":  f"check_db_integrity --host {agent} --audit-queries",
                "priority": 3,
                "reason":   "Check database for exfiltrated data or schema changes"
            })

        # ── XSS ───────────────────────────────────────────────────────────
        if is_xss:
            actions.append({
                "fix_type": "waf_rule",
                "command":  "add_waf_rule --type xss --enable-content-security-policy",
                "priority": 2,
                "reason":   "Enable Content-Security-Policy headers"
            })

        # ── LFI / Directory traversal ─────────────────────────────────────
        if is_traversal:
            actions.append({
                "fix_type": "waf_rule",
                "command":  "add_waf_rule --type traversal --pattern \"\\.\\./|%2e%2e\"",
                "priority": 2,
                "reason":   "Block path traversal patterns in WAF"
            })

        # ── Web shell ─────────────────────────────────────────────────────
        if is_webshell:
            actions.append({
                "fix_type": "scan",
                "command":  f"scan_webroot --host {agent} --find-webshells --remove",
                "priority": 1,
                "reason":   "Scan and remove web shells immediately"
            })
            actions.append({
                "fix_type": "isolate",
                "command":  f"isolate_host --ip {agent} --reason webshell_found",
                "priority": 1,
                "reason":   "Isolate web server — shell found"
            })

        # ── Log4j / CVE exploitation ──────────────────────────────────────
        if is_log4j:
            actions.append({
                "fix_type": "patch",
                "command":  f"apply_patch --host {agent} --cve CVE-2021-44228 --restart-service",
                "priority": 1,
                "reason":   "Apply Log4j patch immediately"
            })
            actions.append({
                "fix_type": "mitigate",
                "command":  "set_jvm_option -Dlog4j2.formatMsgNoLookups=true",
                "priority": 1,
                "reason":   "Disable JNDI lookups as temporary mitigation"
            })

        # ── Command injection ─────────────────────────────────────────────
        if is_cmd_inj:
            actions.append({
                "fix_type": "waf_rule",
                "command":  "add_waf_rule --type cmdi --pattern \";|&&|\\|\\||`\"",
                "priority": 2,
                "reason":   "Block command injection characters in WAF"
            })

        # ── Hardening ─────────────────────────────────────────────────────
        actions.append({
            "fix_type": "hardened",
            "command":  f"enable_waf --host {agent} --mode blocking --ruleset OWASP-CRS",
            "priority": 5,
            "reason":   "Enable WAF in blocking mode with OWASP Core Rule Set"
        })

    actions.sort(key=lambda x: x["priority"])
    return actions


# ===========================================================================
# GROUP I — Data Exfiltration
# Covers: large outbound transfers, DNS tunneling, SMTP exfil,
#         FTP uploads, cloud storage abuse, steganography channels
# ===========================================================================
def run_playbook_I(alerts):
    if isinstance(alerts, dict):
        alerts = [alerts]
    actions = []

    for alert in alerts:
        risk  = calculate_risk(alert)
        if risk["group"] != "I":
            continue

        agent = alert.get("agent", {}).get("ip", "unknown")
        src   = alert.get("data", {}).get("srcip", "")
        desc  = alert.get("rule", {}).get("description", "").lower()
        score = risk["score"]
        label = get_risk_label(score)

        print(f"  [I] {label:8} score={score:3d}  agent={agent}  {alert['rule']['description'][:55]}")

        is_dns_tunnel = "dns tunneling" in desc
        is_smtp       = "smtp" in desc
        is_bulk       = "bulk upload" in desc or "large transfer" in desc

        # ── Immediate: cut the exfil channel ──────────────────────────────
        actions.append({
            "fix_type": "block_ip",
            "command":  f"iptables -I OUTPUT -s {agent} -j DROP",
            "priority": 1,
            "reason":   f"Block ALL outbound from {agent} — active exfiltration"
        })
        actions.append({
            "fix_type": "isolate",
            "command":  f"isolate_host --ip {agent} --reason data_exfiltration",
            "priority": 1,
            "reason":   f"Isolate {agent} to stop data leaving the network"
        })
        actions.append({
            "fix_type": "alert",
            "command":  f"send_soc_alert --level CRITICAL --msg 'DATA EXFILTRATION from {agent}' --page-ciso",
            "priority": 1,
            "reason":   "Notify CISO and SOC — potential data breach"
        })

        # ── DNS tunneling ─────────────────────────────────────────────────
        if is_dns_tunnel:
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I OUTPUT -s {agent} -p udp --dport 53 -j DROP",
                "priority": 1,
                "reason":   "Block outbound DNS from exfiltrating host"
            })
            actions.append({
                "fix_type": "mitigate",
                "command":  "configure_dns --enable-query-logging --block-long-subdomain-queries",
                "priority": 2,
                "reason":   "Block suspiciously long DNS queries used in tunneling"
            })

        # ── SMTP exfil ────────────────────────────────────────────────────
        if is_smtp:
            actions.append({
                "fix_type": "block_ip",
                "command":  f"iptables -I OUTPUT -s {agent} -p tcp --dport 25 -j DROP",
                "priority": 1,
                "reason":   "Block SMTP outbound from exfiltrating host"
            })

        # ── Bulk upload ────────────────────────────────────────────────────
        if is_bulk:
            actions.append({
                "fix_type": "forensics",
                "command":  f"capture_traffic --host {agent} --duration 60 --filter outbound",
                "priority": 2,
                "reason":   "Capture outbound traffic to identify what data is leaving"
            })

        # ── Forensics / compliance ─────────────────────────────────────────
        actions.append({
            "fix_type": "forensics",
            "command":  f"collect_forensics --host {agent} --network-flows --accessed-files",
            "priority": 2,
            "reason":   "Identify what data was accessed and exfiltrated"
        })
        actions.append({
            "fix_type": "compliance",
            "command":  f"trigger_breach_notification --host {agent} --regulation GDPR",
            "priority": 3,
            "reason":   "Start breach notification process (GDPR 72-hour window)"
        })
        actions.append({
            "fix_type": "hardened",
            "command":  "enable_dlp --policy block-sensitive-outbound --inspect-tls",
            "priority": 5,
            "reason":   "Enable Data Loss Prevention policy on all egress points"
        })

    actions.sort(key=lambda x: x["priority"])
    return actions


# ===========================================================================
# GROUP J — Rootkit / Persistence
# Covers: rootkits, hidden processes, LD_PRELOAD hooks, kernel modules,
#         backdoors, cron persistence, startup scripts, bootkit
# ===========================================================================
def run_playbook_J(alerts):
    if isinstance(alerts, dict):
        alerts = [alerts]
    actions = []

    for alert in alerts:
        risk  = calculate_risk(alert)
        if risk["group"] != "J":
            continue

        agent = alert.get("agent", {}).get("ip", "unknown")
        desc  = alert.get("rule", {}).get("description", "").lower()
        score = risk["score"]
        label = get_risk_label(score)

        print(f"  [J] {label:8} score={score:3d}  agent={agent}  {alert['rule']['description'][:55]}")

        is_rootkit    = "rootkit" in desc
        is_hidden     = "hidden process" in desc or "hidden file" in desc
        is_preload    = "ld.so.preload" in desc or "kernel module" in desc
        is_backdoor   = "backdoor" in desc
        is_cron       = "cron" in desc or "startup" in desc

        # ── Immediate isolation — rootkits mean host is fully compromised ──
        actions.append({
            "fix_type": "isolate",
            "command":  f"network_block --host {agent} --all-interfaces --emergency",
            "priority": 1,
            "reason":   f"EMERGENCY isolation — rootkit/backdoor on {agent}"
        })
        actions.append({
            "fix_type": "alert",
            "command":  f"send_soc_alert --level CRITICAL --msg 'ROOTKIT/PERSISTENCE on {agent}' --page-oncall --page-ciso",
            "priority": 1,
            "reason":   "Page entire incident response team"
        })
        actions.append({
            "fix_type": "snapshot",
            "command":  f"take_forensic_snapshot --host {agent} --full-disk-image",
            "priority": 1,
            "reason":   "Full disk image for forensic investigation"
        })

        # ── Hidden processes ───────────────────────────────────────────────
        if is_hidden:
            actions.append({
                "fix_type": "forensics",
                "command":  f"run_rootkit_scanner --host {agent} --tool rkhunter,chkrootkit",
                "priority": 2,
                "reason":   "Run rkhunter and chkrootkit to find hidden processes"
            })

        # ── LD_PRELOAD / kernel module ────────────────────────────────────
        if is_preload:
            actions.append({
                "fix_type": "remediate",
                "command":  f"ssh root@{agent} 'echo > /etc/ld.so.preload'",
                "priority": 2,
                "reason":   "Clear LD_PRELOAD hook"
            })
            actions.append({
                "fix_type": "remediate",
                "command":  f"list_kernel_modules --host {agent} --remove-unsigned",
                "priority": 2,
                "reason":   "Remove unsigned/unknown kernel modules"
            })

        # ── Backdoor ──────────────────────────────────────────────────────
        if is_backdoor:
            actions.append({
                "fix_type": "forensics",
                "command":  f"scan_open_ports --host {agent} --find-backdoor-listeners",
                "priority": 2,
                "reason":   "Find backdoor listener ports"
            })

        # ── Cron/startup persistence ──────────────────────────────────────
        if is_cron:
            actions.append({
                "fix_type": "remediate",
                "command":  f"audit_cron --host {agent} --remove-all-unknown",
                "priority": 2,
                "reason":   "Remove unknown cron entries used for persistence"
            })
            actions.append({
                "fix_type": "remediate",
                "command":  f"audit_startup_scripts --host {agent} --remove-unauthorized",
                "priority": 2,
                "reason":   "Remove unauthorized startup scripts"
            })

        # ── Nuclear option: rebuild ────────────────────────────────────────
        actions.append({
            "fix_type": "remediate",
            "command":  f"rebuild_host --host {agent} --from-golden-image --verify-integrity",
            "priority": 4,
            "reason":   "Rebuild host from golden image — rootkit cannot be trusted to be removed"
        })
        actions.append({
            "fix_type": "hardened",
            "command":  f"enable_secure_boot --host {agent} --tpm-attestation",
            "priority": 5,
            "reason":   "Enable Secure Boot and TPM attestation"
        })
        actions.append({
            "fix_type": "hardened",
            "command":  "deploy_edr --host {agent} --kernel-level-monitoring",
            "priority": 5,
            "reason":   "Deploy EDR with kernel-level process monitoring"
        })

    actions.sort(key=lambda x: x["priority"])
    return actions


# ---------------------------------------------------------------------------
# Convenience router — call by group letter
# ---------------------------------------------------------------------------
PLAYBOOK_MAP = {
    "C": run_playbook_C,
    "D": run_playbook_D,
    "E": run_playbook_E,
    "F": run_playbook_F,
    "G": run_playbook_G,
    "H": run_playbook_H,
    "I": run_playbook_I,
    "J": run_playbook_J,
}

def run_playbook(group, alerts):
    fn = PLAYBOOK_MAP.get(group)
    if fn:
        return fn(alerts)
    return []


# ---------------------------------------------------------------------------
# Self-test: one alert per group
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Standalone self-test — no wazuh_api needed
    TEST_ALERTS = {
        "C": {"rule": {"id": "100200", "level": 12, "description": "Cryptominer xmrig detected running", "groups": []}, "agent": {"ip": "192.168.56.20"}, "data": {"srcip": ""}},
        "D": {"rule": {"id": "550",    "level": 7,  "description": "/etc/passwd integrity checksum changed", "groups": ["syscheck"]}, "agent": {"ip": "192.168.56.20"}, "data": {}},
        "E": {"rule": {"id": "100300", "level": 10, "description": "SYN flood attack detected", "groups": []}, "agent": {"ip": "192.168.56.20"}, "data": {"srcip": "203.0.113.5"}},
        "F": {"rule": {"id": "100400", "level": 10, "description": "SMB lateral movement detected from 203.0.113.5", "groups": []}, "agent": {"ip": "192.168.56.20"}, "data": {"srcip": "203.0.113.5"}},
        "G": {"rule": {"id": "100500", "level": 9,  "description": "sudo privilege escalation detected", "groups": []}, "agent": {"ip": "192.168.56.20"}, "data": {}},
        "H": {"rule": {"id": "100600", "level": 8,  "description": "SQL injection attempt detected", "groups": []}, "agent": {"ip": "192.168.56.20"}, "data": {"srcip": "198.51.100.33"}},
        "I": {"rule": {"id": "100700", "level": 11, "description": "bulk upload large transfer data exfiltration detected", "groups": []}, "agent": {"ip": "192.168.56.20"}, "data": {"srcip": ""}},
        "J": {"rule": {"id": "100800", "level": 13, "description": "Rootkit detected hidden process ld.so.preload modified", "groups": []}, "agent": {"ip": "192.168.56.20"}, "data": {}},
    }
    for grp in "CDEFGHIJ":
        alert = TEST_ALERTS[grp]
        print(f"\n{'='*60}")
        print(f"  PLAYBOOK {grp} TEST")
        print(f"{'='*60}")
        acts = run_playbook(grp, [alert])
        print(f"  → {len(acts)} actions:")
        for a in acts[:5]:
            print(f"    [P{a['priority']}][{a['fix_type']:12}] {a['command'][:60]}")
        if len(acts) > 5:
            print(f"    ... and {len(acts)-5} more")
