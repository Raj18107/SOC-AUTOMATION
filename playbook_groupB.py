# playbook_groupB.py  —  Member 2
# Response Playbook: Group B — Network Scanning / Reconnaissance
# Covers: Nmap, Masscan, Zmap, ping sweeps, service detection, OS fingerprinting,
#         traceroute abuse, host discovery

from risk_engine import calculate_risk

from config import PROTECTED_IPS
WHITELIST = PROTECTED_IPS
SCAN_THRESHOLD = 3   # distinct scan alerts from same IP before escalating

def get_risk_label(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"

def run_playbook_B(alerts):
    actions = []
    scan_counts = {}
    scanned_ports = {}

    for alert in alerts:
        risk = calculate_risk(alert)
        if risk["group"] != "B":
            continue

        src   = alert.get("data", {}).get("srcip", "")
        agent = alert.get("agent", {}).get("ip", "unknown")
        desc  = alert.get("rule", {}).get("description", "").lower()
        score = risk["score"]
        label = get_risk_label(score)

        if src:
            scan_counts[src] = scan_counts.get(src, 0) + 1

        print(f"  [B] {label:8} score={score:3d}  src={src or 'N/A':15}  {alert['rule']['description'][:50]}")

        # Detect specific scan types
        is_nmap     = "nmap" in desc
        is_sweep    = "sweep" in desc or "host discovery" in desc
        is_service  = "service detection" in desc or "os detection" in desc

        # ── Tier 1: CRITICAL ───────────────────────────────────────────────
        if score >= 80:
            if src and src not in WHITELIST:
                actions.append({
                    "fix_type": "block_ip",
                    "command":  f"iptables -I INPUT -s {src} -j DROP",
                    "priority": 1,
                    "reason":   f"CRITICAL scan from {src}"
                })
            actions.append({
                "fix_type": "advisory",          # ✅ Changed from "alert"
                "command":  f"send_soc_alert --level CRITICAL --msg 'Aggressive scan on {agent}' --src {src}",
                "priority": 1,
                "reason":   "Notify SOC of critical scanning activity"
            })

        # ── Tier 2: HIGH ───────────────────────────────────────────────────
        elif score >= 60:
            if src and src not in WHITELIST:
                actions.append({
                    "fix_type": "rate_limit",
                    "command":  f"iptables -I INPUT -s {src} -m limit --limit 10/min -j ACCEPT",
                    "priority": 2,
                    "reason":   f"Rate-limit scanner {src}"
                })
            actions.append({
                "fix_type": "advisory",          # ✅ Changed from "alert"
                "command":  f"send_soc_alert --level HIGH --msg 'Scanning activity from {src}'",
                "priority": 2,
                "reason":   "Alert SOC team"
            })

        # ── Tier 3: MEDIUM / LOW ───────────────────────────────────────────
        else:
            actions.append({
                "fix_type": "advisory",          # ✅ Changed from "log"
                "command":  f"log_event --type scan --src {src} --agent {agent}",
                "priority": 3,
                "reason":   "Log scan activity for baseline analysis"
            })

        # ── Nmap-specific ─────────────────────────────────────────────────
        if is_nmap:
            actions.append({
                "fix_type": "advisory",          # ✅ Changed from "deception"
                "command":  f"honeypot_redirect --src {src} --fake-services 21,23,445",
                "priority": 3,
                "reason":   "Redirect Nmap scanner to honeypot"
            })

        # ── Sweep-specific ────────────────────────────────────────────────
        if is_sweep:
            actions.append({
                "fix_type": "block_ip",          # ✅ Kept — real iptables command
                "command":  f"iptables -I INPUT -s {src} -p icmp -j DROP",
                "priority": 2,
                "reason":   f"Block ICMP ping sweep from {src}"
            })

        # ── Service/OS detection specific ─────────────────────────────────
        if is_service:
            actions.append({
                "fix_type": "advisory",          # ✅ Changed from "hardened"
                "command":  f"configure_port_knocking --host {agent}",
                "priority": 4,
                "reason":   "Hide services with port knocking after OS detection scan"
            })

    # ── Post-scan: escalate repeat scanners ───────────────────────────────
    for src_ip, count in scan_counts.items():
        if count >= SCAN_THRESHOLD and src_ip not in WHITELIST:
            actions.append({
                "fix_type": "block_ip",          # ✅ Kept — real iptables command
                "command":  f"iptables -I INPUT -s {src_ip} -j DROP",
                "priority": 1,
                "reason":   f"Persistent scanner: {count} scan alerts from {src_ip}"
            })
            actions.append({
                "fix_type": "advisory",          # ✅ Changed from "threat_intel"
                "command":  f"check_threat_intel --ip {src_ip} --add-to-blocklist",
                "priority": 3,
                "reason":   "Submit persistent scanner to threat intel feed"
            })

    # ── Network hardening (always recommended) ────────────────────────────
    actions.append({
        "fix_type": "advisory",                  # ✅ Changed from "hardened"
        "command":  "configure_ids --enable-scan-detection --sensitivity high",
        "priority": 5,
        "reason":   "Tune IDS scan detection sensitivity"
    })
    actions.append({
        "fix_type": "advisory",                  # ✅ Changed from "hardened"
        "command":  "firewall_rule --drop-unsolicited-probes --log-to-siem",
        "priority": 5,
        "reason":   "Drop unsolicited probes at perimeter"
    })

    actions.sort(key=lambda x: x["priority"])
    return actions


if __name__ == "__main__":
    TEST_ALERTS = [
        {"id":"b1","rule":{"id":"40110","level":5,
          "description":"Nmap port scan detected from external host",
          "groups":["ids","scan"]},
         "agent":{"ip":"192.168.56.30"},"data":{"srcip":"203.0.113.5"}},

        {"id":"b2","rule":{"id":"40150","level":4,
          "description":"Host discovery sweep / ping sweep detected",
          "groups":["ids","scan"]},
         "agent":{"ip":"192.168.56.30"},"data":{"srcip":"203.0.113.5"}},

        {"id":"b3","rule":{"id":"40160","level":5,
          "description":"Service detection and OS detection scan masscan",
          "groups":["ids","scan"]},
         "agent":{"ip":"192.168.56.30"},"data":{"srcip":"203.0.113.5"}},
    ]
    print("\n=== Playbook B Self-Test ===")
    acts = run_playbook_B(TEST_ALERTS)
    print(f"\n{len(acts)} actions generated:")
    for a in acts:
        print(f"  [P{a['priority']}][{a['fix_type']:12}] {a['command'][:65]}")