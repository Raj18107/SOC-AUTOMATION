import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import pytz
import os
import json
import io
import random

# ────────────────────────────────────────────────────────────────
# FORCE PAGE CONFIG — MUST BE FIRST Streamlit COMMAND
# ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ────────────────────────────────────────────────────────────────
# LOAD .env FILE FOR WAZUH CREDENTIALS
# ────────────────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

# ────────────────────────────────────────────────────────────────
# IST TIMEZONE HELPER
# ────────────────────────────────────────────────────────────────
IST = pytz.timezone('Asia/Kolkata')

def convert_to_ist(timestamp_str):
    """Convert any timestamp to IST format"""
    try:
        # Handle different timestamp formats
        if timestamp_str.endswith('Z'):
            timestamp_str = timestamp_str.replace('Z', '+00:00')
        
        # Parse with timezone info
        if '+' in timestamp_str or '-' in timestamp_str[10:]:
            dt = datetime.fromisoformat(timestamp_str)
        else:
            # Assume UTC if no timezone
            dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
            dt = pytz.UTC.localize(dt)
        
        # Convert to IST
        ist_time = dt.astimezone(IST)
        return ist_time.strftime("%Y-%m-%d %I:%M:%S %p IST")
    except Exception:
        try:
            # Try without microseconds
            dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            dt = pytz.UTC.localize(dt)
            ist_time = dt.astimezone(IST)
            return ist_time.strftime("%Y-%m-%d %I:%M:%S %p IST")
        except Exception:
            return timestamp_str

def get_current_ist():
    """Get current time in IST"""
    return datetime.now(IST).strftime("%Y-%m-%d %I:%M:%S %p IST")

# ────────────────────────────────────────────────────────────────
# TEST MODE — FAKE LOG GENERATOR
# ────────────────────────────────────────────────────────────────

def generate_fake_alerts(count=20):
    """Generate fake alerts for testing without Wazuh"""
    
    attack_types = [
        # Group A - Authentication Attacks
        {"description": "SSH brute force attack from 203.0.113.45", "group": "A", "base_score": 85, "source_ip": "203.0.113.45"},
        {"description": "Failed password for root from 198.51.100.22", "group": "A", "base_score": 75, "source_ip": "198.51.100.22"},
        {"description": "Multiple authentication failures for admin", "group": "A", "base_score": 70, "source_ip": "192.0.2.88"},
        {"description": "SSH login attempt with invalid user", "group": "A", "base_score": 65, "source_ip": "203.0.113.99"},
        {"description": "Brute force attack on port 22 from 185.130.5.253", "group": "A", "base_score": 95, "source_ip": "185.130.5.253"},
        
        # Group B - Reconnaissance
        {"description": "Nmap port scan detected on port 22,80,443", "group": "B", "base_score": 60, "source_ip": "203.0.113.100"},
        {"description": "Massive port sweep from single source", "group": "B", "base_score": 55, "source_ip": "198.51.100.50"},
        {"description": "Network reconnaissance tool detected", "group": "B", "base_score": 65, "source_ip": "45.33.22.11"},
        
        # Group C - Malware
        {"description": "Suspicious process: /tmp/.X11-unix/xord", "group": "C", "base_score": 95, "source_ip": "10.0.0.45"},
        {"description": "Cron job added to /var/spool/cron/root", "group": "C", "base_score": 90, "source_ip": "10.0.0.45"},
        {"description": "Miner malware detected running on system", "group": "C", "base_score": 98, "source_ip": ""},
        
        # Group D - File Integrity
        {"description": "/etc/passwd modified unexpectedly", "group": "D", "base_score": 88, "source_ip": ""},
        {"description": "SSH authorized_keys file changed", "group": "D", "base_score": 92, "source_ip": "203.0.113.67"},
        
        # Group E - Denial of Service
        {"description": "SYN flood attack detected from 203.0.113.77", "group": "E", "base_score": 88, "source_ip": "203.0.113.77"},
        {"description": "UDP flood detected overwhelming port 53", "group": "E", "base_score": 75, "source_ip": "198.51.100.10"},

        # Group F - Lateral Movement
        {"description": "SMB lateral movement detected pass-the-hash", "group": "F", "base_score": 92, "source_ip": "192.168.56.30"},
        {"description": "PSExec remote execution attempt from internal host", "group": "F", "base_score": 85, "source_ip": "192.168.56.30"},

        # Group G - Privilege Escalation
        {"description": "sudo privilege escalation detected on server", "group": "G", "base_score": 90, "source_ip": ""},
        {"description": "SUID binary exploitation attempt detected", "group": "G", "base_score": 80, "source_ip": ""},

        # Group H - Web Attacks
        {"description": "SQL injection attempt: ' OR '1'='1", "group": "H", "base_score": 82, "source_ip": "192.0.2.150"},
        {"description": "XSS attempt with <script>alert(1)</script>", "group": "H", "base_score": 70, "source_ip": "198.51.100.33"},

        # Group I - Data Exfiltration
        {"description": "Large outbound transfer bulk upload detected", "group": "I", "base_score": 93, "source_ip": ""},
        {"description": "DNS tunneling exfiltration channel detected", "group": "I", "base_score": 88, "source_ip": ""},

        # Group J - Persistence
        {"description": "Rootkit detected: suspicious kernel module", "group": "J", "base_score": 100, "source_ip": ""},
        {"description": "Hidden process found with name [kthreadd]", "group": "J", "base_score": 98, "source_ip": ""},
    ]
    
    alerts = []
    for i in range(min(count, len(attack_types) * 2)):
        attack = random.choice(attack_types)
        # Generate timestamp in IST
        timestamp = (datetime.now(IST) - timedelta(minutes=random.randint(0, 60))).isoformat()
        
        risk_score = attack["base_score"] + random.randint(-10, 10)
        risk_score = max(0, min(100, risk_score))
        
        if risk_score >= 80:
            risk_label = "CRITICAL"
        elif risk_score >= 60:
            risk_label = "HIGH"
        elif risk_score >= 40:
            risk_label = "MEDIUM"
        elif risk_score >= 20:
            risk_label = "LOW"
        else:
            risk_label = "INFO"
        
        alerts.append({
            "id": f"alert_{i}_{random.randint(1000,9999)}",
            "timestamp": timestamp,
            "rule_id": f"rule_{random.randint(1000,9999)}",
            "description": attack["description"],
            "level": random.randint(5, 15),
            "agent_name": "ubuntu-vm",
            "agent_ip": "192.168.56.20",
            "source_ip": attack["source_ip"],
            "risk_score": risk_score,
            "risk_label": risk_label,
            "group": attack["group"],
            "confidence": random.choice(["HIGH", "MEDIUM", "LOW"]),
            "group_name": {
                "A": "🔐 Authentication Attack",
                "B": "🔍 Network Reconnaissance",
                "C": "🦠 Malware / Process",
                "D": "📁 File Integrity Violation",
                "E": "💥 Denial of Service",
                "F": "🔄 Lateral Movement",
                "G": "👑 Privilege Escalation",
                "H": "🌐 Web Application Attack",
                "I": "📤 Data Exfiltration",
                "J": "🎭 Rootkit / Persistence",
            }.get(attack["group"], f"Group {attack['group']}")
        })
    
    return sorted(alerts, key=lambda x: x["risk_score"], reverse=True)


# ────────────────────────────────────────────────────────────────
# HUMAN INTERVENTION MANAGER
# ────────────────────────────────────────────────────────────────

class HumanInterventionManager:
    """Manages pause states for critical/high alerts"""
    
    def __init__(self):
        self.paused_alerts = {}
    
    def requires_approval(self, alert):
        """Check if alert needs human approval before action"""
        risk_label = alert.get("risk_label", "LOW")
        
        if risk_label == "CRITICAL":
            return True, "🔴 CRITICAL alert requires your immediate approval"
        if risk_label == "HIGH":
            return True, "🟠 HIGH severity alert requires your approval"
        return False, None
    
    def is_paused(self, alert_id):
        """Check if this alert is currently paused"""
        if alert_id in self.paused_alerts:
            return not self.paused_alerts[alert_id].get("resolved", False)
        return False
    
    def pause_alert(self, alert_id, alert_data):
        """Pause an alert until human intervenes"""
        self.paused_alerts[alert_id] = {
            "timestamp": datetime.now(IST),
            "alert": alert_data,
            "resolved": False,
            "approved": False
        }
    
    def approve_alert(self, alert_id, action="proceed"):
        """Human approves and unpauses"""
        if alert_id in self.paused_alerts:
            self.paused_alerts[alert_id]["resolved"] = True
            self.paused_alerts[alert_id]["approved"] = True
            self.paused_alerts[alert_id]["action"] = action
            self.paused_alerts[alert_id]["resolved_at"] = datetime.now(IST)
            return True
        return False
    
    def reject_alert(self, alert_id):
        """Human rejects/ignores the alert"""
        if alert_id in self.paused_alerts:
            self.paused_alerts[alert_id]["resolved"] = True
            self.paused_alerts[alert_id]["approved"] = False
            self.paused_alerts[alert_id]["resolved_at"] = datetime.now(IST)
            return True
        return False
    
    def get_paused_alerts(self):
        """Get all currently paused alerts"""
        return {k: v for k, v in self.paused_alerts.items() if not v.get("resolved", False)}


# Initialize human intervention manager
if 'human_manager' not in st.session_state:
    st.session_state.human_manager = HumanInterventionManager()

# ────────────────────────────────────────────────────────────────
# TEAM MODULE IMPORTS (with graceful fallbacks)
# ────────────────────────────────────────────────────────────────

_HERE = os.path.dirname(os.path.abspath(__file__))

# Test mode flag
if 'test_mode' not in st.session_state:
    st.session_state.test_mode = False

# Import Wazuh API module
try:
    from wazuh_api import get_alerts
    WA_ZUH_AVAILABLE = True
except ImportError:
    WA_ZUH_AVAILABLE = False
    get_alerts = None

# Import Risk Engine module
try:
    from risk_engine import calculate_risk
    RISK_ENGINE_AVAILABLE = True
except ImportError:
    RISK_ENGINE_AVAILABLE = False
    calculate_risk = None

# Import Playbook module (optional)
try:
    from playbook_groupA import run_playbook_A
    PLAYBOOK_A_AVAILABLE = True
except ImportError:
    PLAYBOOK_A_AVAILABLE = False
    run_playbook_A = None

# Import Database module
try:
    from database import DatabaseManager
    DATABASE_FILE = "database.py"
    DATABASE_AVAILABLE = True
except ImportError:
    try:
        from database2 import DatabaseManager
        DATABASE_FILE = "database2.py"
        DATABASE_AVAILABLE = True
    except ImportError:
        DATABASE_AVAILABLE = False
        DatabaseManager = None


# ────────────────────────────────────────────────────────────────
# DATABASE COMPATIBILITY WRAPPER
# ────────────────────────────────────────────────────────────────

class DatabaseWrapper:
    """Wraps database methods to handle any naming differences"""
    
    def __init__(self, db_instance):
        self.db = db_instance
    
    def get_incident_stats(self):
        """Get statistics - handles multiple possible method names"""
        try:
            if hasattr(self.db, 'get_incident_stats'):
                return self.db.get_incident_stats()
            if hasattr(self.db, 'get_stats'):
                return self.db.get_stats()
            if hasattr(self.db, 'get_summary'):
                return self.db.get_summary()
        except Exception:
            pass
        
        try:
            incidents = self.get_all_incidents(limit=1000)
            stats = {
                "total": len(incidents),
                "open": len([i for i in incidents if i.get("status") == "open"]),
                "critical_open": len([i for i in incidents if i.get("status") == "open" and i.get("severity") == "critical"]),
                "by_status": {},
                "by_severity": {},
                "by_category": {}
            }
            
            for inc in incidents:
                status = inc.get("status", "unknown")
                severity = inc.get("severity", "unknown")
                category = inc.get("category", "unknown")
                
                stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
                stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
                stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            
            return stats
        except Exception:
            return {"total": 0, "open": 0, "critical_open": 0, "by_status": {}, "by_severity": {}, "by_category": {}}
    
    def get_open_incidents(self, limit=50):
        """Get open incidents"""
        try:
            if hasattr(self.db, 'get_open_incidents'):
                return self.db.get_open_incidents(limit=limit)
            if hasattr(self.db, 'get_incidents'):
                incidents = self.db.get_incidents(status="open", limit=limit)
                return incidents if incidents else []
        except Exception:
            pass
        return []
    
    def close_incident(self, incident_id, resolution_notes="", assigned_to="Analyst"):
        """Close an incident"""
        try:
            if hasattr(self.db, 'close_incident'):
                return self.db.close_incident(incident_id, resolution_notes, assigned_to)
            if hasattr(self.db, 'update_incident'):
                return self.db.update_incident(incident_id, {"status": "closed", "resolution_notes": resolution_notes, "assigned_to": assigned_to})
            if hasattr(self.db, 'update_incident_status'):
                return self.db.update_incident_status(incident_id, "closed", resolution_notes)
        except Exception:
            pass
        return False
    
    def get_all_incidents(self, status=None, severity=None, limit=100):
        """Get all incidents with filters"""
        try:
            if hasattr(self.db, 'get_all_incidents'):
                return self.db.get_all_incidents(status=status, severity=severity, limit=limit)
            if hasattr(self.db, 'get_incidents'):
                kwargs = {}
                if status:
                    kwargs['status'] = status
                if severity:
                    kwargs['severity'] = severity
                kwargs['limit'] = limit
                return self.db.get_incidents(**kwargs)
        except Exception:
            pass
        return []
    
    def create_report(self, title, report_type, generated_by, format="txt"):
        """Create a report entry"""
        try:
            if hasattr(self.db, 'create_report'):
                return self.db.create_report(title, report_type, generated_by, format)
        except Exception:
            pass
        return None
    
    def finalize_report(self, report_id, filepath, data_summary=None):
        """Finalize a report"""
        try:
            if hasattr(self.db, 'finalize_report'):
                return self.db.finalize_report(report_id, filepath, data_summary)
        except Exception:
            pass
        return None
    
    def add_history_entry(self, event_type, entity_type, entity_id, summary, user_name, severity="info"):
        """Add audit trail entry"""
        try:
            if hasattr(self.db, 'add_history_entry'):
                return self.db.add_history_entry(event_type, entity_type, entity_id, summary, user_name, severity)
        except Exception:
            pass
        return None


# ────────────────────────────────────────────────────────────────
# DATABASE SETUP
# ────────────────────────────────────────────────────────────────
if DATABASE_AVAILABLE and DatabaseManager:
    DB_PATH = os.path.join(_HERE, "data", "soc_automation.db")
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    try:
        raw_db = DatabaseManager(db_path=DB_PATH)
        db = DatabaseWrapper(raw_db)
        DB_CONNECTED = True
    except Exception:
        DB_CONNECTED = False
        db = None
else:
    DB_CONNECTED = False
    db = None


# ────────────────────────────────────────────────────────────────
# GROUP NAME LOOKUP
# ────────────────────────────────────────────────────────────────
GROUP_NAMES = {
    "A": "🔐 Authentication Attack",
    "B": "🔍 Network Reconnaissance", 
    "C": "🦠 Malware / Process",
    "D": "📁 File Integrity Violation",
    "E": "💥 Denial of Service",
    "F": "🔄 Lateral Movement",
    "G": "👑 Privilege Escalation",
    "H": "🌐 Web Application Attack",
    "I": "📤 Data Exfiltration",
    "J": "🎭 Rootkit / Persistence",
}


# ────────────────────────────────────────────────────────────────
# HELPER: Get Enriched Alerts (with test mode support)
# ────────────────────────────────────────────────────────────────
def get_enriched_alerts(limit=100):
    """Fetch alerts from Wazuh (or test mode only)"""
    
    # TEST MODE: Use fake logs
    if st.session_state.get('test_mode', False):
        return generate_fake_alerts(min(limit, 30))
    
    # NOT test mode — only use real Wazuh, never fake alerts
    if not WA_ZUH_AVAILABLE or not RISK_ENGINE_AVAILABLE:
        return []   # show 0 alerts until Wazuh is connected
    
    try:
        raw = get_alerts(limit=limit, min_level=1)
    except Exception:
        return []   # show 0 alerts if Wazuh call fails
    
    enriched = []
    for a in raw:
        try:
            risk = calculate_risk(a)
        except Exception:
            risk = {"score": 0, "label": "INFO", "group": "B", "confidence": "LOW"}
        
        enriched.append({
            "id": a.get("id", f"sim_{random.randint(1000,9999)}"),
            "timestamp": a.get("timestamp", datetime.now(IST).isoformat()),
            "rule_id": a.get("rule", {}).get("id", ""),
            "description": a.get("rule", {}).get("description", "Unknown alert"),
            "level": a.get("rule", {}).get("level", 0),
            "agent_name": a.get("agent", {}).get("name", "ubuntu-vm"),
            "agent_ip": a.get("agent", {}).get("ip", "192.168.56.20"),
            "source_ip": a.get("data", {}).get("srcip", a.get("srcip", "")),
            "risk_score": risk["score"],
            "risk_label": risk["label"],
            "group": risk["group"],
            "confidence": risk["confidence"],
            "group_name": GROUP_NAMES.get(risk["group"], f"Group {risk['group']}"),
        })
    
    return enriched


# ────────────────────────────────────────────────────────────────
# SIDEBAR — Navigation (TOP) & Status (BOTTOM)
# ────────────────────────────────────────────────────────────────
st.sidebar.title("🛡️ SOC Dashboard")
st.sidebar.markdown("---")

# ================================================================
# SECTION 1: NAVIGATION (TOP)
# ================================================================
st.sidebar.subheader("📋 Navigate")

menu = st.sidebar.radio(
    "Go to page:",
    ["📊 Overview", "🚨 Raw Alerts", "⏸️ Paused Alerts", "✅ Approval Queue", "📋 Incident History", "📄 Reports"],
    label_visibility="collapsed"
)

st.sidebar.markdown("---")

# ================================================================
# SECTION 2: TEST MODE TOGGLE
# ================================================================
st.sidebar.subheader("🧪 Testing")
test_mode = st.sidebar.toggle("🎲 Test Mode (Fake Logs)", value=st.session_state.test_mode)
if test_mode != st.session_state.test_mode:
    st.session_state.test_mode = test_mode
    st.cache_data.clear()
    st.rerun()

if st.session_state.test_mode:
    st.sidebar.info("🎲 TEST MODE ACTIVE — Using generated fake alerts")

st.sidebar.markdown("---")

# ================================================================
# SECTION 3: CONNECTION STATUS (BOTTOM)
# ================================================================
st.sidebar.subheader("🔌 Connection Status")

# Show .env status
wazuh_url    = os.getenv("WAZUH_URL")
indexer_url  = os.getenv("INDEXER_URL")
if wazuh_url:
    st.sidebar.success(f"✅ Wazuh API: {wazuh_url}")
else:
    st.sidebar.warning("⚠️ .env not found or no WAZUH_URL")
if indexer_url:
    st.sidebar.success(f"✅ Indexer: {indexer_url}")
else:
    st.sidebar.warning("⚠️ No INDEXER_URL — alerts may fall back to test data")

# Show module status
if st.session_state.test_mode:
    st.sidebar.info("🎲 Test Mode Active")
else:
    if WA_ZUH_AVAILABLE:
        st.sidebar.success("✅ Wazuh API")
    else:
        st.sidebar.warning("⚠️ Wazuh API (using fallback)")

if RISK_ENGINE_AVAILABLE or st.session_state.test_mode:
    st.sidebar.success("✅ Risk Engine")
else:
    st.sidebar.warning("⚠️ Risk Engine (using fallback)")

if PLAYBOOK_A_AVAILABLE:
    st.sidebar.info("ℹ️ Playbook A (optional)")
else:
    st.sidebar.info("ℹ️ Playbook A (not loaded)")

if DB_CONNECTED:
    st.sidebar.success(f"✅ Database ({DATABASE_FILE if DATABASE_AVAILABLE else 'None'})")
else:
    st.sidebar.warning("⚠️ Database (demo mode)")

st.sidebar.markdown("---")

# Show paused alerts count
paused_count = len(st.session_state.human_manager.get_paused_alerts())
if paused_count > 0:
    st.sidebar.error(f"⏸️ {paused_count} alert(s) awaiting human intervention")
else:
    st.sidebar.success("✅ No paused alerts")

st.sidebar.markdown("---")
st.sidebar.caption(f"🕐 {get_current_ist()}")

if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
    st.cache_data.clear()
    st.rerun()


# ────────────────────────────────────────────────────────────────
# PAGE 1: OVERVIEW
# ────────────────────────────────────────────────────────────────
if menu == "📊 Overview":
    st.title("📊 SOC Automation Dashboard")
    
    if st.session_state.test_mode:
        st.warning("🎲 **TEST MODE ACTIVE** — All data is simulated for testing purposes")
    
    st.markdown(f"*Last updated: {get_current_ist()}*")
    st.markdown("---")
    
    if DB_CONNECTED and db:
        stats = db.get_incident_stats()
    else:
        stats = {"total": 0, "open": 0, "critical_open": 0, "by_status": {}, "by_severity": {}, "by_category": {}}
    
    alerts = get_enriched_alerts(limit=1000)
    paused = st.session_state.human_manager.get_paused_alerts()
    
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("🚨 Alerts", len(alerts))
    with col2:
        st.metric("📌 Open Incidents", stats.get("open", 0))
    with col3:
        st.metric("🔴 Critical Open", stats.get("critical_open", 0))
    with col4:
        st.metric("📊 Total Incidents", stats.get("total", 0))
    with col5:
        st.metric("⏸️ Paused", len(paused), delta="Needs action" if len(paused) > 0 else None)
    
    st.markdown("---")
    
    if len(paused) > 0:
        st.error(f"⚠️ **{len(paused)} CRITICAL/HIGH ALERTS PAUSED** — Waiting for human intervention!")
        
        for alert_id, paused_info in list(paused.items())[:3]:
            alert = paused_info.get("alert", {})
            st.warning(f"🔴 **{alert.get('risk_label', 'UNKNOWN')}** - {alert.get('description', 'No description')[:80]}...")
            
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button(f"✅ Approve", key=f"ov_approve_{alert_id}"):
                    st.session_state.human_manager.approve_alert(alert_id, "proceed")
                    st.rerun()
            with col_b:
                if st.button(f"❌ Reject", key=f"ov_reject_{alert_id}"):
                    st.session_state.human_manager.reject_alert(alert_id)
                    st.rerun()
    
    sev = stats.get("by_severity", {})
    if sev and sum(sev.values()) > 0:
        st.subheader("📈 Incidents by Severity")
        sev_df = pd.DataFrame(list(sev.items()), columns=["Severity", "Count"])
        st.dataframe(sev_df, use_container_width=True, hide_index=True)
    else:
        st.info("No incidents in database yet. Run pipeline or enable Test Mode.")


# ────────────────────────────────────────────────────────────────
# PAGE 2: RAW ALERTS
# ────────────────────────────────────────────────────────────────
elif menu == "🚨 Raw Alerts":
    st.title("🚨 Live Alerts with Human Intervention")
    st.markdown("🔴 **CRITICAL** and 🟠 **HIGH** severity alerts are **PAUSED** until you approve them")
    st.markdown("---")
    
    alerts = get_enriched_alerts(limit=1000)
    
    if not alerts:
        st.info("No alerts available. Enable Test Mode or connect Wazuh.")
        st.stop()
    
    col1, col2, col3 = st.columns(3)
    with col1:
        risk_filter = st.selectbox("Min Risk", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with col2:
        groups = ["All"] + sorted(set(a.get("group", "?") for a in alerts))
        group_filter = st.selectbox("Group", groups)
    with col3:
        show_paused_only = st.checkbox("Show only paused alerts")
    
    filtered = []
    for a in alerts:
        if risk_filter != "All":
            risk_map = {"CRITICAL": 80, "HIGH": 60, "MEDIUM": 40, "LOW": 20}
            if a.get("risk_score", 0) < risk_map.get(risk_filter, 0):
                continue
        if group_filter != "All" and a.get("group") != group_filter:
            continue
        
        alert_id = a.get("id", str(hash(str(a))))
        is_paused = st.session_state.human_manager.is_paused(alert_id)
        
        if show_paused_only and not is_paused:
            continue
        
        filtered.append(a)
    
    for alert in filtered:
        risk_score = alert.get("risk_score", 0)
        risk_label = alert.get("risk_label", "UNKNOWN")
        alert_id = alert.get("id", str(hash(str(alert))))
        needs_approval, reason = st.session_state.human_manager.requires_approval(alert)
        is_paused = st.session_state.human_manager.is_paused(alert_id)
        
        if needs_approval and not is_paused and alert_id not in st.session_state.human_manager.paused_alerts:
            st.session_state.human_manager.pause_alert(alert_id, alert)
            is_paused = True
        
        if risk_score >= 80:
            icon = "🔴"
        elif risk_score >= 60:
            icon = "🟠"
        elif risk_score >= 40:
            icon = "🟡"
        else:
            icon = "🟢"
        
        # Convert timestamp to IST
        timestamp_ist = convert_to_ist(alert.get("timestamp", "N/A"))

        with st.container():
            st.markdown("---")
            
            col1, col2 = st.columns([4, 1])
            
            with col1:
                st.markdown(
                    f"**{icon} {timestamp_ist}** — "
                    f"`{alert.get('description', 'No description')}`"
                )
                st.caption(f"Score: {risk_score} | Group: {alert.get('group', '?')} | Source: {alert.get('source_ip', 'N/A')}")
            
            with col2:
                st.metric("Risk", f"{risk_score}", delta=risk_label)
            
            if is_paused:
                st.error(f"⏸️ **PAUSED — {reason}**")
                
                col_a, col_b = st.columns(2)
                with col_a:
                    if st.button(f"✅ Approve", key=f"approve_{alert_id}"):
                        st.session_state.human_manager.approve_alert(alert_id, "proceed")
                        st.rerun()
                with col_b:
                    if st.button(f"❌ Reject", key=f"reject_{alert_id}"):
                        st.session_state.human_manager.reject_alert(alert_id)
                        st.rerun()
            else:
                st.success(f"✅ Approved — Action will proceed automatically")


# ────────────────────────────────────────────────────────────────
# PAGE 3: PAUSED ALERTS
# ────────────────────────────────────────────────────────────────
elif menu == "⏸️ Paused Alerts":
    st.title("⏸️ Human Intervention Queue")
    st.markdown("**CRITICAL** and **HIGH** severity alerts are paused here until you approve or reject them")
    st.markdown("---")
    
    paused = st.session_state.human_manager.get_paused_alerts()
    
    if not paused:
        st.success("✅ No paused alerts! All critical/high alerts have been handled.")
        st.balloons()
    else:
        st.error(f"⚠️ **{len(paused)} ALERTS AWAITING YOUR DECISION**")
        
        for alert_id, paused_info in paused.items():
            alert = paused_info.get("alert", {})
            paused_time = paused_info.get("timestamp", datetime.now(IST))
            
            risk_score = alert.get("risk_score", 0)
            risk_label = alert.get("risk_label", "UNKNOWN")
            
            # Convert alert timestamp to IST
            alert_timestamp_ist = convert_to_ist(alert.get("timestamp", "N/A"))
            
            with st.container(border=True):
                col1, col2, col3 = st.columns([3, 1, 1])
                
                with col1:
                    if risk_score >= 80:
                        st.markdown(f"🔴 **CRITICAL** — {alert.get('description', 'No description')}")
                    else:
                        st.markdown(f"🟠 **HIGH** — {alert.get('description', 'No description')}")
                    
                    st.caption(f"📅 Time: {alert_timestamp_ist}")
                    st.caption(f"🎯 Source IP: {alert.get('source_ip', 'N/A')}")
                    st.caption(f"📊 Risk Score: {risk_score} | Group: {alert.get('group', '?')}")
                    st.caption(f"⏸️ Paused since: {paused_time.strftime('%Y-%m-%d %I:%M:%S %p IST')}")
                
                with col2:
                    if st.button(f"✅ Approve", key=f"approve_paused_{alert_id}", use_container_width=True):
                        st.session_state.human_manager.approve_alert(alert_id, "proceed")
                        st.rerun()
                
                with col3:
                    if st.button(f"❌ Reject", key=f"reject_paused_{alert_id}", use_container_width=True):
                        st.session_state.human_manager.reject_alert(alert_id)
                        st.rerun()
            
            st.markdown("---")


# ────────────────────────────────────────────────────────────────
# PAGE 4: APPROVAL QUEUE
# ────────────────────────────────────────────────────────────────
elif menu == "✅ Approval Queue":
    st.title("✅ Incident Approval Queue")
    st.markdown("Incidents created by the pipeline — review and close them")
    st.markdown("---")
    
    if not DB_CONNECTED or not db:
        st.info("📭 Database not connected. Run the pipeline first.")
        st.info("💡 Or enable Test Mode to see demo incidents")
        st.stop()
    
    try:
        pending = db.get_open_incidents(limit=50)
    except Exception:
        pending = []
    
    if not pending:
        st.success("🎉 No open incidents! Great work!")
    else:
        st.warning(f"⚠️ {len(pending)} incident(s) awaiting closure")
        
        for inc in pending:
            inc_id = inc.get("incident_id", "N/A")
            title = inc.get("title", "Untitled")
            severity = inc.get("severity", "unknown").upper()
            
            with st.expander(f"{inc_id} — {title} [{severity}]", expanded=False):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.markdown(f"**Description:** {inc.get('description', 'No description')}")
                    st.markdown(f"**Category:** {inc.get('category', 'N/A')}")
                    st.markdown(f"**Source IP:** {inc.get('source', 'N/A')}")
                    
                    # Show detection time in IST if available
                    detection_time = inc.get('detection_time')
                    if detection_time:
                        detection_ist = convert_to_ist(detection_time)
                        st.markdown(f"**Detection Time (IST):** {detection_ist}")
                
                with col2:
                    notes = st.text_area("Resolution notes", key=f"notes_{inc_id}", height=80)
                    
                    if st.button(f"✅ Close Incident", key=f"close_{inc_id}", use_container_width=True):
                        success = db.close_incident(
                            incident_id=inc_id,
                            resolution_notes=notes or "Closed by Analyst",
                            assigned_to="Analyst"
                        )
                        if success:
                            st.success(f"✅ Incident {inc_id} closed!")
                            st.rerun()
                        else:
                            st.error("Failed to close incident")


# ────────────────────────────────────────────────────────────────
# PAGE 5: INCIDENT HISTORY
# ────────────────────────────────────────────────────────────────
elif menu == "📋 Incident History":
    st.title("📋 Incident History")
    st.markdown("---")
    
    if not DB_CONNECTED or not db:
        st.info("No database connection. Run pipeline first.")
        st.stop()
    
    col1, col2 = st.columns(2)
    with col1:
        status_filter = st.selectbox("Status", ["All", "open", "closed"])
    with col2:
        limit = st.number_input("Max records", min_value=10, max_value=500, value=100)
    
    try:
        incidents = db.get_all_incidents(
            status=status_filter if status_filter != "All" else None,
            limit=int(limit)
        )
    except Exception:
        incidents = []
    
    if incidents:
        # Convert timestamps to IST for display
        df = pd.DataFrame(incidents)
        
        # Convert detection_time to IST if present
        if 'detection_time' in df.columns:
            df['detection_time_ist'] = df['detection_time'].apply(
                lambda x: convert_to_ist(x) if pd.notna(x) else 'N/A'
            )
        
        if 'resolved_at' in df.columns:
            df['resolved_at_ist'] = df['resolved_at'].apply(
                lambda x: convert_to_ist(x) if pd.notna(x) else 'N/A'
            )
        
        st.dataframe(df, use_container_width=True, height=400)
        
        csv = df.to_csv(index=False)
        st.download_button("📥 Download CSV", csv, f"incidents_{datetime.now(IST).strftime('%Y%m%d_%H%M%S')}.csv")
        
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total", len(df))
        with col2:
            open_count = len([i for i in incidents if i.get("status") == "open"])
            st.metric("Open", open_count)
        with col3:
            closed_count = len([i for i in incidents if i.get("status") == "closed"])
            st.metric("Closed", closed_count)
    else:
        st.info("No incidents found")


# ────────────────────────────────────────────────────────────────
# PAGE 6: REPORTS
# ────────────────────────────────────────────────────────────────
elif menu == "📄 Reports":
    st.title("📄 Reports")
    st.markdown("---")
    
    REPORTS_DIR = os.path.join(_HERE, "reports")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    tab1, tab2 = st.tabs(["✍️ Write Report", "📑 Generate PDF"])
    
    # TAB 1: Manual Report
    with tab1:
        st.header("Write Daily Report")
        
        col1, col2 = st.columns(2)
        with col1:
            report_title = st.text_input(
                "Report Title",
                value=f"SOC Daily Report - {datetime.now(IST).strftime('%B %d, %Y')}"
            )
        with col2:
            analyst = st.text_input("Analyst Name", value="Analyst")
        
        notes = st.text_area(
            "Observations & Findings",
            height=150,
            placeholder="""Example:
- Detected 3 critical SSH brute-force attacks today
- All source IPs were automatically blocked
- I reviewed and approved all incidents
- No data exfiltration detected
- 0 critical incidents remain open"""
        )
        
        if st.button("💾 Save Report", type="primary", use_container_width=True):
            if not notes.strip():
                st.warning("Please add some notes before saving.")
            else:
                timestamp = datetime.now(IST).strftime("%Y%m%d_%H%M%S")
                filename = f"{REPORTS_DIR}/{report_title.replace(' ', '_')}_{timestamp}.txt"
                
                with open(filename, "w") as f:
                    f.write(f"Report Title: {report_title}\n")
                    f.write(f"Prepared by: {analyst}\n")
                    f.write(f"Date (IST): {get_current_ist()}\n")
                    f.write(f"Notes:\n{notes}\n")
                
                if DB_CONNECTED and db:
                    try:
                        rid = db.create_report(report_title, "manual_daily", analyst, "txt")
                        if rid:
                            db.finalize_report(rid, filename)
                    except Exception:
                        pass
                
                st.success(f"✅ Report saved to `{filename}`")
                
                with open(filename, "r") as f:
                    st.download_button(
                        "📥 Download Report",
                        f.read(),
                        file_name=os.path.basename(filename),
                        mime="text/plain"
                    )
        
        st.markdown("---")
        st.subheader("📁 Previously Saved Reports")
        
        saved_reports = sorted([f for f in os.listdir(REPORTS_DIR) if f.endswith(".txt")], reverse=True)
        if saved_reports:
            for report in saved_reports[:10]:
                col1, col2 = st.columns([4, 1])
                col1.write(f"📄 {report}")
                with col2:
                    with open(os.path.join(REPORTS_DIR, report), "r") as f:
                        st.download_button("Download", f.read(), file_name=report, key=report)
        else:
            st.info("No reports saved yet.")
    
    # TAB 2: PDF Report
    with tab2:
        st.header("Generate PDF Audit Report")
        st.markdown("Create a PDF report of all closed incidents")
        
        if not DB_CONNECTED or not db:
            st.warning("Database not connected. Cannot generate PDF.")
        else:
            try:
                closed_incidents = db.get_all_incidents(status="closed", limit=500)
            except Exception:
                closed_incidents = []
            
            if not closed_incidents:
                st.info("📭 No closed incidents yet. Go to Approval Queue and close some incidents first.")
            else:
                st.success(f"📊 **{len(closed_incidents)}** closed incidents available for report")
                
                col1, col2 = st.columns(2)
                with col1:
                    pdf_title = st.text_input(
                        "PDF Title",
                        value=f"SOC Audit Report - {datetime.now(IST).strftime('%B %Y')}"
                    )
                with col2:
                    pdf_author = st.text_input("Author", value="Analyst")
                
                if st.button("📑 Generate PDF Report", type="primary", use_container_width=True):
                    try:
                        from reportlab.lib.pagesizes import A4, landscape
                        from reportlab.lib import colors
                        from reportlab.lib.styles import getSampleStyleSheet
                        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
                        
                        pdf_buffer = io.BytesIO()
                        doc = SimpleDocTemplate(
                            pdf_buffer,
                            pagesize=landscape(A4),
                            title=pdf_title,
                            author=pdf_author
                        )
                        
                        styles = getSampleStyleSheet()
                        elements = []
                        
                        elements.append(Paragraph(pdf_title, styles["Title"]))
                        elements.append(Spacer(1, 12))
                        
                        elements.append(Paragraph(
                            f"Generated (IST): {get_current_ist()} | Author: {pdf_author}",
                            styles["Normal"]
                        ))
                        elements.append(Spacer(1, 12))
                        
                        critical = len([i for i in closed_incidents if i.get("severity") == "critical"])
                        high = len([i for i in closed_incidents if i.get("severity") == "high"])
                        medium = len([i for i in closed_incidents if i.get("severity") == "medium"])
                        
                        elements.append(Paragraph(
                            f"<b>Summary:</b> {len(closed_incidents)} total closed incidents — "
                            f"{critical} critical, {high} high, {medium} medium",
                            styles["Normal"]
                        ))
                        elements.append(Spacer(1, 20))
                        
                        elements.append(Paragraph("<b>Closed Incidents Detail</b>", styles["Heading2"]))
                        elements.append(Spacer(1, 8))
                        
                        headers = ["ID", "Title", "Severity", "Category", "Closed At (IST)", "Resolution"]
                        table_data = [headers]
                        
                        for inc in closed_incidents[:100]:
                            resolved_at = inc.get("resolved_at", "")
                            resolved_ist = convert_to_ist(resolved_at) if resolved_at else "N/A"
                            
                            table_data.append([
                                str(inc.get("incident_id", ""))[:20],
                                str(inc.get("title", ""))[:35],
                                str(inc.get("severity", "")),
                                str(inc.get("category", ""))[:20],
                                resolved_ist[:16],
                                str(inc.get("resolution_notes", "") or "")[:45],
                            ])
                        
                        table = Table(table_data, repeatRows=1)
                        table.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
                        ]))
                        elements.append(table)
                        elements.append(Spacer(1, 20))
                        
                        report_id = f"RPT-{datetime.now(IST).strftime('%Y%m%d')}-{os.urandom(4).hex().upper()}"
                        elements.append(Paragraph(f"Report ID: {report_id}", styles["Normal"]))
                        elements.append(Paragraph(
                            "<i>Auto-generated by SOC Dashboard</i>",
                            styles["Normal"]
                        ))
                        
                        doc.build(elements)
                        pdf_buffer.seek(0)
                        
                        pdf_filename = f"{REPORTS_DIR}/audit_report_{datetime.now(IST).strftime('%Y%m%d_%H%M%S')}.pdf"
                        with open(pdf_filename, "wb") as f:
                            f.write(pdf_buffer.getvalue())
                        
                        if DB_CONNECTED and db:
                            try:
                                rid = db.create_report(pdf_title, "incident_summary", pdf_author, "pdf")
                                if rid:
                                    db.finalize_report(rid, pdf_filename)
                            except Exception:
                                pass
                        
                        st.success(f"✅ PDF generated successfully!")
                        st.download_button(
                            "📥 Download PDF Report",
                            pdf_buffer.getvalue(),
                            file_name=os.path.basename(pdf_filename),
                            mime="application/pdf"
                        )
                        
                    except ImportError:
                        st.error("❌ ReportLab not installed. Run: `pip install reportlab`")
                    except Exception as e:
                        st.error(f"❌ PDF generation error: {e}")


# ────────────────────────────────────────────────────────────────
# FOOTER
# ────────────────────────────────────────────────────────────────
st.markdown("---")
st.caption(f"🛡️ SOC Dashboard | Mode: {'Test' if st.session_state.test_mode else 'Live'} | Database: {'Connected' if DB_CONNECTED else 'Demo'} | Timezone: IST (UTC+5:30)")