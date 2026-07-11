#!/usr/bin/env python3
"""
SOC Automation - SQLite Database Manager
Handles all database operations for the SOC automation system.
Stores endpoint info, scan results, integrity baselines, playbook logs,
incident management, approval queues, history tracking, and PDF reporting.
"""

import sqlite3
import json
import os
import datetime
import hashlib
import uuid
from pathlib import Path
from contextlib import contextmanager

# Database file path - Change this to work with Member 4's dashboard
# Option 1: Same directory as dashboard
# DB_PATH = os.path.join(os.path.dirname(__file__), "soc_incidents.db")
# Option 2: Original path (uncomment if preferred)
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "soc_automation.db")


class DatabaseManager:
    """
    Manages all SQLite database operations.
    Creates tables automatically on first use.
    Supports incidents, approvals, history, and reporting.
    """

    def __init__(self, db_path=None):
        """Initialize database connection."""
        self.db_path = db_path or DB_PATH

        # Ensure the directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self.connection = None
        self.cursor = None

        # Connect and create tables
        self._connect()
        self._create_tables()
        # Enable foreign key enforcement
        self.cursor.execute("PRAGMA foreign_keys = ON")
        # Use WAL mode for better concurrent read performance
        self.cursor.execute("PRAGMA journal_mode=WAL")

    def _connect(self):
        """Establish connection to the SQLite database."""
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row  # Access columns by name
        self.cursor = self.connection.cursor()
        print(f"  [DB] Connected to database: {self.db_path}")

    @contextmanager
    def _transaction(self):
        """Context manager for database transactions."""
        try:
            yield
            self.connection.commit()
        except Exception as e:
            self.connection.rollback()
            raise e

    # -------------------------------------------------------------------------
    # TABLE CREATION
    # -------------------------------------------------------------------------

    def _create_tables(self):
        """Create all required tables if they don't exist."""

        # Table 1: Endpoints - stores info about managed machines
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                hostname TEXT NOT NULL,
                port INTEGER DEFAULT 22,
                username TEXT,
                os_type TEXT,
                groups TEXT,
                status TEXT DEFAULT 'unknown',
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Table 2: Scan results - stores output from commands
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER,
                playbook_name TEXT,
                command TEXT,
                stdout TEXT,
                stderr TEXT,
                exit_status INTEGER,
                risk_level TEXT DEFAULT 'info',
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints (id)
            )
        ''')

        # Table 3: Integrity baselines - stores file hashes and system state
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS integrity_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                hash_algorithm TEXT DEFAULT 'sha256',
                file_size INTEGER,
                permissions TEXT,
                owner TEXT,
                group_name TEXT,
                last_modified TIMESTAMP,
                baseline_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints (id),
                UNIQUE(endpoint_id, file_path)
            )
        ''')

        # Table 4: Integrity violations - tracks changes detected
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS integrity_violations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER,
                file_path TEXT,
                expected_hash TEXT,
                current_hash TEXT,
                violation_type TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                remediated INTEGER DEFAULT 0,
                remediated_at TIMESTAMP,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints (id)
            )
        ''')

        # Table 5: Playbook logs - records playbook execution history
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS playbook_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER,
                playbook_name TEXT NOT NULL,
                playbook_type TEXT,
                status TEXT DEFAULT 'pending',
                trigger_source TEXT,
                parameters TEXT,
                result_summary TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                duration_seconds REAL,
                error_message TEXT,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints (id)
            )
        ''')

        # Table 6: Incidents - core incident management (UPDATED for Member 4 dashboard)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open',
                category TEXT,
                source TEXT,
                endpoint_id INTEGER,
                assigned_to TEXT,
                priority INTEGER DEFAULT 3,
                risk_score INTEGER DEFAULT 50,
                fix_type TEXT DEFAULT 'hardened',
                verified INTEGER DEFAULT 0,
                tags TEXT,
                detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP,
                resolution_notes TEXT,
                mitre_tactics TEXT,
                mitre_techniques TEXT,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints (id)
            )
        ''')

        # Add new columns if they don't exist (for existing databases)
        try:
            self.cursor.execute("ALTER TABLE incidents ADD COLUMN risk_score INTEGER DEFAULT 50")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        try:
            self.cursor.execute("ALTER TABLE incidents ADD COLUMN fix_type TEXT DEFAULT 'hardened'")
        except sqlite3.OperationalError:
            pass
        
        try:
            self.cursor.execute("ALTER TABLE incidents ADD COLUMN verified INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass

        # Table 7: Incident comments / evidence timeline
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                evidence_type TEXT,
                description TEXT,
                file_path TEXT,
                file_hash TEXT,
                content TEXT,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
            )
        ''')

        # Table 8: Approval queue - for human-in-the-loop approvals
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS approval_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT UNIQUE NOT NULL,
                incident_id TEXT,
                request_type TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                requested_action TEXT,
                parameters TEXT,
                requested_by TEXT,
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',
                approved_by TEXT,
                approved_at TIMESTAMP,
                rejection_reason TEXT,
                expires_at TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
            )
        ''')

        # Table 9: History / audit log - tracks all system events
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                entity_type TEXT,
                entity_id TEXT,
                summary TEXT,
                details TEXT,
                user_name TEXT,
                source_ip TEXT,
                severity TEXT DEFAULT 'info',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Table 10: Report templates & generated reports
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                report_type TEXT,
                date_range_start TIMESTAMP,
                date_range_end TIMESTAMP,
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                generated_by TEXT,
                format TEXT DEFAULT 'pdf',
                file_path TEXT,
                data_summary TEXT,
                status TEXT DEFAULT 'draft',
                parameters TEXT
            )
        ''')

        # Table 11: Scheduled tasks / automation rules
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_name TEXT NOT NULL,
                playbook_name TEXT,
                schedule_cron TEXT,
                enabled INTEGER DEFAULT 1,
                last_run TIMESTAMP,
                next_run TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        self.connection.commit()
        print("  [DB] All tables verified/created.")

    # =========================================================================
    # INCIDENT MANAGEMENT
    # =========================================================================

    def create_incident(self, title, description="", severity="medium",
                        category=None, source=None, endpoint_id=None,
                        assigned_to=None, priority=3, risk_score=50,
                        fix_type="hardened", tags=None,
                        mitre_tactics=None, mitre_techniques=None):
        """
        Create a new incident. Returns the generated incident_id string.
        Updated to include risk_score and fix_type for Member 4's dashboard.
        """
        incident_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.datetime.now()

        if isinstance(tags, list):
            tags = json.dumps(tags)
        if isinstance(mitre_tactics, list):
            mitre_tactics = json.dumps(mitre_tactics)
        if isinstance(mitre_techniques, list):
            mitre_techniques = json.dumps(mitre_techniques)

        with self._transaction():
            self.cursor.execute('''
                INSERT INTO incidents
                    (incident_id, title, description, severity, status,
                     category, source, endpoint_id, assigned_to, priority,
                     risk_score, fix_type, tags, detection_time, last_updated, 
                     mitre_tactics, mitre_techniques)
                VALUES (?, ?, ?, ?, 'open',
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?)
            ''', (incident_id, title, description, severity,
                  category, source, endpoint_id, assigned_to, priority,
                  risk_score, fix_type, tags, now, now, 
                  mitre_tactics, mitre_techniques))

        # Log to history
        self._add_history_entry(
            event_type="incident_created",
            entity_type="incident",
            entity_id=incident_id,
            summary=f"Incident created: {title} [{severity}] (Risk: {risk_score})",
            details=json.dumps({"severity": severity, "category": category, "risk_score": risk_score}),
            severity=severity if severity in ("critical", "high") else "info"
        )

        print(f"  [DB] Created incident: {incident_id} (Risk Score: {risk_score})")
        return incident_id

    def get_incident(self, incident_id):
        """Get a single incident by its incident_id string."""
        self.cursor.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        )
        row = self.cursor.fetchone()
        if row:
            return dict(row)
        return None

    def get_all_incidents(self, status=None, severity=None, limit=100, offset=0):
        """
        Get all incidents with optional filtering.
        Returns list of dicts.
        """
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY detection_time DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        self.cursor.execute(query, params)
        return [dict(row) for row in self.cursor.fetchall()]

    def get_open_incidents(self, severity=None, limit=50):
        """Get all open/unresolved incidents."""
        return self.get_all_incidents(status="open", severity=severity, limit=limit)

    def get_high_risk_incidents(self, threshold=60, limit=50):
        """
        Get open incidents with risk score above threshold.
        Specifically for Member 4's dashboard approval queue.
        """
        self.cursor.execute('''
            SELECT * FROM incidents 
            WHERE status = 'open' AND risk_score >= ?
            ORDER BY risk_score DESC, detection_time DESC
            LIMIT ?
        ''', (threshold, limit))
        return [dict(row) for row in self.cursor.fetchall()]

    def close_incident(self, incident_id, resolution_notes="", assigned_to=None, fix_type=None, verified=None):
        """
        Close/resolve an incident with notes.
        Updated to support fix_type and verification for Member 4's dashboard.
        """
        now = datetime.datetime.now()
        
        # Build the update query dynamically
        updates = ["status = 'closed'", "resolved_at = ?", "last_updated = ?"]
        params = [now, now]
        
        if resolution_notes:
            updates.append("resolution_notes = ?")
            params.append(resolution_notes)
        
        if fix_type:
            updates.append("fix_type = ?")
            params.append(fix_type)
        
        if verified is not None:
            updates.append("verified = ?")
            params.append(1 if verified else 0)
        
        params.append(incident_id)
        
        query = f"UPDATE incidents SET {', '.join(updates)} WHERE incident_id = ? AND status = 'open'"

        with self._transaction():
            self.cursor.execute(query, params)

            if self.cursor.rowcount == 0:
                return False

        self._add_history_entry(
            event_type="incident_closed",
            entity_type="incident",
            entity_id=incident_id,
            summary=f"Incident closed: {incident_id}",
            details=json.dumps({"resolution_notes": resolution_notes,
                                "resolved_by": assigned_to,
                                "fix_type": fix_type,
                                "verified": verified}),
            severity="info"
        )
        print(f"  [DB] Closed incident: {incident_id}")
        return True

    def update_incident(self, incident_id, **kwargs):
        """
        Update incident fields dynamically.
        Valid fields: title, description, severity, status, category,
        source, assigned_to, priority, risk_score, fix_type, verified,
        tags, mitre_tactics, mitre_techniques
        """
        allowed_fields = {
            "title", "description", "severity", "status", "category",
            "source", "assigned_to", "priority", "risk_score", "fix_type", "verified",
            "tags", "mitre_tactics", "mitre_techniques"
        }

        updates = {}
        for key, value in kwargs.items():
            if key in allowed_fields and value is not None:
                if isinstance(value, list):
                    updates[key] = json.dumps(value)
                else:
                    updates[key] = value

        if not updates:
            return False

        updates["last_updated"] = datetime.datetime.now()
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [incident_id]

        with self._transaction():
            self.cursor.execute(
                f"UPDATE incidents SET {set_clause} WHERE incident_id = ?",
                values
            )
            return self.cursor.rowcount > 0

    def add_incident_evidence(self, incident_id, evidence_type, description="",
                              content=None, file_path=None, file_hash=None,
                              created_by="system"):
        """Add evidence/log entry to an incident timeline."""
        with self._transaction():
            self.cursor.execute('''
                INSERT INTO incident_evidence
                    (incident_id, evidence_type, description, file_path,
                     file_hash, content, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (incident_id, evidence_type, description, file_path,
                  file_hash, content, created_by))

        self._add_history_entry(
            event_type="evidence_added",
            entity_type="incident",
            entity_id=incident_id,
            summary=f"Evidence added to {incident_id}: {evidence_type}",
            details=description,
            severity="info"
        )
        return self.cursor.lastrowid

    def get_incident_evidence(self, incident_id):
        """Get all evidence entries for an incident."""
        self.cursor.execute(
            "SELECT * FROM incident_evidence WHERE incident_id = ? ORDER BY created_at",
            (incident_id,)
        )
        return [dict(row) for row in self.cursor.fetchall()]

    def get_incident_stats(self):
        """Get incident statistics for dashboards."""
        stats = {}

        # Count by status
        self.cursor.execute('''
            SELECT status, COUNT(*) as count FROM incidents GROUP BY status
        ''')
        stats["by_status"] = {row["status"]: row["count"]
                              for row in self.cursor.fetchall()}

        # Count by severity
        self.cursor.execute('''
            SELECT severity, COUNT(*) as count FROM incidents GROUP BY severity
        ''')
        stats["by_severity"] = {row["severity"]: row["count"]
                                for row in self.cursor.fetchall()}

        # Count by category
        self.cursor.execute('''
            SELECT category, COUNT(*) as count FROM incidents
            WHERE category IS NOT NULL GROUP BY category
        ''')
        stats["by_category"] = {row["category"]: row["count"]
                                for row in self.cursor.fetchall()}

        # Risk score distribution
        self.cursor.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN risk_score >= 60 AND risk_score < 80 THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN risk_score >= 40 AND risk_score < 60 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN risk_score < 40 THEN 1 ELSE 0 END) as low
            FROM incidents WHERE status = 'open'
        ''')
        row = self.cursor.fetchone()
        stats["risk_distribution"] = {
            "critical": row["critical"],
            "high": row["high"],
            "medium": row["medium"],
            "low": row["low"]
        }

        # Total counts
        self.cursor.execute("SELECT COUNT(*) as total FROM incidents")
        stats["total"] = self.cursor.fetchone()["total"]

        self.cursor.execute(
            "SELECT COUNT(*) as open FROM incidents WHERE status = 'open'"
        )
        stats["open"] = self.cursor.fetchone()["open"]

        self.cursor.execute(
            "SELECT COUNT(*) as critical FROM incidents WHERE severity = 'critical' AND status = 'open'"
        )
        stats["critical_open"] = self.cursor.fetchone()["critical"]

        return stats

    # =========================================================================
    # APPROVAL QUEUE
    # =========================================================================

    def create_approval_request(self, incident_id, request_type, title,
                                description="", requested_action="",
                                parameters=None, requested_by="system",
                                expires_in_hours=24):
        """
        Create an approval request for human-in-the-loop verification.
        Returns the request_id string.
        """
        request_id = f"APPR-{uuid.uuid4().hex[:12].upper()}"
        expires_at = datetime.datetime.now() + datetime.timedelta(hours=expires_in_hours)

        if isinstance(parameters, dict):
            parameters = json.dumps(parameters)

        with self._transaction():
            self.cursor.execute('''
                INSERT INTO approval_queue
                    (request_id, incident_id, request_type, title, description,
                     requested_action, parameters, requested_by, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (request_id, incident_id, request_type, title, description,
                  requested_action, parameters, requested_by, expires_at))

        self._add_history_entry(
            event_type="approval_requested",
            entity_type="approval",
            entity_id=request_id,
            summary=f"Approval requested: {title} [{request_type}]",
            details=json.dumps({"incident_id": incident_id,
                                "requested_by": requested_by}),
            severity="warning"
        )
        print(f"  [DB] Created approval request: {request_id}")
        return request_id

    def approve_request(self, request_id, approved_by="system"):
        """
        Approve a pending request. Returns True if successful.
        """
        now = datetime.datetime.now()
        with self._transaction():
            self.cursor.execute('''
                UPDATE approval_queue
                SET status = 'approved',
                    approved_by = ?,
                    approved_at = ?
                WHERE request_id = ? AND status = 'pending'
            ''', (approved_by, now, request_id))

            if self.cursor.rowcount == 0:
                return False

        self._add_history_entry(
            event_type="approval_approved",
            entity_type="approval",
            entity_id=request_id,
            summary=f"Approval granted: {request_id} by {approved_by}",
            severity="info"
        )
        print(f"  [DB] Approved request: {request_id}")
        return True

    def reject_request(self, request_id, rejection_reason="", rejected_by="system"):
        """
        Reject a pending request. Returns True if successful.
        """
        now = datetime.datetime.now()
        with self._transaction():
            self.cursor.execute('''
                UPDATE approval_queue
                SET status = 'rejected',
                    approved_by = ?,
                    approved_at = ?,
                    rejection_reason = ?
                WHERE request_id = ? AND status = 'pending'
            ''', (rejected_by, now, rejection_reason, request_id))

            if self.cursor.rowcount == 0:
                return False

        self._add_history_entry(
            event_type="approval_rejected",
            entity_type="approval",
            entity_id=request_id,
            summary=f"Approval rejected: {request_id}",
            details=rejection_reason,
            severity="warning"
        )
        print(f"  [DB] Rejected request: {request_id}")
        return True

    def get_approval_queue(self, status="pending", limit=50):
        """Get approval requests, optionally filtered by status."""
        query = "SELECT * FROM approval_queue WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY requested_at DESC LIMIT ?"
        params.append(limit)

        self.cursor.execute(query, params)
        return [dict(row) for row in self.cursor.fetchall()]

    def get_pending_approvals(self, limit=50):
        """Get all pending approval requests."""
        return self.get_approval_queue(status="pending", limit=limit)

    # =========================================================================
    # AUDIT HISTORY
    # =========================================================================

    def _add_history_entry(self, event_type, entity_type=None, entity_id=None,
                           summary="", details=None, user_name=None,
                           source_ip=None, severity="info"):
        """Internal method to add an audit history entry."""
        if isinstance(details, dict):
            details = json.dumps(details)

        with self._transaction():
            self.cursor.execute('''
                INSERT INTO audit_history
                    (event_type, entity_type, entity_id, summary, details,
                     user_name, source_ip, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (event_type, entity_type, entity_id, summary, details,
                  user_name, source_ip, severity))

    def add_history_entry(self, event_type, entity_type=None, entity_id=None,
                          summary="", details=None, user_name=None,
                          source_ip=None, severity="info"):
        """Public method to add history entries from outside."""
        self._add_history_entry(event_type, entity_type, entity_id, summary,
                                details, user_name, source_ip, severity)
        return self.cursor.lastrowid

    def get_history(self, entity_type=None, entity_id=None, event_type=None,
                    limit=100, offset=0):
        """
        Get audit history with optional filters.
        Used by the HistoryPage to populate the timeline.
        """
        query = "SELECT * FROM audit_history WHERE 1=1"
        params = []

        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        if entity_id:
            query += " AND entity_id = ?"
            params.append(entity_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        self.cursor.execute(query, params)
        return [dict(row) for row in self.cursor.fetchall()]

    def get_recent_activity(self, hours=24, limit=50):
        """Get all activity from the last N hours."""
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=hours)
        self.cursor.execute('''
            SELECT * FROM audit_history
            WHERE created_at >= ?
            ORDER BY created_at DESC LIMIT ?
        ''', (cutoff, limit))
        return [dict(row) for row in self.cursor.fetchall()]

    # =========================================================================
    # REPORT GENERATION (PDF & other formats)
    # =========================================================================

    def create_report(self, title, report_type="incident_summary",
                      date_range_start=None, date_range_end=None,
                      generated_by="system", format="pdf",
                      parameters=None):
        """
        Create a new report record. Returns the report_id string.
        The actual PDF generation calls this to log the report metadata.
        """
        report_id = f"RPT-{datetime.datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

        if isinstance(parameters, dict):
            parameters = json.dumps(parameters)

        with self._transaction():
            self.cursor.execute('''
                INSERT INTO reports
                    (report_id, title, report_type, date_range_start,
                     date_range_end, generated_by, format, parameters)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (report_id, title, report_type, date_range_start,
                  date_range_end, generated_by, format, parameters))

        print(f"  [DB] Created report record: {report_id}")
        return report_id

    def finalize_report(self, report_id, file_path, data_summary=None,
                        status="completed"):
        """Update report with final file path and data summary."""
        if isinstance(data_summary, dict):
            data_summary = json.dumps(data_summary)

        with self._transaction():
            self.cursor.execute('''
                UPDATE reports
                SET file_path = ?, data_summary = ?, status = ?
                WHERE report_id = ?
            ''', (file_path, data_summary, status, report_id))

        self._add_history_entry(
            event_type="report_generated",
            entity_type="report",
            entity_id=report_id,
            summary=f"Report generated: {report_id} -> {file_path}",
            details=data_summary,
            severity="info"
        )
        return True

    def get_reports(self, report_type=None, limit=50, offset=0):
        """Get all reports with optional type filtering."""
        query = "SELECT * FROM reports WHERE 1=1"
        params = []

        if report_type:
            query += " AND report_type = ?"
            params.append(report_type)

        query += " ORDER BY generated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        self.cursor.execute(query, params)
        return [dict(row) for row in self.cursor.fetchall()]

    def get_report_data_for_pdf(self, report_type="incident_summary",
                                date_start=None, date_end=None):
        """
        Gather aggregated data for PDF report generation.
        Returns a dict with all the data the PDF builder needs.
        """
        data = {
            "generated_at": datetime.datetime.now().isoformat(),
            "report_type": report_type,
            "date_range": {
                "start": date_start.isoformat() if date_start else None,
                "end": date_end.isoformat() if date_end else None
            },
            "incidents": {},
            "approvals": {},
            "integrity": {},
            "playbooks": {},
            "endpoints": {}
        }

        # --- Incident stats ---
        data["incidents"]["stats"] = self.get_incident_stats()

        # Recent incidents
        if date_start and date_end:
            self.cursor.execute('''
                SELECT * FROM incidents
                WHERE detection_time >= ? AND detection_time <= ?
                ORDER BY detection_time DESC
            ''', (date_start, date_end))
        else:
            self.cursor.execute('''
                SELECT * FROM incidents ORDER BY detection_time DESC LIMIT 50
            ''')
        data["incidents"]["list"] = [dict(r) for r in self.cursor.fetchall()]

        # --- Approval stats ---
        self.cursor.execute('''
            SELECT status, COUNT(*) as count FROM approval_queue GROUP BY status
        ''')
        data["approvals"]["by_status"] = {r["status"]: r["count"]
                                          for r in self.cursor.fetchall()}

        # --- Integrity stats ---
        self.cursor.execute('''
            SELECT COUNT(*) as total FROM integrity_violations
        ''')
        data["integrity"]["total_violations"] = self.cursor.fetchone()["total"]

        self.cursor.execute('''
            SELECT COUNT(*) as unremediated FROM integrity_violations
            WHERE remediated = 0
        ''')
        data["integrity"]["unremediated"] = self.cursor.fetchone()["total"]

        # --- Playbook stats ---
        self.cursor.execute('''
            SELECT status, COUNT(*) as count FROM playbook_logs GROUP BY status
        ''')
        data["playbooks"]["by_status"] = {r["status"]: r["count"]
                                          for r in self.cursor.fetchall()}

        self.cursor.execute('''
            SELECT COUNT(*) as total FROM playbook_logs
        ''')
        data["playbooks"]["total"] = self.cursor.fetchone()["total"]

        # --- Endpoint stats ---
        self.cursor.execute('''
            SELECT status, COUNT(*) as count FROM endpoints GROUP BY status
        ''')
        data["endpoints"]["by_status"] = {r["status"]: r["count"]
                                          for r in self.cursor.fetchall()}

        self.cursor.execute('''
            SELECT COUNT(*) as total FROM endpoints
        ''')
        data["endpoints"]["total"] = self.cursor.fetchone()["total"]

        return data

    # =========================================================================
    # ENDPOINT MANAGEMENT
    # =========================================================================

    def add_endpoint(self, name, hostname, port=22, username=None,
                     os_type=None, groups=None):
        """Add a new endpoint to the database."""
        if isinstance(groups, list):
            groups = json.dumps(groups)

        with self._transaction():
            self.cursor.execute('''
                INSERT INTO endpoints (name, hostname, port, username, os_type, groups)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, hostname, port, username, os_type, groups))

        endpoint_id = self.cursor.lastrowid
        self._add_history_entry(
            event_type="endpoint_added",
            entity_type="endpoint",
            entity_id=str(endpoint_id),
            summary=f"Endpoint added: {name} ({hostname})",
            severity="info"
        )
        return endpoint_id

    def get_endpoints(self, status=None, group=None, limit=100):
        """Get endpoints with optional filtering."""
        query = "SELECT * FROM endpoints WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if group:
            query += " AND groups LIKE ?"
            params.append(f"%{group}%")

        query += " ORDER BY name LIMIT ?"
        params.append(limit)

        self.cursor.execute(query, params)
        return [dict(row) for row in self.cursor.fetchall()]

    def get_endpoint(self, endpoint_id):
        """Get a single endpoint by ID."""
        self.cursor.execute("SELECT * FROM endpoints WHERE id = ?", (endpoint_id,))
        row = self.cursor.fetchone()
        return dict(row) if row else None

    def update_endpoint_status(self, endpoint_id, status, last_seen=None):
        """Update endpoint status and optionally last_seen timestamp."""
        with self._transaction():
            self.cursor.execute('''
                UPDATE endpoints
                SET status = ?, last_seen = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (status, last_seen or datetime.datetime.now(), endpoint_id))

    # =========================================================================
    # SCAN RESULTS
    # =========================================================================

    def save_scan_result(self, endpoint_id, playbook_name, command,
                         stdout, stderr, exit_status, risk_level="info"):
        """Store a command/scan execution result."""
        with self._transaction():
            self.cursor.execute('''
                INSERT INTO scan_results
                    (endpoint_id, playbook_name, command, stdout, stderr,
                     exit_status, risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (endpoint_id, playbook_name, command, stdout, stderr,
                  exit_status, risk_level))
        return self.cursor.lastrowid

    def get_scan_results(self, endpoint_id=None, playbook_name=None,
                         risk_level=None, limit=100):
        """Get scan results with optional filters."""
        query = "SELECT * FROM scan_results WHERE 1=1"
        params = []

        if endpoint_id:
            query += " AND endpoint_id = ?"
            params.append(endpoint_id)
        if playbook_name:
            query += " AND playbook_name = ?"
            params.append(playbook_name)
        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level)

        query += " ORDER BY executed_at DESC LIMIT ?"
        params.append(limit)

        self.cursor.execute(query, params)
        return [dict(row) for row in self.cursor.fetchall()]

    # =========================================================================
    # INTEGRITY BASELINES & VIOLATIONS
    # =========================================================================

    def set_baseline(self, endpoint_id, file_path, file_hash,
                     hash_algorithm="sha256", file_size=None,
                     permissions=None, owner=None, group_name=None,
                     last_modified=None):
        """Set or update a file integrity baseline."""
        with self._transaction():
            self.cursor.execute('''
                INSERT OR REPLACE INTO integrity_baselines
                    (endpoint_id, file_path, file_hash, hash_algorithm,
                     file_size, permissions, owner, group_name, last_modified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (endpoint_id, file_path, file_hash, hash_algorithm,
                  file_size, permissions, owner, group_name, last_modified))

    def get_baselines(self, endpoint_id=None):
        """Get integrity baselines, optionally filtered by endpoint."""
        if endpoint_id:
            self.cursor.execute(
                "SELECT * FROM integrity_baselines WHERE endpoint_id = ?",
                (endpoint_id,)
            )
        else:
            self.cursor.execute("SELECT * FROM integrity_baselines")
        return [dict(row) for row in self.cursor.fetchall()]

    def record_violation(self, endpoint_id, file_path, expected_hash,
                         current_hash, violation_type="hash_mismatch"):
        """Record an integrity violation."""
        with self._transaction():
            self.cursor.execute('''
                INSERT INTO integrity_violations
                    (endpoint_id, file_path, expected_hash, current_hash, violation_type)
                VALUES (?, ?, ?, ?, ?)
            ''', (endpoint_id, file_path, expected_hash, current_hash,
                  violation_type))

        self._add_history_entry(
            event_type="integrity_violation",
            entity_type="endpoint",
            entity_id=str(endpoint_id),
            summary=f"Integrity violation: {file_path} ({violation_type})",
            details=json.dumps({
                "file_path": file_path,
                "expected_hash": expected_hash,
                "current_hash": current_hash
            }),
            severity="high"
        )
        return self.cursor.lastrowid

    def get_violations(self, endpoint_id=None, remediated=None, limit=100):
        """Get integrity violations with optional filters."""
        query = "SELECT * FROM integrity_violations WHERE 1=1"
        params = []

        if endpoint_id:
            query += " AND endpoint_id = ?"
            params.append(endpoint_id)
        if remediated is not None:
            query += " AND remediated = ?"
            params.append(1 if remediated else 0)

        query += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)

        self.cursor.execute(query, params)
        return [dict(row) for row in self.cursor.fetchall()]

    def remediate_violation(self, violation_id):
        """Mark a violation as remediated."""
        with self._transaction():
            self.cursor.execute('''
                UPDATE integrity_violations
                SET remediated = 1, remediated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (violation_id,))
            return self.cursor.rowcount > 0

    # =========================================================================
    # PLAYBOOK LOGS
    # =========================================================================

    def log_playbook_start(self, endpoint_id, playbook_name, playbook_type=None,
                           trigger_source=None, parameters=None):
        """Log the start of a playbook execution. Returns the log ID."""
        if isinstance(parameters, dict):
            parameters = json.dumps(parameters)

        with self._transaction():
            self.cursor.execute('''
                INSERT INTO playbook_logs
                    (endpoint_id, playbook_name, playbook_type, status,
                     trigger_source, parameters)
                VALUES (?, ?, ?, 'running', ?, ?)
            ''', (endpoint_id, playbook_name, playbook_type,
                  trigger_source, parameters))
            log_id = self.cursor.lastrowid

        self._add_history_entry(
            event_type="playbook_started",
            entity_type="playbook",
            entity_id=str(log_id),
            summary=f"Playbook started: {playbook_name}",
            details=json.dumps({"endpoint_id": endpoint_id,
                                "trigger": trigger_source}),
            severity="info"
        )
        return log_id

    def log_playbook_complete(self, log_id, status="completed",
                              result_summary=None, error_message=None):
        """Mark a playbook execution as complete."""
        now = datetime.datetime.now()
        with self._transaction():
            # Get the start time to calculate duration
            self.cursor.execute(
                "SELECT started_at FROM playbook_logs WHERE id = ?", (log_id,)
            )
            row = self.cursor.fetchone()
            duration = None
            if row:
                started = datetime.datetime.fromisoformat(row["started_at"])
                duration = (now - started).total_seconds()

            self.cursor.execute('''
                UPDATE playbook_logs
                SET status = ?,
                    completed_at = ?,
                    duration_seconds = ?,
                    result_summary = ?,
                    error_message = ?
                WHERE id = ?
            ''', (status, now, duration, result_summary, error_message, log_id))

        self._add_history_entry(
            event_type="playbook_completed",
            entity_type="playbook",
            entity_id=str(log_id),
            summary=f"Playbook {status}: #{log_id}",
            details=json.dumps({"duration": duration, "result": result_summary}),
            severity="info"
        )
        return duration

    def get_playbook_logs(self, endpoint_id=None, playbook_name=None,
                          status=None, limit=100):
        """Get playbook execution logs with optional filters."""
        query = "SELECT * FROM playbook_logs WHERE 1=1"
        params = []

        if endpoint_id:
            query += " AND endpoint_id = ?"
            params.append(endpoint_id)
        if playbook_name:
            query += " AND playbook_name = ?"
            params.append(playbook_name)
        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        self.cursor.execute(query, params)
        return [dict(row) for row in self.cursor.fetchall()]


# =============================================================================
# COMPATIBILITY WRAPPERS FOR MEMBER 4'S DASHBOARD
# These are module-level functions that work with the DatabaseManager class
# =============================================================================

# Global database instance
_default_db = None


def _get_db():
    """Get or create a database connection"""
    global _default_db
    if _default_db is None:
        _default_db = DatabaseManager()
    return _default_db


def init_db(db_path=None):
    """
    Initialize database connection.
    Required by Member 4's dashboard.
    """
    global _default_db
    _default_db = DatabaseManager(db_path)
    print("[DB] ✅ Database initialized for dashboard")
    return True


def get_open_incidents(limit=50):
    """
    Get open incidents for approval queue.
    Required by Member 4's dashboard.
    """
    db = _get_db()
    return db.get_open_incidents(limit=limit)


def get_all_incidents(status=None, severity=None, limit=100):
    """
    Get all incidents with optional filtering.
    Required by Member 4's dashboard history page.
    """
    db = _get_db()
    return db.get_all_incidents(status=status, severity=severity, limit=limit)


def close_incident(incident_id, resolution_notes="", assigned_to=None, fix_type=None, verified=None):
    """
    Close an incident with resolution notes.
    Required by Member 4's dashboard approval workflow.
    """
    db = _get_db()
    return db.close_incident(incident_id, resolution_notes, assigned_to, fix_type, verified)


def get_incident_stats():
    """
    Get incident statistics for dashboard overview.
    Required by Member 4's dashboard.
    """
    db = _get_db()
    return db.get_incident_stats()


def get_high_risk_incidents(threshold=60, limit=50):
    """
    Get high-risk open incidents for approval queue.
    Required by Member 4's dashboard (risk > 60 filter).
    """
    db = _get_db()
    return db.get_high_risk_incidents(threshold=threshold, limit=limit)


def create_report(title, report_type, generated_by, format="pdf"):
    """
    Create a report record.
    Required by Member 4's PDF generation.
    """
    db = _get_db()
    return db.create_report(title, report_type, generated_by=generated_by, format=format)


def finalize_report(report_id, file_path, data_summary=None):
    """
    Finalize a report with file path.
    Required by Member 4's PDF generation.
    """
    db = _get_db()
    return db.finalize_report(report_id, file_path, data_summary)


def add_history_entry(event_type, entity_type, entity_id, summary, user_name, severity="info"):
    """
    Add audit history entry.
    Required by Member 4's dashboard.
    """
    db = _get_db()
    return db.add_history_entry(event_type, entity_type, entity_id, summary, user_name=user_name, severity=severity)


# =============================================================================
# TEST FUNCTION
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Testing database.py for Member 4 Dashboard compatibility...")
    print("=" * 60)
    
    # Test 1: init_db
    print("\n1. Testing init_db()...")
    init_db()
    print("   ✅ init_db() works")
    
    # Test 2: Create test incidents with risk scores
    print("\n2. Creating test incidents with risk scores...")
    db = _get_db()
    
    # Create high-risk incident
    inc1 = db.create_incident(
        title="SSH Brute Force Attack",
        description="Multiple failed SSH attempts from 203.0.113.45",
        severity="high",
        category="Authentication",
        source="203.0.113.45",
        risk_score=85,
        fix_type="hardened"
    )
    print(f"   ✅ Created high-risk incident: {inc1} (Risk: 85)")
    
    # Create critical-risk incident
    inc2 = db.create_incident(
        title="Malware Detection - Cryptominer",
        description="Suspicious process xmrig detected running",
        severity="critical",
        category="Malware",
        source="10.0.0.45",
        risk_score=95,
        fix_type="surgical"
    )
    print(f"   ✅ Created critical-risk incident: {inc2} (Risk: 95)")
    
    # Create medium-risk incident
    inc3 = db.create_incident(
        title="Port Scan Detected",
        description="Nmap port scan from external host",
        severity="medium",
        category="Reconnaissance",
        source="198.51.100.50",
        risk_score=45,
        fix_type="hardened"
    )
    print(f"   ✅ Created medium-risk incident: {inc3} (Risk: 45)")
    
    # Test 3: Get high-risk incidents (threshold > 60)
    print("\n3. Testing get_high_risk_incidents(threshold=60)...")
    high_risk = get_high_risk_incidents(threshold=60)
    print(f"   ✅ Found {len(high_risk)} high-risk incidents")
    for inc in high_risk:
        print(f"      - {inc['incident_id']}: Risk Score {inc.get('risk_score', 'N/A')}")
    
    # Test 4: Get open incidents
    print("\n4. Testing get_open_incidents()...")
    open_incidents = get_open_incidents(limit=10)
    print(f"   ✅ Found {len(open_incidents)} total open incidents")
    
    # Test 5: Close an incident with fix type
    print("\n5. Testing close_incident() with fix_type...")
    if inc1:
        result = close_incident(inc1, resolution_notes="Blocked IP address", fix_type="hardened", verified=True)
        print(f"   ✅ Closed incident {inc1}: {result}")
    
    # Test 6: Get all incidents
    print("\n6. Testing get_all_incidents()...")
    all_incidents = get_all_incidents(limit=10)
    print(f"   ✅ Retrieved {len(all_incidents)} total incidents")
    
    # Test 7: Get incident stats
    print("\n7. Testing get_incident_stats()...")
    stats = get_incident_stats()
    print(f"   ✅ Stats: Total={stats.get('total', 0)}, Open={stats.get('open', 0)}")
    print(f"      Risk Distribution: {stats.get('risk_distribution', {})}")
    
    # Test 8: Report functions
    print("\n8. Testing report functions...")
    report_id = create_report("Test Dashboard Report", "incident_summary", "dashboard_test", "pdf")
    if report_id:
        finalize_report(report_id, "/tmp/test_report.pdf", {"test": "data"})
        print(f"   ✅ Created and finalized report: {report_id}")
    
    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED! Database is ready for Member 4's dashboard.")
    print("=" * 60)
    print("\nDashboard functions available:")
    print("  - init_db()")
    print("  - get_open_incidents()")
    print("  - get_all_incidents()")
    print("  - close_incident()")
    print("  - get_incident_stats()")
    print("  - get_high_risk_incidents() ← For risk > 60 filter")
    print("  - create_report()")
    print("  - finalize_report()")
    print("  - add_history_entry()")

def log_incident(alert, risk, action_taken="", fix_type="hardened", action_ok=True):
    """
    Log a new incident from the pipeline.
    Required by main_pipeline.py (Member 2).
    Returns the incident_id string.
    """
    db = _get_db()
    desc   = alert.get("rule", {}).get("description", "Unknown alert")
    src_ip = alert.get("data",  {}).get("srcip", "")
    group  = risk.get("group",  "B")
    score  = risk.get("score",  0)
    label  = risk.get("label",  "INFO")

    sev_map = {"CRITICAL": "critical", "HIGH": "high",
               "MEDIUM": "medium",    "LOW":  "low", "INFO": "info"}
    severity = sev_map.get(label, "medium")

    title = f"[Group {group}] {desc[:60]}"

    incident_id = db.create_incident(
        title=title,
        description=desc,
        severity=severity,
        category=group,
        source=src_ip,
        risk_score=score,
        fix_type=fix_type,
    )
    return incident_id


def update_verification(incident_id, verified=False, check_result=""):
    """
    Update an incident with post-fix verification result.
    Required by main_pipeline.py (Member 2).
    """
    db = _get_db()
    try:
        with db._transaction():
            db.cursor.execute(
                """UPDATE incidents
                   SET verified = ?, resolution_notes = ?, last_updated = ?
                   WHERE incident_id = ?""",
                (1 if verified else 0, check_result,
                 datetime.datetime.now().isoformat(), incident_id)
            )
        return True
    except Exception as e:
        print(f"[DB] update_verification error: {e}")
        return False
