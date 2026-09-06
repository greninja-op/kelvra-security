"""SecurityAuditLogger: Persistent Audit Trail for High-Risk & Defensive Security Actions.

Implements OWASP Top 10 for Agentic Applications (2026 - ASI09: Insufficient Agent Observability)
and §3 / §5 of Kelvra Security Spec.

Maintains an immutable append-only JSONL log of every security screening, high-risk gate,
blocked injection attempt, secret leak finding, and command denylist denial.
"""
import os
import time
import json
import uuid
from typing import Dict, Any, List, Optional
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_LOG_FILE = DATA_DIR / "security_audit.jsonl"


class SecurityAuditLogger:
    """Logs and queries structured security events."""

    def __init__(self, log_path: Path = AUDIT_LOG_FILE):
        self.log_path = log_path

    def log_event(
        self,
        event_type: str,
        severity: str,
        source: str,
        action: str,
        details: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append a structured audit event to the append-only JSONL audit trail."""
        now = time.time()
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        event = {
            "event_id": f"sec-{uuid.uuid4().hex[:8]}",
            "timestamp": now,
            "time_str": time_str,
            "event_type": event_type.upper(),  # PROMPT_SCREENED, COMMAND_DENIED, SECRET_LEAK_BLOCKED, GATE_CHALLENGE_CREATED, etc.
            "severity": severity.upper(),      # INFO, WARNING, CRITICAL
            "source": source,                  # voice, typed, agent, external_browser, mcp
            "action": action,
            "session_id": session_id,
            "workspace_id": workspace_id,
            "details": details or {},
        }

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            print(f"[SecurityAuditLogger] Error writing audit log: {e}")

        return event

    def get_logs(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent security audit events with optional severity and event_type filters."""
        if not self.log_path.exists():
            return []

        results = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if severity and record.get("severity") != severity.upper():
                            continue
                        if event_type and record.get("event_type") != event_type.upper():
                            continue
                        results.append(record)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"[SecurityAuditLogger] Error reading audit log: {e}")
            return []

        # Return most recent first up to limit
        return results[::-1][:limit]


# Global singleton
audit_logger = SecurityAuditLogger()
