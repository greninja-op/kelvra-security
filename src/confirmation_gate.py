"""ConfirmationGate: Human-in-the-Loop Confirmation Gate for High-Risk Actions.

Implements OWASP Top 10 for LLM Applications (2026 - LLM03: Excessive Agency)
and OWASP Top 10 for Agentic Applications (2026 - ASI02: Tool/Action Hijacking).

Enforces §2.1 & §2.2:
- High-risk actions require explicit confirmation regardless of source.
- Voice is NOT authentication: voice alone is never sufficient to authorize high-risk actions.
- Requires secondary confirmation (UI click, typed confirmation word, or PIN challenge).
"""
import time
import uuid
import secrets
from typing import Dict, Any, List, Optional, Tuple


class ConfirmationGate:
    """Manages high-risk action classification, challenge generation, and secondary validation."""

    HIGH_RISK_ACTION_TYPES = {
        "git_force_push": "Force-pushing git branches",
        "git_merge_protected": "Merging into protected production branch (main/master/prod)",
        "delete_workspace": "Deleting or wiping a workspace directory",
        "delete_terminal_session": "Terminating or killing active agent sessions",
        "credential_mutation": "Revoking, deleting, or rotating provider credentials",
        "catastrophic_command": "Executing catastrophic or denylisted shell commands",
        "mcp_elevated_execution": "Invoking destructive or elevated MCP tool capabilities",
        "bulk_file_deletion": "Bulk deletion of project files",
    }

    PROTECTED_BRANCHES = {"main", "master", "prod", "production", "release"}

    def __init__(self, challenge_ttl_seconds: int = 120):
        self.ttl = challenge_ttl_seconds
        self._pending_challenges: Dict[str, Dict[str, Any]] = {}

    def classify_action(self, action_type: str, payload: Optional[Dict[str, Any]] = None) -> Tuple[bool, str, str]:
        """Classifies whether an action is high-risk and returns (is_high_risk, risk_level, reason)."""
        payload = payload or {}
        act = (action_type or "").lower().strip()

        # 1. Exact match in high-risk action types
        if act in self.HIGH_RISK_ACTION_TYPES:
            return True, "HIGH_RISK_GATED", self.HIGH_RISK_ACTION_TYPES[act]

        # 2. Check git branch protections in payload
        branch = str(payload.get("branch") or payload.get("target_branch") or "").lower().strip()
        if branch in self.PROTECTED_BRANCHES and ("merge" in act or "push" in act or "delete" in act):
            return True, "HIGH_RISK_GATED", f"Action targets protected branch '{branch}'"

        # 3. Check force flag
        if payload.get("force") is True or payload.get("is_force") is True:
            return True, "HIGH_RISK_GATED", "Action specifies forced execution override"

        # 4. Check workspace deletion
        if "delete" in act and ("workspace" in act or "repo" in act or "all" in act):
            return True, "HIGH_RISK_GATED", "Action requests destructive workspace deletion"

        # 5. Check credential access/deletion
        if ("credential" in act or "secret" in act or "token" in act) and ("delete" in act or "revoke" in act or "export" in act):
            return True, "HIGH_RISK_GATED", "Action requests credential modification or export"

        return False, "LOW_RISK", "Standard operational directive"

    def requires_confirmation(self, action_type: str, source: str = "voice", payload: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Determines if confirmation is required based on action risk and input channel (§2.1, §2.2)."""
        is_high, level, reason = self.classify_action(action_type, payload)
        if not is_high:
            return False, "Action is within normal agent scope and does not require confirmation gate."

        # High risk action: ALWAYS requires confirmation.
        # Voice is explicitly a weaker channel (§2.2):
        if source.lower() == "voice":
            return True, f"Voice is not authentication. '{reason}' requires secondary non-voice confirmation (UI click or typed token)."

        # Even for typed or agent decisions, high-risk actions require explicit human confirmation (§2.1)
        return True, f"High-risk action '{reason}' requires human confirmation gate approval."

    def create_challenge(
        self,
        action_type: str,
        payload: Dict[str, Any],
        source: str = "voice",
        requested_by: str = "operator",
    ) -> Dict[str, Any]:
        """Creates a pending confirmation challenge with TTL and secondary confirmation tokens."""
        self._cleanup_expired()
        challenge_id = f"gate-{uuid.uuid4().hex[:8]}"
        pin = f"{secrets.randbelow(9000) + 1000}"  # 4-digit PIN challenge
        token = "CONFIRM"

        now = time.time()
        expires_at = now + self.ttl

        _, _, reason = self.classify_action(action_type, payload)

        challenge = {
            "challenge_id": challenge_id,
            "action_type": action_type,
            "payload": payload,
            "source": source,
            "requested_by": requested_by,
            "reason": reason,
            "pin": pin,
            "confirmation_token": token,
            "created_at": now,
            "expires_at": expires_at,
            "status": "PENDING_CONFIRMATION",
            "spoken_warning": f"Confirmation required. {reason} is a high-risk action. Please confirm on your screen or type confirmation.",
            "ui_prompt": f"High-Risk Action Gated: {reason}. Click Confirm or type '{token}' or PIN {pin} to proceed.",
        }

        self._pending_challenges[challenge_id] = challenge
        return challenge

    def confirm_challenge(
        self,
        challenge_id: str,
        verification_method: str = "ui_click",
        token_or_pin: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Validates secondary confirmation via click, typed word, or PIN challenge."""
        self._cleanup_expired()
        challenge = self._pending_challenges.get(challenge_id)
        if not challenge:
            return False, "Challenge not found or expired.", None

        if challenge["status"] != "PENDING_CONFIRMATION":
            return False, f"Challenge is already {challenge['status']}.", None

        now = time.time()
        if now > challenge["expires_at"]:
            challenge["status"] = "EXPIRED"
            return False, "Confirmation window expired (TTL exceeded). Action aborted.", None

        method = (verification_method or "").lower()

        # Channel 1: Interactive UI click
        if method in ("ui_click", "click", "button"):
            challenge["status"] = "CONFIRMED"
            challenge["confirmed_at"] = now
            challenge["verification_method"] = "ui_click"
            return True, "Action approved via interactive UI confirmation.", challenge

        # Channel 2: Typed confirmation token or word
        clean_input = (token_or_pin or "").strip().upper()
        if clean_input in (challenge["confirmation_token"], challenge["pin"], "CONFIRM", "YES", "APPROVE"):
            challenge["status"] = "CONFIRMED"
            challenge["confirmed_at"] = now
            challenge["verification_method"] = "typed_confirmation"
            return True, "Action approved via typed secondary confirmation token.", challenge

        return False, "Invalid confirmation token or verification method.", None

    def cancel_challenge(self, challenge_id: str, reason: str = "Cancelled by user") -> bool:
        """Cancels a pending high-risk challenge."""
        challenge = self._pending_challenges.get(challenge_id)
        if not challenge:
            return False
        challenge["status"] = "CANCELLED"
        challenge["cancelled_at"] = time.time()
        challenge["cancel_reason"] = reason
        return True

    def get_challenge(self, challenge_id: str) -> Optional[Dict[str, Any]]:
        self._cleanup_expired()
        return self._pending_challenges.get(challenge_id)

    def list_active_challenges(self) -> List[Dict[str, Any]]:
        self._cleanup_expired()
        now = time.time()
        return [
            c for c in self._pending_challenges.values()
            if c["status"] == "PENDING_CONFIRMATION" and now <= c["expires_at"]
        ]

    def _cleanup_expired(self):
        now = time.time()
        expired_ids = [
            cid for cid, c in self._pending_challenges.items()
            if c["status"] == "PENDING_CONFIRMATION" and now > c["expires_at"]
        ]
        for cid in expired_ids:
            self._pending_challenges[cid]["status"] = "EXPIRED"


# Global singleton
confirmation_gate = ConfirmationGate()
