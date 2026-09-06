"""RateLimiter & Anomaly Detector: Burst and Runaway Loop Mitigation.

Implements OWASP Top 10 for Agentic Applications (2026 - ASI08: Cascading Failures / Runaway Loops)
and §2.11 of Kelvra Security Spec.

Catches compromised or injected sessions executing rapid destructive actions
or entering infinite tool-call loops by pausing execution and tripping circuit breakers.
"""
import time
from typing import Dict, List, Any, Tuple


class ActionRateLimiter:
    """Sliding-window rate limiter and anomaly detector for agent and voice actions."""

    def __init__(
        self,
        high_risk_burst_limit: int = 3,
        high_risk_window_seconds: float = 60.0,
        general_action_limit: int = 15,
        general_window_seconds: float = 10.0,
    ):
        self.high_risk_limit = high_risk_burst_limit
        self.high_risk_window = high_risk_window_seconds
        self.general_limit = general_action_limit
        self.general_window = general_window_seconds

        # Key: entity_id -> List of timestamps
        self._high_risk_events: Dict[str, List[float]] = {}
        self._general_events: Dict[str, List[float]] = {}
        self._tripped_entities: Dict[str, Dict[str, Any]] = {}

    def record_and_check(
        self,
        entity_id: str,
        action_type: str,
        is_high_risk: bool = False,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Records an action and checks if velocity limits or anomaly thresholds are exceeded (§2.11).

        Returns:
            (is_allowed, reason, details)
        """
        now = time.time()
        eid = entity_id or "global"

        # Check if already tripped and locked
        if eid in self._tripped_entities:
            trip_info = self._tripped_entities[eid]
            return False, f"Anomaly Circuit Breaker Active: {trip_info['reason']}. Human confirmation required to unlock.", {
                "entity_id": eid,
                "tripped": True,
                "reason": trip_info["reason"],
                "tripped_at": trip_info["tripped_at"],
            }

        # 1. Prune and check general action velocity
        g_times = self._general_events.setdefault(eid, [])
        g_times = [t for t in g_times if now - t <= self.general_window]
        g_times.append(now)
        self._general_events[eid] = g_times

        if len(g_times) > self.general_limit:
            reason = f"Rapid runaway loop detected: {len(g_times)} actions in {self.general_window}s exceeds limit of {self.general_limit}."
            self._tripped_entities[eid] = {"reason": reason, "tripped_at": now}
            return False, reason, {"entity_id": eid, "tripped": True, "reason": reason}

        # 2. Prune and check high-risk destructive action velocity
        if is_high_risk:
            h_times = self._high_risk_events.setdefault(eid, [])
            h_times = [t for t in h_times if now - t <= self.high_risk_window]
            h_times.append(now)
            self._high_risk_events[eid] = h_times

            if len(h_times) > self.high_risk_limit:
                reason = f"Destructive action burst detected: {len(h_times)} high-risk actions in {self.high_risk_window}s exceeds limit of {self.high_risk_limit}."
                self._tripped_entities[eid] = {"reason": reason, "tripped_at": now}
                return False, reason, {"entity_id": eid, "tripped": True, "reason": reason}

        return True, "Action within safe rate thresholds.", {
            "entity_id": eid,
            "tripped": False,
            "current_general_rate": len(g_times),
            "current_high_risk_rate": len(self._high_risk_events.get(eid, [])),
        }

    def reset_entity(self, entity_id: str) -> bool:
        """Operator unlock resetting anomaly flags and rate history for an entity."""
        eid = entity_id or "global"
        self._tripped_entities.pop(eid, None)
        self._high_risk_events.pop(eid, None)
        self._general_events.pop(eid, None)
        return True

    def is_tripped(self, entity_id: str) -> bool:
        return (entity_id or "global") in self._tripped_entities


# Global singleton
rate_limiter = ActionRateLimiter()
