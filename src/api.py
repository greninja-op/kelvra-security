"""KelvraSecurity — Autonomous AI Security, Prompt Guardrail, Secret Leak Detection, and Confirmation Gate Microservice.

Runs as an independent service on port 8100.
Implements OWASP Top 10 for LLM Applications (2026) and OWASP Top 10 for Agentic Applications (2026).
"""
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .prompt_guard import PromptGuard
from .secrets_auditor import AppSecAuditor
from .deny_dangerous import check_command
from .confirmation_gate import confirmation_gate
from .mcp_authorizer import mcp_authorizer
from .rate_limiter import rate_limiter
from .security_audit_logger import audit_logger

app = FastAPI(
    title="Kelvra Security Service",
    version="1.1.0",
    description="Pre-execution prompt guardrails, human confirmation gate, command denylists, and pre-commit secret leak auditing service.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request & Response Models
# ---------------------------------------------------------------------------
class ScreenRequest(BaseModel):
    directive: str
    source: Optional[str] = "untrusted"


class ScreenResponse(BaseModel):
    is_safe: bool
    verdict: str
    flags: List[str]
    flag_count: int
    sanitized_prompt: str
    source: Optional[str] = "untrusted"


class ContentScreenRequest(BaseModel):
    content: str
    content_type: Optional[str] = "web_page"
    source_url: Optional[str] = None


class SkillScreenRequest(BaseModel):
    skill_content: str
    skill_name: Optional[str] = "custom_skill"


class AuditRequest(BaseModel):
    content: Optional[str] = ""
    diff: Optional[str] = ""
    filepath: Optional[str] = "workspace"


class AuditResponse(BaseModel):
    is_clean: bool
    status: str
    secret_count: int
    secret_leaks: List[Dict[str, Any]]
    vuln_count: int
    vulnerabilities: List[Dict[str, Any]]


class CommandCheckRequest(BaseModel):
    command: str
    session_id: Optional[str] = None


class GateCheckRequest(BaseModel):
    action_type: str
    payload: Optional[Dict[str, Any]] = None
    source: Optional[str] = "voice"
    requested_by: Optional[str] = "operator"


class GateConfirmRequest(BaseModel):
    challenge_id: str
    verification_method: Optional[str] = "ui_click"
    token_or_pin: Optional[str] = None


class GateCancelRequest(BaseModel):
    challenge_id: str
    reason: Optional[str] = "Cancelled by operator"


class MCPAuthorizeRequest(BaseModel):
    server_id: str
    tool_name: str
    tool_args: Optional[Dict[str, Any]] = None


class MCPServerRegisterRequest(BaseModel):
    server_id: str
    name: str
    trust_tier: Optional[str] = "user_managed"
    allowed_tools: Optional[List[str]] = None
    denied_tools: Optional[List[str]] = None
    read_only: Optional[bool] = False


class AnomalyCheckRequest(BaseModel):
    entity_id: str
    action_type: str
    is_high_risk: Optional[bool] = False


class AnomalyResetRequest(BaseModel):
    entity_id: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Liveness, capability, and framework compliance probe."""
    return {
        "status": "healthy",
        "service": "kelvra-security",
        "port": 8100,
        "version": "1.1.0",
        "compliance": [
            "OWASP Top 10 for LLM Applications (2026)",
            "OWASP Top 10 for Agentic Applications (2026)",
            "davidondrej/skills global-agent-guardrails",
        ],
        "capabilities": [
            "prompt_screening",
            "indirect_injection_screening",
            "skill_file_auditing",
            "secret_auditing",
            "catastrophic_command_denylist",
            "confirmation_gate",
            "mcp_least_privilege",
            "rate_limiting_anomaly_detector",
            "immutable_audit_logging",
        ],
    }


# ---------------------------------------------------------------------------
# 1. Prompt & Untrusted Content Screening (§2.3, §2.4, §3)
# ---------------------------------------------------------------------------
@app.post("/screen", response_model=ScreenResponse)
async def screen_directive(req: ScreenRequest) -> Dict[str, Any]:
    """Screen an incoming user directive (voice/text) for prompt injection or catastrophic shell commands."""
    directive_text = req.directive.strip()
    if not directive_text:
        return {
            "is_safe": True,
            "verdict": "SAFE",
            "flags": [],
            "flag_count": 0,
            "sanitized_prompt": "",
            "source": req.source,
        }

    verdict_data = PromptGuard.is_safe_for_swarm(directive_text, source=req.source or "untrusted")
    
    # Audit log if suspicious
    if not verdict_data["is_safe"]:
        audit_logger.log_event(
            event_type="PROMPT_INJECTION_BLOCKED",
            severity="WARNING",
            source=req.source or "untrusted",
            action="screen_directive",
            details=verdict_data,
        )
    return verdict_data


@app.post("/screen-content")
async def screen_external_content(req: ContentScreenRequest) -> Dict[str, Any]:
    """Screen agent-consumed external content (web pages via browser-use, MCP outputs, PRs) for indirect injection (§2.3)."""
    verdict = PromptGuard.screen_external_content(
        content=req.content,
        content_type=req.content_type or "web_page",
        source_url=req.source_url,
    )
    if not verdict["is_safe"]:
        audit_logger.log_event(
            event_type="INDIRECT_INJECTION_BLOCKED",
            severity="CRITICAL",
            source="external_content",
            action="screen_external_content",
            details=verdict,
        )
    return verdict


@app.post("/screen-skill")
async def screen_skill(req: SkillScreenRequest) -> Dict[str, Any]:
    """Screen user-uploaded SKILL.md before allowing it to be registered or trusted (§3)."""
    verdict = PromptGuard.screen_skill_content(
        skill_content=req.skill_content,
        skill_name=req.skill_name or "custom_skill",
    )
    if not verdict["is_safe"]:
        audit_logger.log_event(
            event_type="MALICIOUS_SKILL_REJECTED",
            severity="CRITICAL",
            source="user_upload",
            action="screen_skill",
            details=verdict,
        )
    return verdict


# ---------------------------------------------------------------------------
# 2. Pre-Commit / Pre-Push Secret Auditor (§2.4, §2.5)
# ---------------------------------------------------------------------------
@app.post("/audit", response_model=AuditResponse)
async def audit_code(req: AuditRequest) -> Dict[str, Any]:
    """Audit diff or file content for leaked secrets, API keys, and high-risk vulnerabilities before commit/push."""
    payload_content = req.diff if req.diff else req.content
    res = AppSecAuditor.scan_content(payload_content or "", filepath=req.filepath or "workspace")
    if not res["is_clean"]:
        audit_logger.log_event(
            event_type="SECRET_LEAK_BLOCKED",
            severity="CRITICAL",
            source="git_diff",
            action="audit_code",
            details={"filepath": req.filepath, "secret_count": res["secret_count"]},
        )
    return res


# ---------------------------------------------------------------------------
# 3. Dangerous Command Denylist (§2.6)
# ---------------------------------------------------------------------------
@app.post("/check-command")
async def verify_command(req: CommandCheckRequest) -> Dict[str, Any]:
    """PreToolUse-style hook blocking catastrophic shell commands before execution."""
    is_safe, reason = check_command(req.command)
    if not is_safe:
        audit_logger.log_event(
            event_type="CATASTROPHIC_COMMAND_DENIED",
            severity="CRITICAL",
            source="agent_command",
            action="verify_command",
            session_id=req.session_id,
            details={"command": req.command, "reason": reason},
        )
    return {
        "is_safe": is_safe,
        "verdict": "ALLOWED" if is_safe else "BLOCKED_CATASTROPHIC_COMMAND",
        "reason": reason,
        "command": req.command,
    }


# ---------------------------------------------------------------------------
# 4. Human-in-the-Loop Confirmation Gate (§2.1, §2.2)
# ---------------------------------------------------------------------------
@app.post("/gate/check")
async def gate_check(req: GateCheckRequest) -> Dict[str, Any]:
    """Evaluates whether an action requires a confirmation gate and generates challenge if high-risk."""
    requires_confirm, reason = confirmation_gate.requires_confirmation(
        action_type=req.action_type,
        source=req.source or "voice",
        payload=req.payload,
    )

    if not requires_confirm:
        return {
            "requires_confirmation": False,
            "risk_level": "LOW_RISK",
            "action_type": req.action_type,
            "message": "Action permitted without confirmation gate.",
        }

    # Generate pending challenge
    challenge = confirmation_gate.create_challenge(
        action_type=req.action_type,
        payload=req.payload or {},
        source=req.source or "voice",
        requested_by=req.requested_by or "operator",
    )

    audit_logger.log_event(
        event_type="GATE_CHALLENGE_CREATED",
        severity="WARNING",
        source=req.source or "voice",
        action=req.action_type,
        details=challenge,
    )

    return {
        "requires_confirmation": True,
        "risk_level": "HIGH_RISK_GATED",
        "reason": reason,
        "challenge": challenge,
    }


@app.post("/gate/confirm")
async def gate_confirm(req: GateConfirmRequest) -> Dict[str, Any]:
    """Validates secondary confirmation via interactive UI click, typed word, or PIN challenge (§2.2)."""
    success, msg, challenge = confirmation_gate.confirm_challenge(
        challenge_id=req.challenge_id,
        verification_method=req.verification_method or "ui_click",
        token_or_pin=req.token_or_pin,
    )

    audit_logger.log_event(
        event_type="GATE_RESOLVED" if success else "GATE_CONFIRMATION_FAILED",
        severity="INFO" if success else "WARNING",
        source=req.verification_method or "ui_click",
        action="gate_confirm",
        details={"challenge_id": req.challenge_id, "success": success, "reason": msg},
    )

    return {
        "success": success,
        "message": msg,
        "challenge": challenge,
    }


@app.post("/gate/cancel")
async def gate_cancel(req: GateCancelRequest) -> Dict[str, Any]:
    """Cancels a pending confirmation challenge."""
    cancelled = confirmation_gate.cancel_challenge(req.challenge_id, reason=req.reason or "Cancelled by user")
    return {"success": cancelled, "challenge_id": req.challenge_id}


@app.get("/gate/challenges")
async def list_challenges() -> Dict[str, Any]:
    """Lists currently active pending confirmation challenges."""
    return {"active_challenges": confirmation_gate.list_active_challenges()}


# ---------------------------------------------------------------------------
# 5. MCP Least-Privilege Scoping & Vetting (§2.7, §3)
# ---------------------------------------------------------------------------
@app.post("/mcp/authorize")
async def authorize_mcp_tool(req: MCPAuthorizeRequest) -> Dict[str, Any]:
    """Authorizes an MCP tool call against per-connector least-privilege scoping (§2.7)."""
    is_authorized, reason, meta = mcp_authorizer.authorize_tool_call(
        server_id=req.server_id,
        tool_name=req.tool_name,
        tool_args=req.tool_args,
    )
    if not is_authorized:
        audit_logger.log_event(
            event_type="MCP_TOOL_UNAUTHORIZED",
            severity="WARNING",
            source="mcp_connector",
            action=f"{req.server_id}:{req.tool_name}",
            details={"reason": reason, "meta": meta},
        )
    return {
        "authorized": is_authorized,
        "reason": reason,
        "details": meta,
    }


@app.get("/mcp/servers")
async def list_mcp_servers() -> Dict[str, Any]:
    """Lists vetted and registered MCP servers with current scoping policies (§3)."""
    return {"servers": mcp_authorizer.list_servers()}


@app.post("/mcp/servers")
async def register_mcp_server(req: MCPServerRegisterRequest) -> Dict[str, Any]:
    """Registers or updates least-privilege scoping configuration for an MCP server (§2.7)."""
    server = mcp_authorizer.register_server(
        server_id=req.server_id,
        name=req.name,
        trust_tier=req.trust_tier or "user_managed",
        allowed_tools=req.allowed_tools,
        denied_tools=req.denied_tools,
        read_only=bool(req.read_only),
    )
    return {"success": True, "server": server}


# ---------------------------------------------------------------------------
# 6. Rate Limiting & Anomaly Detection (§2.11)
# ---------------------------------------------------------------------------
@app.post("/anomaly/check")
async def check_anomaly(req: AnomalyCheckRequest) -> Dict[str, Any]:
    """Checks for rapid bursts of destructive actions or runaway execution loops (§2.11)."""
    allowed, reason, details = rate_limiter.record_and_check(
        entity_id=req.entity_id,
        action_type=req.action_type,
        is_high_risk=bool(req.is_high_risk),
    )
    if not allowed:
        audit_logger.log_event(
            event_type="ANOMALY_RATE_LIMIT_TRIPPED",
            severity="CRITICAL",
            source="agent_session",
            action=req.action_type,
            session_id=req.entity_id,
            details=details,
        )
    return {
        "allowed": allowed,
        "reason": reason,
        "details": details,
    }


@app.post("/anomaly/reset")
async def reset_anomaly(req: AnomalyResetRequest) -> Dict[str, Any]:
    """Operator unlock resetting tripped circuit breaker state for an entity."""
    rate_limiter.reset_entity(req.entity_id)
    return {"success": True, "entity_id": req.entity_id, "message": "Circuit breaker reset."}


# ---------------------------------------------------------------------------
# 7. Immutable Security Audit Trail (§3, §5)
# ---------------------------------------------------------------------------
@app.get("/audit-logs")
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieves immutable security audit logs."""
    logs = audit_logger.get_logs(limit=limit, severity=severity, event_type=event_type)
    return {
        "count": len(logs),
        "limit": limit,
        "logs": logs,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8100)
