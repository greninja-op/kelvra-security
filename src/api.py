"""KelvraSecurity — Autonomous AI Security, Prompt Guardrail, and Secret Leak Detection Microservice.

Runs as an independent service on port 8100.
"""
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .prompt_guard import PromptGuard
from .secrets_auditor import AppSecAuditor

app = FastAPI(
    title="Kelvra Security Service",
    version="1.0.0",
    description="Pre-execution prompt guardrails and pre-commit secret leak auditing service.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScreenRequest(BaseModel):
    directive: str
    source: Optional[str] = "untrusted"


class ScreenResponse(BaseModel):
    is_safe: bool
    verdict: str
    flags: List[str]
    flag_count: int
    sanitized_prompt: str


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


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Liveness and service readiness probe."""
    return {
        "status": "healthy",
        "service": "kelvra-security",
        "port": 8100,
        "version": "1.0.0",
        "capabilities": ["prompt_screening", "secret_auditing", "cwe_scanning"],
    }


@app.post("/screen", response_model=ScreenResponse)
async def screen_directive(req: ScreenRequest) -> Dict[str, Any]:
    """Screen an incoming user directive for prompt injection or catastrophic shell commands."""
    directive_text = req.directive.strip()
    if not directive_text:
        return {
            "is_safe": True,
            "verdict": "SAFE",
            "flags": [],
            "flag_count": 0,
            "sanitized_prompt": "",
        }

    verdict_data = PromptGuard.is_safe_for_swarm(directive_text)
    return verdict_data


@app.post("/audit", response_model=AuditResponse)
async def audit_code(req: AuditRequest) -> Dict[str, Any]:
    """Audit diff or file content for leaked secrets, API keys, and high-risk vulnerabilities."""
    payload_content = req.diff if req.diff else req.content
    return AppSecAuditor.scan_content(payload_content, filepath=req.filepath or "workspace")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8100)
