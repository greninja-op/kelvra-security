"""Coding Agent CLI Subscription Authentication Detector & Login Orchestrator.

Handles subscription/OAuth based CLIs (Claude Code, Codex, Antigravity, Git-Sentinel)
where authentication is user/device-code based, not raw API keys.
"""
import os
import shutil
import asyncio
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger("cli_workflow.cli_auth")


class CLIAuthDetector:
    """Monitors installation and subscription authentication states for coding CLIs."""

    SUPPORTED_CLIS = [
        {
            "id": "claude",
            "name": "Claude Code",
            "executable": "claude",
            "powers_roles": ["agent-backend"],
            "description": "Anthropic's agent CLI. Requires subscription login (Claude Pro/Team/Max).",
            "auth_type": "OAuth Subscription",
        },
        {
            "id": "codex",
            "name": "Codex CLI",
            "executable": "codex",
            "powers_roles": ["agent-frontend", "agent-db"],
            "description": "OpenAI's coding agent CLI. Requires ChatGPT Plus/Team subscription auth.",
            "auth_type": "OAuth Subscription",
        },
        {
            "id": "antigravity",
            "name": "Antigravity",
            "executable": "antigravity",
            "powers_roles": ["agent-scout", "agent-qa"],
            "description": "Google DeepMind pair programming assistant runtime.",
            "auth_type": "Workspace Session",
        },
        {
            "id": "git-sentinel",
            "name": "Git Sentinel",
            "executable": "git",
            "powers_roles": ["agent-sentinel"],
            "description": "Autonomous worktree arbiter, secrets scanner, and merge governor.",
            "auth_type": "Local Git Runtime",
        },
    ]

    @classmethod
    def get_cli_status(cls, cli_id: str) -> Dict[str, Any]:
        cli_meta = next((c for c in cls.SUPPORTED_CLIS if c["id"] == cli_id), None)
        if not cli_meta:
            return {"id": cli_id, "status": "UNKNOWN", "installed": False}

        exec_name = cli_meta["executable"]
        is_installed = shutil.which(exec_name) is not None

        # Check special paths on Windows / Home directory
        home = Path.home()
        claude_dir = home / ".claude"
        codex_dir = home / ".codex"

        status = "NOT_INSTALLED"
        account_name = None

        if cli_id == "claude":
            if is_installed or claude_dir.exists():
                status = "INSTALLED_NOT_LOGGED_IN"
                # Check for session token or config
                creds_file = claude_dir / "credentials.json"
                settings_file = claude_dir / "settings.json"
                if creds_file.exists():
                    status = "SIGNED_IN"
                    account_name = "Claude Pro Subscriber"
                elif is_installed:
                    try:
                        res = subprocess.run(["claude", "auth", "status"], capture_output=True, text=True, timeout=2)
                        if "logged in" in res.stdout.lower():
                            status = "SIGNED_IN"
                            account_name = "Claude Subscriber"
                    except Exception:
                        pass
        elif cli_id == "codex":
            if is_installed or codex_dir.exists():
                status = "INSTALLED_NOT_LOGGED_IN"
                auth_file = codex_dir / "auth.json"
                if auth_file.exists():
                    status = "SIGNED_IN"
                    account_name = "Codex Subscriber"
        elif cli_id == "antigravity":
            # Always available in Antigravity IDE
            status = "SIGNED_IN"
            account_name = "Workspace Active"
            is_installed = True
        elif cli_id == "git-sentinel":
            if is_installed:
                status = "SIGNED_IN"
                account_name = "Local Git Engine"

        return {
            "id": cli_meta["id"],
            "name": cli_meta["name"],
            "executable": cli_meta["executable"],
            "powers_roles": cli_meta["powers_roles"],
            "description": cli_meta["description"],
            "auth_type": cli_meta["auth_type"],
            "installed": is_installed,
            "status": status,  # NOT_INSTALLED | INSTALLED_NOT_LOGGED_IN | SIGNED_IN
            "account": account_name,
        }

    @classmethod
    def get_all_clis_status(cls) -> List[Dict[str, Any]]:
        return [cls.get_cli_status(c["id"]) for c in cls.SUPPORTED_CLIS]

    @classmethod
    async def trigger_login(cls, cli_id: str) -> Dict[str, Any]:
        """Trigger interactive or device-code login flow for the specified CLI."""
        status_info = cls.get_cli_status(cli_id)
        if not status_info["installed"] and cli_id not in ("antigravity", "git-sentinel"):
            return {
                "success": False,
                "error": f"CLI '{cli_id}' is not installed on this system. Please run 'npm install -g @anthropic-ai/claude-code' or equivalent.",
            }

        cmd = None
        if cli_id == "claude":
            cmd = "claude login"
        elif cli_id == "codex":
            cmd = "codex login"

        if not cmd:
            return {
                "success": True,
                "message": f"CLI '{cli_id}' is already ready for workspace sessions.",
            }

        # Spawn background process or print instructions
        try:
            # We initiate a non-blocking process
            proc = subprocess.Popen(cmd, shell=True)
            return {
                "success": True,
                "pid": proc.pid,
                "message": f"Started login flow for {status_info['name']} (PID: {proc.pid}). Follow prompt in your terminal or browser.",
            }
        except Exception as e:
            return {"success": False, "error": f"Could not launch login command: {e}"}
