#!/usr/bin/env python3
"""PreToolUse Guardrail Hook: Blocks catastrophic shell commands.

Compatible with Claude Code PreToolUse and Codex hook formats.
Sourced from davidondrej/skills ops-and-setup/global-agent-guardrails.
"""
import sys
import re
import json
from pathlib import Path

PATTERNS_FILE = Path(__file__).resolve().parent / "dangerous-patterns.txt"


def load_patterns():
    patterns = []
    if not PATTERNS_FILE.exists():
        return patterns
    with open(PATTERNS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                try:
                    patterns.append(re.compile(stripped, re.IGNORECASE))
                except re.error:
                    pass
    return patterns


def check_command(cmd_str: str):
    patterns = load_patterns()
    for pat in patterns:
        if pat.search(cmd_str):
            return False, f"Command matched denylist pattern: '{pat.pattern}'"
    return True, "Allowed"


def main():
    cmd = ""
    # Check CLI argument first
    if len(sys.argv) > 1:
        cmd = " ".join(sys.argv[1:])
    else:
        # Check stdin (supports JSON tool call payloads from Claude Code/Codex)
        raw = sys.stdin.read().strip()
        if raw:
            try:
                data = json.loads(raw)
                # Look for tool input command
                tool_input = data.get("tool_input") or data.get("parameters") or {}
                if isinstance(tool_input, dict):
                    cmd = tool_input.get("command") or tool_input.get("CommandLine") or ""
                elif isinstance(tool_input, str):
                    cmd = tool_input
                else:
                    cmd = raw
            except Exception:
                cmd = raw

    if not cmd:
        sys.exit(0)

    is_safe, reason = check_command(cmd)
    if not is_safe:
        sys.stderr.write(f"\n[SECURITY BLOCK] Catastrophic Command Denied by Guardrail Hook:\n  Target: {cmd}\n  Reason: {reason}\n\n")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
