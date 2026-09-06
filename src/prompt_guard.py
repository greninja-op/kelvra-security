"""PromptGuard: AI Prompt Injection Defense and Skeptical-Reading Guard for Kelvra.

Grounded against OWASP Top 10 for LLM Applications (2026 - LLM01: Prompt Injection,
LLM02: Sensitive Information Disclosure, LLM03: Excessive Agency) and OWASP Top 10
for Agentic Applications (2026 - ASI01: Agent Goal Hijacking, ASI02: Tool/Action Hijacking).
"""
import re
from typing import Dict, List, Any, Tuple, Optional
from .deny_dangerous import check_command


class PromptGuard:
    """Detects and neutralizes prompt injections, indirect injections, and untrusted inputs."""

    # 1. Direct prompt injection & jailbreak patterns
    DIRECT_INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior|current)\s+(instructions|prompts|rules|commands)",
        r"(?i)disregard\s+(all\s+)?(previous|prior|safety)\s+(guidelines|instructions|rules)",
        r"(?i)system\s+prompt\s+override",
        r"(?i)you\s+are\s+now\s+(in\s+)?(developer|unrestricted|god|dan|jailbreak)\s+mode",
        r"(?i)new\s+operating\s+instructions?:",
        r"(?i)developer\s+mode\s+(enabled|activated)",
        r"(?i)override\s+all\s+security\s+controls",
        r"(?i)bypass\s+(safety|guardrails|filters)",
        r"(?i)act\s+as\s+an\s+unrestricted\s+ai",
    ]

    # 2. Delimiter & system boundary spoofing
    DELIMITER_INJECTION_PATTERNS = [
        r"\[/?INST\]",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"</?system>",
        r"###\s*(System|Instruction|Assistant):",
        r"<<SYS>>",
        r"<</SYS>>",
    ]

    # 3. Data exfiltration & secret harvesting vectors
    EXFILTRATION_PATTERNS = [
        r"(?i)exfiltrat(e|ion)\s+(secrets|env|keys|tokens|passwords)",
        r"(?i)send\s+(the\s+)?(\.env|api[_-]?key|password|token|credentials)\s+to",
        r"(?i)curl\s+-[X\s]+POST.*(webhook|pastebin|requestbin|ngrok|pipedream|hookdeck)",
        r"(?i)Invoke-Expression.*DownloadString",
        r"(?i)!\[.*?\]\(https?://[^\s)]*(?:webhook|requestbin|pastebin|ngrok|leak|token|secret)[^\s)]*\)",
    ]

    # 4. Indirect injection in external content (web pages, files, tool outputs, PRs)
    INDIRECT_INJECTION_PATTERNS = [
        r"(?i)<\s*(div|span|p|a)[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^>]*>.*?(?:ignore|run|delete|send|curl|token)",
        r"(?i)<!--\s*(?:ignore\s+previous|system\s+override|run\s+command|new\s+instructions?).*?-->",
        r"(?i)(?:Assistant|AI|Agent)\s*:\s*(?:must|should|now)\s*(?:execute|run|read|exfiltrate|delete)\s+",
        r"(?i)IMPORTANT\s*:\s*do\s+not\s+tell\s+the\s+user.*?(?:execute|run|delete|send)",
        r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>",
    ]

    # 5. Catastrophic commands inside prompt text
    DANGEROUS_COMMAND_PATTERNS = [
        r"(?i)rm\s+-rf\s+[/~]",
        r"(?i)format\s+[c-z]:",
        r"(?i)mkfs(\.[a-z0-9]+)?\s+",
        r"(?i)git\s+push\s+.*--force",
        r"(?i)git\s+branch\s+(-D|-d)\s+(main|master|prod|production)",
        r"(?i)security\s+dump-keychain",
    ]

    @classmethod
    def normalize_text(cls, text: str) -> str:
        """Strip zero-width spaces and Unicode obfuscation characters used for evasion."""
        return re.sub(r"[\u200b-\u200f\u2028-\u202e\ufeff\u00ad]", "", text)

    @classmethod
    def sanitize_input(cls, raw_input: str, source_label: str = "untrusted") -> Tuple[str, List[str]]:
        """Scans input for injection vectors and returns sanitized text with any detected flags."""
        clean_text = cls.normalize_text(raw_input or "")
        flags = []

        # Check all direct & delimiter patterns
        for pattern in cls.DIRECT_INJECTION_PATTERNS + cls.DELIMITER_INJECTION_PATTERNS + cls.EXFILTRATION_PATTERNS:
            if re.search(pattern, clean_text):
                flags.append(f"Suspicious pattern matched: '{pattern}'")

        # Check dangerous shell command patterns embedded in prompt
        for pattern in cls.DANGEROUS_COMMAND_PATTERNS:
            if re.search(pattern, clean_text):
                flags.append(f"Dangerous command pattern matched: '{pattern}'")

        # Also run deny_dangerous command check if prompt looks like a command
        is_cmd_safe, cmd_reason = check_command(clean_text)
        if not is_cmd_safe:
            flags.append(f"Command denylist triggered: {cmd_reason}")

        sanitized = clean_text.strip()
        return sanitized, flags

    @classmethod
    def is_safe_for_swarm(cls, prompt: str, source: str = "untrusted") -> Dict[str, Any]:
        """Returns security verdict for a user voice or text instruction."""
        sanitized, flags = cls.sanitize_input(prompt, source_label=source)
        is_safe = len(flags) == 0
        verdict = "SAFE" if is_safe else "REJECTED_UNTRUSTED_INJECTION"
        return {
            "is_safe": is_safe,
            "flags": flags,
            "flag_count": len(flags),
            "sanitized_prompt": sanitized,
            "source": source,
            "verdict": verdict,
        }

    @classmethod
    def screen_external_content(cls, content: str, content_type: str = "web_page", source_url: Optional[str] = None) -> Dict[str, Any]:
        """Screens agent-consumed external content (browser-use, MCP outputs, files, PRs) for indirect prompt injections (§2.3)."""
        clean_text = cls.normalize_text(content or "")
        flags = []

        # 1. Check all direct and delimiter patterns
        for pattern in cls.DIRECT_INJECTION_PATTERNS + cls.DELIMITER_INJECTION_PATTERNS + cls.EXFILTRATION_PATTERNS:
            if re.search(pattern, clean_text):
                flags.append(f"Indirect injection pattern detected: '{pattern}'")

        # 2. Check indirect web/markdown injection patterns
        for pattern in cls.INDIRECT_INJECTION_PATTERNS:
            if re.search(pattern, clean_text):
                flags.append(f"Hidden or stealth directive pattern detected: '{pattern}'")

        is_safe = len(flags) == 0
        return {
            "is_safe": is_safe,
            "content_type": content_type,
            "source_url": source_url,
            "flags": flags,
            "flag_count": len(flags),
            "verdict": "SAFE" if is_safe else "BLOCKED_INDIRECT_INJECTION",
        }

    @classmethod
    def screen_skill_content(cls, skill_content: str, skill_name: str = "custom_skill") -> Dict[str, Any]:
        """Screens uploaded SKILL.md before allowing it to be registered or trusted (§3)."""
        clean_text = cls.normalize_text(skill_content or "")
        flags = []

        # Check for catastrophic commands embedded in scripts or instructions
        for pattern in cls.DANGEROUS_COMMAND_PATTERNS + cls.EXFILTRATION_PATTERNS:
            if re.search(pattern, clean_text):
                flags.append(f"Prohibited skill payload pattern: '{pattern}'")

        # Check for system boundary tampering or privilege escalation directives
        for pattern in cls.DELIMITER_INJECTION_PATTERNS + [r"(?i)elevat(e|ed)\s+privileges?", r"(?i)bypass\s+denylist"]:
            if re.search(pattern, clean_text):
                flags.append(f"Unauthorized privilege escalation in skill: '{pattern}'")

        is_safe = len(flags) == 0
        return {
            "is_safe": is_safe,
            "skill_name": skill_name,
            "flags": flags,
            "flag_count": len(flags),
            "verdict": "APPROVED_SKILL" if is_safe else "REJECTED_MALICIOUS_SKILL",
        }
