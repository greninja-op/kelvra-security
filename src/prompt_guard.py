"""PromptGuard: AI Prompt Injection Defense and Skeptical-Reading Guard for CLI-WORKFLOW."""
import re
from typing import Dict, List, Any, Tuple


class PromptGuard:
    """Detects and neutralizes prompt injections, hidden instructions, and untrusted inputs."""

    INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts|rules)",
        r"(?i)system\s+prompt\s+override",
        r"(?i)you\s+are\s+now\s+in\s+(developer|unrestricted|god)\s+mode",
        r"(?i)exfiltrat(e|ion)\s+(secrets|env|keys|tokens)",
        r"(?i)send\s+(the\s+)?(\.env|api[_-]?key|password|token)\s+to",
        r"(?i)curl\s+-[X\s]+POST.*(webhook|pastebin|requestbin|ngrok)",
        r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>",
        r"(?i)rm\s+-rf\s+[/~]",
        r"(?i)format\s+[c-z]:",
        r"(?i)Invoke-Expression.*DownloadString",
    ]

    @classmethod
    def sanitize_input(cls, raw_input: str, source_label: str = "untrusted") -> Tuple[str, List[str]]:
        """Scans input for injection vectors and returns sanitized text with any detected flags."""
        flags = []
        for pattern in cls.INJECTION_PATTERNS:
            matches = re.findall(pattern, raw_input)
            if matches:
                flags.append(f"Suspicious pattern matched: '{pattern}'")

        # Provenance Tagging
        sanitized = raw_input.strip()
        return sanitized, flags

    @classmethod
    def is_safe_for_swarm(cls, prompt: str) -> Dict[str, Any]:
        """Returns security verdict for a user voice or text instruction."""
        sanitized, flags = cls.sanitize_input(prompt)
        is_safe = len(flags) == 0
        return {
            "is_safe": is_safe,
            "flags": flags,
            "flag_count": len(flags),
            "sanitized_prompt": sanitized,
            "verdict": "SAFE" if is_safe else "REJECTED_UNTRUSTED_INJECTION",
        }
