"""AppSec Auditor: Secret Leaks, CWE/OWASP Top 10 Vulnerability Scanner for CLI-WORKFLOW."""
import re
from typing import Dict, List, Any


class AppSecAuditor:
    """Pre-commit security and secret auditor for multi-agent swarm workspaces."""

    SECRET_REGEXES = {
        "OpenAI API Key": r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}",
        "Anthropic API Key": r"sk-ant-api03-[A-Za-z0-9_-]{32,}",
        "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "AWS Access Key ID": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "Stripe Secret Key": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
        "Generic Private Key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "JWT Secret": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
    }

    VULNERABILITY_PATTERNS = {
        "SQL Injection Risk": r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*['\"]|execute\(['\"].*%\s*\(",
        "Dangerous Code Eval": r"(?i)\beval\(|\bexec\(|__import__\(|Function\(",
        "Insecure Deserialization": r"(?i)pickle\.loads?\(|yaml\.load\([^,)]+\)",
        "Hardcoded Localhost Auth": r"(?i)(password|secret|key)\s*=\s*['\"][a-zA-Z0-9_@#!$%^&*]{6,}['\"]",
    }

    @classmethod
    def scan_content(cls, content: str, filepath: str = "workspace") -> Dict[str, Any]:
        """Scans code for leaked credentials or high-risk vulnerability patterns."""
        leaks = []
        vulns = []

        for secret_type, pattern in cls.SECRET_REGEXES.items():
            matches = re.finditer(pattern, content)
            for m in matches:
                val = m.group(0)
                masked = val[:6] + "..." + val[-4:] if len(val) > 10 else "***"
                leaks.append({
                    "type": secret_type,
                    "location": filepath,
                    "masked_value": masked,
                })

        for vuln_name, pattern in cls.VULNERABILITY_PATTERNS.items():
            if re.search(pattern, content):
                vulns.append({
                    "vuln_type": vuln_name,
                    "location": filepath,
                })

        is_clean = len(leaks) == 0
        return {
            "is_clean": is_clean,
            "secret_leaks": leaks,
            "secret_count": len(leaks),
            "vulnerabilities": vulns,
            "vuln_count": len(vulns),
            "status": "APPROVED" if is_clean else "BLOCKED_LEAK_DETECTED",
        }
