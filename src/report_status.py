"""Report freshness status: LIVE parse of the repo's own security report file.

Reads ``docs/SECURITY-REPORT-UPDATE-web-mobile-connection.md`` at request time
(same repo — reading your own repo's file at runtime is fine) and extracts the
review-cadence front matter plus the audit status line. Never fabricates dates:
any field that cannot be parsed is returned as ``None`` with an honest note.

No secrets involved; this module handles no key material. No new dependencies.
"""
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPORT_FILENAME = "SECURITY-REPORT-UPDATE-web-mobile-connection.md"
REPORT_PATH = Path(__file__).resolve().parent.parent / "docs" / REPORT_FILENAME


def _collapse_ws(text: str) -> str:
    """Collapse all whitespace runs to single spaces and strip."""
    return re.sub(r"\s+", " ", text or "").strip()


def _valid_date(value: Optional[str]) -> Optional[str]:
    """Return the YYYY-MM-DD string only if it is a real calendar date, else None."""
    if not value:
        return None
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return value
    except ValueError:
        return None


def _parse_next_manual_due(text: str) -> Optional[str]:
    m = re.search(
        r"Next manual review due:\s*\*{0,2}\s*(\d{4}-\d{2}-\d{2})",
        text,
        re.IGNORECASE,
    )
    return _valid_date(m.group(1)) if m else None


def _parse_automated(text: str) -> Optional[str]:
    m = re.search(
        r"automated\s+.*?checks?\s+on\s+\*{0,2}\s*([^*>\n;]+?)\s*\*{0,2}\s*;",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return None
    value = _collapse_ws(m.group(1).strip("* "))
    return value or None


def _parse_manual(text: str) -> Optional[str]:
    m = re.search(
        r"full manual review\s+\*{0,2}\s*([^*>\n.]+?)\s*\*{0,2}\s*[\.\n]",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return None
    value = _collapse_ws(m.group(1).strip("* "))
    return value or None


def _parse_last_audit(text: str) -> Optional[str]:
    m = re.search(
        r"findings from live code audit,\s*(\d{4}-\d{2}-\d{2})",
        text,
        re.IGNORECASE,
    )
    return _valid_date(m.group(1)) if m else None


def _parse_freshness_rule(text: str) -> Optional[str]:
    # Primary: the §6 Steering rule `rule-security-report-freshness` blockquote
    # ("If this task touches ... push it."). Collapse to one line.
    m = re.search(r"If this task touches.*?push it", text, re.IGNORECASE | re.DOTALL)
    if m:
        snippet = m.group(0)
        snippet = re.sub(r"(?m)^\s*>\s?", "", snippet)  # strip blockquote markers
        snippet = snippet.replace("`", "").replace("**", "")
        one_line = _collapse_ws(snippet)
        if one_line and not one_line.endswith("."):
            one_line += "."
        return one_line or None
    # Fallback: the front-matter "**Freshness rule:** ..." paragraph.
    m2 = re.search(r"\*\*Freshness rule:\*\*\s*(.*?)(?:\(enforced by|\n\s*\n)",
                   text, re.IGNORECASE | re.DOTALL)
    if m2:
        snippet = re.sub(r"(?m)^\s*>\s?", "", m2.group(1))
        one_line = _collapse_ws(snippet.replace("`", "").replace("**", ""))
        return one_line or None
    return None


def parse_report_text(text: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Pure parser (testable without disk I/O).

    Returns (automated, manual, next_manual_due, last_audit, freshness_rule).
    """
    automated = _parse_automated(text)
    manual = _parse_manual(text)
    next_due = _parse_next_manual_due(text)
    last_audit = _parse_last_audit(text)
    freshness_rule = _parse_freshness_rule(text)
    return automated, manual, next_due, last_audit, freshness_rule


def get_report_status(report_path: Optional[Path] = None) -> Dict[str, Any]:
    """Read the report file LIVE and build the status payload (null-honest)."""
    path = Path(report_path) if report_path is not None else REPORT_PATH
    notes: List[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        notes.append(
            f"report file not found at '{path.name}'; returning nulls (not fabricated)."
        )
        return {
            "report": REPORT_FILENAME,
            "cadence": {"automated": None, "manual": None, "next_manual_due": None},
            "last_audit": None,
            "freshness_rule": None,
            "notes": notes,
        }
    except OSError as exc:
        notes.append(f"could not read report file ({exc}); returning nulls (not fabricated).")
        return {
            "report": REPORT_FILENAME,
            "cadence": {"automated": None, "manual": None, "next_manual_due": None},
            "last_audit": None,
            "freshness_rule": None,
            "notes": notes,
        }

    automated, manual, next_due, last_audit, freshness_rule = parse_report_text(text)

    if automated is None:
        notes.append("could not parse 'cadence.automated' from report; returning null (not fabricated).")
    if manual is None:
        notes.append("could not parse 'cadence.manual' from report; returning null (not fabricated).")
    if next_due is None:
        notes.append("could not parse 'cadence.next_manual_due' from report; returning null (not fabricated).")
    if last_audit is None:
        notes.append("could not parse 'last_audit' from report; returning null (not fabricated).")
    if freshness_rule is None:
        notes.append("could not parse 'freshness_rule' from report; returning null (not fabricated).")

    return {
        "report": REPORT_FILENAME,
        "cadence": {
            "automated": automated,
            "manual": manual,
            "next_manual_due": next_due,
        },
        "last_audit": last_audit,
        "freshness_rule": freshness_rule,
        "notes": notes,
    }
