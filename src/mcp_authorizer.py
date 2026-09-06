"""MCPAuthorizer: Least-Privilege Permission Scoping and Vetting Engine for MCP Connectors.

Implements OWASP Top 10 for LLM Applications (2026 - LLM07: Insecure Plugin Design)
and OWASP Top 10 for Agentic Applications (2026 - ASI03: Insecure Agent Supply Chain).

Enforces §2.7 & §3:
- Least-privilege scoping enforced per connection (explicit tool allowlists, never blanket access).
- Trust-tier classification: first_party (native), allowlisted (curated), user_managed (unvetted).
- Pre-execution tool authorization hook.
"""
from typing import Dict, Any, List, Optional, Tuple


class MCPAuthorizer:
    """Manages MCP connector permissions, scoping rules, and pre-execution tool checks."""

    DEFAULT_SERVERS = {
        "kelvra-filesystem": {
            "server_id": "kelvra-filesystem",
            "name": "Kelvra Local Filesystem",
            "trust_tier": "first_party",
            "allowed_tools": ["read_file", "write_file", "list_dir", "view_file", "grep_search", "find_by_name"],
            "denied_tools": ["delete_root", "format_disk", "execute_binary"],
            "read_only": False,
            "requires_confirmation_for_write": False,
        },
        "kelvra-git": {
            "server_id": "kelvra-git",
            "name": "Kelvra Git Worktree Manager",
            "trust_tier": "first_party",
            "allowed_tools": ["git_status", "git_diff", "git_log", "git_commit", "git_branch"],
            "denied_tools": ["git_force_push", "git_delete_protected_branch"],
            "read_only": False,
            "requires_confirmation_for_write": False,
        },
        "postgres-mcp": {
            "server_id": "postgres-mcp",
            "name": "PostgreSQL Database Connector",
            "trust_tier": "allowlisted",
            "allowed_tools": ["execute_query", "list_tables", "describe_table"],
            "denied_tools": ["drop_database", "truncate_all", "grant_superuser"],
            "read_only": True,
            "requires_confirmation_for_write": True,
        },
        "github-mcp": {
            "server_id": "github-mcp",
            "name": "GitHub API Connector",
            "trust_tier": "allowlisted",
            "allowed_tools": ["get_issue", "list_pull_requests", "get_diff", "create_pr_comment"],
            "denied_tools": ["delete_repository", "force_push", "delete_branch"],
            "read_only": False,
            "requires_confirmation_for_write": True,
        },
    }

    def __init__(self):
        self._servers: Dict[str, Dict[str, Any]] = dict(self.DEFAULT_SERVERS)

    def register_server(
        self,
        server_id: str,
        name: str,
        trust_tier: str = "user_managed",
        allowed_tools: Optional[List[str]] = None,
        denied_tools: Optional[List[str]] = None,
        read_only: bool = False,
    ) -> Dict[str, Any]:
        """Registers or configures an MCP server with enforced least-privilege scoping (§2.7)."""
        sid = server_id.strip().lower()
        tier = trust_tier.lower()
        if tier not in ("first_party", "allowlisted", "user_managed"):
            tier = "user_managed"

        # Blanket wildcard ["*"] is explicitly prohibited for non-first-party servers per §2.7
        tools = allowed_tools or []
        if tier != "first_party" and "*" in tools:
            tools = [t for t in tools if t != "*"]

        entry = {
            "server_id": sid,
            "name": name,
            "trust_tier": tier,
            "allowed_tools": tools,
            "denied_tools": denied_tools or ["delete_all", "format", "drop", "force_push"],
            "read_only": read_only,
            "requires_confirmation_for_write": tier == "user_managed",
        }
        self._servers[sid] = entry
        return entry

    def authorize_tool_call(
        self,
        server_id: str,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Pre-execution validation ensuring tool call complies with least-privilege scoping (§2.7)."""
        sid = (server_id or "").strip().lower()
        tname = (tool_name or "").strip().lower()
        tool_args = tool_args or {}

        server = self._servers.get(sid)
        if not server:
            return False, f"Unauthorized: MCP server '{server_id}' is unvetted and not registered in security policy.", {
                "server_id": server_id,
                "tool_name": tool_name,
                "reason": "unregistered_server",
            }

        # Check explicit denylist first
        if tname in [d.lower() for d in server.get("denied_tools", [])]:
            return False, f"Permission Denied: Tool '{tool_name}' is explicitly denylisted for connector '{server.get('name')}'.", {
                "server_id": sid,
                "tool_name": tname,
                "reason": "denylisted_tool",
            }

        # Check read-only constraint
        if server.get("read_only"):
            destructive_keywords = ["write", "create", "delete", "drop", "truncate", "update", "insert", "modify", "exec"]
            if any(k in tname for k in destructive_keywords):
                return False, f"Permission Denied: Connector '{server.get('name')}' is scoped as Read-Only. Tool '{tool_name}' blocked.", {
                    "server_id": sid,
                    "tool_name": tname,
                    "reason": "read_only_violation",
                }

        # Check allowed tools list
        allowed = [a.lower() for a in server.get("allowed_tools", [])]
        if "*" not in allowed and tname not in allowed:
            return False, f"Permission Denied: Tool '{tool_name}' is outside the least-privilege scope for connector '{server.get('name')}'.", {
                "server_id": sid,
                "tool_name": tname,
                "reason": "outside_scope",
                "allowed_tools": server.get("allowed_tools", []),
            }

        return True, "Tool execution authorized under least-privilege scoping.", {
            "server_id": sid,
            "tool_name": tname,
            "trust_tier": server.get("trust_tier"),
            "authorized": True,
        }

    def get_server(self, server_id: str) -> Optional[Dict[str, Any]]:
        return self._servers.get(server_id.strip().lower())

    def list_servers(self) -> List[Dict[str, Any]]:
        return list(self._servers.values())


# Global singleton
mcp_authorizer = MCPAuthorizer()
