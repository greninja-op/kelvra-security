# Kelvra Security (`kelvra-security`)

Autonomous AI security, prompt guardrails, and secret leak detection microservice for the Kelvra platform.

Runs independently on port **8100** (MCP endpoint served at `/mcp`).

## Endpoints

- `POST /screen`, `POST /screen-content`, `POST /screen-skill`: prompt/directive/content screening against injection, jailbreak, and catastrophic command denylists.
- `POST /audit`: audits code changes, diffs, or files for leaked credentials, private keys, API tokens, and OWASP Top 10 issues.
- `POST /check-command`: PreToolUse shell-command denylist check.
- `POST /gate/check|/gate/confirm|/gate/cancel`, `GET /gate/challenges`: confirmation gate for destructive acts.
- `POST /mcp/authorize`, `GET|POST /mcp/servers`: MCP authorization + server registry (MCP at `/mcp`).
- `POST /anomaly/check|/anomaly/reset`, `GET /audit-logs`, `GET /api/report/status`.
- `GET /health`: liveness and capabilities probe.

## Security report

`docs/SECURITY-REPORT-UPDATE-web-mobile-connection.md` — OWASP Top 10:2025 + API Top 10 + MASVS mapping,
connection trust model (**§4.5 DECIDED relay-first**, owner 2026-09-11), the Session-3 mobile surface
(§4.7), and the freshness steering rule (§6) that keeps the report in the same commit as security-relevant changes.

## Running Locally

```bash
uvicorn src.api:app --host 127.0.0.1 --port 8100
```

## Running Tests

```bash
python -m pytest -q
```

21-25 green depending on optional extras.
