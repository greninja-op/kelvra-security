# Kelvra Security (`kelvra-security`)

Autonomous AI security, prompt guardrails, and secret leak detection microservice for the Kelvra platform.

Runs independently on port **8100**.

## Endpoints

- `POST /screen`: Evaluates an incoming prompt or directive against prompt injection, jailbreak, and catastrophic command denylists.
- `POST /audit`: Audits code changes, diffs, or files for leaked credentials, private keys, API tokens, and OWASP Top 10 vulnerabilities.
- `GET /health`: Liveness and capabilities probe.

## Running Locally

```bash
uvicorn src.api:app --host 127.0.0.1 --port 8100
```

## Running Tests

```bash
python -m unittest discover -s tests -p "test_*.py"
```
