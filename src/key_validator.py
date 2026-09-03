"""Two-Tier API Key Validation Engine.

- Tier 1 (Quick Test): Free model-listing endpoint call.
  Verifies key format and authentication in <800ms with zero token cost.
- Tier 2 (Live Test): Trivial 1-token generation to cheapest model.
  Surfaces billing/quota ceilings and measures real round-trip latency.
"""
import time
import httpx
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("cli_workflow.key_validator")


class KeyValidator:
    """Validates direct API keys with Tier 1 and Tier 2 protocols."""

    # Free model listing endpoints (Tier 1)
    MODEL_LIST_ENDPOINTS = {
        "anthropic": {
            "url": "https://api.anthropic.com/v1/models",
            "headers": lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01"},
        },
        "openai": {
            "url": "https://api.openai.com/v1/models",
            "headers": lambda k: {"Authorization": f"Bearer {k}"},
        },
        "gemini": {
            "url": "https://generativelanguage.googleapis.com/v1beta/models",
            "headers": lambda k: {},
            "params": lambda k: {"key": k},
        },
        "groq": {
            "url": "https://api.groq.com/openai/v1/models",
            "headers": lambda k: {"Authorization": f"Bearer {k}"},
        },
        "openrouter": {
            "url": "https://openrouter.ai/api/v1/models",
            "headers": lambda k: {"Authorization": f"Bearer {k}"},
        },
    }

    # Cheapest models for Tier 2 live generation test
    LIVE_TEST_MODELS = {
        "openai": {"model": "gpt-4o-mini", "url": "https://api.openai.com/v1/chat/completions"},
        "anthropic": {"model": "claude-3-haiku-20240307", "url": "https://api.anthropic.com/v1/messages"},
        "gemini": {"model": "gemini-1.5-flash", "url": "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"},
        "groq": {"model": "llama-3.1-8b-instant", "url": "https://api.groq.com/openai/v1/chat/completions"},
        "openrouter": {"model": "meta-llama/llama-3.1-8b-instruct:free", "url": "https://openrouter.ai/api/v1/chat/completions"},
    }

    @classmethod
    async def validate_tier1(cls, provider: str, api_key: str) -> Dict[str, Any]:
        """Tier 1 Quick Test: Calls free model-listing endpoint."""
        prov = provider.lower().strip()
        cleaned_key = api_key.strip()
        if not cleaned_key:
            return {"status": "INVALID", "error": "API key cannot be empty", "latency_ms": 0}

        if prov not in cls.MODEL_LIST_ENDPOINTS:
            return {"status": "ERROR", "error": f"Unsupported provider: {provider}", "latency_ms": 0}

        config = cls.MODEL_LIST_ENDPOINTS[prov]
        url = config["url"]
        headers = config["headers"](cleaned_key)
        params = config.get("params", lambda k: {})(cleaned_key)

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(url, headers=headers, params=params)
                latency_ms = round((time.perf_counter() - start_time) * 1000)

                if res.status_code == 200:
                    return {
                        "status": "VALID",
                        "tier": 1,
                        "latency_ms": latency_ms,
                        "message": f"Authenticated successfully ({latency_ms}ms)",
                    }
                elif res.status_code in (401, 403):
                    return {
                        "status": "INVALID",
                        "tier": 1,
                        "latency_ms": latency_ms,
                        "error": f"Authentication failed ({res.status_code}): Invalid API key",
                    }
                elif res.status_code == 429:
                    return {
                        "status": "VALID_NO_QUOTA",
                        "tier": 1,
                        "latency_ms": latency_ms,
                        "error": "Key valid, but rate limit or quota/billing credit exhausted (HTTP 429)",
                    }
                else:
                    return {
                        "status": "INVALID",
                        "tier": 1,
                        "latency_ms": latency_ms,
                        "error": f"Provider returned HTTP {res.status_code}",
                    }
        except httpx.TimeoutException:
            return {"status": "ERROR", "tier": 1, "error": "Request timed out after 8s", "latency_ms": 8000}
        except Exception as e:
            return {"status": "ERROR", "tier": 1, "error": f"Connection error: {str(e)[:100]}", "latency_ms": 0}

    @classmethod
    async def validate_tier2(cls, provider: str, api_key: str) -> Dict[str, Any]:
        """Tier 2 Live Test: Sends 1-token prompt to cheapest model to verify billing."""
        prov = provider.lower().strip()
        cleaned_key = api_key.strip()
        if not cleaned_key:
            return {"status": "INVALID", "error": "API key cannot be empty"}

        if prov not in cls.LIVE_TEST_MODELS:
            return await cls.validate_tier1(provider, api_key)

        cfg = cls.LIVE_TEST_MODELS[prov]
        start_time = time.perf_counter()

        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                if prov in ("openai", "groq", "openrouter"):
                    payload = {
                        "model": cfg["model"],
                        "messages": [{"role": "user", "content": "Reply with OK"}],
                        "max_tokens": 5,
                    }
                    headers = {"Authorization": f"Bearer {cleaned_key}", "Content-Type": "application/json"}
                    res = await client.post(cfg["url"], json=payload, headers=headers)
                elif prov == "anthropic":
                    payload = {
                        "model": cfg["model"],
                        "messages": [{"role": "user", "content": "Reply with OK"}],
                        "max_tokens": 5,
                    }
                    headers = {
                        "x-api-key": cleaned_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    }
                    res = await client.post(cfg["url"], json=payload, headers=headers)
                elif prov == "gemini":
                    url = f"{cfg['url']}?key={cleaned_key}"
                    payload = {"contents": [{"parts": [{"text": "Reply with OK"}]}]}
                    res = await client.post(url, json=payload)
                else:
                    return await cls.validate_tier1(provider, api_key)

                latency_ms = round((time.perf_counter() - start_time) * 1000)

                if res.status_code == 200:
                    data = res.json()
                    sample = "OK"
                    if prov in ("openai", "groq", "openrouter") and "choices" in data:
                        sample = data["choices"][0]["message"]["content"].strip()
                    elif prov == "anthropic" and "content" in data:
                        sample = data["content"][0]["text"].strip()
                    elif prov == "gemini" and "candidates" in data:
                        sample = data["candidates"][0]["content"]["parts"][0]["text"].strip()

                    return {
                        "status": "VALID",
                        "tier": 2,
                        "latency_ms": latency_ms,
                        "sample_response": sample,
                        "estimated_cost": "< $0.0001",
                        "message": f"Live test passed: '{sample}' in {latency_ms}ms",
                    }
                elif res.status_code in (401, 403):
                    return {
                        "status": "INVALID",
                        "tier": 2,
                        "latency_ms": latency_ms,
                        "error": f"Authentication rejected: {res.text[:120]}",
                    }
                elif res.status_code == 429 or "insufficient_quota" in res.text:
                    return {
                        "status": "VALID_NO_QUOTA",
                        "tier": 2,
                        "latency_ms": latency_ms,
                        "error": "Valid key, but no billing quota/credits available (HTTP 429)",
                    }
                else:
                    return {
                        "status": "INVALID",
                        "tier": 2,
                        "latency_ms": latency_ms,
                        "error": f"HTTP {res.status_code}: {res.text[:100]}",
                    }
        except Exception as e:
            return {"status": "ERROR", "tier": 2, "error": f"Live test failed: {str(e)[:100]}", "latency_ms": 0}
