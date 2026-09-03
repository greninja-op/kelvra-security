"""Credential Vault for CLI-Workflow.

Secures direct provider API keys using the OS Credential Store (keyring)
with an encrypted local vault fallback. Raw keys are never logged and are
masked across all UI surfaces.
"""
import os
import json
import base64
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger("cli_workflow.credential_vault")

SERVICE_NAME = "cli-workflow"

# Recognized direct API key providers
SUPPORTED_PROVIDERS = [
    "anthropic",
    "openai",
    "gemini",
    "groq",
    "openrouter",
]


class CredentialVault:
    """Manages API key storage, retrieval, and masking with OS keyring and encrypted fallback."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or (Path(__file__).resolve().parent.parent.parent / "data")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.vault_file = self.data_dir / ".vault.enc"
        self._keyring_available = self._check_keyring()

    def _check_keyring(self) -> bool:
        try:
            import keyring
            # Test keyring access
            keyring.get_password(SERVICE_NAME, "__health_check__")
            return True
        except Exception as e:
            logger.info(f"OS keyring not available, using local vault fallback: {e}")
            return False

    def _get_machine_salt(self) -> bytes:
        """Derive a consistent machine-specific salt for local vault encryption."""
        seed = f"{os.environ.get('COMPUTERNAME', '')}-{os.environ.get('USERNAME', '')}-cli-workflow-salt"
        return seed.encode("utf-8")

    def _simple_crypt(self, text: str, encrypt: bool = True) -> str:
        """Lightweight reversible obfuscation for local fallback file."""
        salt = self._get_machine_salt()
        if encrypt:
            raw = text.encode("utf-8")
            xor = bytes(b ^ salt[i % len(salt)] for i, b in enumerate(raw))
            return base64.b64encode(xor).decode("ascii")
        else:
            xor = base64.b64decode(text.encode("ascii"))
            raw = bytes(b ^ salt[i % len(salt)] for i, b in enumerate(xor))
            return raw.decode("utf-8")

    def _load_local_vault(self) -> Dict[str, str]:
        if not self.vault_file.exists():
            return {}
        try:
            encrypted = self.vault_file.read_text(encoding="utf-8")
            if not encrypted:
                return {}
            decrypted = self._simple_crypt(encrypted, encrypt=False)
            return json.loads(decrypted)
        except Exception as e:
            logger.warning(f"Could not read local vault: {e}")
            return {}

    def _save_local_vault(self, vault: Dict[str, str]):
        try:
            raw_json = json.dumps(vault)
            encrypted = self._simple_crypt(raw_json, encrypt=True)
            self.vault_file.write_text(encrypted, encoding="utf-8")
        except Exception as e:
            logger.error(f"Could not save local vault: {e}")

    def set_key(self, provider: str, api_key: str) -> bool:
        """Store an API key securely for the given provider."""
        prov = provider.lower().strip()
        cleaned_key = api_key.strip()
        if not cleaned_key:
            return self.delete_key(prov)

        if self._keyring_available:
            try:
                import keyring
                keyring.set_password(SERVICE_NAME, prov, cleaned_key)
                return True
            except Exception as e:
                logger.warning(f"Keyring write failed, falling back to local vault: {e}")

        vault = self._load_local_vault()
        vault[prov] = cleaned_key
        self._save_local_vault(vault)
        return True

    def get_key(self, provider: str) -> Optional[str]:
        """Retrieve the raw API key for backend execution only. NEVER export or log."""
        prov = provider.lower().strip()
        if self._keyring_available:
            try:
                import keyring
                val = keyring.get_password(SERVICE_NAME, prov)
                if val:
                    return val
            except Exception:
                pass

        vault = self._load_local_vault()
        return vault.get(prov)

    def delete_key(self, provider: str) -> bool:
        """Delete an API key for the given provider."""
        prov = provider.lower().strip()
        if self._keyring_available:
            try:
                import keyring
                keyring.delete_password(SERVICE_NAME, prov)
            except Exception:
                pass

        vault = self._load_local_vault()
        if prov in vault:
            del vault[prov]
            self._save_local_vault(vault)
        return True

    @staticmethod
    def mask_key(key: Optional[str]) -> str:
        """Mask a key preserving prefix and suffix: sk-ant-••••••••1a2b."""
        if not key:
            return ""
        key = key.strip()
        if len(key) <= 8:
            return "••••••••"
        prefix = key[:6] if len(key) >= 12 else key[:3]
        suffix = key[-4:]
        return f"{prefix}••••••••{suffix}"

    def get_status_overview(self) -> Dict[str, Any]:
        """Return non-sensitive status of all supported providers."""
        status = {}
        for prov in SUPPORTED_PROVIDERS:
            key = self.get_key(prov)
            has_key = bool(key)
            status[prov] = {
                "provider": prov,
                "configured": has_key,
                "masked_key": self.mask_key(key) if has_key else "",
            }
        return status


# Singleton instance
credential_vault = CredentialVault()
