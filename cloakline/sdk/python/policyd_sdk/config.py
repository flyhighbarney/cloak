"""Config resolution for policyd_sdk.

Reads ~/.config/policyctl/config.yaml if present, then applies environment
variable overrides (POLICYD_GATEWAY, POLICYD_API_KEY).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class PolicydConfig:
    gateway: str
    api_key: str
    tenant: str = ""

    def openai_base_url(self) -> str:
        """Return the OpenAI-compatible base URL (adds /v1 if missing)."""
        base = self.gateway.rstrip("/")
        if base.endswith("/v1"):
            return base
        return base + "/v1"

    def anthropic_base_url(self) -> str:
        """The Anthropic Python SDK expects the origin without /v1."""
        return self.gateway.rstrip("/")


def _config_path() -> Path:
    """Match policyctl's config path convention across OSes."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "policyctl" / "config.yaml"
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "policyctl" / "config.yaml"
    return Path.home() / ".config" / "policyctl" / "config.yaml"


def load_config(
    gateway: Optional[str] = None,
    api_key: Optional[str] = None,
    tenant: Optional[str] = None,
) -> PolicydConfig:
    """Resolve config with the documented precedence.

    Raises ValueError if neither gateway nor api_key can be found anywhere.
    """
    # Start with disk values.
    disk = _read_disk_config()
    resolved_gateway = gateway or os.environ.get("POLICYD_GATEWAY") or disk.get("gateway", "")
    resolved_key = api_key or os.environ.get("POLICYD_API_KEY") or disk.get("api_key", "")
    resolved_tenant = tenant or os.environ.get("POLICYD_TENANT") or disk.get("tenant", "")

    if not resolved_gateway:
        raise ValueError(
            "no policyd gateway URL configured. "
            "Set POLICYD_GATEWAY, pass gateway=..., or run `policyctl login <url>`."
        )
    if not resolved_key:
        raise ValueError(
            "no policyd virtual key configured. "
            "Set POLICYD_API_KEY, pass api_key=..., or run `policyctl login <url>`."
        )
    if not resolved_key.startswith("sk-gw-"):
        raise ValueError(
            f"api_key does not look like a policyd virtual key (must start with sk-gw-): {resolved_key[:8]}..."
        )
    return PolicydConfig(
        gateway=resolved_gateway.rstrip("/"),
        api_key=resolved_key,
        tenant=resolved_tenant,
    )


def _read_disk_config() -> dict:
    """Return an empty dict when the file doesn't exist. Uses a very small
    hand-rolled YAML parser so this package has zero runtime dependencies
    other than what the OpenAI/Anthropic SDKs already bring."""
    path = _config_path()
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    result: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        result[key.strip()] = value.strip().strip("'\"")
    return result
