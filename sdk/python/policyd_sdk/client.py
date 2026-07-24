"""Client factories that hand back OpenAI / Anthropic SDK clients
pre-configured to talk to your policyd gateway."""

from __future__ import annotations

from typing import Any, Optional

from .config import load_config, PolicydConfig


def openai_client(
    gateway: Optional[str] = None,
    api_key: Optional[str] = None,
    **extra: Any,
):
    """Return an `openai.OpenAI` client pointed at a policyd gateway.

    Requires the `openai` package to be installed:  pip install openai

    Every kwarg not consumed here is forwarded to `openai.OpenAI(...)`.
    """
    try:
        from openai import OpenAI  # type: ignore
    except ImportError as e:
        raise ImportError(
            "openai package not installed. Run: pip install openai"
        ) from e

    cfg = load_config(gateway=gateway, api_key=api_key)
    return OpenAI(base_url=cfg.openai_base_url(), api_key=cfg.api_key, **extra)


def anthropic_client(
    gateway: Optional[str] = None,
    api_key: Optional[str] = None,
    **extra: Any,
):
    """Return an `anthropic.Anthropic` client pointed at a policyd gateway.

    Requires the `anthropic` package to be installed:  pip install anthropic
    """
    try:
        from anthropic import Anthropic  # type: ignore
    except ImportError as e:
        raise ImportError(
            "anthropic package not installed. Run: pip install anthropic"
        ) from e

    cfg = load_config(gateway=gateway, api_key=api_key)
    return Anthropic(base_url=cfg.anthropic_base_url(), api_key=cfg.api_key, **extra)


def config() -> PolicydConfig:
    """Return the resolved config without instantiating an SDK client."""
    return load_config()
