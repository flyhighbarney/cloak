"""policyd_sdk — a thin convenience wrapper that points the OpenAI and
Anthropic Python SDKs at a running policyd gateway.

Typical usage:

    from policyd_sdk import openai_client, anthropic_client

    client = openai_client()  # reads ~/.config/policyctl/config.yaml
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hello"}],
    )

    aclient = anthropic_client()
    resp = aclient.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        messages=[{"role": "user", "content": "hello"}],
    )

Overrides (in precedence order):
    1. Explicit args to openai_client() / anthropic_client()
    2. Environment: POLICYD_GATEWAY, POLICYD_API_KEY
    3. ~/.config/policyctl/config.yaml
"""

from .config import load_config, PolicydConfig
from .client import openai_client, anthropic_client

__all__ = [
    "load_config",
    "PolicydConfig",
    "openai_client",
    "anthropic_client",
]

__version__ = "0.1.0"
