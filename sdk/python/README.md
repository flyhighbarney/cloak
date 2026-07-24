# policyd-sdk (Python)

A zero-config Python wrapper that points the official OpenAI and Anthropic SDKs at your [policyd](https://github.com/flyhighbarney/policyd) gateway.

## Install

```bash
pip install policyd-sdk openai anthropic
```

## Configure

Either run `policyctl login https://your-gateway.com` (writes `~/.config/policyctl/config.yaml`) or set env vars:

```bash
export POLICYD_GATEWAY=https://gateway.example.com
export POLICYD_API_KEY=sk-gw-your-key
```

## Use

```python
from policyd_sdk import openai_client, anthropic_client

# OpenAI, routed through your gateway
oai = openai_client()
resp = oai.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
)

# Anthropic (Claude), routed through your gateway
ant = anthropic_client()
resp = ant.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
```

Every call runs through policyd's DLP, injection-defense, and audit trail.

## Explicit override

```python
oai = openai_client(gateway="https://staging.gateway.com", api_key="sk-gw-...")
```

## License

Apache 2.0.
