import logging
import httpx
from app.config import (
    OLLAMA_URL, OLLAMA_MODEL,
    CLAUDE_CODE_OAUTH_TOKEN, ANTHROPIC_API_KEY, CLAUDE_MODEL, CLAUDE_BRIDGE_URL,
)

logger = logging.getLogger(__name__)

OLLAMA_TIMEOUT = 300.0
# Summary prompts include full tool outputs and need more context + generation time.
# 7B models on CPU can take 10-20 minutes for a large structured summary.
OLLAMA_SUMMARY_TIMEOUT = 1200.0
CLAUDE_TIMEOUT = 60.0


class AuthError(RuntimeError):
    """Raised when the LLM provider rejects the API key. Never retry on this."""
    pass


async def generate(prompt: str, provider: str = "local") -> tuple[str, str]:
    """Call the configured LLM and return (response_text, model_name).

    provider: "local" → Ollama, "claude" → Anthropic API
    """
    if provider == "claude":
        text = await _call_claude(prompt)
        return text, CLAUDE_MODEL
    text = await _call_ollama(prompt)
    return text, OLLAMA_MODEL


async def generate_report(prompt: str, provider: str = "claude") -> str:
    """Generate a long-form narrative report. Prefers Claude for quality."""
    if provider == "claude" or CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY:
        if CLAUDE_CODE_OAUTH_TOKEN:
            return await _call_claude_bridge(prompt)
        if ANTHROPIC_API_KEY:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
            try:
                message = await client.messages.create(
                    model=CLAUDE_MODEL,
                    max_tokens=4096,
                    messages=[{"role": "user", "content": prompt}],
                )
            except anthropic.AuthenticationError as e:
                raise AuthError(f"Anthropic authentication failed: {e}") from e
            return message.content[0].text.strip()
    # Fallback to local model
    return await _call_ollama_summary(prompt)


async def generate_summary(prompt: str, provider: str = "local") -> tuple[str, str]:
    """Like generate() but tuned for the final campaign summary.

    Uses a larger context window and longer timeout — 7B models on CPU are
    genuinely slow when processing many tool outputs at once.
    """
    if provider == "claude":
        text = await _call_claude(prompt)
        return text, CLAUDE_MODEL
    text = await _call_ollama_summary(prompt)
    return text, OLLAMA_MODEL


async def _call_ollama(prompt: str) -> str:
    async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
        resp = await client.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_ctx": 4096,
                    "num_predict": 1024,
                },
            },
        )
    if resp.status_code != 200:
        raise RuntimeError(f"Ollama returned {resp.status_code}: {resp.text[:300]}")
    return resp.json().get("response", "").strip()


async def _call_ollama_summary(prompt: str) -> str:
    async with httpx.AsyncClient(timeout=OLLAMA_SUMMARY_TIMEOUT) as client:
        resp = await client.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_ctx": 8192,
                    "num_predict": 2048,
                },
            },
        )
    if resp.status_code != 200:
        raise RuntimeError(f"Ollama returned {resp.status_code}: {resp.text[:300]}")
    return resp.json().get("response", "").strip()


async def _call_claude(prompt: str) -> str:
    # OAuth route: forward to the claude-bridge sidecar (Claude Code CLI).
    # Takes priority so that subscriptions are used before a pay-per-token key.
    if CLAUDE_CODE_OAUTH_TOKEN:
        return await _call_claude_bridge(prompt)

    # Standard API key route
    if not ANTHROPIC_API_KEY:
        raise AuthError(
            "No Claude credentials found. Set CLAUDE_CODE_OAUTH_TOKEN (OAuth/subscription) "
            "or ANTHROPIC_API_KEY (API key) in your .env file."
        )
    import anthropic
    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    try:
        message = await client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.AuthenticationError as e:
        raise AuthError(
            f"Anthropic authentication failed. Check ANTHROPIC_API_KEY in your .env. Details: {e}"
        ) from e
    return message.content[0].text.strip()


async def _call_claude_bridge(prompt: str) -> str:
    """Forward a prompt to the claude-bridge sidecar and return the response text.

    The bridge runs the Claude Code CLI, which handles OAuth token auth natively.
    Timeout is set above the bridge's own 120s subprocess timeout so the Python
    side always receives the bridge's error response rather than timing out first.
    """
    try:
        async with httpx.AsyncClient(timeout=150.0) as client:
            resp = await client.post(
                f"{CLAUDE_BRIDGE_URL}/generate",
                json={"prompt": prompt},
            )
    except httpx.ConnectError:
        raise RuntimeError(
            "Cannot connect to the claude-bridge service. "
            "Make sure the claude-bridge container is running "
            "(docker-compose up claude-bridge)."
        )
    if resp.status_code == 401:
        raise AuthError(
            "claude-bridge: authentication failed. "
            "Check that CLAUDE_CODE_OAUTH_TOKEN in your .env is valid."
        )
    if resp.status_code != 200:
        detail = ""
        if resp.content and resp.headers.get("content-type", "").startswith("application/json"):
            detail = resp.json().get("error", "")
        raise RuntimeError(f"claude-bridge error ({resp.status_code}): {detail or resp.text[:200]}")
    return resp.json().get("response", "").strip()
