import logging
import httpx
from app.config import OLLAMA_URL, OLLAMA_MODEL, ANTHROPIC_API_KEY, CLAUDE_MODEL

logger = logging.getLogger(__name__)

OLLAMA_TIMEOUT = 360.0
CLAUDE_TIMEOUT = 60.0


async def generate(prompt: str, provider: str = "local") -> tuple[str, str]:
    """Call the configured LLM and return (response_text, model_name).

    provider: "local" → Ollama, "claude" → Anthropic API
    """
    if provider == "claude":
        text = await _call_claude(prompt)
        return text, CLAUDE_MODEL
    text = await _call_ollama(prompt)
    return text, OLLAMA_MODEL


async def _call_ollama(prompt: str) -> str:
    async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
        resp = await client.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_ctx": 4096},
            },
        )
    if resp.status_code != 200:
        raise RuntimeError(f"Ollama returned {resp.status_code}: {resp.text[:300]}")
    return resp.json().get("response", "").strip()


async def _call_claude(prompt: str) -> str:
    if not ANTHROPIC_API_KEY:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Add it to docker-compose.yml or a .env file."
        )
    import anthropic
    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    message = await client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text.strip()
