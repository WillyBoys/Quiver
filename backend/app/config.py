import os

# Local Ollama settings
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ai:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

# Anthropic / Claude settings
# Two auth routes (set one in .env, not both):
#   CLAUDE_CODE_OAUTH_TOKEN — OAuth token from a Claude Pro/Team subscription.
#     Routed through the claude-bridge sidecar which runs the Claude Code CLI.
#   ANTHROPIC_API_KEY — Standard pay-per-token API key from console.anthropic.com.
#     Called directly via the Anthropic Python SDK.
# If both are set, CLAUDE_CODE_OAUTH_TOKEN takes priority.
CLAUDE_CODE_OAUTH_TOKEN = os.getenv("CLAUDE_CODE_OAUTH_TOKEN", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
CLAUDE_BRIDGE_URL = os.getenv("CLAUDE_BRIDGE_URL", "http://claude-bridge:3001")
