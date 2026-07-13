import os

# Local Ollama settings
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ai:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi3:mini")

# Anthropic / Claude settings
# Set ANTHROPIC_API_KEY in docker-compose.yml or a .env file to enable the Claude provider
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
