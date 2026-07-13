import os

# AI / Ollama settings
# To swap models: set OLLAMA_MODEL in docker-compose.yml or .env
# To use a remote Ollama instance: set OLLAMA_URL to its base URL
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ai:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi3:mini")
