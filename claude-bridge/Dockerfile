FROM node:20-slim

WORKDIR /app

# Install Claude Code CLI — this provides the `claude` binary and handles OAuth
# token auth natively via CLAUDE_CODE_OAUTH_TOKEN env var.
RUN npm install -g @anthropic-ai/claude-code

# Bridge uses only Node.js built-ins, no local npm dependencies
COPY package.json server.js ./

EXPOSE 3001
CMD ["node", "server.js"]
