# Runs the MCP server over stdio. The bundle in plugin/dist is self-contained (no npm install needed).
FROM node:22-slim
WORKDIR /app
COPY package.json ./
COPY bin ./bin
COPY plugin/dist ./plugin/dist
USER node
ENTRYPOINT ["node", "bin/mcp-security-guard.mjs"]
