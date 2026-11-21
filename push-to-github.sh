#!/usr/bin/env bash
set -euo pipefail

echo "=== GlassBox GitHub Publisher ==="
read -rp "Enter your GitHub username (e.g. octocat): " GH_USER
REPO_NAME="${1:-glassbox}"

if [ -z "$GH_USER" ]; then
  echo "Error: GitHub username is required."
  exit 1
fi

if [ ! -d ".git" ]; then
  git init -b main
fi

git add .
git commit -m "feat: initial release of GlassBox v0.1.0 (MCP Flight Recorder & Lethal-Trifecta Firewall)" || true

if command -v gh >/dev/null 2>&1; then
  echo "Creating public GitHub repo ${GH_USER}/${REPO_NAME} via GitHub CLI..."
  gh repo create "${GH_USER}/${REPO_NAME}" --public --source=. --remote=origin --push \
    --description "The Flight Recorder & Lethal-Trifecta Firewall for AI Agents (MCP). Zero-dependency dynamic taint lattice, schema pinning, and \$0 offline time-travel replay."
  gh repo edit "${GH_USER}/${REPO_NAME}" --add-topic mcp,ai-agents,claude-code,cursor,security,prompt-injection,firewall,time-travel-debugging,developer-tools,python,zero-dependencies,json-rpc,merkle-tree,information-flow-control,llm-security,agent-harness,replay,cli,open-source,devtools
else
  REMOTE_URL="https://github.com/${GH_USER}/${REPO_NAME}.git"
  git remote remove origin 2>/dev/null || true
  git remote add origin "$REMOTE_URL"
  echo ""
  echo "GitHub CLI (gh) not found. Create an empty public repo named '${REPO_NAME}' at https://github.com/new"
  echo "Then run:"
  echo "  git push -u origin main"
fi

echo ""
echo "Done! Next step: follow LAUNCH_PLAYBOOK.md to coordinate your Show HN, X, and Reddit launch."
