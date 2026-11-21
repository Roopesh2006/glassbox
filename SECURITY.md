# Security Policy & Threat Model

## What GlassBox Protects Against
1. **Lethal Trifecta Exfiltration (`PRIVATE ∧ UNTRUSTED → EGRESS`)**: When an agent reads sensitive data (e.g., `.env`, private keys, customer DB rows) and ingests untrusted external input (e.g., GitHub issues, web pages, emails) in the same session, GlassBox deterministically downgrades outbound MCP tool calls to `SHADOW_SIMULATE` (suppressing the real side effect and capturing the payload forensically) or `BLOCK`.
2. **Destructive Side Effects Under Prompt Decay**: Blocks destructive tool calls (`DROP TABLE`, `TRUNCATE`, `rm -rf`, `force_push`) at the wire layer outside the LLM's context window—immune to prompt decay or jailbreaks.
3. **MCP Tool Rug-Pulls (`MCPoison` / Schema Mutation)**: Pins the SHA-256 digest of every tool's name, description, and `inputSchema` on initial `tools/list` and blocks any tool whose schema mutates mid-session.
4. **Trace Tampering**: Chains every recorded frame in a SHA-256 Merkle ledger (`.gbx`). Any post-hoc alteration breaks `glassbox verify`.

## Explicit Security Boundaries (What GlassBox Does NOT Cover)
- **Unwrapped Non-MCP Channels**: If an agent invokes a native shell tool (`bash`, `powershell`) or HTTP client *outside* a wrapped MCP server, GlassBox cannot intercept those syscalls. Always pair GlassBox with an OS-level sandbox (`bubblewrap`, macOS Seatbelt, or ephemeral containers) for unattended autonomous runs.
- **Covert Side Channels Inside an Allowed Tool**: If a benign-labeled local tool itself makes hidden outbound network calls inside its own process, an OS egress firewall is required to block it.
- **Heuristic Tool Classification**: Built-in regex classifiers cover common MCP naming conventions (`read_file`, `fetch_github_issue`, `http_post`, `sql_query`, etc.). For production deployments, supply an explicit custom JSON policy mapping your exact MCP server tool names.

## Reporting a Vulnerability
Please open a GitHub Security Advisory on the canonical repository rather than posting exploit payloads in public issues.
