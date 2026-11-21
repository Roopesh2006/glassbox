# Contradictions & Failure Log

## 2026-11-21 — AI Agent Harnesses & Local MCP Runtime Substrates — Static Allowlist / OS-Only Sandbox Approach
- **Claim attempted:** Wrapping coding agents in static per-tool JSON allowlists or Bash-only OS sandboxes prevents destructive actions and prompt-injection exfiltration.
- **Killed by:** Phase 0 Operational Reality + Axiom Stress Test (Falsification & Scale).
- **Exact reason:** DuneSlide (`CVE-2026-50548/50549`) and GitHub MCP Toxic Agent Flow both succeeded using 100% legitimate, pre-approved tools; Anthropic's `@anthropic-ai/sandbox-runtime` wraps Bash only and leaves MCP servers/hooks outside; static ask-on-write triggers approval fatigue at 50–150 tool calls/session.
- **Redirect:** Shift from static per-tool grants to dynamic session-level Information-Flow Control (`PRIVATE ∧ UNTRUSTED → EGRESS` lattice downgrade) at the MCP JSON-RPC wire layer.

## 2026-11-21 — AI Agent Harnesses & Local MCP Runtime Substrates — Pure Record/Replay Without IFC or Schema Pinning
- **Claim attempted:** Building a standalone MCP trace recorder/replayer (like `Reprise`) as the primary viral open-source wedge.
- **Killed by:** Phase 4 Round 1 (Move 3 — Adjacent-field import / Prior art).
- **Exact reason:** `Reprise` and `OrcaReplay` already exist for basic record/replay, and pure observability alone lacks the immediate, hair-on-fire security wedge (Lethal Trifecta & MCPoison rug-pulls) driving developer urgency in late 2026.
- **Redirect:** Unify dynamic taint-lattice `SHADOW_SIMULATE` enforcement, SHA-256 tool-schema pinning, and Merkle-chained deterministic time-travel/counterfactual forking into one zero-dependency stdio MCP wire shim (`GlassBox`).
