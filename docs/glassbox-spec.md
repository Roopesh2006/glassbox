# GlassBox — Full Spec

## Executive Summary
GlassBox is a zero-dependency, wire-level MCP Flight Recorder and Dynamic Taint-Lattice Firewall for developers running local AI coding and autonomous agents (Claude Code, Cursor, Codex CLI, Windsurf, OpenClaw, Hermes). It wraps any stdio MCP server in one command (`glassbox wrap -- <cmd>`), deterministically intercepting Lethal Trifecta exfiltration (`PRIVATE ∧ UNTRUSTED → EGRESS`) via `SHADOW_SIMULATE` downgrade and SHA-256 schema pinning while recording a tamper-evident Merkle cassette (`.gbx`) for `<5ms` offline counterfactual time-travel forking at `$0.00` cost.

## Gap Evidence
- **[NEW] Unified Wire-Level IFC + Forensic Shadow-Capture + Offline Counterfactual Replay**:
  - `arXiv:2603.20847` (3,864 CLI agent bugs across Claude Code, Codex CLI, Gemini CLI): 62.6% of bugs occur in Tool/API Orchestration (37.6%) and Command Execution & Monitoring (25.0%); only 10% are model errors.
  - `arXiv:2606.08162v1` (40,000+ multi-agent trials): prompt-based "memory gates" decay from 94% to 61% adherence, requiring deterministic external "physical gates".
  - Real 2025–2026 incidents: DuneSlide (`CVE-2026-50548/50549`, CVSS 9.8), CurXecute (`CVE-2025-54135`), Plugin4Shell (Sep 2026), GitHub MCP Toxic Agent Flow (Invariant Labs), Replit production DB wipe (1,206 executives), and `arXiv:2611.11104v1` (87.5% of 24 validated MCP CVEs Critical/High).
  - Ecosystem gap: `Langfuse` (35k stars) provides OTel tracing with no deterministic replay or enforcement; `Reprise` (v0.1.0) lacks taint lattices and schema pinning; `Bifrost` and `Microsoft MCP Gateway` are Enterprise/K8s-gated and bypassed by local IDE stdio MCP servers; `APPA` (`arXiv:2607.24625v2`) is an academic online IFC architecture without Merkle-chained offline counterfactual forking.

## Core Thesis
GlassBox intercepts MCP JSON-RPC 2.0 stdio frames at the wire to enforce a dynamic 3-bit information-flow taint lattice `(PRIVATE, UNTRUSTED, EGRESS)` and SHA-256 tool-schema pins while appending every frame to a content-addressed Merkle cassette (`.gbx`) for instant `$0.00` offline time-travel forking.

## Personas / Stakeholders
| Persona | Pain Point | How This Solves It |
|---|---|---|
| Daily Coding-Agent Developer (Claude Code / Cursor / Codex) | Approval fatigue on safe local edits vs. fear of zero-click prompt injection exfiltrating `.env` or wiping prod DBs | 0 prompts on benign local coding; automatic `SHADOW_SIMULATE` / `BLOCK` when Lethal Trifecta or destructive SQL trips |
| Agent / Harness Engineer | Non-reproducible 20-step agent failures and expensive token burn when re-testing fixes | `<5ms` deterministic offline replay & counterfactual policy forking at `$0.00` cost |
| Security / DevSecOps Lead | Local IDE/CLI MCP servers bypass cloud gateways; rug-pull tool mutations (`MCPoison`) | Cryptographic SHA-256 schema pinning + tamper-evident Merkle audit trail verifiable in CI |

## Judge / Market Profile
- **Buyer / Adopter Profile**: 73% of developers using coding agents daily (Stack Overflow 2026; [survey.stackoverflow.co/2026/ai](https://survey.stackoverflow.co/2026/ai)).
- **Switching Trigger**: Zero-friction 1-line MCP JSON wrap (`glassbox wrap -- <cmd>`) + keyless 30-second demo (`glassbox demo`) + zero external dependencies (no Docker, ClickHouse, or API keys).
- **Distribution Path**: Open-source MIT GitHub launch (Show HN Tue–Thu 8:30 AM ET, X 40-second demo video, problem-framed Reddit posts in `r/ClaudeCode`, `r/LocalLLaMA`, `r/programming`), followed by PyPI `glassbox-mcp` adoption and team CI policy enforcement.

## Product Completeness Map
| Feature | Status | Note |
|---|---|---|
| Stdio JSON-RPC 2.0 MCP Wire Proxy (`wrap`) | INCLUDE-MVP | Transparently wraps any stdio MCP server |
| 3-Bit Dynamic Taint Lattice (`balanced`/`strict`/`audit` + JSON) | INCLUDE-MVP | `PRIVATE`, `UNTRUSTED`, `EGRESS_ATTEMPTED` |
| Forensic `SHADOW_SIMULATE` Downgrade | INCLUDE-MVP | Suppresses real side effect; captures attacker args |
| SHA-256 Tool-Schema Pinning (Anti-Rug-Pull) | INCLUDE-MVP | Detects mid-session `tools/list` mutation |
| Merkle-Chained `.gbx` Ledger & `verify` | INCLUDE-MVP | Tamper-evident SHA-256 chain |
| Offline Time-Travel `replay` & `fork` | INCLUDE-MVP | `<5ms` counterfactual policy re-simulation at `$0` |
| Interactive Local Web Flight Recorder (`ui`) | INCLUDE-MVP | Zero-dependency `http.server` SPA |
| 30-Second Keyless Live Demo (`demo` + `demo-data/`) | INCLUDE-MVP | 3 realistic pre-recorded incident cassettes + live attack run |
| Drop-In Config Generator (`config`) | INCLUDE-MVP | Generates JSON for Claude Code, Cursor, Codex, OpenClaw |
| Streamable HTTP / SSE MCP Transport | INCLUDE-V2 | Planned good-first-issue post-v0.1.0 |
| SARIF CI Export | INCLUDE-V2 | Planned post-v0.1.0 |
| Cloud SaaS Dashboard / Auth / Billing | EXCLUDE | Local-first CLI substrate (`PROJECT_TYPE = cli`) |

## Build Mode Decisions
| Feature | Mode | Tool | Reason |
|---|---|---|---|
| MCP Wire Proxy, Taint Lattice, Merkle Ledger, CLI, Web UI | SCRATCH | Python 3.10+ stdlib | Zero external dependencies is a core viral adoption moat (<1ms wire latency, zero install friction) |
| CI Pipeline | PLATFORM | GitHub Actions | Standard OSS verification across Python 3.10–3.12 |

## Demo Reliability Map
| Integration | Rating | Fallback | Fallback Data Location |
|---|---|---|---|
| Local stdio MCP subprocess (`demo-server`) | 🟢 | Built-in pure-Python server, zero network | `src/glassbox/demo_server.py` |
| Pre-recorded Incident Cassettes | 🟢 | 3 Merkle-verified `.gbx` files bundled | `demo-data/*.gbx` |
| Interactive Web Flight Recorder UI | 🟢 | Pure stdlib `ThreadingHTTPServer`, offline localhost | `src/glassbox/ui.py` |

**Demo offline rule:** 100% of `glassbox demo`, `glassbox ui`, `glassbox replay`, `glassbox fork`, `glassbox verify`, and `unittest` run completely offline with zero API keys.

## Technical Architecture
- **Runtime**: Python 3.10+ standard library only (`subprocess`, `json`, `hashlib`, `http.server`, `argparse`, `re`, `dataclasses`).
- **Data Flow**: `MCP Client (Claude Code / Cursor / Codex)` ↔ `stdio JSON-RPC 2.0` ↔ `GlassBox Wire Proxy (Schema Pinning + TaintLattice + MerkleLedger)` ↔ `Downstream MCP Server`.
- **Storage**: Local append-only JSONL `.gbx` cassettes (`.glassbox/traces/*.gbx` and `demo-data/*.gbx`).

## Free Stack Cost Table
| Tool | Category | Free Tier Limit | Overage | Rating |
|---|---|---|---|---|
| Python 3.10+ Stdlib | Runtime | Unlimited (local) | $0 | 🟢 |
| GitHub + GitHub Actions | Hosting & CI | Unlimited public repos | $0 | 🟢 |
**Estimated demo-day cost: $0**

## Open Source Repos / Prior Work
| Repo | URL | Replaces | Hours Saved | Complexity | License |
|---|---|---|---|---|---|
| `langfuse/langfuse` | https://github.com/langfuse/langfuse | Cloud OTel LLM tracing (not local replay/firewall) | — | 4 | MIT / EE |
| `itsshreyasbhardwaj-design/reprise` | https://github.com/itsshreyasbhardwaj-design/reprise | Basic local MCP record/replay (no taint lattice) | — | 2 | MIT |
| `maximhq/bifrost` | https://github.com/maximhq/bifrost | Cloud MCP gateway (enterprise-gated guardrails) | — | 4 | Apache-2.0 / EE |
| `microsoft/mcp-gateway` | https://github.com/microsoft/mcp-gateway | Kubernetes/Entra ID MCP proxy | — | 4 | MIT |
| `elsium-ai/elsium-ai` | https://github.com/elsium-ai/elsium-ai | Full TS runtime with provenance labels | — | 3 | MIT |

## Competitive Moat
Single zero-dependency stdio wire shim unifying **dynamic taint-lattice `SHADOW_SIMULATE` forensic interception**, **SHA-256 tool-schema pinning**, and **Merkle-chained `<5ms` offline counterfactual policy forking**—dropping into any existing MCP client in 1 line without adopting a new agent framework or deploying Docker/ClickHouse/Kubernetes.

## 30-Second Wow Moment
Running `glassbox demo` (zero keys) and watching a live wrapped MCP agent execute 3 benign coding calls with 0 prompts, then get prompt-injected by a GitHub issue to exfiltrate `.env`—intercepted in `0.04ms` via `SHADOW_SIMULATE`—followed immediately by an offline `strict` policy fork flipping the outcome in `1.2ms` at `$0.00`, then clicking through the Merkle-verified timeline in `glassbox ui`.

## Post-Deadline Plan
Ship v0.1.0 via the coordinated 24-hour launch in `LAUNCH_PLAYBOOK.md`, publish `glassbox-mcp` to PyPI, and accept community PRs for Streamable HTTP/SSE MCP transport, SARIF CI export, and official server policy packs.

## Pitch Notes
- **Boring baseline**: Another LLM wrapper or prompt-based guardrail library that calls an LLM judge on every tool call (adding 500ms+ latency and token cost) or a CRUD trace viewer requiring Docker + Postgres.
- **Differentiator**: Deterministic `<1ms` wire-level information-flow taint lattice + SHA-256 schema pinning + Merkle-chained offline counterfactual replay in zero-dependency Python stdlib.
