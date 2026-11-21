# How GlassBox Compares to Existing Tools (2026)

| Tool | Primary Focus | Zero-Dependency Local Stdio MCP Wrap? | Dynamic Lethal-Trifecta Taint Lattice? | Shadow-Simulate Forensic Capture? | SHA-256 Schema Rug-Pull Pinning? | Offline $0 Counterfactual Time-Travel Fork? | Infrastructure Required |
|---|---|---|---|---|---|---|---|
| **GlassBox** | Wire-level MCP Firewall + Flight Recorder | **Yes** (`glassbox wrap -- <cmd>`) | **Yes** (`PRIVATE ∧ UNTRUSTED -> EGRESS`) | **Yes** | **Yes** | **Yes** (`<5ms`, Merkle-verified) | **None** (Python 3.10+ stdlib) |
| **Claude Code OS Sandbox** | Bash process/network isolation (Seatbelt / `bubblewrap`) | No (wraps Bash only; MCP servers & hooks run outside) | No | No | No | No (file checkpoints only) | macOS / Linux |
| **Langfuse** | OpenTelemetry LLM tracing & evals | No | No | No | No | No | Postgres + ClickHouse + Redis |
| **Reprise / OrcaReplay** | MCP / agent trace record & replay | Partial (early beta) | No | No | No | Partial (no policy lattice) | Local runtime |
| **Bifrost / MS MCP Gateway** | Enterprise cloud MCP routing & RBAC | No (cloud/K8s gateways bypassed by local IDE stdio servers) | Enterprise / partial | No | Partial | No | Kubernetes / Entra ID / Enterprise license |
| **APPA** (`arXiv:2607.24625v2`) | Academic recoverable IFC reference monitor | Research prototype | Yes | No (abort + online LLM recovery) | No | No | Research harness |

## When to Stack GlassBox With Other Tools
- **Pair with OS Sandboxing (`bubblewrap` / Seatbelt / Docker)**: GlassBox guards the **MCP JSON-RPC wire**; OS sandboxes guard raw Bash/filesystem/network syscalls outside MCP.
- **Pair with Langfuse / OpenTelemetry**: Use Langfuse for cloud-scale prompt analytics and evals; use GlassBox locally and in CI for deterministic zero-cost replay and Lethal Trifecta enforcement.
