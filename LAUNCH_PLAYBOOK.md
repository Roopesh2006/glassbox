# GlassBox — Viral Launch & Star-Velocity Playbook

This playbook is engineered from 2025–2026 empirical open-source launch benchmarks (GitHub Trending velocity mechanics, Hacker News Show HN timing, Reddit problem-framing conversion data, and X/Twitter demo video structure).

---

## 1. Pre-Flight Checklist (Do Before Going Public)

1. **Publish the repo cleanly** using `./push-to-github.sh` under a bare repo name (`<your-handle>/glassbox`, NOT `glassbox-mcp-firewall-tool`).
2. **Set all 20 GitHub Topics** on the repo settings page:
   `mcp`, `ai-agents`, `claude-code`, `cursor`, `security`, `prompt-injection`, `firewall`, `time-travel-debugging`, `developer-tools`, `python`, `zero-dependencies`, `json-rpc`, `merkle-tree`, `information-flow-control`, `llm-security`, `agent-harness`, `replay`, `cli`, `open-source`, `devtools`
3. **Record a 40-second demo video (MP4 + GIF)** using the script in Section 3 and embed the GIF right under the headline in `README.md`.
4. **Open 5 `good first issue` tickets** on GitHub (e.g., *Add SSE/Streamable-HTTP MCP transport*, *Add custom YAML policy support*, *Add VS Code / Windsurf config preset*, *Add SARIF export for CI*, *Add Slack/Discord webhook redaction pattern*).
5. **Upload a custom 1280×640 Social Preview image** in GitHub Settings → General → Social Preview (dark terminal showing `PRIVATE + UNTRUSTED -> SHADOW_SIMULATE [LETHAL_TRIFECTA]`).
6. **Never buy fake stars.** GitHub's StarScout enforcement flags inorganic bursts and destroys credibility permanently.

---

## 2. Coordinated 24-Hour Launch Window (GitHub Trending Mechanics)

GitHub Trending ranks by **short-window star velocity** (80+ stars in 24h can trigger daily Trending, which then compounds organically). Compress all channels into **one Tuesday, Wednesday, or Thursday** window:

| Time (US Eastern) | Channel | Action |
|---|---|---|
| **08:25 AM ET** | GitHub | Push final tag `v0.1.0` + GitHub Release with changelog and Verified Run snippet. |
| **08:30 AM ET** | **Hacker News (`Show HN`)** | Post direct GitHub URL (never a landing page). Stay in the thread answering technical questions for **3+ hours**. |
| **09:00 AM ET** | **X / Twitter** | Post native 40-second muted-friendly video (burned-in captions, NO logo intro) from your personal account. Put the GitHub link in the **first reply** (not the main tweet, to avoid link throttling). |
| **09:30 AM ET** | **Reddit** | Post problem-framed technical writeups (never "please upvote!") in `r/ClaudeCode`, `r/LocalLLaMA`, `r/programming`, and `r/selfhosted` (stagger by 20 min, tailor each post to the sub's norms). |
| **11:00 AM ET** | **LinkedIn / Dev.to / Discord** | Share the architecture diagram + `COMPARISONS.md` breakdown in MCP, Claude Code, and AI engineering Discords. |

---

## 3. Ready-to-Use 40-Second Demo Video Script (For X, Reddit, & README GIF)

*Rule: First 3 seconds must show the live product catching an attack — zero logo sting, zero "Hey guys". Burn in bold white captions.*

- **0:00–0:05 (Hook — live terminal split screen)**: Run `glassbox demo`. Show `#10 read_file (.env) -> [PRIVATE]`, `#11 fetch_github_issue -> [PRIVATE, UNTRUSTED]`, and `#12 http_post -> SHADOW_SIMULATE [LETHAL_TRIFECTA]` flashing amber in `0.04ms`.
  - *Caption:* "My coding agent just got prompt-injected by a GitHub issue. Watch GlassBox catch the .env exfiltration in 0.04ms—without a single approval prompt."
- **0:05–0:18 (The Pain & Mechanism)**: Show the 1-line JSON config wrapping `@modelcontextprotocol/server-github`.
  - *Caption:* "Benign local coding = 0 prompts. The instant private data + untrusted input meet an outbound tool, GlassBox downgrades it to SHADOW_SIMULATE and captures the attacker's payload."
- **0:18–0:32 (The 30-Second Wow — Web Flight Recorder)**: Switch to `http://127.0.0.1:8765` (`glassbox ui`). Click the Merkle Verified badge, click Step #12 to show the captured `STRIPE_SECRET` payload, then click **Run Offline Fork (strict)** and watch `SHADOW_SIMULATE -> BLOCK` flip in `1.2ms` at `$0.00`.
  - *Caption:* "Every run is Merkle-chained. Rewind any incident, swap policies, and prove the fix offline in 1ms at $0 cost."
- **0:32–0:40 (CTA)**: Show `pip install -e . && glassbox demo` + MIT license badge.
  - *Caption:* "Zero dependencies. Zero API keys. MIT open source. Link in reply."

---

## 4. Copy-Paste Launch Posts

### Hacker News (`Show HN`)
- **Title:** `Show HN: GlassBox – Zero-dependency MCP wire firewall and $0 offline time-travel debugger`
- **URL:** `https://github.com/<your-handle>/glassbox`
- **First Comment (post immediately after submitting):**
  > Hi HN — I built GlassBox after getting frustrated with two things when running Claude Code and Cursor with MCP servers:
  > 1. Static allowlists cause constant approval fatigue, yet still let the "Lethal Trifecta" (reading `.env` + reading an untrusted GitHub issue + calling an outbound MCP tool) sail right through because every individual tool is pre-approved.
  > 2. When an agent goes sideways 20 tool calls deep, there's no lightweight local way to replay and fork the session without burning tokens or re-executing side effects.
  >
  > GlassBox sits on the MCP stdio JSON-RPC 2.0 wire (`glassbox wrap -- <server_cmd>`). It uses zero external dependencies (pure Python 3.10+ stdlib), adds <1ms wire overhead, pins SHA-256 tool schemas on `tools/list` to catch mid-session rug-pulls, tracks a 3-bit `(PRIVATE, UNTRUSTED, EGRESS)` taint lattice, and records every frame into a SHA-256 Merkle-chained `.gbx` file. When the Lethal Trifecta trips, it dynamically downgrades the call to `SHADOW_SIMULATE`—returning a synthetic dry-run receipt to the agent while capturing the exfiltration payload forensically.
  >
  > You can test the whole thing offline with zero API keys via `glassbox demo` and `glassbox ui`.
  >
  > Honest limitation: it only sees wrapped MCP stdio traffic, not unwrapped native Bash/network side channels (pair it with Seatbelt/bubblewrap for OS-level isolation). Would love feedback on the taint lattice rules and what MCP transports (Streamable HTTP/SSE) to add next.

### Reddit (`r/ClaudeCode` / `r/LocalLLaMA`)
- **Title:** `I built a zero-dependency MCP wire proxy that stops prompt-injection exfiltration (Lethal Trifecta) without approval fatigue + lets you time-travel fork agent runs offline at $0`
- **Body:** Lead with the DuneSlide / GitHub MCP problem, paste the 6-line JSON wrap snippet, paste the real `glassbox demo` terminal output, state the honest boundary (MCP wire only), and ask which MCP servers people want pre-tuned taint rules for.

### X / Twitter Launch Post
- **Tweet 1 (with 40s native video):**
  > Static MCP allowlists are broken: they nag you on safe local edits, yet let prompt-injected agents exfiltrate `.env` using 100% pre-approved tools.
  >
  > So I open-sourced **GlassBox** — a zero-dependency MCP Flight Recorder & Dynamic Taint-Lattice Firewall.
  >
  > - 0 prompts on benign local coding (<1ms overhead)
  > - Auto-downgrades Lethal Trifecta calls to `SHADOW_SIMULATE`
  > - SHA-256 schema pinning catches mid-session rug-pulls
  > - Merkle-chained offline time-travel replay & policy forking at $0.00
  >
  > Try it in 30s with zero API keys (`glassbox demo`). MIT licensed.
- **Reply 1:** `GitHub repo: https://github.com/<your-handle>/glassbox`

---

## 5. Post-Launch Supply-Chain Hygiene
Viral AI repos attract typosquatted malware clones within days. Pin your official PyPI package name (`glassbox-mcp`), enable GitHub branch protection + signed release tags, and list the canonical repo URL prominently in `SECURITY.md`.
