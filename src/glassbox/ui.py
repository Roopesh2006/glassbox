"""Zero-dependency Interactive Local Web Flight Recorder UI (`glassbox ui`).

Serves a self-contained single-page application using Python's built-in `http.server`
that lets developers visually inspect Merkle-verified `.gbx` flight cassettes, view
live 3-bit taint-lattice transitions, examine captured exfiltration payloads, run
one-click counterfactual policy forks, and copy 1-line MCP wrapper configs.
"""

from __future__ import annotations

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from glassbox.ledger import counterfactual_fork, load_cassette, verify_cassette

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>GlassBox — MCP Flight Recorder &amp; Taint Firewall</title>
<style>
  :root {
    --bg: #0b0f17;
    --panel: #111827;
    --panel-2: #161f33;
    --border: #24304a;
    --text: #e5edf9;
    --muted: #8ea0bf;
    --accent: #38bdf8;
    --green: #22c55e;
    --amber: #f59e0b;
    --red: #ef4444;
    --purple: #a855f7;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: var(--sans); background: var(--bg); color: var(--text);
    line-height: 1.5;
  }
  header {
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
    padding: 16px 24px; border-bottom: 1px solid var(--border); background: #0e1422;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .logo {
    width: 34px; height: 34px; border-radius: 8px;
    background: linear-gradient(135deg, #0ea5e9, #a855f7);
    display: grid; place-items: center; font-weight: 800; color: #fff; font-family: var(--mono);
  }
  .brand h1 { margin: 0; font-size: 18px; letter-spacing: -0.02em; }
  .brand span { color: var(--muted); font-size: 12px; display: block; }
  .controls { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  select, button {
    background: var(--panel-2); color: var(--text); border: 1px solid var(--border);
    border-radius: 8px; padding: 8px 12px; font-size: 13px; cursor: pointer;
  }
  button.primary { background: #0284c7; border-color: #38bdf8; font-weight: 600; }
  button.primary:hover { background: #0369a1; }
  .badge {
    display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px;
    border-radius: 999px; font-size: 12px; font-weight: 600; font-family: var(--mono);
  }
  .badge.ok { background: rgba(34,197,94,0.14); color: #4ade80; border: 1px solid rgba(34,197,94,0.35); }
  .badge.fail { background: rgba(239,68,68,0.14); color: #f87171; border: 1px solid rgba(239,68,68,0.35); }
  .badge.shadow { background: rgba(245,158,11,0.16); color: #fbbf24; border: 1px solid rgba(245,158,11,0.38); }
  .badge.taint { background: rgba(168,85,247,0.16); color: #d8b4fe; border: 1px solid rgba(168,85,247,0.35); }
  main {
    max-width: 1280px; margin: 0 auto; padding: 20px 24px;
    display: grid; grid-template-columns: 1.35fr 1fr; gap: 20px;
  }
  @media (max-width: 960px) { main { grid-template-columns: 1fr; } }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 18px;
  }
  .card h2 {
    margin: 0 0 12px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--muted); display: flex; justify-content: space-between; align-items: center;
  }
  .kpi-row {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px;
  }
  @media (max-width: 640px) { .kpi-row { grid-template-columns: repeat(2, 1fr); } }
  .kpi {
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 10px; padding: 12px;
  }
  .kpi .label { font-size: 11px; color: var(--muted); text-transform: uppercase; }
  .kpi .val { font-size: 20px; font-weight: 700; margin-top: 4px; font-family: var(--mono); }
  .step-item {
    border: 1px solid var(--border); background: var(--panel-2); border-radius: 10px;
    padding: 12px 14px; margin-bottom: 10px; cursor: pointer; transition: border-color .15s;
  }
  .step-item:hover, .step-item.active { border-color: var(--accent); }
  .step-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
  .step-title { font-family: var(--mono); font-weight: 700; font-size: 13px; }
  .step-meta { font-size: 12px; color: var(--muted); margin-top: 6px; }
  pre {
    background: #070b12; border: 1px solid var(--border); border-radius: 8px;
    padding: 12px; overflow-x: auto; font-family: var(--mono); font-size: 12px; color: #cbd5e1;
    max-height: 280px;
  }
  .fork-bar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: var(--mono); }
  th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; }
  .changed { background: rgba(56,189,248,0.12); }
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo">GB</div>
    <div>
      <h1>GlassBox Flight Recorder</h1>
      <span>Wire-level MCP Taint-Lattice Firewall &amp; Deterministic Time-Travel Debugger</span>
    </div>
  </div>
  <div class="controls">
    <select id="cassetteSelect"></select>
    <span id="merkleBadge" class="badge ok">VERIFYING...</span>
  </div>
</header>

<main>
  <section class="card">
    <h2>
      <span>Execution Timeline</span>
      <span id="merkleRoot" style="font-family:var(--mono);font-size:11px;color:#64748b;"></span>
    </h2>
    <div class="kpi-row">
      <div class="kpi"><div class="label">Steps</div><div class="val" id="kpiSteps">-</div></div>
      <div class="kpi"><div class="label">Intercepted</div><div class="val" id="kpiBlocked">-</div></div>
      <div class="kpi"><div class="label">Max Risk</div><div class="val" id="kpiRisk">-</div></div>
      <div class="kpi"><div class="label">Replay Cost</div><div class="val" style="color:#4ade80">$0.00</div></div>
    </div>
    <div id="timeline"></div>
  </section>

  <aside style="display:flex;flex-direction:column;gap:20px;">
    <section class="card">
      <h2><span>Forensic Step Inspector</span><span id="stepHash" style="font-family:var(--mono);font-size:11px;"></span></h2>
      <div id="inspectorEmpty" style="color:var(--muted);font-size:13px;">Select any step to inspect arguments, schema pin, taint state, and captured response.</div>
      <div id="inspectorBody" style="display:none;">
        <div id="inspectorSummary" style="margin-bottom:10px;font-size:13px;"></div>
        <div style="font-size:11px;color:var(--muted);margin-bottom:4px;">ARGUMENTS</div>
        <pre id="inspectorArgs"></pre>
        <div style="font-size:11px;color:var(--muted);margin:10px 0 4px;">RESPONSE / INTERCEPT RECEIPT</div>
        <pre id="inspectorResp"></pre>
      </div>
    </section>

    <section class="card">
      <h2><span>Counterfactual Time-Travel Fork</span><span id="forkSpeed" style="font-family:var(--mono);font-size:11px;color:#4ade80;"></span></h2>
      <div class="fork-bar">
        <label style="font-size:12px;color:var(--muted);">Fork at step:</label>
        <select id="forkStep"></select>
        <label style="font-size:12px;color:var(--muted);">Policy:</label>
        <select id="forkPolicy">
          <option value="strict">strict (BLOCK)</option>
          <option value="balanced">balanced (SHADOW_SIMULATE)</option>
          <option value="audit">audit (ALLOW / observe)</option>
        </select>
        <button class="primary" id="runForkBtn">Run Offline Fork</button>
      </div>
      <div id="forkOutput" style="font-size:12px;color:var(--muted);">Click "Run Offline Fork" to deterministically re-simulate the trace under another policy at $0.00 cost.</div>
    </section>

    <section class="card">
      <h2><span>1-Line MCP Config Generator</span></h2>
      <pre id="mcpConfig">{
  "mcpServers": {
    "github-guarded": {
      "command": "glassbox",
      "args": ["wrap", "--policy", "balanced", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}</pre>
    </section>
  </aside>
</main>

<script>
let currentEntries = [];
let currentName = "";

function actionBadge(action) {
  if (action === "ALLOW") return '<span class="badge ok">ALLOW</span>';
  if (action === "SHADOW_SIMULATE") return '<span class="badge shadow">SHADOW_SIMULATE</span>';
  return '<span class="badge fail">' + action + '</span>';
}

async function loadList() {
  const res = await fetch("/api/cassettes");
  const data = await res.json();
  const sel = document.getElementById("cassetteSelect");
  sel.innerHTML = "";
  for (const item of data.cassettes) {
    const opt = document.createElement("option");
    opt.value = item.name;
    opt.textContent = item.name + " (" + item.steps + " steps)";
    sel.appendChild(opt);
  }
  if (data.cassettes.length > 0) {
    await loadCassette(data.cassettes[0].name);
  }
}

async function loadCassette(name) {
  currentName = name;
  const res = await fetch("/api/cassette?name=" + encodeURIComponent(name));
  const data = await res.json();
  currentEntries = data.entries;

  const badge = document.getElementById("merkleBadge");
  if (data.verification.valid) {
    badge.className = "badge ok";
    badge.textContent = "MERKLE VERIFIED (" + data.verification.total_steps + " frames)";
  } else {
    badge.className = "badge fail";
    badge.textContent = "TAMPER DETECTED @ STEP " + data.verification.broken_at_step;
  }
  document.getElementById("merkleRoot").textContent = "root: " + data.verification.merkle_root.slice(0, 16) + "...";

  const intercepted = currentEntries.filter(e => e.action === "BLOCK" || e.action === "SHADOW_SIMULATE").length;
  const maxRisk = Math.max(0, ...currentEntries.map(e => e.risk_score || 0));
  document.getElementById("kpiSteps").textContent = currentEntries.length;
  document.getElementById("kpiBlocked").textContent = intercepted;
  document.getElementById("kpiRisk").textContent = maxRisk + "/100";

  const tl = document.getElementById("timeline");
  const forkSel = document.getElementById("forkStep");
  tl.innerHTML = "";
  forkSel.innerHTML = "";

  currentEntries.forEach((e, idx) => {
    const opt = document.createElement("option");
    opt.value = e.step;
    opt.textContent = "Step " + e.step + " (" + e.tool_name + ")";
    forkSel.appendChild(opt);

    const div = document.createElement("div");
    div.className = "step-item" + (idx === currentEntries.length - 1 ? " active" : "");
    const taints = (e.taint_after || []).map(t => '<span class="badge taint">' + t + '</span>').join(" ");
    div.innerHTML = `
      <div class="step-head">
        <span class="step-title">#${e.step} · ${e.tool_name} <span style="color:var(--muted);font-weight:400">[${e.event_type}]</span></span>
        <div>${actionBadge(e.action)}</div>
      </div>
      <div class="step-meta">${e.reason}</div>
      <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
        ${taints || '<span style="font-size:11px;color:#64748b;">taint: CLEAN</span>'}
        <span style="margin-left:auto;font-family:var(--mono);font-size:11px;color:#64748b;">${e.latency_ms}ms · risk ${e.risk_score}</span>
      </div>
    `;
    div.onclick = () => {
      document.querySelectorAll(".step-item").forEach(el => el.classList.remove("active"));
      div.classList.add("active");
      showInspector(e);
    };
    tl.appendChild(div);
  });

  if (currentEntries.length > 0) {
    showInspector(currentEntries[currentEntries.length - 1]);
  }
  document.getElementById("forkOutput").innerHTML = 'Click "Run Offline Fork" to deterministically re-simulate the trace under another policy at $0.00 cost.';
  document.getElementById("forkSpeed").textContent = "";
}

function showInspector(e) {
  document.getElementById("inspectorEmpty").style.display = "none";
  document.getElementById("inspectorBody").style.display = "block";
  document.getElementById("stepHash").textContent = "sha256:" + e.entry_hash.slice(0, 12);
  document.getElementById("inspectorSummary").innerHTML =
    actionBadge(e.action) + ' <strong style="margin-left:6px;">' + e.rule_triggered + '</strong><div style="margin-top:6px;color:var(--muted);">' + e.reason + '</div>';
  document.getElementById("inspectorArgs").textContent = JSON.stringify(e.arguments, null, 2);
  document.getElementById("inspectorResp").textContent = JSON.stringify(e.response, null, 2);
}

async function runFork() {
  const step = document.getElementById("forkStep").value;
  const policy = document.getElementById("forkPolicy").value;
  const res = await fetch(`/api/fork?name=${encodeURIComponent(currentName)}&at_step=${step}&policy=${encodeURIComponent(policy)}`);
  const data = await res.json();
  document.getElementById("forkSpeed").textContent = `${data.elapsed_ms}ms · $0.00`;
  let rows = data.diffs.map(d => `
    <tr class="${d.changed ? 'changed' : ''}">
      <td>#${d.step}</td>
      <td>${d.tool_name}</td>
      <td>${d.original_action}</td>
      <td>${d.counterfactual_action}</td>
      <td>${d.changed ? 'FLIPPED' : 'same'}</td>
    </tr>
  `).join("");
  document.getElementById("forkOutput").innerHTML = `
    <div style="margin-bottom:8px;font-family:var(--mono);font-size:11px;color:#94a3b8;">
      Prefix hashes identical: <strong>${data.prefix_hashes_identical}</strong> · New Merkle root: ${data.forked_merkle_root.slice(0,14)}...
    </div>
    <table>
      <thead><tr><th>Step</th><th>Tool</th><th>Original</th><th>Counterfactual</th><th>Delta</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

document.getElementById("cassetteSelect").onchange = (e) => loadCassette(e.target.value);
document.getElementById("runForkBtn").onclick = runFork;
loadList();
</script>
</body>
</html>
"""


def discover_cassettes(search_dirs: list[Path]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for d in search_dirs:
        if not d.exists():
            continue
        for p in sorted(d.glob("*.gbx")):
            found[p.name] = p
    return found


def make_handler(search_dirs: list[Path]) -> type[BaseHTTPRequestHandler]:
    class GlassBoxHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, obj: Any, status: int = 200) -> None:
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            cassettes = discover_cassettes(search_dirs)

            if parsed.path in ("/", "/index.html"):
                body = HTML_PAGE.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed.path == "/api/cassettes":
                items = []
                for name, p in cassettes.items():
                    entries = load_cassette(p)
                    items.append({"name": name, "path": str(p), "steps": len(entries)})
                self._send_json({"cassettes": items})
                return

            if parsed.path == "/api/cassette":
                name = qs.get("name", [""])[0]
                if name not in cassettes:
                    self._send_json({"error": f"Cassette '{name}' not found"}, status=404)
                    return
                p = cassettes[name]
                entries = [e.to_dict() for e in load_cassette(p)]
                ver = verify_cassette(p)
                self._send_json(
                    {
                        "name": name,
                        "entries": entries,
                        "verification": {
                            "valid": ver.valid,
                            "total_steps": ver.total_steps,
                            "merkle_root": ver.merkle_root,
                            "broken_at_step": ver.broken_at_step,
                            "error": ver.error,
                        },
                    }
                )
                return

            if parsed.path == "/api/fork":
                name = qs.get("name", [""])[0]
                if name not in cassettes:
                    self._send_json({"error": f"Cassette '{name}' not found"}, status=404)
                    return
                at_step = int(qs.get("at_step", ["1"])[0])
                policy = qs.get("policy", ["strict"])[0]
                res = counterfactual_fork(cassettes[name], at_step=at_step, policy_name=policy)
                self._send_json(
                    {
                        "source_path": res.source_path,
                        "fork_step": res.fork_step,
                        "policy_name": res.policy_name,
                        "elapsed_ms": res.elapsed_ms,
                        "original_merkle_root": res.original_merkle_root,
                        "forked_merkle_root": res.forked_merkle_root,
                        "prefix_hashes_identical": res.prefix_hashes_identical,
                        "diffs": [
                            {
                                "step": d.step,
                                "tool_name": d.tool_name,
                                "original_action": d.original_action,
                                "counterfactual_action": d.counterfactual_action,
                                "original_rule": d.original_rule,
                                "counterfactual_rule": d.counterfactual_rule,
                                "changed": d.changed,
                                "taint_after": d.taint_after,
                                "reason": d.reason,
                            }
                            for d in res.diffs
                        ],
                    }
                )
                return

            self._send_json({"error": "Not found"}, status=404)

    return GlassBoxHandler


def serve_ui(host: str = "127.0.0.1", port: int = 8765, search_dirs: list[Path] | None = None) -> int:
    dirs = search_dirs or [Path("demo-data"), Path(".glassbox/traces")]
    server = ThreadingHTTPServer((host, port), make_handler(dirs))
    print(f"GlassBox Flight Recorder UI running at http://{host}:{port}")
    print(f"Watching cassettes in: {', '.join(str(d) for d in dirs)}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
