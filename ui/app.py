import os
import json
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

DEFAULT_LOG_PATH = os.path.join("logs", "events.jsonl")

HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Process Sentinel</title>
  <style>
    body { font-family: Arial, Helvetica, sans-serif; background:#f5f7fb; margin:0; }
    .topbar { background:#0f172a; color:#fff; padding:16px 20px; display:flex; justify-content:space-between; align-items:center; }
    .pill { background:#10b981; color:#fff; padding:6px 12px; border-radius:999px; font-weight:700; font-size:12px; }
    .container { padding:20px; max-width:1200px; margin:0 auto; }
    .card { background:#fff; border-radius:12px; padding:16px; box-shadow: 0 1px 2px rgba(0,0,0,.06); margin-bottom:16px; }
    .row { display:flex; gap:16px; flex-wrap:wrap; }
    .kpi { flex:1; min-width:220px; }
    .kpi .label { color:#64748b; font-size:12px; }
    .kpi .value { font-size:28px; font-weight:800; margin-top:6px; color:#0f172a; }
    table { width:100%; border-collapse:collapse; }
    th { text-align:left; color:#64748b; font-size:12px; padding:10px 8px; border-bottom:1px solid #e2e8f0; }
    td { padding:10px 8px; border-bottom:1px solid #eef2f7; color:#0f172a; font-size:13px; vertical-align:top; }
    .sev { display:inline-block; padding:4px 10px; border-radius:999px; font-weight:800; font-size:12px; color:#fff; }
    .sev-high { background:#ef4444; }
    .sev-medium { background:#f59e0b; }
    .sev-low { background:#10b981; }
    .muted { color:#475569; }
    .toolbar { display:flex; gap:10px; align-items:center; justify-content:space-between; flex-wrap:wrap; }
    .btn { background:#2563eb; color:#fff; border:none; padding:8px 12px; border-radius:8px; font-weight:700; cursor:pointer; }
    .btn.secondary { background:#0ea5e9; }
    .small { font-size:12px; color:#64748b; }
    input[type="text"] { padding:8px 10px; border-radius:8px; border:1px solid #e2e8f0; min-width:260px; }
    code { font-size:12px; }
  </style>
</head>
<body>
  <div class="topbar">
    <div style="font-size:18px; font-weight:800;">Process Sentinel</div>
    <div class="pill" id="statusPill">Running</div>
  </div>

  <div class="container">
    <div class="card">
      <div class="toolbar">
        <div>
          <div style="font-size:18px; font-weight:800; color:#0f172a;">Dashboard</div>
          <div class="small">Log source: <code>{{ log_path }}</code></div>
        </div>
        <div style="display:flex; gap:10px; align-items:center;">
          <input id="search" type="text" placeholder="Search process, rule, or cmdline">
          <button class="btn secondary" onclick="refresh()">Refresh</button>
          <button class="btn" onclick="toggleAuto()"><span id="autoLabel">Auto: Off</span></button>
        </div>
      </div>
    </div>

    <div class="row">
      <div class="card kpi">
        <div class="label">Detections (last {{ limit }})</div>
        <div class="value" id="kpiDetections">0</div>
      </div>
      <div class="card kpi">
        <div class="label">High severity</div>
        <div class="value" id="kpiHigh">0</div>
      </div>
      <div class="card kpi">
        <div class="label">Last update</div>
        <div class="value" style="font-size:18px;" id="kpiUpdated">-</div>
      </div>
    </div>

    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <div style="font-size:16px; font-weight:800;">Recent Alerts</div>
        <div class="small" id="countLabel"></div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Time (UTC)</th>
            <th>Process</th>
            <th>Rule</th>
            <th>Severity</th>
            <th>Parent</th>
            <th>User</th>
            <th>Cmdline</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>

<script>
let auto = false;
let timer = null;

function sevClass(sev) {
  sev = (sev || "").toLowerCase();
  if (sev === "high") return "sev sev-high";
  if (sev === "medium") return "sev sev-medium";
  return "sev sev-low";
}

function escapeHtml(s) {
  if (!s) return "";
  return s.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;");
}

async function refresh() {
  const q = document.getElementById("search").value || "";
  const res = await fetch(`/api/alerts?limit={{ limit }}&q=` + encodeURIComponent(q));
  const data = await res.json();

  const alerts = data.alerts || [];
  document.getElementById("kpiDetections").textContent = alerts.length.toString();

  let high = 0;
  for (const a of alerts) if ((a.severity || "").toLowerCase() === "high") high++;
  document.getElementById("kpiHigh").textContent = high.toString();

  document.getElementById("kpiUpdated").textContent = new Date().toISOString().slice(0,19).replace("T"," ");
  document.getElementById("countLabel").textContent = `Showing ${alerts.length} alerts`;

  const tbody = document.getElementById("tbody");
  tbody.innerHTML = "";

  for (const a of alerts) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="muted">${escapeHtml(a.ts || "")}</td>
      <td><b>${escapeHtml(a.name || "")}</b><div class="small">PID ${escapeHtml(String(a.pid ?? ""))}</div></td>
      <td><b>${escapeHtml(a.rule_id || "")}</b><div class="small">${escapeHtml(a.rule_description || "")}</div></td>
      <td><span class="${sevClass(a.severity)}">${escapeHtml((a.severity || "low").toUpperCase())}</span></td>
      <td>${escapeHtml(a.parent_name || "")}</td>
      <td>${escapeHtml(a.username || "")}</td>
      <td><code>${escapeHtml(a.cmdline || "")}</code></td>
    `;
    tbody.appendChild(tr);
  }
}

function toggleAuto() {
  auto = !auto;
  document.getElementById("autoLabel").textContent = auto ? "Auto: On" : "Auto: Off";
  if (auto) {
    refresh();
    timer = setInterval(refresh, 2000);
  } else {
    if (timer) clearInterval(timer);
    timer = null;
  }
}

document.getElementById("search").addEventListener("keydown", (e) => {
  if (e.key === "Enter") refresh();
});

refresh();
</script>
</body>
</html>
"""

def read_jsonl_tail(path: str, max_lines: int = 5000):
    """
    Reads up to max_lines lines from the end of a JSONL file.
    Simple approach: read whole file if small, otherwise read last chunk.
    """
    if not os.path.exists(path):
        return []

    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            # Read last ~1MB (enough for thousands of lines usually)
            chunk = 1024 * 1024
            start = max(0, size - chunk)
            f.seek(start)
            data = f.read().decode("utf-8", errors="ignore")
    except Exception:
        return []

    lines = [ln for ln in data.splitlines() if ln.strip()]
    lines = lines[-max_lines:]
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    return out

def load_alerts(log_path: str, limit: int, q: str = ""):
    events = read_jsonl_tail(log_path)
    alerts = [e for e in events if e.get("type") == "detection"]

    # Newest first
    alerts.sort(key=lambda x: x.get("ts", ""), reverse=True)

    if q:
        qq = q.lower()
        def matches(a):
            hay = " ".join([
                str(a.get("name", "")),
                str(a.get("rule_id", "")),
                str(a.get("rule_description", "")),
                str(a.get("cmdline", "")),
                str(a.get("parent_name", "")),
                str(a.get("username", "")),
            ]).lower()
            return qq in hay
        alerts = [a for a in alerts if matches(a)]

    return alerts[:limit]

@app.get("/")
def index():
    log_path = request.args.get("log", DEFAULT_LOG_PATH)
    limit = int(request.args.get("limit", "50"))
    return render_template_string(HTML, log_path=log_path, limit=limit)

@app.get("/api/alerts")
def api_alerts():
    log_path = request.args.get("log", DEFAULT_LOG_PATH)
    limit = int(request.args.get("limit", "50"))
    q = request.args.get("q", "")
    alerts = load_alerts(log_path, limit, q)

    # Keep response small and predictable
    trimmed = []
    for a in alerts:
        trimmed.append({
            "ts": a.get("ts", ""),
            "rule_id": a.get("rule_id", ""),
            "rule_description": a.get("rule_description", ""),
            "severity": a.get("severity", ""),
            "pid": a.get("pid", ""),
            "name": a.get("name", ""),
            "parent_name": a.get("parent_name", ""),
            "username": a.get("username", ""),
            "cmdline": a.get("cmdline", ""),
        })

    return jsonify({"alerts": trimmed, "count": len(trimmed), "log_path": log_path})

if __name__ == "__main__":
    # Use 127.0.0.1 for local-only
    app.run(host="127.0.0.1", port=5000, debug=True)
