"""Report rendering: text, JSON, and the React HTML dashboard."""

import html as html_lib
import json
from datetime import datetime, timezone

from .rules import RULES, RULE_BY_ID

SEV_COLORS = {
    "critical": "#F43F5E",
    "high": "#FB923C",
    "medium": "#FACC15",
    "low": "#38BDF8",
}


def build_payload(result, scored):
    by_rule = scored.get("by_rule", {})
    rules = {}
    for rule in RULES:
        rid = rule["id"]
        rules[rid] = {
            "id": rid,
            "name": rule["name"],
            "severity": rule["severity"],
            "description": rule["description"],
            "remediation": rule["remediation"],
            "fired": rid in by_rule,
            "count": by_rule.get(rid, 0),
        }
    return {
        "product": "MCP Warden",
        "target": result.target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": scored["score"],
        "grade": scored["grade"],
        "deductions": scored["deductions"],
        "weights": scored["weights"],
        "files_scanned": result.files_scanned,
        "files_skipped": result.skipped_files,
        "tools": result.tools,
        "by_severity": scored["by_severity"],
        "by_rule": by_rule,
        "rules": rules,
        "findings": [f.to_dict() for f in result.findings],
        "probe": result.probe or {},
    }


def render_text(payload):
    lines = []
    lines.append("MCP WARDEN scan report")
    lines.append("Target: %s" % payload["target"])
    lines.append("Scanned: %s" % payload["scanned_at"])
    lines.append("Score: %d/100  Grade: %s" % (payload["score"], payload["grade"]))
    lines.append(
        "Files scanned: %d   Tools detected: %d   Findings: %d"
        % (len(payload["files_scanned"]), len(payload["tools"]), len(payload["findings"]))
    )
    if payload.get("files_skipped"):
        lines.append(
            "Files skipped (unreadable or not valid Python): %d: %s"
            % (len(payload["files_skipped"]), ", ".join(payload["files_skipped"]))
        )
    if payload["by_severity"]:
        sev = ", ".join(
            "%s: %d" % (sev, payload["by_severity"].get(sev, 0))
            for sev in ("critical", "high", "medium", "low")
            if payload["by_severity"].get(sev, 0)
        )
        lines.append("By severity: %s" % sev)
    probe = payload.get("probe") or {}
    if probe:
        lines.append("Probe: %s" % probe.get("status", "unknown"))
    if not payload["findings"]:
        lines.append("")
        if payload.get("files_skipped"):
            lines.append("No findings in the files that could be scanned. Some files were skipped; see above.")
        else:
            lines.append("No findings. All seven rules are clean.")
        return "\n".join(lines) + "\n"
    current_rule = None
    for finding in payload["findings"]:
        if finding["rule_id"] != current_rule:
            current_rule = finding["rule_id"]
            rule = payload["rules"][current_rule]
            lines.append("")
            lines.append(
                "[%s] %s %s"
                % (rule["severity"].upper(), current_rule, rule["name"])
            )
        lines.append("  %s:%d  %s" % (finding["file"], finding["line"], finding["message"]))
        if finding["evidence"]:
            for ev_line in finding["evidence"].splitlines():
                lines.append("    | %s" % ev_line)
        lines.append("  Remediation: %s" % finding["remediation"])
    lines.append("")
    lines.append(
        "Scoring: 100 points minus severity weights %s; grades A 90+, B 75+, C 60+, D 40+, F below 40."
        % ", ".join("%s %d" % (k, v) for k, v in payload["weights"].items())
    )
    lines.append("Scan ran locally.")
    return "\n".join(lines) + "\n"


def render_json(payload):
    return json.dumps(payload, indent=2) + "\n"


_DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Warden Report</title>
<style>
:root{
  --bg:#0B1220; --panel:#0F172A; --raised:#111C33; --border:#1E293B;
  --text:#E2E8F0; --muted:#94A3B8; --accent:#22D3EE; --pass:#34D399;
  --critical:#F43F5E; --high:#FB923C; --medium:#FACC15; --low:#38BDF8;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,-apple-system,"Segoe UI",Roboto,sans-serif}
.mono{font-family:ui-monospace,"JetBrains Mono",SFMono-Regular,Menlo,monospace}
header{position:sticky;top:0;z-index:10;background:rgba(11,18,32,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--border)}
.hwrap{max-width:1100px;margin:0 auto;padding:14px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.mark{width:38px;height:38px;flex:0 0 38px}
.brand{font-weight:800;letter-spacing:.14em;font-size:15px}
.brand small{display:block;font-weight:500;letter-spacing:.02em;color:var(--muted);font-size:11px}
.target{color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:340px}
.spacer{flex:1}
.ringwrap{display:flex;align-items:center;gap:10px}
.ringmeta{font-size:12px;color:var(--muted)}
.ringmeta b{display:block;font-size:20px;color:var(--text)}
main{max-width:1100px;margin:0 auto;padding:20px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.kpi{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.kpi .v{font-size:26px;font-weight:800}
.kpi .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
.sevrow{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.sevdot{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--border);color:var(--muted)}
.filters{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px 14px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:6px}
.chip{cursor:pointer;border:1px solid var(--border);background:var(--raised);color:var(--muted);border-radius:999px;padding:6px 12px;font-size:12px}
.chip.active{color:#04121a;background:var(--accent);border-color:var(--accent);font-weight:700}
select,input[type=text]{background:var(--raised);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:8px 10px;font-size:13px}
input[type=text]{flex:1;min-width:180px}
.tabs{display:flex;gap:8px;margin:16px 0 4px}
.tab{cursor:pointer;padding:8px 16px;border-radius:8px 8px 0 0;font-size:13px;font-weight:600;color:var(--muted);border:1px solid transparent;border-bottom:none}
.tab.active{color:var(--text);background:var(--panel);border-color:var(--border)}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:0 12px 12px 12px;padding:6px 0}
.rgroup{border-bottom:1px solid var(--border);padding:10px 18px 4px}
.rgroup:last-child{border-bottom:none}
.rhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.rid{font-weight:800;font-size:13px}
.rname{font-size:13px;color:var(--muted)}
.badge{font-size:10px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;padding:3px 9px;border-radius:999px}
.count{margin-left:auto;font-size:12px;color:var(--muted)}
.frow{border:1px solid var(--border);background:var(--raised);border-radius:10px;margin:10px 0;overflow:hidden}
.fhead{cursor:pointer;display:flex;gap:10px;align-items:baseline;padding:10px 14px;width:100%;background:none;border:none;color:var(--text);text-align:left;font-size:13px}
.fhead:hover{background:rgba(34,211,238,.05)}
.floc{color:var(--accent);font-size:12px;white-space:nowrap}
.fmsg{flex:1}
.chev{color:var(--muted);transition:transform .18s ease}
.chev.open{transform:rotate(90deg)}
.fbody{max-height:0;overflow:hidden;transition:max-height .25s ease}
.fbody.open{max-height:1200px}
.finner{padding:0 14px 14px;border-top:1px dashed var(--border)}
.finner h4{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:12px 0 6px}
pre{background:#070D1A;border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-size:12px;overflow:auto;margin:0}
.rem{font-size:13px;color:var(--text);line-height:1.5}
.covrow{display:flex;gap:12px;align-items:flex-start;padding:14px 18px;border-bottom:1px solid var(--border)}
.covrow:last-child{border-bottom:none}
.covstatus{flex:0 0 auto;font-size:11px;font-weight:800;padding:4px 10px;border-radius:999px;margin-top:2px}
.covbody .rid{margin-right:8px}
.covbody p{margin:6px 0;font-size:13px;color:var(--muted);line-height:1.55}
.covbody .rem{color:var(--text)}
.empty{text-align:center;padding:60px 20px;color:var(--muted)}
.empty .big{font-size:44px;margin-bottom:10px}
footer{max-width:1100px;margin:0 auto;padding:24px 20px 40px;color:var(--muted);font-size:12px;line-height:1.6}
#fallback{max-width:700px;margin:80px auto;padding:30px;background:var(--panel);border:1px solid var(--border);border-radius:12px;text-align:center}
@media print{
  body{background:#fff;color:#111}
  header{background:#fff;border-bottom:1px solid #ccc}
  .kpi,.filters,.panel,.frow,.covrow{background:#fff;border-color:#ccc;color:#111}
  .fhead,.rem,.rname,.count,.target,.ringmeta{color:#111}
  .chip,.tab{display:none}
  pre{background:#f4f4f4;color:#111}
}
</style>
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/htm@3/dist/htm.umd.js"></script>
</head>
<body>
<div id="root"></div>
<div id="fallback" hidden>
  <h2>MCP Warden Report</h2>
  <p>The interactive dashboard needs the React CDN, which was unreachable. The full results are embedded in this file as JSON.</p>
</div>
<script id="scan-data" type="application/json">%%SCAN_JSON%%</script>
<script>
(function(){
  var raw = document.getElementById("scan-data").textContent;
  var data;
  try { data = JSON.parse(raw); }
  catch(e){ document.getElementById("fallback").hidden = false; return; }
  if(!window.React || !window.ReactDOM || !window.htm){
    document.getElementById("fallback").hidden = false; return;
  }
  var useState = React.useState, useMemo = React.useMemo, useEffect = React.useEffect;
  var html = htm.bind(React.createElement);
  var SEV = {critical:"#F43F5E", high:"#FB923C", medium:"#FACC15", low:"#38BDF8"};
  var SEVS = ["critical","high","medium","low"];
  var RULE_ORDER = ["MW001","MW002","MW003","MW004","MW005","MW006","MW007"];

  function sevBadge(sev){
    return html`<span className="badge" style=${{background:SEV[sev]+"22",color:SEV[sev],border:"1px solid "+SEV[sev]+"55"}}>${sev}</span>`;
  }

  function ScoreRing(props){
    var R = 34, C = 2*Math.PI*R;
    var st = useState(false), mounted = st[0], setMounted = st[1];
    useEffect(function(){ var t = setTimeout(function(){ setMounted(true); }, 60); return function(){ clearTimeout(t); }; }, []);
    var frac = mounted ? props.score/100 : 0;
    var color = props.grade === "A" ? "#34D399" : props.grade === "F" ? "#F43F5E" : "#22D3EE";
    return html`<div className="ringwrap">
      <svg width="84" height="84" viewBox="0 0 84 84">
        <circle cx="42" cy="42" r=${R} fill="none" stroke="#1E293B" strokeWidth="9"/>
        <circle cx="42" cy="42" r=${R} fill="none" stroke=${color} strokeWidth="9" strokeLinecap="round"
          strokeDasharray=${C} strokeDashoffset=${C*(1-frac)}
          style=${{transition:"stroke-dashoffset 1.2s ease", transform:"rotate(-90deg)", transformOrigin:"42px 42px"}}/>
        <text x="42" y="49" textAnchor="middle" fill="#E2E8F0" fontSize="22" fontWeight="800" fontFamily="Inter,sans-serif">${props.grade}</text>
      </svg>
      <div className="ringmeta"><b className="mono">${props.score}/100</b>security score</div>
    </div>`;
  }

  function FindingRow(props){
    var f = props.finding;
    var open = props.open, onToggle = props.onToggle;
    return html`<div className="frow">
      <button className="fhead" onClick=${onToggle}>
        <span className=${"chev"+(open?" open":"")}>▸</span>
        <span className="floc mono">${f.file.split("/").pop()}:${f.line}</span>
        <span className="fmsg">${f.message}</span>
        ${sevBadge(f.severity)}
      </button>
      <div className=${"fbody"+(open?" open":"")}>
        <div className="finner">
          <h4>Evidence</h4>
          <pre className="mono">${f.evidence || "(no source excerpt)"}</pre>
          <h4>Remediation</h4>
          <div className="rem">${f.remediation}</div>
        </div>
      </div>
    </div>`;
  }

  function App(){
    var _sev = useState("all"), sevF = _sev[0], setSevF = _sev[1];
    var _rule = useState("all"), ruleF = _rule[0], setRuleF = _rule[1];
    var _qq = useState(""), q = _qq[0], setQ = _qq[1];
    var _tab = useState("findings"), tab = _tab[0], setTab = _tab[1];
    var _exp = useState({}), expanded = _exp[0], setExpanded = _exp[1];

    var filtered = useMemo(function(){
      var needle = q.trim().toLowerCase();
      return data.findings.filter(function(f){
        if(sevF !== "all" && f.severity !== sevF) return false;
        if(ruleF !== "all" && f.rule_id !== ruleF) return false;
        if(needle){
          var hay = (f.file+" "+f.rule_id+" "+f.rule_name+" "+f.message+" "+f.evidence).toLowerCase();
          if(hay.indexOf(needle) < 0) return false;
        }
        return true;
      });
    }, [sevF, ruleF, q]);

    var grouped = useMemo(function(){
      var g = {};
      filtered.forEach(function(f){ (g[f.rule_id] = g[f.rule_id] || []).push(f); });
      return RULE_ORDER.filter(function(rid){ return g[rid]; }).map(function(rid){
        return {rule: data.rules[rid], findings: g[rid]};
      });
    }, [filtered]);

    function toggle(key){
      var next = Object.assign({}, expanded);
      if(next[key]) delete next[key]; else next[key] = true;
      setExpanded(next);
    }

    var sevCounts = SEVS.map(function(s){ return {sev:s, n: data.by_severity[s] || 0}; });

    return html`<div>
      <header><div className="hwrap">
        <svg className="mark" viewBox="0 0 40 40"><path d="M20 3l13 5v10c0 8.5-5.5 14.5-13 17C12.5 32.5 7 26.5 7 18V8z" fill="none" stroke="#22D3EE" strokeWidth="2.5"/><path d="M14 20l4.5 4.5L27 15" fill="none" stroke="#34D399" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
        <div className="brand">MCP WARDEN<small>security scanner for MCP servers</small></div>
        <div className="target mono">${data.target}</div>
        <div className="spacer"></div>
        <${ScoreRing} score=${data.score} grade=${data.grade} />
      </div></header>
      <main>
        <div className="kpis">
          <div className="kpi"><div className="v mono">${data.files_scanned.length}</div><div className="l">Files scanned</div></div>
          <div className="kpi"><div className="v mono">${data.tools.length}</div><div className="l">Tools detected</div></div>
          <div className="kpi"><div className="v mono">${data.findings.length}</div><div className="l">Total findings</div></div>
          <div className="kpi"><div className="v mono" style=${{color: data.score >= 90 ? "#34D399" : "#F43F5E"}}>${data.score}</div><div className="l">Score / Grade ${data.grade}</div>
            <div className="sevrow">${sevCounts.map(function(s){
              return html`<span className="sevdot mono" key=${s.sev} style=${{color:SEV[s.sev]}}>${s.sev[0].toUpperCase()}: ${s.n}</span>`;
            })}</div>
          </div>
        </div>
        <div className="filters">
          ${["all"].concat(SEVS).map(function(s){
            return html`<button key=${s} className=${"chip"+(sevF===s?" active":"")} onClick=${function(){setSevF(s);}}>${s}</button>`;
          })}
          <select value=${ruleF} onChange=${function(e){setRuleF(e.target.value);}}>
            <option value="all">All rules</option>
            ${RULE_ORDER.map(function(rid){
              var r = data.rules[rid];
              return html`<option key=${rid} value=${rid}>${rid} · ${r.name}</option>`;
            })}
          </select>
          <input type="text" placeholder="Search files, rules, messages…" value=${q} onInput=${function(e){setQ(e.target.value);}} />
        </div>
        <div className="tabs">
          <div className=${"tab"+(tab==="findings"?" active":"")} onClick=${function(){setTab("findings");}}>Findings (${filtered.length})</div>
          <div className=${"tab"+(tab==="coverage"?" active":"")} onClick=${function(){setTab("coverage");}}>Rule Coverage</div>
        </div>
        ${tab === "findings" ? html`<div className="panel">
          ${grouped.length === 0 ? html`<div className="empty">
            ${data.findings.length === 0
              ? html`<div><div className="big">✓</div><h3>Clean pass</h3><p>All seven rules are clean. No findings on this target.</p></div>`
              : html`<div><h3>No findings match the current filters</h3><p>Loosen the filters to see results.</p></div>`}
          </div>` : grouped.map(function(g){
            return html`<div className="rgroup" key=${g.rule.id}>
              <div className="rhead"><span className="rid mono">${g.rule.id}</span>${sevBadge(g.rule.severity)}
                <span className="rname">${g.rule.name}</span><span className="count mono">${g.findings.length} finding${g.findings.length===1?"":"s"}</span></div>
              ${g.findings.map(function(f, i){
                var key = g.rule.id+":"+i;
                return html`<${FindingRow} key=${key} finding=${f} open=${!!expanded[key]} onToggle=${function(){toggle(key);}} />`;
              })}
            </div>`;
          })}
        </div>` : html`<div className="panel">
          ${RULE_ORDER.map(function(rid){
            var r = data.rules[rid];
            var clean = !r.fired;
            return html`<div className="covrow" key=${rid}>
              <span className="covstatus" style=${clean
                ? {background:"#34D39922", color:"#34D399", border:"1px solid #34D39955"}
                : {background:SEV[r.severity]+"22", color:SEV[r.severity], border:"1px solid "+SEV[r.severity]+"55"}}>
                ${clean ? "CLEAN" : "FIRED ×"+r.count}</span>
              <div className="covbody">
                <div><span className="rid mono">${rid}</span>${sevBadge(r.severity)}</div>
                <div style=${{fontWeight:700, marginTop:"4px"}}>${r.name}</div>
                <p>${r.description}</p>
                <p className="rem"><b>Remediation:</b> ${r.remediation}</p>
              </div>
            </div>`;
          })}
        </div>`}
      </main>
      <footer>
        Scoring: 100 points minus severity weights
        ${Object.keys(data.weights).map(function(k){ return k+" "+data.weights[k]; }).join(", ")}.
        Grades: A 90+, B 75+, C 60+, D 40+, F below 40.
        Scan ran locally at ${data.scanned_at}. Report generated by MCP Warden ${"%%VERSION%%"}.
      </footer>
    </div>`;
  }

  ReactDOM.createRoot(document.getElementById("root")).render(html`<${App} />`);
})();
</script>
</body>
</html>
"""


def render_html(payload):
    scan_json = json.dumps(payload)
    scan_json = scan_json.replace("</", "<\\/")
    page = _DASHBOARD_TEMPLATE.replace("%%SCAN_JSON%%", scan_json)
    page = page.replace("%%VERSION%%", "0.1.0")
    return page
