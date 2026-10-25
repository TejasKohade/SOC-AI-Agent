"""AutoSOC dashboard: live cases, approvals, vulnerability management, tickets and tool state."""
import datetime as dt
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from autosoc import config, db, ingest, pipeline, siem, soar  # noqa: E402
from autosoc.agents import orchestrator  # noqa: E402
from autosoc.vm import lifecycle  # noqa: E402

st.set_page_config(page_title="AutoSOC", page_icon="🛡️", layout="wide")

TIER_LABEL = {0: "T0 read-only", 1: "T1 auto", 2: "T2 one approver", 3: "T3 analyst + SOC lead"}
STATUS_ICON = {"closed": "✅", "false_positive": "⚪", "awaiting_approval": "⏳", "escalated": "🚨",
               "triage": "🔎", "investigating": "🔎", "responding": "⚙️", "verifying": "🔁", "new": "🆕"}


def ts(v):
    return dt.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S") if v else "-"


# ---------------- sidebar: who is approving ----------------
with st.sidebar:
    st.title("🛡️ AutoSOC")
    st.caption("End-to-end SOC automation POC · mocked tools, real AI agents")
    me = st.text_input("Your name", value="ana")
    role = st.selectbox("Your role", ["analyst", "soc_lead", "owner"])
    st.divider()
    st.markdown(f"**LLM provider:** `{config.LLM_PROVIDER}`")
    from autosoc import llm
    for prov, stt in llm.status().items():
        st.caption(f"{prov}: {stt}")
    st.caption("If Bedrock is unavailable (for example an expired key), agents use the offline "
               "deterministic stand-in, and each case shows which one answered.")
    if st.button("Refresh"):
        st.rerun()
    if st.button("Reset all state", type="secondary"):
        db.wipe()
        st.success("State wiped")
        st.rerun()

tabs = st.tabs(["Overview", "Live SOC", "Scoreboard", "Cases", "Approvals",
                "Vulnerabilities", "Audit"])
SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

# ---------------- Overview ----------------
with tabs[0]:
    cases = db.query("SELECT * FROM cases ORDER BY created DESC")
    pend = soar.pending()
    findings = db.query("SELECT * FROM findings")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Open cases", sum(c["status"] not in ("closed", "false_positive") for c in cases))
    c2.metric("Awaiting approval", len(pend))
    c3.metric("Closed", sum(c["status"] in ("closed", "false_positive") for c in cases))
    c4.metric("Escalated", sum(c["status"] == "escalated" for c in cases))
    c5.metric("Open vulns", sum(f["state"] not in ("closed", "false_positive") for f in findings))

    st.subheader("Replay a scenario")
    scs = pipeline.list_scenarios()
    labels = {f"[{s['kind'].upper()}] {s['id']} - {s['description']}": s for s in scs}
    pick = st.selectbox("Scenario", list(labels))
    a, b, c = st.columns(3)
    auto = a.checkbox("Auto-approve tier 2/3 (demo)", value=False)
    fresh = b.checkbox("Reset state first", value=labels[pick]["kind"] == "vm")
    if c.button("▶ Run scenario", type="primary"):
        if fresh:
            db.wipe_keep_metrics()
        with st.spinner("Replaying events through SIEM -> agents -> SOAR ..."):
            r = pipeline.run(labels[pick]["path"], auto_approve=auto)
        (st.success if r["passed"] else st.error)(f"{r['scenario']}: {'PASS' if r['passed'] else 'FAIL'} "
                                                   f"in {r['duration_s']}s")
        st.json(r["checks"], expanded=False)
    if st.button("Run ALL scenarios (fresh state each)"):
        db.wipe()
        prog = st.progress(0.0)
        for i, s in enumerate(scs):
            db.wipe_keep_metrics()
            pipeline.run(s["path"])
            prog.progress((i + 1) / len(scs), text=s["id"])
        st.rerun()

    st.subheader("POC metrics")
    m = db.query("SELECT scenario, kind, passed, detected, verdict_ok, playbook_ok, duration, ts FROM metrics ORDER BY id DESC")
    if m:
        df = pd.DataFrame(m)
        soc = df[df.kind == "soc"]
        if len(soc):
            k1, k2, k3, k4 = st.columns(4)
            k1.metric("Detection coverage", f"{int(soc.detected.sum())}/{len(soc)}")
            k2.metric("Verdict accuracy", f"{soc.verdict_ok.mean():.0%}", help="target ≥ 90%")
            k3.metric("Right playbook", f"{int(soc.playbook_ok.sum())}/{len(soc)}")
            k4.metric("Mean loop time", f"{soc.duration.mean():.1f}s", help="target < 120s")
        df["ts"] = df["ts"].map(ts)
        st.dataframe(df, hide_index=True, width="stretch")
    else:
        st.info("No runs yet. Pick a scenario above.")

# ---------------- Live logs ----------------
LOG_COLS = ["@timestamp", "event.module", "event.action", "host.name", "user.name", "source.ip",
            "destination.ip", "process.name", "url.domain"]


@st.fragment(run_every=3)
def live_logs():
    only_live = st.toggle("Only the live feed (hide scenario replays)", value=True, key="live_only")
    where, args = ("WHERE run_id=?", (ingest.RUN_ID,)) if only_live else ("", ())
    rows = db.query(f"SELECT id, raw, run_id FROM events {where} ORDER BY rowid DESC LIMIT 200", args)
    alerts = db.query(f"SELECT a.*, c.status cstatus, c.verdict cverdict FROM alerts a "
                      f"LEFT JOIN cases c ON c.id = a.case_id {where.replace('run_id', 'a.run_id')} "
                      f"ORDER BY a.ts DESC LIMIT 100", args)
    n = db.one(f"SELECT COUNT(*) n FROM events {where}", args)["n"]
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Events ingested", n)
    k2.metric("Alerts", db.one(f"SELECT COUNT(*) n FROM alerts {where}", args)["n"])
    k3.metric("Cases", len({a["case_id"] for a in alerts if a["case_id"]}))
    k4.metric("Alerts waiting for agents", sum(1 for a in alerts if not a["case_id"]),
              help="Alerts settle until their activity is quiet, then go to the agents")
    if alerts:
        st.markdown("**Alerts**")
        st.dataframe(pd.DataFrame([{
            "time": ts(a["ts"]), "rule": a["rule_title"], "severity": a["severity"], "host": a["host"],
            "user": a["user"], "src_ip": a["src_ip"], "events": len(db.loads(a["event_ids"], [])),
            "case": a["case_id"] or "settling …",
            "case status": f"{STATUS_ICON.get(a['cstatus'], '')} {a['cstatus']}" if a["case_id"] else "",
            "verdict": a["cverdict"] or ""} for a in alerts]), hide_index=True, width="stretch")
        st.caption("Open a case in the **Cases** tab to see triage, investigation and response.")
    if not rows:
        st.info("No live events yet. Start the server with `python -m autosoc mocks`, then run "
                "`python tools/send_logs.py scenarios/soc/01_ssh_bruteforce.yml`.")
        return
    in_alert, by_activity = {}, {}
    for a in alerts:
        for eid in db.loads(a["event_ids"], []):
            in_alert.setdefault(eid, a)
        by_activity.setdefault((a["rule_id"], a["host"], a["src_ip"]), a)
    rules = siem.load_rules()
    table = []
    for r in rows:
        e = db.loads(r["raw"], {}) or {}
        hit = [ru for ru in rules if _safe_match(ru, e)]
        # an event that matches an alert's rule from the same host/source belongs to that activity,
        # even if it arrived after the threshold fired
        a = in_alert.get(r["id"]) or next(
            (x for ru in hit for x in (by_activity.get((ru["id"], e.get("host.name"), e.get("source.ip"))),
                                       by_activity.get((ru["id"], e.get("host.name"), None))) if x), None)
        hit = [ru["title"] for ru in hit]
        row = {k: e.get(k) for k in LOG_COLS}
        row["@timestamp"] = ts(e.get("@timestamp"))
        row["rule match"] = ", ".join(hit)
        row["case"] = (a["case_id"] or "settling …") if a else ""
        table.append(row)
    df = pd.DataFrame(table)

    def hl(row):
        color = "rgba(255, 75, 75, 0.25)" if row["case"] else ("rgba(255, 170, 0, 0.18)" if row["rule match"] else "")
        return [f"background-color: {color}" if color else ""] * len(row)

    st.markdown("**Latest 200 events** · red = part of an alert, amber = matches a rule (below its threshold)")
    st.dataframe(df.style.apply(hl, axis=1), hide_index=True, width="stretch", height=600)


def _safe_match(rule, event):
    try:
        return siem.matches(rule, event)
    except Exception:
        return False


# ---------------- Live SOC (continuous stream -> incidents by severity) ----------------
with tabs[1]:
    from autosoc import incidents
    st.caption("One continuous mixed-source feed. Start it from a terminal: "
               "`.venv/bin/python -m autosoc stream --rate 5 --interval 30`  (attacks injected every 30 s, "
               "synthetic and real OTRF captures).")
    auto = st.checkbox("Auto-refresh every 4 s", value=True, key="soc_auto")

    # Only this panel reruns on the timer (a fragment), so the other tabs stay usable.
    @st.fragment(run_every=4 if auto else None)
    def live_soc_panel():
        ev_total = db.one("SELECT COUNT(*) n FROM events WHERE run_id='stream'")["n"]
        inj = db.query("SELECT * FROM injections ORDER BY ts DESC")
        incs = incidents.list_open()
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Events ingested", f"{ev_total:,}")
        m2.metric("Attacks injected", len(inj))
        m3.metric("Detected", sum(i["detected"] for i in inj))
        m4.metric("Open incidents", sum(i["status"] == "open" for i in incs))
        m5.metric("Critical / High", sum(i["severity"] in ("critical", "high") for i in incs))

        st.subheader("Incidents by severity")
        if incs:
            for i in incs[:20]:
                cs = [orchestrator.get_case(c) for c in i["case_ids"]]
                cs = [c for c in cs if c]
                with st.container(border=True):
                    left, right = st.columns([4, 1])
                    left.markdown(f"### {SEV_ICON.get(i['severity'],'')} {i['severity'].upper()} · "
                                  f"{i['host'] or i['user']}")
                    left.caption(" → ".join(i["stages"]) + f"  ·  {i['rationale']}")
                    right.metric("Severity", i["severity_score"])
                    for c in cs:
                        prov = orchestrator.providers(c["id"])
                        acts = orchestrator.case_actions(c["id"])
                        done = [a for a in acts if a["status"] == "executed"]
                        wait = [a for a in acts if a["status"] == "pending_approval"]
                        line = f"- **{c['id']}** {c['title']} — {c['verdict']} ({(c['confidence'] or 0):.0%})"
                        if done:
                            line += f" · ✅ {', '.join(a['tool'] for a in done)}"
                        if wait:
                            line += f" · ⏳ {', '.join(a['tool'] for a in wait)} awaiting approval"
                        if prov:
                            line += f" · _{'/'.join(prov)}_"
                        left.markdown(line)
        else:
            st.info("No incidents yet. Start the stream, wait ~30 s for the first attack.")

        st.subheader("Live event stream (latest 60)")
        rows = db.query("SELECT ts, source_type, category, host, user, action, src_ip FROM events "
                        "WHERE run_id='stream' ORDER BY ts DESC LIMIT 60")
        if rows:
            df = pd.DataFrame([{"time": ts(r["ts"]), "source": r["source_type"], "category": r["category"],
                                "host": r["host"], "user": r["user"], "action": r["action"],
                                "src_ip": r["src_ip"]} for r in rows])
            st.dataframe(df, hide_index=True, width="stretch", height=320)
        else:
            st.info("No events yet.")

    live_soc_panel()

# ---------------- Scoreboard (detection honesty) ----------------
with tabs[2]:
    from autosoc.stream.engine import scoreboard
    st.caption("Injected attacks vs. what the pipeline caught. Ground truth is recorded when each attack "
               "is injected; the detection side never sees it. Refreshes every 10 s.")

    @st.fragment(run_every=10)
    def scoreboard_panel():
        sb = scoreboard()
        if sb["injected"]:
            c1, c2, c3 = st.columns(3)
            c1.metric("Detection rate", f"{sb['detection_rate']:.0%}", f"{sb['detected']}/{sb['injected']}")
            c2.metric("Mean time to detect",
                      f"{sb['mean_detect_latency_s']}s" if sb["mean_detect_latency_s"] else "-")
            syn = sb["by_origin"].get("synthetic", {})
            real = sb["by_origin"].get("real", {})
            c3.metric("Real captures caught", f"{real.get('detected',0)}/{real.get('total',0)}",
                      help="OTRF Security-Datasets: genuine attack telemetry")
            st.markdown(f"**Synthetic attacks:** {syn.get('detected',0)}/{syn.get('total',0)}  ·  "
                        f"**Real OTRF captures:** {real.get('detected',0)}/{real.get('total',0)}")
            inj = db.query("SELECT * FROM injections ORDER BY ts DESC")
            df = pd.DataFrame([{"time": ts(i["ts"]), "attack": i["label"], "ATT&CK": i["mitre"],
                                "origin": i["origin"], "source": i["source"],
                                "detected": "✅" if i["detected"] else "❌ MISSED",
                                "latency_s": i["detect_latency"], "case": i["matched_case"]} for i in inj])
            st.dataframe(df, hide_index=True, width="stretch")
            if sb["missed"]:
                st.warning("Missed: " + ", ".join(f"{m['label']} ({m['mitre']})" for m in sb["missed"]))
        else:
            st.info("No attacks injected yet. The scoreboard is fed by **stream mode** only "
                    "(not the Live logs feed or single scenario runs). Start it from a terminal:")
            st.code(".venv/bin/python -m autosoc stream --rate 5 --interval 30 --fresh", language="bash")

    scoreboard_panel()

# ---------------- Cases ----------------
with tabs[3]:
    cases = db.query("SELECT * FROM cases ORDER BY created DESC")
    if not cases:
        st.info("No cases yet.")
    else:
        df = pd.DataFrame([{"": STATUS_ICON.get(c["status"], ""), "id": c["id"], "status": c["status"],
                            "kind": c["kind"], "severity": c["severity"], "verdict": c["verdict"],
                            "conf": c["confidence"], "title": c["title"], "created": ts(c["created"]),
                            "llm calls": c["llm_calls"], "tool calls": c["tool_calls"]} for c in cases])
        st.dataframe(df, hide_index=True, width="stretch")
        cid = st.selectbox("Open case", [c["id"] for c in cases],
                           format_func=lambda i: f"{i} · {next(c['title'] for c in cases if c['id'] == i)}")
        c = orchestrator.get_case(cid)
        rep = c["report"]
        st.markdown(f"### {STATUS_ICON.get(c['status'], '')} {c['title']}")
        x1, x2, x3, x4 = st.columns(4)
        x1.metric("Status", c["status"])
        x2.metric("Verdict", c["verdict"] or "-")
        x3.metric("Confidence", f"{c['confidence']:.0%}" if c["confidence"] is not None else "-")
        x4.metric("Severity", c["severity"])
        prov = orchestrator.providers(cid)
        if prov:
            st.caption("Agents answered by: " + ", ".join(f"{k} × {v}" for k, v in prov.items()) +
                       (" ⚠️ offline fallback was used (LLM quota or outage)" if "offline" in prov else ""))
        if c["summary"]:
            st.info(c["summary"])
        tri = rep.get("triage")
        if tri:
            with st.expander("Triage", expanded=True):
                st.write(tri.get("reasoning"))
                st.caption("Evidence: " + ", ".join(tri.get("evidence", [])))
                flags = (rep.get("enrichment") or {}).get("injection_flags")
                if flags:
                    st.warning(f"Prompt-injection text found in log fields (treated as data): {flags}")
        inv = c["investigation_data"]
        if inv:
            with st.expander("Investigation", expanded=True):
                st.write(inv.get("summary"))
                if inv.get("timeline"):
                    st.dataframe(pd.DataFrame(inv["timeline"]), hide_index=True, width="stretch")
                cc1, cc2 = st.columns(2)
                cc1.write("**MITRE ATT&CK**")
                cc1.write([f"{m['id']} {m.get('name', '')}" for m in inv.get("mitre", [])])
                cc2.write("**IOCs**")
                cc2.write([f"{i.get('type')}: {i.get('value')}" for i in inv.get("iocs", [])])
        if rep.get("hunt"):
            st.json(rep["hunt"])
        st.markdown("#### Response actions")
        for act in orchestrator.case_actions(cid):
            with st.container(border=True):
                st.markdown(f"**{act['tool']}** `{json.dumps(act['params'])}` · {TIER_LABEL[act['tier']]} · "
                            f"**{act['status']}**")
                if act["tier_reasons"]:
                    st.caption("Tier raised: " + "; ".join(act["tier_reasons"]))
                if act["approvals"]:
                    st.caption("Decisions: " + ", ".join(f"{x['user']} ({x['role']}): {x['decision']}"
                                                         for x in act["approvals"]))
                if act["status"] == "executed" and act["rollback"]:
                    if st.button(f"↩ Roll back ({act['rollback']['tool']})", key=f"rb-{act['id']}"):
                        soar.rollback(act["id"], me)
                        st.rerun()
        if rep.get("plan"):
            with st.expander("Response plan (agent)"):
                st.json(rep["plan"])
        if rep.get("verification"):
            with st.expander("Verification"):
                st.json(rep["verification"])
        if rep.get("final"):
            with st.expander("Case report", expanded=c["status"] in ("closed", "false_positive")):
                st.markdown(rep["final"].get("report_markdown", ""))
                if rep["final"].get("lessons_learned"):
                    st.markdown("**Lessons learned**\n" + "\n".join(f"- {x}" for x in rep["final"]["lessons_learned"]))
                if rep["final"].get("rule_tuning"):
                    st.markdown("**Rule tuning suggestions** (written to `tuning/suggestions/`)")
                    st.json(rep["final"]["rule_tuning"])
        with st.expander("Audit trail (every prompt, tool call and decision)"):
            for r in db.query("SELECT * FROM audit WHERE case_id=? ORDER BY id", (cid,)):
                st.markdown(f"`{ts(r['ts'])}` **{r['actor']}** · {r['kind']}")
                st.code(r["data"][:3000], language="json")

# ---------------- Approvals ----------------
with tabs[4]:
    pend = soar.pending()
    st.caption(f"Acting as **{me}** ({role}). Tier 2 needs one approver; tier 3 needs an analyst AND a SOC lead.")
    if not pend:
        st.success("Nothing waiting for approval.")
    for act in pend:
        case = orchestrator.get_case(act["case_id"]) if act["case_id"] else None
        f = lifecycle.get(act["finding_id"]) if act["finding_id"] else None
        with st.container(border=True):
            head = case["title"] if case else f"{f['cve']} on {f['host']}"
            st.markdown(f"### {TIER_LABEL[act['tier']]} · {act['tool']}")
            st.markdown(f"**{head}**" + (" · ⚠️ escalated (unanswered > 15 min)" if act["escalated"] else ""))
            if case:
                tri = case["report"].get("triage", {})
                st.write((case["investigation_data"] or {}).get("summary") or tri.get("reasoning", ""))
                st.markdown(f"Verdict **{case['verdict']}**, confidence **{(case['confidence'] or 0):.0%}**")
                st.caption("Evidence: " + ", ".join(tri.get("evidence", [])))
            if f:
                st.write(f.get("summary") or "")
                st.markdown(f"Priority **{f['priority']}**, risk **{f['risk']}** · fix plan: {f.get('fix_plan') or '-'}")
            st.markdown(f"**Exact action:** `{act['tool']}` `{json.dumps(act['params'])}`")
            st.markdown(f"**Rollback:** `{(act['rollback'] or {}).get('tool', 'not reversible')}`")
            if act["tier_reasons"]:
                st.caption("Why this tier: " + "; ".join(act["tier_reasons"]))
            if act["approvals"]:
                st.caption("So far: " + ", ".join(f"{x['user']} ({x['role']})" for x in act["approvals"]))
            b1, b2, b3 = st.columns([1, 1, 3])
            if b1.button("✅ Approve", key=f"ap-{act['id']}", type="primary"):
                soar.approve(act["id"], me, role)
                st.rerun()
            if b2.button("✖ Reject", key=f"rj-{act['id']}"):
                soar.reject(act["id"], me, role, "rejected in UI")
                st.rerun()
            if case:
                note = b3.text_input("Investigate more: what should the agent look at?", key=f"note-{act['id']}")
                if note and b3.button("🔎 Investigate more", key=f"im-{act['id']}"):
                    with st.spinner("Investigation agent working ..."):
                        orchestrator.investigate_more(case["id"], note, me)
                    st.rerun()

# ---------------- Vulnerabilities ----------------
with tabs[5]:
    st.caption("risk = CVSS × w_asset × w_exposure + 3·KEV + 5·EPSS · SLA P1 72h · P2 7d · P3 30d · P4 90d")
    # Enable each job only when there is something for it to do, so the lifecycle reads in order.
    def _n(sql, args=()):
        return db.one(f"SELECT COUNT(*) n FROM findings {sql}", args)["n"]
    any_findings = _n("") > 0
    needs_agent = _n("WHERE state='triaged' AND priority IN ('P1','P2','P3') AND ticket_id IS NULL "
                     "AND (proposal IS NULL OR proposal='')") > 0
    needs_remediate = _n("WHERE state IN ('assigned','reopened') AND (exception IS NULL OR exception='')") > 0
    needs_verify = _n("WHERE state='pending_verification'") > 0
    has_exception = _n("WHERE state='risk_accepted'") > 0

    groups = [
        ("1 · Pipeline — run in order", [
            ("Scan", lifecycle.run_scan, True, "Compare installed software to the CVE catalogue"),
            ("VM agent", lifecycle.vm_agent_job, needs_agent, "Needs new scanned findings to analyse"),
            ("Remediate", lifecycle.remediation_job, needs_remediate, "Needs findings assigned by the VM agent"),
            ("Verify", lifecycle.verify_job, needs_verify, "Needs a remediated finding awaiting rescan"),
        ]),
        ("2 · Time-driven — use with the clock below", [
            ("SLA check", lifecycle.sla_monitor, any_findings, "Needs findings to check deadlines on"),
            ("Exceptions", lifecycle.exception_expiry, has_exception, "Needs a risk-accepted finding to expire"),
        ]),
        ("3 · Shortcuts & reports", [
            ("Full cycle", lifecycle.run_cycle, True, "Run scan → agent → remediate → verify → SLA → exceptions"),
            ("Weekly report", lifecycle.weekly_report, any_findings, "Needs findings to summarise"),
        ]),
    ]
    for title, jobs in groups:
        st.markdown(f"**{title}**")
        cols = st.columns(4)
        for col, (label, fn, enabled, help_text) in zip(cols, jobs):
            if col.button(label, disabled=not enabled, help=help_text, width="stretch"):
                with st.spinner(label):
                    st.session_state["vm_last"] = fn()
                st.rerun()
    if "vm_last" in st.session_state:
        with st.expander("Last job output"):
            st.json(json.loads(json.dumps(st.session_state["vm_last"], default=str)))
    k1, k2 = st.columns([2, 1])
    adv = k1.select_slider("Advance the mock clock", options=["1h", "24h", "72h", "7d", "30d"], value="24h")
    if k2.button("⏩ Advance clock"):
        from autosoc.telemetry import _parse_dur
        db.advance_clock(_parse_dur(adv))
        st.rerun()
    st.caption(f"Mock clock: {ts(db.now())}")

    rows = db.query("SELECT * FROM findings ORDER BY risk DESC")
    if rows:
        df = pd.DataFrame([{"id": r["id"], "host": r["host"], "cve": r["cve"], "package": r["package"],
                            "risk": r["risk"], "priority": r["priority"], "state": r["state"], "KEV": bool(r["kev"]),
                            "EPSS": r["epss"], "SLA due": ts(r["sla_due"]), "ticket": r["ticket_id"],
                            "SLA": "breached" if r["sla_breached"] else ("75% warn" if r["sla_warned"] else "ok"),
                            "proposal": (db.loads(r["proposal"], {}) or {}).get("type")} for r in rows])
        st.dataframe(df, hide_index=True, width="stretch")
        fid = st.selectbox("Finding", [r["id"] for r in rows],
                           format_func=lambda i: next(f"{r['cve']} on {r['host']} ({r['priority']}, {r['state']})"
                                                      for r in rows if r["id"] == i))
        f = lifecycle.get(fid)
        st.write(f.get("summary") or "")
        if f.get("fix_plan"):
            st.markdown(f"**Fix plan:** {f['fix_plan']}  \n**Campaign:** {f.get('campaign')}")
        if f.get("proposal"):
            st.warning(f"VM agent proposes **{f['proposal']['type']}**: {f['proposal']['evidence']}")
            p1, p2 = st.columns(2)
            if p1.button("Confirm false positive"):
                lifecycle.confirm_false_positive(fid, me, True)
                st.rerun()
            if p2.button("Reject proposal (ticket it)"):
                lifecycle.confirm_false_positive(fid, me, False)
                st.rerun()
        if f["state"] not in ("closed", "false_positive", "risk_accepted"):
            with st.expander("File a risk exception"):
                need = sorted(lifecycle.scoring.EXCEPTION_APPROVERS[f["priority"]])
                st.caption(f"{f['priority']} needs approval from: {need}. Max 90 days.")
                reason = st.text_input("Reason")
                control = st.text_input("Compensating control")
                days = st.number_input("Days", 1, 90, 30)
                approvers = st.multiselect("Approvals (role)", ["soc_lead", "owner", "analyst"], default=[role])
                if st.button("Accept risk"):
                    try:
                        lifecycle.accept_risk(fid, reason, control, int(days),
                                              [{"user": me, "role": r} for r in approvers])
                        st.rerun()
                    except ValueError as e:
                        st.error(str(e))
        with st.expander("History"):
            st.dataframe(pd.DataFrame([{**h, "ts": ts(h["ts"])} for h in f["history"] or []]),
                         hide_index=True, width="stretch")
        with st.expander("Emergency: a CVE was just added to CISA KEV"):
            cve = st.selectbox("CVE", sorted({r["cve"] for r in rows}))
            if st.button("Apply KEV update (rescore, rescan, threat hunt)"):
                st.success(f"Threat hunt case {lifecycle.kev_update(cve)} opened")
    rep = db.one("SELECT v FROM kv WHERE k='vm_weekly_report'")
    if rep:
        with st.expander("Weekly posture report", expanded=False):
            st.markdown(json.loads(rep["v"])["summary"])

# ---------------- Audit ----------------
with tabs[6]:
    kind = st.multiselect("Kinds", ["prompt", "llm_response", "tool_call", "decision", "action", "approval",
                                    "escalated", "status", "finding_state", "invalid_output"],
                          default=["decision", "action", "approval", "escalated"])
    if kind:
        rows = db.query(f"SELECT * FROM audit WHERE kind IN ({','.join('?' * len(kind))}) ORDER BY id DESC LIMIT 300",
                        kind)
        st.dataframe(pd.DataFrame([{"ts": ts(r["ts"]), "case": r["case_id"], "actor": r["actor"], "kind": r["kind"],
                                    "data": r["data"][:400]} for r in rows]), hide_index=True, width="stretch")
