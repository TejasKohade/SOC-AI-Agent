# AutoSOC — streaming SOC demo script (~15 min)

A live, continuous demo: one endless mixed log feed, attacks hidden in it, caught and handled by AI,
graded honestly. This is the realistic picture (not one scripted attack at a time).

## Before the demo (5 min earlier)

1. **Check the Bedrock key.** It expires ~12 h after it was issued. If AWS says the key is expired,
   paste a fresh one into `AWS_BEARER_TOKEN_BEDROCK` in `.env`. (If it has expired, the AI quietly
   falls back to offline rules — the dashboard shows `bedrock: unavailable`.)
2. **Terminal 1 — dashboard:**
   ```bash
   .venv/bin/streamlit run ui/app.py
   ```
   Open http://localhost:8501. Sidebar: name `ana`, role **analyst**. Confirm it says `bedrock: ok`.
3. Leave the **Live SOC** tab open. Don't start the stream yet.

## Act 1 — the idea (1 min)

**Say:** "A real SOC sees one endless stream of logs from everything — servers, laptops, firewall,
email — with the occasional attack buried inside. Watch AutoSOC do that live. The AI is real (Claude
on AWS Bedrock); the company and its tools are simulated so we can run attacks safely."

Point at the empty **Live SOC** tab: counters at zero, "No incidents yet."

## Act 2 — start the stream (1 min)

**Terminal 2:**
```bash
.venv/bin/python -m autosoc stream --rate 5 --interval 30 --fresh
```

**Say:** "Five events a second of normal activity. Every 30 seconds it injects one attack, chosen at
random — sometimes a synthetic one, sometimes a **real recorded attack** from a public research dataset
(genuine Windows/Sysmon telemetry of Mimikatz, PsExec, and the like). The system doesn't know which,
or when."

Switch to the **Live SOC** tab (it auto-refreshes). Watch the **Live event stream** fill: each row is
tagged with a **source** (sshd, sysmon, firewall, email-gateway, …) and a **category**
(authentication, process, network, identity, email). "Step one is making sense of raw, mixed logs."

## Act 3 — the first attack lands (3 min)

Within ~30 s the counters move: **Attacks injected 1**, then an **incident** appears under
"Incidents by severity."

**Point out, on the incident card:**
- A **severity score** (0–100) and band (critical / high / medium). "Severity reflects the real
  situation: how deep the attack got × how important the machine is × the user's privilege, plus
  threat-intel and the AI's confidence — not just a rule's label."
- The **stages** (MITRE ATT&CK techniques) the AI mapped.
- Under it, the **case(s)**: verdict, confidence, the provider that answered (`bedrock`), and either
  ✅ actions already taken or ⏳ actions **awaiting approval**.

**Say:** "Two detection engines ran on every event: the signature rules, and behaviour baselines
learned from the normal feed — so it also catches things no rule was written for, like a login from a
never-seen network."

## Act 4 — approve a response (2 min)

Open the **Approvals** tab. For a disruptive action (isolate a host, disable an account):
- Walk the card: summary, verdict, evidence, the exact action, and its rollback.
- Click **Approve** as `ana` / analyst. For a tier-3 action, switch the sidebar to `lee` / **soc_lead**
  and approve again. "High-impact actions need two people; the AI can raise that bar but never lower it."

Open **Cases** → the case is now **closed ✅** with a written report.

## Act 5 — let a few more attacks run (2 min)

Leave it running through 2–3 more injections. Point out:
- Incidents are **ranked by severity** — the worst sits on top.
- **Real** recorded attacks (Mimikatz, PsExec, WMIC backdoor) produce critical incidents, same as the
  synthetic ones. "It works on genuine attack telemetry, not just our own test data."
- Normal activity keeps flowing and produces **no** incidents. "Low false-alarm rate is half the job."

## Act 6 — the honest scoreboard (2 min)

Open the **Scoreboard** tab.

**Say:** "Every attack we inject is secretly written down as ground truth — the detection side never
sees it. Here's the honest grade."

- **Detection rate** and **mean time to detect**.
- Split: **synthetic caught** vs **real OTRF captures caught**.
- The table: each attack, its ATT&CK id, synthetic or real, detected ✅ or ❌ missed, and latency.

## Close (1 min)

**Say:** "One stream in; categorised, detected two ways, correlated into incidents, scored by real
severity, and the risky actions routed to a human — most of it with no analyst touch. In production
the only thing that changes is the left-hand side: these same logs come from your machines via a log
shipper, and the simulated tools become your real EDR, firewall and identity provider."

Stop the stream with **Ctrl-C** in Terminal 2 — it prints the final scoreboard.

---

## Cheat sheet

| | Command |
|---|---|
| Dashboard | `.venv/bin/streamlit run ui/app.py` |
| Start stream | `.venv/bin/python -m autosoc stream --rate 5 --interval 30 --fresh` |
| Faster attacks (impatient room) | `… --interval 15` |
| Only real recorded attacks | `… --kind real` |
| Fixed-length run | `… --duration 120` |

## Tips

- Each attack takes ~20–30 s from injection to a scored incident (a short settle window plus the AI
  agents). Fill the wait by narrating the event stream and the categories.
- Watch the provider label on each case. `bedrock` = live Claude; `offline` = the key expired or AWS
  is unreachable, so it fell back to rules.
- If the room is impatient, use `--interval 15`.
- The dashboard reads the shared database, so you can keep clicking around while the stream runs in the
  terminal.
- Known rough edge: firing many attacks on the *same* host in the same few seconds can merge their
  incidents; with the normal 30 s spacing each attack gets its own.
