# AutoSOC — end-to-end SOC automation POC

A fully mocked SOC where real AI agents (Claude Sonnet 4.6 on Amazon Bedrock) take a scripted attack
from raw logs to a closed case. A human approves only the risky response actions.
Built from the spec in the *AutoSOC: End-to-End SOC Automation POC* doc.

```
telemetry generator ──► asyncio queue ──► SIEM (Sigma rules / SQLite) ──► alert queue
   ──► orchestrator: dedupe → enrich (threat intel, inventory, open CVEs) → triage agent
       → investigation agent → response agent → approval gate (tiers 0-3) → SOAR playbook runner
       → mock EDR / firewall / IdP / email → verify → reporting agent → case closed
vulnerability management: asset sync → scan → score → track → VM agent → ticket → remediate (same gate) → rescan
```

## Quick start

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r requirements.txt
cp .env.example .env            # add AWS_BEARER_TOKEN_BEDROCK
.venv/bin/python -m autosoc list
.venv/bin/python -m autosoc run ssh-bruteforce-01 --fresh
.venv/bin/streamlit run ui/app.py   # dashboard at http://localhost:8501
```

| Command | What it does |
|---|---|
| `python -m autosoc run <id> [--approve] [--fresh]` | replay one scenario (`--approve` auto-approves tier 2/3 for demos) |
| `python -m autosoc run-all [--kind soc\|vm]` | every scenario on a clean state, prints the POC metrics |
| `python -m autosoc vm-cycle` | run VM jobs 1-10 once |
| `python -m autosoc scheduler` | APScheduler: all 11 VM jobs on their triggers, plus approval escalation |
| `python -m autosoc mocks [--host 0.0.0.0]` | serve the mock tool APIs and the live `/ingest` feed on :8000 (set `MOCK_BASE_URL` to use them over HTTP) |
| `python tools/send_logs.py <file> [--speed N]` | stream a scenario, raw syslog or JSONL file to `/ingest` as a live feed |
| `.venv/bin/python -m pytest` | 29 tests: every scenario, live ingestion + guardrails, offline and deterministic |

## Continuous stream mode (the realistic demo)

Scenario replay and `/ingest` both handle one attack at a time. `stream` mode is the realistic picture:
one never-ending mixed feed with attacks hidden in it.

```bash
.venv/bin/python -m autosoc stream --rate 5 --interval 30 --fresh   # 5 events/s, an attack every 30 s
```

Open the dashboard's **Live SOC** tab to watch it. Every second it emits normal activity from many
sources (SSH and Windows logons, process starts, DNS, email). Every 30 seconds it injects one attack,
picked at random from:

- **synthetic techniques** - SSH brute force, phishing, encoded PowerShell, impossible-travel login, data exfiltration
- **real recorded attacks** - genuine Windows/Sysmon telemetry from the
  [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets): Mimikatz LSASS dump, LSASS dump via
  comsvcs, scheduled-task persistence, WMIC backdoor account, local-admin discovery, PsExec lateral
  movement, BITS download, mshta execution. (Downloaded under `data/datasets/otrf/`.)

What happens to each event, in order:

1. **Categorise** - tagged with a source type (sshd, sysmon, firewall, email, ...) and a category
   (authentication, process, network, identity, email, web).
2. **Detect** - two detectors run: the Sigma signature rules *and* behaviour baselines learned from the
   normal feed (login from a new network, a rare admin tool on a host, first-time host access,
   off-hours admin activity). Baselines catch what no signature was written for.
3. **Correlate** - cases that share a host or user within an hour are linked into one **incident**, so a
   multi-stage attack reads as one story.
4. **Score severity** - each incident gets a 0-100 score from how deep the attack reached x asset
   importance x user privilege + intel confirmation + the agents' confidence, mapped to
   low / medium / high / critical. The **Live SOC** tab ranks incidents by this score.
5. **Respond by severity** - the same risk-tier approval gate: low-impact actions run automatically,
   disruptive ones wait for approval.

The **Scoreboard** tab grades the system honestly: every injected attack is recorded as ground truth
(the detection side never sees it), then compared against what was caught, split by synthetic vs. real,
with the mean time to detect and any misses listed.

## Going live

Scenario replay is how the POC is tested; the same pipeline also takes a live log feed.

```bash
.venv/bin/python -m autosoc reset                 # optional: start from a clean case list
.venv/bin/python -m autosoc mocks                 # tool APIs + POST /ingest on :8000
.venv/bin/python tools/send_logs.py scenarios/soc/01_ssh_bruteforce.yml            # real time (~80 s)
.venv/bin/python tools/send_logs.py scenarios/soc/01_ssh_bruteforce.yml --speed 5  # 5x faster
```

Open the **Live logs** tab in the dashboard to watch events arrive (it refreshes every 3 s): rows that
match a rule are amber, rows that are part of an alert are red and show the case they joined. The
brute-force case then appears in **Cases** with the same verdict and actions as
`python -m autosoc run ssh-bruteforce-01`.

**Endpoints** (on the mocks server; `--host 0.0.0.0` to accept logs from other machines):

| Endpoint | Body |
|---|---|
| `POST /ingest` | one ECS event or a JSON array; nested (`{"source": {"ip": ...}}`) or dotted keys, or the scenario short aliases. `@timestamp` may be ISO-8601 or epoch; missing → ingest time |
| `POST /ingest/syslog` | raw text, one BSD-syslog line per event. sshd `Failed password` / `Accepted password\|publickey` lines become `ssh_login_failed` / `ssh_login_success` with `user.name` and `source.ip`; other lines are stored as `syslog_message` |
| `GET /ingest/status` | counters, alerts still settling, and the cases opened from the live feed |

**How logs would arrive in production.** Endpoint and server agents collect the logs and a shipper
forwards them as JSON: Sysmon and Windows Security events through Winlogbeat or the Wazuh agent,
Linux `auth.log`/auditd through the Wazuh agent, auditbeat or Fluent Bit's tail input, network devices
over syslog into Vector or rsyslog. Vector (`http` sink, `encoding.codec = "json"`) or Fluent Bit
(`http` output, `format json`) posts to `/ingest`; a raw syslog stream can go to `/ingest/syslog`
unparsed. In a real deployment the SIEM (Wazuh, Elastic, Sentinel, Splunk) usually does this
collection and runs the detections, and AutoSOC would take its alerts by webhook instead; `/ingest`
shows the whole chain in one process.

**Everything after ingestion is identical to the scenario path:** each event gets an id and timestamp,
then `siem.store_event` → `siem.RuleEngine.process` → `siem.store_alert` → `orchestrator.process_alert`
(enrich, triage, investigate, respond, approval gate, playbook, verify, report). The server keeps one
long-lived rule engine, so threshold rules such as the brute force count events across requests.
Alerts go to a background worker, so a shipper's POST returns in milliseconds. The one live-only
behaviour: an alert waits until its activity (same host and source IP, or host and user) has been
quiet for 10 s, at most 120 s (`INGEST_SETTLE_QUIET_S`, `INGEST_SETTLE_MAX_S`), before the agents
see it. A replay hands the agents the whole window at once; live, the agents would otherwise judge a
brute force before the successful login that follows it arrives.

## Layout

| Path | Contents |
|---|---|
| `scenarios/soc`, `scenarios/vm` | attack and VM scenarios; each carries its expected outcome, so it is also a test |
| `siem/rules` | Sigma-style YAML detection rules |
| `playbooks` | YAML playbooks: steps, base tier, `raise_if`, rollback is automatic per tool |
| `inventory`, `intel`, `vulns` | mock CMDB/IdP, threat-intel feed, NVD+EPSS+KEV snapshot (fictional CVE ids) |
| `autosoc/agents` | orchestrator, triage, investigation, response, reporting, VM agent |
| `autosoc/soar.py` | playbook runner + risk-tier approval gate |
| `autosoc/vm` | scoring (`risk = CVSS×w_asset×w_exposure + 3·KEV + 5·EPSS`) and the lifecycle jobs |
| `autosoc/ingest.py` | live log feed: `POST /ingest` (ECS JSON), `POST /ingest/syslog` (raw lines), `GET /ingest/status` |
| `tools/send_logs.py` | log shipper stand-in: streams a file to `/ingest` with real-time pacing |
| `autosoc/mocks/app.py` | FastAPI mocks: `/intel`, `/edr`, `/firewall`, `/idp`, `/email`, `/tickets`, `/patch` |
| `ui/app.py` | Streamlit: live logs, cases, approvals, vulnerabilities, tickets, tool state, audit |
| `tuning/suggestions` | rule-tuning suggestions written by the reporting agent |

## Guardrails (as specified)

- **Least privilege:** per-agent tool allowlists; only the playbook runner can call state-changing APIs.
- **Structured output:** each agent's JSON is validated; invalid output → one retry → escalate to a human.
- **Evidence required:** a `malicious` verdict must cite real event ids or malicious intel hits; response
  parameters must appear in the case facts.
- **Prompt-injection defence:** attacker-controlled fields are wrapped as `<untrusted>` and flagged
  (the PowerShell scenario hides "ignore previous instructions…" in the payload).
- **Budgets:** ≤ 20 tool calls and ≤ 5 LLM calls per alert; responses cached; backoff on 429/5xx.
- **Tiers come from playbooks:** the gate only raises them (low confidence, critical asset, single-source
  evidence, admin/exec user, server host, agent request). Tier 3 needs an analyst **and** a SOC lead.
- **Reversible + audited:** every action records its rollback; every prompt, tool call and decision is in `audit`.

## LLM providers

`LLM_PROVIDER=bedrock` is the provider. If it fails (expired key, outage, throttling past the retries),
OpenRouter is tried when `OPENROUTER_API_KEY` is set, then the deterministic offline stand-in.
The UI marks each case with the provider that answered.

**Amazon Bedrock** uses the Converse API with a Bedrock API key (`AWS_BEARER_TOKEN_BEDROCK`) in
`AWS_REGION=ap-southeast-2`, through the `au.` inference profile so requests stay in Australia.
`BEDROCK_MODEL=au.anthropic.claude-sonnet-4-6` is the newest Claude model this account has enabled; the
Claude 5.x models need model access granted in the Bedrock console first. Bedrock is pay-per-token, not
a free tier. Short-term Bedrock API keys expire after 12 hours: when it expires, calls fall through to the
next provider until you paste a new key into `.env`.

`LLM_PROVIDER=offline` forces the offline stand-in; the tests use it.
