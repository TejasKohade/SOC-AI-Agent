"""Live ingestion: events posted to /ingest take the same path as a scenario replay."""
import pytest
from fastapi.testclient import TestClient

from autosoc import db, ingest, pipeline, telemetry
from autosoc.agents import orchestrator
from autosoc.mocks.app import app


@pytest.fixture
def client():
    ingest.reset()
    return TestClient(app)


def test_ingest_triggers_bruteforce_across_requests(client):
    fail = {"source": "auditd", "host": "web-01", "action": "ssh_login_failed", "src_ip": "203.0.113.45",
            "user": "deploy"}
    # Nine single posts then a batch: the threshold window must survive between requests.
    for _ in range(9):
        assert client.post("/ingest", json=fail).json()["alerts"] == []
    r = client.post("/ingest", json=[fail, {"event": {"module": "auditd", "action": "ssh_login_success"},
                                            "host": {"name": "web-01"}, "source": {"ip": "203.0.113.45"},
                                            "user": {"name": "deploy"}}])
    assert r.status_code == 200 and len(r.json()["alerts"]) == 1
    assert db.one("SELECT case_id FROM alerts WHERE id=?", (r.json()["alerts"][0],))["case_id"] is None

    ingest.flush()
    cases = client.get("/ingest/status").json()["cases"]
    assert len(cases) == 1
    c = orchestrator.get_case(cases[0]["id"])
    assert c["verdict"] == "malicious"
    tools = {a["tool"] for a in orchestrator.case_actions(c["id"])}
    assert {"firewall.block_ip", "idp.revoke_sessions"} <= tools  # nested ECS success login was seen


def test_scenario_through_ingest_matches_replay(client):
    path = pipeline.find_scenario("ssh-bruteforce-01")
    sc = telemetry.load_scenario(path)
    events = [{k: v for k, v in e.items() if k not in ("@timestamp", "_id")} for e in telemetry.generate(sc)]
    for i in range(0, len(events), 25):
        client.post("/ingest", json=events[i:i + 25])
    ingest.flush()
    case_ids = [c["id"] for c in client.get("/ingest/status").json()["cases"]]
    alerts = db.query("SELECT id, rule_id, case_id FROM alerts WHERE run_id='live'")
    res = pipeline.evaluate_soc(sc, case_ids, alerts)
    assert res["passed"], res["checks"]


def test_syslog_sshd_lines(client):
    lines = "\n".join([f"Oct 17 10:00:{i:02d} web-01 sshd[811]: Failed password for invalid user admin "
                       f"from 198.51.100.7 port {40000 + i} ssh2" for i in range(10)] +
                      ["Oct 17 10:00:30 web-01 sshd[811]: Accepted password for admin from 198.51.100.7 port 40100 ssh2",
                       "Oct 17 10:00:31 web-01 CRON[90]: (root) CMD (run-parts /etc/cron.hourly)"])
    r = client.post("/ingest/syslog", content=lines, headers={"content-type": "text/plain"}).json()
    assert r["accepted"] == 12 and len(r["alerts"]) == 1
    ev = ingest.parse_syslog(lines.splitlines()[10])
    assert ev["event.action"] == "ssh_login_success" and ev["user.name"] == "admin"
    assert ev["source.ip"] == "198.51.100.7" and ev["host.name"] == "web-01"
    assert ingest.parse_syslog(lines.splitlines()[0])["user.invalid"] is True
    assert ingest.parse_syslog(lines.splitlines()[-1])["event.action"] == "syslog_message"
