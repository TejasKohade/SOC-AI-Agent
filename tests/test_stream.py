"""The continuous stream: categorisation, real-dataset ingestion, detection and the scoreboard."""
from autosoc import db, incidents
from autosoc.stream import otrf, simulator
from autosoc.stream.categorize import categorize
from autosoc.stream.engine import StreamEngine, scoreboard


def test_categorisation_tags_every_source():
    for action, (src, cat) in {"ssh_login_failed": ("sshd", "authentication"),
                               "process_start": ("sysmon", "process"),
                               "dns_query": ("dns", "network"),
                               "email_delivered": ("email-gateway", "email"),
                               "user_created": ("windows-security", "identity")}.items():
        ev = {"event.action": action}
        assert categorize(ev) == (src, cat)
        assert ev["event.category"] == cat


def test_real_otrf_datasets_present_and_parse():
    avail = otrf.available()
    assert len(avail) >= 6, "real attack datasets should be downloaded"
    for name in avail:
        evs, meta = otrf.load(name, "srv-win-04", "bob")
        assert evs and meta["mitre"].startswith("T")
        assert all(e["host.name"] == "srv-win-04" for e in evs)


def test_stream_detects_injected_attacks():
    eng = StreamEngine(rate=500, interval=999)
    eng.warmup(250)
    for origin, _ in simulator.attack_catalogue():
        eng.inject_attack(origin)
    eng._work(now=float("inf"))
    sb = scoreboard()
    assert sb["injected"] >= 10
    # torture test fires every attack on shared hosts at once; still expect most caught
    assert sb["detection_rate"] >= 0.75
    assert sb["by_origin"]["real"]["detected"] >= 5   # real captures are detected, not just synthetic


def test_incidents_ranked_by_severity():
    eng = StreamEngine(rate=500, interval=999)
    eng.warmup(200)
    eng.inject_attack(technique="empire_mimikatz_logonpasswords")
    eng._work(now=float("inf"))
    incs = incidents.list_open()
    assert incs
    scores = [i["severity_score"] for i in incs]
    assert scores == sorted(scores, reverse=True)
    assert all(i["severity"] in ("low", "medium", "high", "critical") for i in incs)
