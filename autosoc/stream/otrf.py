"""Adapter for OTRF Security-Datasets: real Windows/Sysmon logs of lab attacks.

These are genuine telemetry captures (not synthetic) published by the Open Threat Research Forge for
defensive detection engineering. Each file is one attack technique recorded end to end. We map the
raw Windows event-log rows to the same ECS-ish shape the SIEM uses, tag each with a source and
category, and remap the lab host/user onto our own inventory so an attack lands on a real asset.

No attack command strings are printed by this module; they live only inside the event records that
flow through the normal detection pipeline.
"""
import glob
import json
import os

from .. import config

DATASET_DIR = config.ROOT / "data" / "datasets" / "otrf" / "json"

# OTRF technique folder -> (MITRE id, a label, the ATT&CK tactic)
TECHNIQUES = {
    "empire_mimikatz_logonpasswords": ("T1003.001", "LSASS credential dump (Mimikatz)", "credential_access"),
    "psh_lsass_memory_dump_comsvcs": ("T1003.001", "LSASS memory dump via comsvcs.dll", "credential_access"),
    "empire_schtasks_creation_standard_user": ("T1053.005", "Scheduled task persistence", "persistence"),
    "cmd_bitsadmin_download_psh_script": ("T1197", "BITS job payload download", "defense_evasion"),
    "cmd_mshta_vbscript_execute_psh": ("T1218.005", "mshta VBScript proxy execution", "defense_evasion"),
    "empire_wmic_add_user_backdoor": ("T1136.001", "Backdoor account via WMIC", "persistence"),
    "empire_shell_net_localgroup_administrators": ("T1069.001", "Local admin group discovery", "discovery"),
    "empire_psexec_dcerpc_tcp_svcctl": ("T1021.002", "Lateral movement via PsExec/SMB", "lateral_movement"),
}


def _text(v):
    return v if isinstance(v, str) else ("" if v is None else str(v))


def _convert(r, host, user):
    """One OTRF row -> a flat ECS event, or None if it is not one we model."""
    chan, eid = r.get("Channel", ""), r.get("EventID")
    base = {"host.name": host, "event.ingested": None, "event.dataset": "otrf"}

    def proc():
        img = _text(r.get("Image") or r.get("NewProcessName"))
        parent = _text(r.get("ParentImage") or r.get("ParentProcessName"))
        return {**base, "event.module": "sysmon", "event.action": "process_start",
                "winlog.event_id": 1, "user.name": user,
                "process.name": img.split("\\")[-1].lower(), "process.command_line": _text(r.get("CommandLine")),
                "process.parent.name": parent.split("\\")[-1].lower()}

    if "Sysmon" in chan and eid == 1:
        return proc()
    if chan in ("Security", "security") and eid == 4688:
        return proc()
    if "Sysmon" in chan and eid == 3:  # network connection
        return {**base, "event.module": "sysmon", "event.action": "network_connection", "winlog.event_id": 3,
                "user.name": user, "process.name": _text(r.get("Image")).split("\\")[-1].lower(),
                "destination.ip": _text(r.get("DestinationIp")), "destination.port": r.get("DestinationPort")}
    if "Sysmon" in chan and eid == 10:  # process access (e.g. LSASS read)
        return {**base, "event.module": "sysmon", "event.action": "process_access", "winlog.event_id": 10,
                "user.name": user, "process.name": _text(r.get("SourceImage")).split("\\")[-1].lower(),
                "process.target.name": _text(r.get("TargetImage")).split("\\")[-1].lower(),
                "process.granted_access": _text(r.get("GrantedAccess"))}
    if chan in ("Security", "security") and eid == 4720:  # a user account was created
        return {**base, "event.module": "windows", "event.action": "user_created", "winlog.event_id": 4720,
                "user.name": user, "user.target.name": _text(r.get("TargetUserName") or r.get("SamAccountName"))}
    if chan in ("Security", "security") and eid in (4732, 4728):  # added to a privileged group
        return {**base, "event.module": "windows", "event.action": "added_to_group", "winlog.event_id": eid,
                "user.name": user, "user.target.name": _text(r.get("MemberName") or r.get("TargetUserName")),
                "group.name": _text(r.get("TargetUserName") or r.get("GroupName"))}
    return None


def _file_for(name):
    hits = sorted(glob.glob(str(DATASET_DIR / name / "*.json")))
    return hits[0] if hits else None


def available():
    """Techniques whose dataset is present on disk."""
    return {k: v for k, v in TECHNIQUES.items() if _file_for(k)}


def load(name, host, user, limit=400):
    """Return (events, meta) for one technique, remapped onto `host`/`user`.

    Events keep their original relative timing; the simulator re-stamps them to 'now'.
    `limit` keeps the burst demo-sized (the raw captures hold thousands of rows)."""
    path = _file_for(name)
    if not path:
        raise FileNotFoundError(name)
    mitre, label, tactic = TECHNIQUES[name]
    rows = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    rows.sort(key=lambda r: _text(r.get("@timestamp")))
    out = []
    for r in rows:
        ev = _convert(r, host, user)
        if ev is None:
            continue
        ev = {k: v for k, v in ev.items() if v not in (None, "")}
        ev["_otrf"] = name
        out.append(ev)

    # The raw captures are mostly repeated process-access noise; keep the events detection
    # actually keys on (process starts, account changes, LSASS reads, outbound connections)
    # so the signal survives the demo-sized cap, then restore time order.
    def rank(e):
        act = e["event.action"]
        if act in ("process_start", "user_created", "added_to_group"):
            return 0
        if act == "process_access" and e.get("process.target.name") == "lsass.exe":
            return 1
        if act == "network_connection":
            return 2
        return 3
    out.sort(key=lambda e: (rank(e), _text(e.get("@timestamp"))))
    out = out[:limit]
    out.sort(key=lambda e: _text(e.get("@timestamp")))
    meta = {"technique": name, "mitre": mitre, "label": label, "tactic": tactic, "events": len(out),
            "source": "OTRF Security-Datasets (real capture)"}
    return out, meta
