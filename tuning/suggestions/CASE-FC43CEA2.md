# Rule tuning from CASE-FC43CEA2

Case: rare process net.exe first seen on dc-01 on dc-01  
Verdict: benign

- **baseline-rare-process**: Add baseline exception for user=carol on asset=dc-01 executing net.exe with parent=powershell.exe; alternatively implement allowlist for net.exe commands when executed by members of IT-Infra group with admin role on domain controllers to reduce false positive rate on administrative assets
