# Rule tuning from CASE-08967FCC

Case: bob logged into web-01 from a never-seen network (203.0) on web-01  
Verdict: malicious

- **baseline-new-location**: Current rule correctly triggered on SSH login from never-seen IP 203.0.113.45 with malicious threat intel score. Consider enhancing tuning to: (1) lower confidence threshold when threat intel tags include SSH brute-force/scanner, (2) auto-escalate to P1 if target is internet-facing production host with known vulnerabilities, (3) correlate with concurrent workstation activity to distinguish credential compromise from legitimate MFA from new location.
