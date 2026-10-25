# Rule tuning from CASE-FF1A1473

Case: SSH brute force from a single source on web-01  
Verdict: malicious

- **autosoc-ssh-bruteforce**: Add a correlation sub-rule that triggers a 'brute force succeeded' critical alert when any SSH failure burst from a known-malicious IP is followed by a successful login from the same source IP within a configurable window (e.g., 60 seconds). This is distinct from the brute-force detection itself and should auto-escalate to Tier 3 containment. Additionally, consider lowering the failure threshold for external IPs with AbuseIPDB scores above 80 to trigger the rule after 5 failures rather than the current threshold.
