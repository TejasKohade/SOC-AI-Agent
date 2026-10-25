# Rule tuning from CASE-A869F9D7

Case: carol logged into web-01 from a never-seen network (203.0) on web-01  
Verdict: malicious

- **baseline-new-location**: Increase detection sensitivity for SSH logins from known malicious IPs (threat intel score >80) by triggering automatic account lockdown and MFA challenge, rather than alerting only. Consider integrating real-time threat intelligence feeds to lower alert thresholds for high-confidence malicious sources.
