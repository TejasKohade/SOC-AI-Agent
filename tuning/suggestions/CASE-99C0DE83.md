# Rule tuning from CASE-99C0DE83

Case: Phishing email with look-alike domain or user report on mail-gw  
Verdict: malicious

- **autosoc-phishing-url**: Extend detection coverage to include homograph attacks on cloud provider domains (Microsoft, Google, Amazon). Add pattern matching for common phishing URL paths like /reset, /login, /verify, /confirm with look-alike domains.
