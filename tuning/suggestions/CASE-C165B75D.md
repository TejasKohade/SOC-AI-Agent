# Rule tuning from CASE-C165B75D

Case: Phishing email with look-alike domain or user report on mail-gw  
Verdict: malicious

- **autosoc-phishing-url**: Expand rule to detect homograph domains (visual lookalikes of major vendors) in addition to known malicious URLs. Current rule successfully detected login-micros0ft.test; consider adding classifier for common typosquatting patterns (0/O substitution, missing/extra characters) as preventive measure for zero-day lookalike campaigns.
