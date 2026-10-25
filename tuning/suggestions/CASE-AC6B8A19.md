# Rule tuning from CASE-AC6B8A19

Case: Phishing email with look-alike domain or user report on mail-gw  
Verdict: malicious

- **autosoc-phishing-url**: Enhance rule to flag emails with URLs containing typosquatted domains (character substitution patterns like '0' for 'o', '1' for 'l') combined with common phishing pretext keywords ('password reset', 'action required', 'verify account'). Current confidence of 99 on login-micros0ft.test validates the rule's effectiveness; consider adding visual similarity scoring to catch additional variants.
