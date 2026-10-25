# Rule tuning from CASE-0B71EEB0

Case: Phishing email with look-alike domain or user report on mail-gw  
Verdict: malicious

- **autosoc-phishing-url**: Rule successfully triggered on malicious URL; consider expanding to detect homograph domains with character substitutions (e.g., zero-O, one-L) in known brand names like 'microsoft', 'apple', 'google' to catch similar attacks earlier
