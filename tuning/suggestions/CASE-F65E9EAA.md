# Rule tuning from CASE-F65E9EAA

Case: Phishing email with look-alike domain or user report on mail-gw  
Verdict: malicious

- **autosoc-phishing-url**: Extend the rule to include lookalike/homoglyph domain detection (e.g., character substitution patterns such as '0' for 'o', '1' for 'l') to enable pre-delivery blocking rather than relying solely on post-delivery URL reputation checks. Additionally, consider lowering the alert threshold for emails with both a typosquatted sender domain and a password-reset lure keyword combination.
