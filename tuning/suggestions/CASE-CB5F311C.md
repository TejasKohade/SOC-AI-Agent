# Rule tuning from CASE-CB5F311C

Case: Phishing email with look-alike domain or user report on mail-gw  
Verdict: malicious

- **autosoc-phishing-url**: Enhance rule to detect homoglyph-based domains impersonating known technology vendors (e.g., microsoft, apple, google) by flagging domains with high visual similarity scores; consider adding lookalike domain scoring to improve catch rate for similar campaigns
