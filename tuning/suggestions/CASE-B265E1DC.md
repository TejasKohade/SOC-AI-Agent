# Rule tuning from CASE-B265E1DC

Case: Phishing email with look-alike domain or user report on mail-gw  
Verdict: malicious

- **autosoc-phishing-url**: Rule performed well with 99% confidence detection. Consider adding heuristic for homograph attacks and common Microsoft service look-alikes (login-microsoft, support-microsoft variants) to catch similar future campaigns earlier in the detection pipeline.
