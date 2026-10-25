# Rule tuning from CASE-C235DFEA

Case: Phishing email with look-alike domain or user report on mail-gw  
Verdict: malicious

- **autosoc-phishing-url**: Rule performed effectively with 0.99 confidence detection. Consider adding enhancement to detect typo-squatting patterns using edit-distance algorithms against common lookalike domains (e.g., 's' substituted with '0', common transpositions) to catch similar variants earlier in future campaigns
