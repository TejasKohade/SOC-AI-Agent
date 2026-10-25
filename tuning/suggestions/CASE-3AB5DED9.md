# Rule tuning from CASE-3AB5DED9

Case: Phishing email with look-alike domain or user report on mail-gw  
Verdict: malicious

- **autosoc-phishing-url**: Extend rule scope to include look-alike domain patterns with common misspellings (e.g., 'micros0ft' with numeric substitutions). Current rule successfully detected this campaign; recommend adding pattern-based detection for homograph attacks to catch variants earlier.
