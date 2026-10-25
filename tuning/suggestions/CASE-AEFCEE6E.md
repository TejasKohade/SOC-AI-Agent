# Rule tuning from CASE-AEFCEE6E

Case: Phishing email with look-alike domain or user report on mail-gw  
Verdict: malicious

- **autosoc-phishing-url**: Extend rule to detect homograph/typosquatting variations of known vendor domains (e.g., login-micros0ft.test vs. login.microsoft.com). Consider adding sender domain verification to flag spoofed IT support addresses.
