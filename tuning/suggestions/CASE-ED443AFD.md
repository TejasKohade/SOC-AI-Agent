# Rule tuning from CASE-ED443AFD

Case: Phishing email with look-alike domain or user report on mail-gw  
Verdict: malicious

- **autosoc-phishing-url**: Extend the rule to also match zero-substitution and common homoglyph variants of high-value impersonation targets (e.g., 'micros0ft', 'micr0soft', 'rn' substituting 'm') at the mail gateway ingress stage to enable pre-delivery rejection rather than post-delivery quarantine.
- **autosoc-phishing-url**: Add a correlated alert condition: when multiple users receive emails from the same look-alike domain within a short time window (e.g., < 5 minutes), escalate severity to 'critical' automatically to trigger broader recipient sweep actions.
