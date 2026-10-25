# Rule tuning from CASE-0C504CB9

Case: Local account created and added to Administrators on app-02  
Verdict: benign

- **autosoc-new-local-admin**: Require the rule to also detect a subsequent group membership change (e.g., net localgroup Administrators ...) before flagging as high severity.
