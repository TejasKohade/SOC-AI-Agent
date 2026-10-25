# Rule tuning from CASE-EA17AAAE

Case: Encoded PowerShell or download cradle on wks-alice-01  
Verdict: false_positive

- **autosoc-encoded-powershell**: Add a whitelist for PowerShell processes spawned by CcmExec.exe with benign decoded commands such as Get‑CimInstance to suppress similar alerts.
