# Rule tuning from CASE-2EA3129D

Case: Encoded PowerShell or download cradle on wks-alice-01  
Verdict: benign

- **autosoc-encoded-powershell**: Add a whitelist condition to ignore events where the parent process is CcmExec.exe and the command is limited to benign inventory queries.
