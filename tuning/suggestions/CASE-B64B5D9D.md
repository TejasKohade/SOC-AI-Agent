# Rule tuning from CASE-B64B5D9D

Case: Encoded PowerShell or download cradle on wks-alice-01  
Verdict: benign

- **autosoc-encoded-powershell**: Exclude PowerShell processes spawned by CcmExec.exe (Configuration Manager client) when running as SCCM service accounts (e.g., svc-sccm). Alternatively, whitelist encoded PowerShell commands that decode to Win32_OperatingSystem queries from known SCCM deployment infrastructure.
