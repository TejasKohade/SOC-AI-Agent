# Rule tuning from CASE-27C7ECE8

Case: Encoded PowerShell or download cradle on wks-alice-01  
Verdict: false_positive

- **autosoc-encoded-powershell**: Add an exclusion condition: suppress alerts when process.parent.name is 'CcmExec.exe' AND user.name matches a maintained allowlist of known SCCM service accounts (e.g., 'svc-sccm'), AND the decoded PowerShell command contains only benign WMI/CIM inventory queries with no download cradle indicators (e.g., no 'IEX', 'DownloadString', 'WebClient', 'Invoke-Expression', 'Invoke-WebRequest', or URL patterns).
