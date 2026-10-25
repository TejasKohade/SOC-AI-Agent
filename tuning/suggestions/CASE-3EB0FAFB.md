# Rule tuning from CASE-3EB0FAFB

Case: Encoded PowerShell or download cradle on wks-alice-01  
Verdict: malicious

- **autosoc-encoded-powershell**: Add a correlation condition to automatically elevate severity to critical and trigger host isolation when encoded PowerShell is spawned by an Office application (winword.exe, excel.exe, powerpnt.exe) AND a subsequent outbound network connection is observed within 60 seconds, reducing the need for manual analyst approval for isolation in this high-confidence scenario.
- **autosoc-encoded-powershell**: Add detection logic for rapid successive local logon events (3+ within 10 seconds) on the same host following a PowerShell execution alert, and correlate these as a composite indicator of post-exploitation activity to trigger a separate high-severity alert.
