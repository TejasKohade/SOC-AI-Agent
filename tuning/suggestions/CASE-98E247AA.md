# Rule tuning from CASE-98E247AA

Case: Living-off-the-land binary used to download or execute a payload on srv-win-04  
Verdict: benign

- **autosoc-lolbin-exec**: Whitelist mshta.exe execution with 'Get-Service' commands under user bob on srv-win-04, or add broader exception for service diagnostic commands from known admin users. Alternatively, require secondary indicators (network connections, file writes, suspicious child processes) before alerting on this pattern.
