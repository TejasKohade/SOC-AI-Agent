# Rule tuning from CASE-B531BA61

Case: Credential dumping (Mimikatz-like) activity on srv-win-04  
Verdict: benign

- **autosoc-credential-dumping**: Exclude process_access events where process.name is svchost.exe or other system processes accessing lsass.exe with low access masks (0x1000), especially when user is an authorized admin on the host. Consider adding context filters for admin user role and low-risk access patterns.
