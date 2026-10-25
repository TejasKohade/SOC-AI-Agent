# Rule tuning from CASE-94CF818A

Case: Credential dumping (Mimikatz-like) activity on wks-bob-02  
Verdict: malicious

- **autosoc-credential-dumping**: Maintain strict detection on command line strings such as 'sekurlsa::logonpasswords' and 'privilege::debug', and integrate automated EDR prevention to block process execution prior to lsass handle acquisition.
