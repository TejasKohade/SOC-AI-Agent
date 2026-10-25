# Rule tuning from CASE-DE6EC1F8

Case: Credential dumping (Mimikatz-like) activity on dc-01  
Verdict: benign

- **autosoc-credential-dumping**: Exclude svchost.exe → lsass.exe process access with access code 0x1000 (limited query access) from triggering alerts. Require access code 0x1410 (full access with query/read) or higher to differentiate legitimate system service behavior from actual credential dumping attempts on domain controllers.
