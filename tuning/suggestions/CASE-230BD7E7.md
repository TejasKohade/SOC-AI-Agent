# Rule tuning from CASE-230BD7E7

Case: Credential dumping (Mimikatz-like) activity on srv-win-04  
Verdict: benign

- **autosoc-credential-dumping**: Exclude process_access events to lsass.exe with access code 0x1000 (PROCESS_QUERY_LIMITED_INFORMATION) from triggering alerts. This access right is routinely used by legitimate system processes for informational queries. Consider implementing a whitelist for benign access codes or requiring multiple suspicious accesses within a time window, along with higher-privilege access codes (0x40, 0x40B, 0x1F3FFF) as correlation criteria.
