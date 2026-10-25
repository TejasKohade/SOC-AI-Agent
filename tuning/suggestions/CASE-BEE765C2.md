# Rule tuning from CASE-BEE765C2

Case: LSASS process memory accessed (credential dumping) on srv-win-04  
Verdict: benign

- **autosoc-lsass-access**: Exclude LSASS process_access events from svchost.exe with access codes 0x1000 or lower, as these represent legitimate system authentication and token management operations rather than credential dumping attempts. Focus detection on suspicious access masks (0x1F1FFF or equivalent) combined with non-system processes.
