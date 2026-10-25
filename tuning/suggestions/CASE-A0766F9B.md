# Rule tuning from CASE-A0766F9B

Case: LSASS process memory accessed (credential dumping) on dc-01  
Verdict: false_positive

- **autosoc-lsass-access**: Exclude LSASS access events when: (1) source process is svchost.exe, system, or lsass.exe AND access mask is ≤0x1000 (PROCESS_QUERY_LIMITED_INFORMATION); OR (2) require access mask ≥0x1400 (PROCESS_VM_READ) to detect actual memory read attempts. This reduces false positives on domain controllers while preserving detection of actual credential dumping techniques.
