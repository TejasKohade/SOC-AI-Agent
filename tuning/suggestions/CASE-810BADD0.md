# Rule tuning from CASE-810BADD0

Case: Living-off-the-land binary used to download or execute a payload on srv-win-04  
Verdict: benign

- **autosoc-lolbin-exec**: Whitelist bitsadmin.exe downloads from redcanaryco/atomic-red-team domain when initiated by members of the IT admin security group. Alternatively, elevate detection thresholds to require multiple correlated malicious indicators (process injection + credential theft + C2 beaconing) to reduce false positives from authorized penetration testing activities.
