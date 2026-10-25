# Rule tuning from CASE-8CCAC035

Case: SSH brute force from a single source on web-01  
Verdict: malicious

- **autosoc-ssh-bruteforce**: Enhance rule to correlate SSH brute force attempts with concurrent DNS queries to suspicious domains from the same host, as this pattern may indicate a compromised system attempting to contact command-and-control infrastructure.
- **autosoc-ssh-bruteforce**: Lower brute force attempt threshold from current setting to trigger alerts on 10+ failed attempts within 10 seconds (currently triggered at 18 attempts in 7 seconds), enabling faster detection and response.
