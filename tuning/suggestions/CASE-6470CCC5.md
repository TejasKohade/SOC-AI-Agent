# Rule tuning from CASE-6470CCC5

Case: admin tool net.exe run on wks-carol-03 outside business hours on wks-carol-03  
Verdict: benign

- **baseline-off-hours-admin**: Add exception for user bob or exclude net.exe localgroup command queries from this rule. This command is administrative reconnaissance, not privilege escalation or lateral movement. Consider refining rule to focus on dangerous admin tools (psexec, wmic lateral movement patterns, credential dumping utilities) rather than informational queries.
