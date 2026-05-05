# 🔍 Brute Force Detection Using Splunk & Windows Event Logs

## 📌 Problem
Detect brute-force login attacks by identifying repeated failed authentications followed by a successful login, using Splunk as a SIEM tool.

## 🎯 Objectives
- Simulate realistic Windows authentication log data
- Ingest logs into Splunk for analysis
- Write SPL detection queries to identify attack patterns
- Flag suspicious IPs using threshold and correlation logic

## 🗃️ Logs Used
Simulated Windows Authentication Logs (CSV format)

| Event ID | Meaning |
|---|---|
| 4625 | Failed Login Attempt |
| 4624 | Successful Login |

## 🛠️ Tools Used
- **Splunk** — SIEM platform for log analysis
- **Python** — Log simulation and data generation
- **Windows Event IDs** — Authentication log standards

## 🔎 Detection Logic (SPL Queries)

### Query 1 — Find All Failed Logins
index=main source="windows_auth_logs.csv" event_id=4625

Retrieves all failed login attempts from the dataset.

### Query 2 — Count Failures by IP Address
index=main source="windows_auth_logs.csv" event_id=4625
| stats count by ip_address
| sort -count
Groups failed logins by IP address to identify
the highest offenders.

### Query 3 — Flag IPs Exceeding Threshold
index=main source="windows_auth_logs.csv" event_id=4625
| stats count by ip_address
| where count > 5
| sort -count

Flags any IP address with more than 5 failed login
attempts as suspicious.

### Query 4 — Correlation: Failed Then Successful Login
index=main source="windows_auth_logs.csv"
| stats count(eval(event_id="4625")) as failures, count(eval(event_id="4624")) as successes by ip_address
| where failures > 5 AND successes > 0
| sort -failures

Identifies IPs that repeatedly failed and then
successfully logged in — the classic brute force pattern.

## 📸 Results


![Query 1 - All Failures](screenshots/query1_all_failures.png)




![Query 2 - Count by IP](screenshots/query2_count_by_ip.png)




![Query 3 - Threshold](screenshots/query3_threshold.png)




![Query 4 - Smoking Gun](screenshots/query4_smoking_gun.png)



## 🧠 Analysis
The IP address 192.168.1.105 generated 60+ failed login
attempts against the "admin" account within minutes,
followed by a successful authentication. This pattern
is consistent with an automated brute-force attack.

A second IP address was also flagged by the detection
logic, demonstrating that the queries work beyond a
single hardcoded attacker; they detect the pattern,
not just the IP.

## ✅ Conclusion
Detection logic successfully identified attacker IPs 
using threshold and correlation analysis in Splunk.
In a real SOC environment, the next steps would be:
- Block flagged IPs at the firewall
- Reset compromised account credentials
- Investigate lateral movement from the attacker IP
- Escalate to Tier 2 analyst for further investigation

## 👤 Author
Fredrick Agufenwa  
Cybersecurity Student | SOC & Threat Detection
