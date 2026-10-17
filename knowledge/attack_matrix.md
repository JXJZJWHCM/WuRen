# MITRE ATT&CK Matrix Summary

> [!NOTE] 雾刃自动化渗透测试平台知识库 (WuRen Knowledge Base)
> 提供渗透测试方法论、ATT&CK框架与安全理论指导。

The MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) framework is a comprehensive matrix of tactics and techniques used by threat actors during cyberattacks.

## 1. Reconnaissance
The adversary is trying to gather information they can use to plan for future operations.
- **Active Scanning**: Scanning IP blocks, vulnerability scanning.
- **Search Open Technical Databases**: querying WHOIS, DNS, certificates.
- **Search Open Websites/Domains**: Social media, search engines.
- **Gather Victim Identity Information**: Email addresses, employee names.

## 2. Resource Development
The adversary is trying to establish resources they can use to support operations.
- **Acquire Infrastructure**: Domains, DNS servers, VPS.
- **Compromise Accounts**: Social media accounts, email accounts.
- **Compromise Infrastructure**: Botnets, web servers.
- **Develop Capabilities**: Malware, exploits, tools.

## 3. Initial Access
The adversary is trying to get into your network.
- **Phishing**: Spearphishing attachments, links.
- **Drive-by Compromise**: Exploiting browser vulnerabilities.
- **Exploit Public-Facing Application**: Web servers, databases.
- **Valid Accounts**: Using stolen credentials.

## 4. Execution
The adversary is trying to run malicious code.
- **Command and Scripting Interpreter**: PowerShell, Python, Bash.
- **Native API**: Windows API.
- **Scheduled Task/Job**: Cron, Task Scheduler.
- **User Execution**: Malicious file, link.

## 5. Persistence
The adversary is trying to maintain their foothold.
- **Boot or Logon Autostart Execution**: Registry keys, startup folders.
- **Create Account**: Local account, domain account.
- **Scheduled Task/Job**: Persistence via scheduled tasks.
- **Server Software Component**: IIS modules, SQL stored procedures.

## 6. Privilege Escalation
The adversary is trying to gain higher-level permissions.
- **Abuse Elevation Control Mechanism**: UAC bypass, sudo caching.
- **Access Token Manipulation**: Token theft, impersonation.
- **Exploitation for Privilege Escalation**: Kernel exploits, service exploits.
- **Process Injection**: DLL injection, process hollowing.

## 7. Defense Evasion
The adversary is trying to avoid being detected.
- **Deobfuscate/Decode Files or Information**: Base64, XOR.
- **Hide Artifacts**: Hidden files, alternate data streams.
- **Impair Defenses**: Disable antivirus, firewall.
- **Masquerading**: Mimicking legitimate filenames or services.

## 8. Credential Access
The adversary is trying to steal account names and passwords.
- **Brute Force**: Password guessing, spraying.
- **Credentials from Password Stores**: Browser passwords, password managers.
- **OS Credential Dumping**: LSASS memory, SAM hive.
- **Steal or Forge Kerberos Tickets**: Golden Ticket, Silver Ticket.

## 9. Discovery
The adversary is trying to figure out your environment.
- **Account Discovery**: Listing users, groups.
- **File and Directory Discovery**: Listing files, permissions.
- **Network Service Scanning**: Port scanning, service enumeration.
- **System Information Discovery**: OS version, hostname, IP address.

## 10. Lateral Movement
The adversary is trying to move through your environment.
- **Exploitation of Remote Services**: SMB, RDP vulnerabilities.
- **Internal Spearphishing**: Phishing internal users.
- **Lateral Tool Transfer**: Copying tools between systems.
- **Remote Services**: RDP, SSH, SMB.

## 11. Collection
The adversary is trying to gather data of interest to their goal.
- **Archive Collected Data**: Zip, Rar.
- **Audio Capture**: Microphone recording.
- **Data from Local System**: Files, clipboard.
- **Screen Capture**: Screenshots.

## 12. Command and Control
The adversary is trying to communicate with compromised systems to control them.
- **Application Layer Protocol**: HTTP, DNS.
- **Encrypted Channel**: SSL/TLS.
- **Ingress Tool Transfer**: Downloading tools.
- **Multi-Stage Channels**: Using intermediate C2 servers.

## 13. Exfiltration
The adversary is trying to steal data.
- **Exfiltration Over C2 Channel**: Sending data over C2.
- **Exfiltration Over Alternative Protocol**: ICMP, DNS.
- **Exfiltration Over Physical Medium**: USB drive.
- **Scheduled Transfer**: Exfiltrating at specific times.

## 14. Impact
The adversary is trying to manipulate, interrupt, or destroy your systems and data.
- **Data Destruction**: Wiping disk, deleting files.
- **Data Encrypted for Impact**: Ransomware.
- **Defacement**: Changing website content.
- **Denial of Service**: Network DoS, endpoint DoS.
