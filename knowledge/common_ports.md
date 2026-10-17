# Common Ports and Services

> [!NOTE] 雾刃自动化渗透测试平台知识库 (WuRen Knowledge Base)
> 提供渗透测试方法论、ATT&CK框架与安全理论指导。

| Port | Service | Description | Potential Vulnerabilities |
| :--- | :--- | :--- | :--- |
| **21** | FTP | File Transfer Protocol | Anonymous login, cleartext credentials, buffer overflows, brute force. |
| **22** | SSH | Secure Shell | Weak credentials, brute force, outdated versions (rare), key leakage. |
| **23** | Telnet | Unencrypted remote login | Cleartext credentials, man-in-the-middle attacks, no authentication. |
| **25** | SMTP | Simple Mail Transfer Protocol | Open relay, user enumeration, spam, spoofing. |
| **53** | DNS | Domain Name System | Zone transfer, DNS cache poisoning, amplification attacks. |
| **80** | HTTP | Hypertext Transfer Protocol | Web vulnerabilities (SQLi, XSS, etc.), unencrypted traffic. |
| **110** | POP3 | Post Office Protocol v3 | Cleartext credentials, brute force. |
| **135** | RPC | Microsoft RPC Endpoint Mapper | Enumeration, buffer overflows, DoS. |
| **139** | NetBIOS | NetBIOS Session Service | Null session, user enumeration, SMB vulnerabilities. |
| **143** | IMAP | Internet Message Access Protocol | Cleartext credentials, brute force. |
| **443** | HTTPS | HTTP Secure | Web vulnerabilities (SQLi, XSS), SSL/TLS misconfigurations (Heartbleed, POODLE). |
| **445** | SMB | Server Message Block | EternalBlue (MS17-010), null session, brute force, ransomware propagation. |
| **1433** | MSSQL | Microsoft SQL Server | Weak SA password, brute force, SQL injection, RCE (xp_cmdshell). |
| **3306** | MySQL | MySQL Database | Weak root password, brute force, UDF exploitation, file write access. |
| **3389** | RDP | Remote Desktop Protocol | BlueKeep, brute force, weak credentials, clipboard hijacking. |
| **5432** | PostgreSQL | PostgreSQL Database | Weak password, brute force, RCE (copy command), SQL injection. |
| **6379** | Redis | Redis Key-Value Store | Unauthenticated access, RCE (writing authorized_keys or cron jobs). |
| **8080** | HTTP-Alt | HTTP Alternative (often Tomcat/Jenkins) | Default credentials, manager console access, web vulnerabilities. |
| **27017**| MongoDB | MongoDB Database | Unauthenticated access, weak authentication, NoSQL injection. |
