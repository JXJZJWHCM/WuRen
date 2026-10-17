# Kali Linux Everything 原包全工具清单与 ATT&CK 映射指南

> [!NOTE] 雾刃自动化渗透测试平台知识库 (WuRen Knowledge Base)
> 提供渗透测试方法论、ATT&CK框架与安全理论指导。

- Updated: 2026-03-22 (Aligned with Kali Linux 2025.x / Everything Image)
- Category: 工具级战术映射

## 概述
作为雾刃(WRAPT)平台的 AI 渗透专家，你已被赋予通过 `run_kali_tool` 接口自主调用任何 Kali 内置工具的权限。为了帮助你更精准地选择武器，以下是 Kali Linux (Everything 版本) 中最核心的工具清单，并已严格映射到 MITRE ATT&CK 战术阶段。

**使用原则**：遇到特定场景时，不要仅依赖 Nmap 或 MSF。翻阅此清单，选择最垂直、最专业的工具进行打击。

---

## 1. 侦察 (Reconnaissance) & 发现 (Discovery)
*目标：获取目标域名、IP、端口、服务、目录结构、子域名、WAF 等信息。*

### 1.1 主机与端口扫描
- **nmap**: 端口扫描、服务指纹识别、操作系统推测、NSE 脚本引擎。
- **masscan**: 极速大范围端口扫描（适合 /8 网络）。
- **rustscan**: 类似 masscan，速度极快，支持自动将结果传递给 nmap。
- **naabu**: 快速可靠的端口扫描器，用 Go 编写。
- **netdiscover**: 局域网内基于 ARP 的存活主机发现。

### 1.2 DNS 与子域名枚举
- **subfinder**: 快速被动子域名枚举工具。
- **amass**: 深度 DNS 枚举、攻击面映射工具。
- **dnsenum**: 字典爆破和区域传输检查。
- **fierce**: 快速的 DNS 扫描与主机发现工具。

### 1.3 Web 目录爆破与爬虫
- **dirsearch**: 高效的 Web 路径扫描工具。
- **ffuf**: 极速的 Web 模糊测试工具（Fuzzer），可用于爆破目录、参数、Host 头。
- **gobuster**: 用 Go 编写的极速目录/DNS/VHost 爆破器。
- **wfuzz**: 灵活的 Web 应用 Fuzzer。
- **hakrawler**: 快速的 Web 爬虫，用于提取端点和 JS 文件。

### 1.4 指纹识别与 WAF 探测
- **whatweb**: 下一代 Web 扫描器，用于识别 CMS、Web 服务器、嵌入式设备。
- **wafw00f**: 识别并定位目标受何种 WAF 保护。
- **wappalyzer**: 识别网站使用的技术栈。

### 1.5 OSINT（开源情报）
- **theHarvester**: 针对域名的综合情报收集。
- **maltego**: 收集邮箱、子域、员工信息。
- **recon-ng**: 收集目标机构的 OSINT 信息。

---

## 2. 初始访问 (Initial Access) & 执行 (Execution)
*目标：通过漏洞利用、口令爆破或逻辑缺陷获取目标系统的立足点（Shell）。*

### 2.1 漏洞扫描与分析
- **nuclei**: 基于 YAML 模板的快速可定制漏洞扫描器（寻找 CVE 和配置错误）。
- **nikto**: 经典的 Web 服务器漏洞扫描器。
- **searchsploit**: 离线查询 Exploit-DB 中的漏洞利用脚本。

### 2.2 Web 漏洞利用 (SQLi/XSS/SSRF/LFI)
- **sqlmap**: 自动化 SQL 注入与数据库接管工具。
- **commix**: 自动化操作系统命令注入工具。
- **xsstrike**: 极具威胁的 XSS 自动化检测与利用工具。
- **tplmap**: 服务器端模板注入 (SSTI) 检测与利用工具。
- **lfisuite**: 自动化本地文件包含 (LFI) 利用工具。

### 2.3 密码爆破与身份验证绕过
- **hydra**: 支持多协议（SSH, FTP, RDP, HTTP 等）的快速网络登录破解工具。
- **medusa**: 类似于 hydra，稳定性与速度极佳。
- **john (John the Ripper)**: 离线密码哈希破解工具。
- **hashcat**: 极速的高级密码恢复工具。
- **cewl**: 根据目标网站内容生成定制化密码字典。

### 2.4 CMS 专杀工具
- **wpscan**: WordPress 漏洞扫描与枚举工具。
- **joomscan**: Joomla 漏洞扫描器。
- **droopescan**: Drupal 等 CMS 的扫描工具。

---

## 3. 权限提升 (Privilege Escalation)
*目标：从低权限用户提升至 root 或 SYSTEM。*

- **linux-exploit-suggester (les)**: 分析 Linux 内核版本，推荐可用的内核提权 CVE。
- **windows-exploit-suggester**: 分析 Windows 补丁情况，推荐提权 CVE。
- **peass-ng (linpeas / winpeas)**: 寻找系统中所有可能导致提权的配置错误（文件权限、密码遗留、SUID）。
- **gtfobins / lolbas**: (在线库) 查找如何滥用系统合法二进制文件提权。

---

## 4. 凭据访问 (Credential Access)
*目标：在已攻陷的系统中窃取内存密码、哈希或令牌。*

- **mimikatz**: Windows 下抓取明文密码、哈希、票据的终极神器。
- **impacket (如 secretsdump.py)**: 远程转储 Windows SAM、LSA 凭据和 NTDS.dit。
- **responder**: 毒化 LLMNR/NBT-NS/mDNS，抓取网络中的 NTLMv2 哈希。
- **crackmapexec**: 一款瑞士军刀，用于在活动目录环境中喷洒哈希（Pass-the-Hash）并转储凭据。
- **lapsus$ / rubeus**: 活动目录环境下的高级凭据提取与喷洒。

---

## 5. 横向移动 (Lateral Movement)
*目标：利用窃取到的凭据或哈希，在内网中移动到其他主机。*

- **impacket (psexec.py / wmiexec.py / smbexec.py)**: 利用 SMB 或 WMI 协议执行远程命令，实现横向移动。
- **proxychains4**: 强制任何 TCP 协议工具通过 Socks 代理进入内网。
- **chisel**: 快速、稳定的 TCP/UDP 隧道工具（基于 HTTP）。
- **ligolo-ng**: 高级内网穿透工具，比 proxychains 更底层（基于 Tun 接口）。
- **sshuttle**: 透明的代理工具，无需在目标机器上拥有管理员权限即可建立隧道。

---

## 6. 指挥与控制 (C2) & 综合渗透框架
*目标：维持对目标网络的长期、隐蔽的控制，并协同多工具作战。*

- **metasploit-framework (msfconsole)**: 地表最强开源渗透测试框架，包含 exploits, payloads, post, encoders。
- **sliver**: 用 Go 编写的高级跨平台 C2 框架（可用于替代商业版 Cobalt Strike）。
- **havoc**: 现代化的 C2 框架，专为绕过现代 EDR 设计。
- **empire / starkiller**: 强大的 PowerShell 和 Python 后渗透代理框架。

---

## 总结提醒

当你在执行 `run_kali_tool` 时：
1. **参数未知？** 先执行 `run_kali_tool("tool_name", "-h")` 或查询 `skills` 库。
2. **找不到工具？** 尝试不同的名称（如 `impacket-wmiexec` 而不是 `wmiexec.py`）。
3. **遇到 WAF？** 不要盲目用 sqlmap，先用 `wafw00f` 探测，再给 sqlmap 加上 `--tamper` 脚本。
4. **内网不出网？** 使用 `chisel` 建立隧道，配合 `proxychains` 调用 Nmap。