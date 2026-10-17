# ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) 攻击框架全流程指南

> [!NOTE] 雾刃自动化渗透测试平台知识库 (WuRen Knowledge Base)
> 提供渗透测试方法论、ATT&CK框架与安全理论指导。

- Updated: 2026-03-22 (Aligned with ATT&CK v18 / October 2025 Release)
- Category: 战术级理论架构

## 概述

MITRE ATT&CK 是一个基于真实世界观察结果的全球化对抗战术和技术知识库（当前最新版本涵盖 14 个战术、216 项技术和 475 项子技术）。在雾刃 (WRAPT) AI 自动化渗透测试平台中，所有的攻击规划 (Main Planner) 与底层执行 (SubAI) 必须严格遵循该流程，以确保测试的深度、广度和专业性。

以下是 ATT&CK 框架的 14 个核心战术阶段（Tactics），它们构成了攻击者的完整生命周期。

---

## 1. 侦察 (Reconnaissance)
**目标**：收集有关目标组织的信息，为未来的操作做准备。
- **关键技术**：主动扫描 (Active Scanning)、被动 DNS 收集 (Passive DNS)、端口探测 (Port Scanning)、指纹识别 (Fingerprinting)、公开情报收集 (OSINT)。
- **AI 职责**：SubAI_Recon 负责进行全方位资产测绘，识别出 Web 框架、服务版本、暴露路径及存在的 WAF/IDS 等防御机制。

## 2. 资源构建 (Resource Development)
**目标**：建立支持操作的基础设施或能力。
- **关键技术**：购买域名、租赁 VPS、构建或修改恶意软件、获取僵尸网络、生成 Payload。
- **AI 职责**：SubAI_Exploit 根据识别出的防御体系（WAF），自动组装或编写（POC Writer）能够绕过防御的定制化 Payload。

## 3. 初始访问 (Initial Access)
**目标**：在目标网络中获得最初的立足点。
- **关键技术**：钓鱼攻击 (Phishing)、利用面向公众的应用 (Exploit Public-Facing Application)、供应链攻击 (Supply Chain Compromise)、利用有效凭证。
- **AI 职责**：SubAI_Exploit 通过投递 EXP，针对 Web 漏洞（SQLi, RCE, 逻辑漏洞等）或服务漏洞进行打击，获取第一个 Shell。

## 4. 执行 (Execution)
**目标**：在本地或远程系统上运行恶意代码。
- **关键技术**：命令行接口 (Command and Scripting Interpreter)、系统服务 (System Services)、WMI、计划任务 (Scheduled Task)。
- **AI 职责**：在获取立足点后，通过系统命令行（bash, cmd, powershell）执行后续的渗透指令。

## 5. 持久化 (Persistence)
**目标**：在系统重启或凭证更改后依然保持对系统的访问。
- **关键技术**：注册表运行键 (Registry Run Keys)、修改启动文件夹、创建隐藏服务 (Create Service)、WebShell。
- **AI 职责**：SubAI_PostExploit 会自动植入持久化后门（如通过 `add_cron_job`, `add_registry_run_key` 等工具）。

## 6. 权限提升 (Privilege Escalation)
**目标**：获得更高级别的系统权限（如 root 或 SYSTEM）。
- **关键技术**：利用内核漏洞 (Exploitation for Privilege Escalation)、DLL 劫持、服务配置错误、Bypass UAC、滥用 SUID 权限。
- **AI 职责**：SubAI_PostExploit 运行提权检查脚本（如 LinPEAS/WinPEAS 逻辑的替代工具），尝试利用内核漏洞或提权配置错误。

## 7. 防御规避 (Defense Evasion)
**目标**：避免被防御系统发现。
- **关键技术**：卸载/修改安全软件、混淆/加密 Payload (Obfuscated Files or Information)、修改时间戳 (Timestomp)、隐藏文件和目录、清除日志。
- **AI 职责**：SubAI 必须通过 `detect_waf` 和 `find_bypass_strategies` 进行预判，并在后渗透阶段通过 `clear_logs` 清理痕迹。

## 8. 凭据访问 (Credential Access)
**目标**：窃取账户名称和密码。
- **关键技术**：LSASS 内存转储、抓取浏览器密码、提取 /etc/shadow、Kerberoasting、强制身份验证。
- **AI 职责**：SubAI_PostExploit 使用 Mimikatz 等技术或直接读取配置文件来提取凭据，为横向移动做准备。

## 9. 探测 (Discovery)
**目标**：了解系统内部环境和网络拓扑。
- **关键技术**：网络服务扫描 (Network Service Scanning)、系统网络配置探测、进程探测、文件和目录探测、域信任发现。
- **AI 职责**：利用 `scan_internal_network` 和系统内置命令（如 `netstat`, `ipconfig`, `arp`）摸清内网资产。

## 10. 横向移动 (Lateral Movement)
**目标**：在目标网络中移动到其他系统。
- **关键技术**：Pass the Hash (PtH)、Pass the Ticket (PtT)、远程桌面协议 (RDP)、SMB/Windows 管理规范 (WMI)、SSH 劫持。
- **AI 职责**：SubAI_PostExploit 获取凭据后，使用 `psexec`, `wmiexec`, 或代理工具向域控或核心数据库服务器移动。

## 11. 收集 (Collection)
**目标**：收集对目标有价值的数据。
- **关键技术**：自动化收集 (Automated Collection)、屏幕截图、从本地系统收集数据、从网络共享收集数据。
- **AI 职责**：搜寻敏感文件（如数据库连接串、私钥、配置文件），并通过浏览器自动化工具进行页面截图。

## 12. 指挥与控制 (Command and Control - C2)
**目标**：与受控系统进行通信，控制恶意软件。
- **关键技术**：应用层协议 (Application Layer Protocol - 如 HTTP/HTTPS)、加密通道、域名生成算法 (DGA)、代理。
- **AI 职责**：通过 MSF RPC 或建立隧道（如 Chisel, FRP）保持稳定、加密的控制链路。

## 13. 数据渗出 (Exfiltration)
**目标**：将收集到的数据偷运出目标网络。
- **关键技术**：通过 C2 通道渗出、加密数据、压缩数据。
- **AI 职责**：平台通常在合规测试中停止于收集阶段，但理论上可通过打包文件向外传输。

## 14. 影响 (Impact)
**目标**：破坏目标系统的可用性或破坏数据（如勒索软件）。
- **关键技术**：数据破坏、磁盘擦除、系统关机/重启、服务拒绝 (DoS)。
- **AI 职责**：在标准的授权渗透测试中，AI 严禁执行破坏性操作。

---
**AI 指导原则**：在生成攻击计划时，必须明确指出当前属于 ATT&CK 的哪个战术阶段，并按照逻辑顺序递进，严禁跳过“初始访问”直接幻想“横向移动”。
