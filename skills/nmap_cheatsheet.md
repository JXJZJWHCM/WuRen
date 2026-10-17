# Nmap Cheatsheet

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: 自动化渗透测试专属技能包
> 用途: 扩展 AI 智能体的实战能力与外部工具调用规范。

Nmap ("Network Mapper") is a free and open source utility for network discovery and security auditing.

## Host Discovery
- `nmap -sn <target>`: Ping scan (disable port scan).
- `nmap -Pn <target>`: Treat all hosts as online (skip host discovery).
- `nmap -PS <ports> <target>`: TCP SYN discovery on specific ports.
- `nmap -PA <ports> <target>`: TCP ACK discovery on specific ports.
- `nmap -PU <ports> <target>`: UDP discovery on specific ports.

## Port Scanning Techniques
- `nmap -sS <target>`: TCP SYN scan (Stealth scan, default requires root).
- `nmap -sT <target>`: TCP Connect scan (Default without root).
- `nmap -sU <target>`: UDP scan.
- `nmap -sA <target>`: TCP ACK scan (Detect firewall rules).
- `nmap -sW <target>`: TCP Window scan.
- `nmap -sM <target>`: TCP Maimon scan.

## Service Version and OS Detection
- `nmap -sV <target>`: Probe open ports to determine service/version info.
- `nmap -sV --version-intensity <0-9> <target>`: Set version scan intensity.
- `nmap -O <target>`: Enable OS detection.
- `nmap -A <target>`: Enable OS detection, version detection, script scanning, and traceroute.

## Script Scan (NSE)
- `nmap -sC <target>`: Scan with default NSE scripts.
- `nmap --script=<script_name> <target>`: Run a specific script.
- `nmap --script=vuln <target>`: Run vulnerability scanning scripts.
- `nmap --script=http* <target>`: Run all scripts starting with "http".
- `nmap --script-args <args> <target>`: Pass arguments to scripts.

## Timing and Performance
- `nmap -T<0-5> <target>`: Set timing template (higher is faster).
  - `T0` (Paranoid)
  - `T1` (Sneaky)
  - `T2` (Polite)
  - `T3` (Normal)
  - `T4` (Aggressive)
  - `T5` (Insane)
- `nmap --min-rate <number> <target>`: Send packets no slower than <number> per second.
- `nmap --max-retries <number> <target>`: Caps number of port scan probe retransmissions.

## Output
- `nmap -oN <file> <target>`: Output scan in normal format.
- `nmap -oX <file> <target>`: Output scan in XML format.
- `nmap -oG <file> <target>`: Output scan in Grepable format.
- `nmap -oA <basename> <target>`: Output in all three major formats at once.

## Examples
- **Fast scan**: `nmap -T4 -F <target>`
- **Comprehensive scan**: `nmap -sS -sV -sC -O -p- <target>`
- **Vulnerability scan**: `nmap -sV --script=vuln <target>`
