# Nuclei Usage Guide

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: 自动化渗透测试专属技能包
> 用途: 扩展 AI 智能体的实战能力与外部工具调用规范。

Nuclei is a fast, template-based vulnerability scanner focused on extensive configurability, massive extensibility and ease of use.

## Basic Scan
- `nuclei -u <target>`: Scan a single URL.
  - Example: `nuclei -u https://example.com`
- `nuclei -l <list_of_urls.txt>`: Scan a list of URLs from a file.
  - Example: `nuclei -l urls.txt`

## Template Selection
- `nuclei -t <template_path>`: Run a specific template or directory of templates.
  - Example: `nuclei -u https://example.com -t cves/`
- `nuclei -t <template_path> -id <template_id>`: Run a specific template by ID.
  - Example: `nuclei -u https://example.com -id cve-2021-44228`
- `nuclei -tags <tag>`: Run templates based on tags.
  - Example: `nuclei -u https://example.com -tags cve,ssrf`
- `nuclei -etags <tag>`: Exclude templates based on tags.
  - Example: `nuclei -u https://example.com -tags cve -etags dos`
- `nuclei -s <severity>`: Run templates based on severity (info, low, medium, high, critical).
  - Example: `nuclei -u https://example.com -s critical,high`

## Filtering and Optimization
- `nuclei -rate-limit <number>`: Maximum number of requests to send per second (default 150).
- `nuclei -c <number>`: Maximum number of templates to be executed in parallel (default 25).
- `nuclei -timeout <number>`: Time to wait in seconds before timing out (default 5).
- `nuclei -retries <number>`: Number of times to retry a failed request (default 1).

## Output
- `nuclei -o <output_file>`: Write output to a file.
  - Example: `nuclei -u https://example.com -o results.txt`
- `nuclei -json`: Write output in JSONL(ines) format.
  - Example: `nuclei -u https://example.com -json -o results.json`
- `nuclei -silent`: Show only results in the output.
- `nuclei -v`: Show verbose output.

## Update
- `nuclei -update`: Update Nuclei engine to the latest version.
- `nuclei -ut`: Update Nuclei templates to the latest version.

## Examples
- **Scan for critical vulnerabilities**:
  `nuclei -u https://example.com -s critical`
- **Scan for CVEs**:
  `nuclei -u https://example.com -tags cve`
- **Scan list of subdomains for takeovers**:
  `nuclei -l subdomains.txt -t takeovers/`
