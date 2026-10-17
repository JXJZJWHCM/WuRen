---
name: vulhub/struts2/CVE-2023-50164
description: Vulhub-based validation guidance for struts2 (CVE-2023-50164) with structured detection, bounded exploitation verification, and evidence capture.
version: 2.1
source: vulhub/struts2/s2-066/README.md
source_type: vulhub
cve: CVE-2023-50164
product: struts2
vuln_type: path_traversal
severity: low
tags:
  - vulhub
  - auto-migrated
  - struts2
  - path_traversal
  - CVE-2023-50164
references:
  - local://vulhub/struts2/s2-066/README.md
  - http://your-ip:8080/shell.jsp`.
  - http://your-ip:8080`
  - https://cwiki.apache.org/confluence/display/WW/s2-066
  - https://y4tacker.github.io/2023/12/09/year/2023/12/Apache-Struts2-%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E5%88%86%E6%9E%90-S2-066/
trust_level: high
created_at: 2026-03-11T11:19:41.471497+00:00
updated_at: 2026-03-11T11:19:41.471497+00:00
---

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: Vulhub 漏洞复现指南
> 用途: AI 智能体可参考本指南中的靶场环境与 Payload 执行漏洞检测与验证。

## Overview
struts2 CVE-2023-50164 validation playbook

Vulhub-based validation guidance for struts2 (CVE-2023-50164) with structured detection, bounded exploitation verification, and evidence capture.

## Applicability
Use only in authorized testing scope with legal approval.
Relevant identifier: CVE-2023-50164.

## Environment Preparation
1. Source reference: `vulhub/struts2/s2-066/README.md`.
2. Reproduce target environment in an isolated lab.
3. Prepare logging, snapshot, and rollback controls before execution.

## Detection Steps
1. Identify exposed service and version fingerprint.
2. Build minimal verification request based on vulnerable behavior.
3. Record response artifacts and confidence level.

## Exploitation Validation
Perform minimum-impact validation and keep execution bounded.
- `docker compose up -d`

## Evidence
Preserve request parameters, response snippets, command output, privilege context, and timestamps.
Key markers: CVE-2023-50164 / struts2 / path_traversal.

## Risk and Mitigation
Risk: may lead to unauthorized access, code execution, data exposure, or lateral movement.
Mitigation: patch affected components, enforce least privilege, reduce exposed attack surface, and enable monitoring + alerting.
