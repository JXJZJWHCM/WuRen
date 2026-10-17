---
name: vulhub/fastjson/CVE-2017-18349
description: Vulhub-based validation guidance for fastjson (CVE-2017-18349) with structured detection, bounded exploitation verification, and evidence capture.
version: 2.1
source: vulhub/fastjson/1.2.24-rce/README.md
source_type: vulhub
cve: CVE-2017-18349
product: fastjson
vuln_type: rce
severity: high
tags:
  - vulhub
  - auto-migrated
  - fastjson
  - rce
  - CVE-2017-18349
references:
  - local://vulhub/fastjson/1.2.24-rce/README.md
  - http://evil.com/TouchFile.class`:
  - http://xxlegend.com/2017/04/29/title-%20fastjson%20%E8%BF%9C%E7%A8%8B%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96poc%E7%9A%84%E6%9E%84%E9%80%A0%E5%92%8C%E5%88%86%E6%9E%90/
  - http://your-ip:8090`
  - https://github.com/mbechler/marshalsec
  - https://www.freebuf.com/vuls/208339.html
trust_level: high
created_at: 2026-03-11T11:19:41.353515+00:00
updated_at: 2026-03-11T11:19:41.353515+00:00
---

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: Vulhub 漏洞复现指南
> 用途: AI 智能体可参考本指南中的靶场环境与 Payload 执行漏洞检测与验证。

## Overview
fastjson CVE-2017-18349 validation playbook

Vulhub-based validation guidance for fastjson (CVE-2017-18349) with structured detection, bounded exploitation verification, and evidence capture.

## Applicability
Use only in authorized testing scope with legal approval.
Relevant identifier: CVE-2017-18349.

## Environment Preparation
1. Source reference: `vulhub/fastjson/1.2.24-rce/README.md`.
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
Key markers: CVE-2017-18349 / fastjson / rce.

## Risk and Mitigation
Risk: may lead to unauthorized access, code execution, data exposure, or lateral movement.
Mitigation: patch affected components, enforce least privilege, reduce exposed attack surface, and enable monitoring + alerting.
