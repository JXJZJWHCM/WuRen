---
name: vulhub/aj-report/CNVD-2024-15077
description: Vulhub-based validation guidance for aj-report (N/A) with structured detection, bounded exploitation verification, and evidence capture.
version: 2.1
source: vulhub/aj-report/CNVD-2024-15077/README.md
source_type: vulhub
cve: N/A
product: aj-report
vuln_type: rce
severity: high
tags:
  - vulhub
  - auto-migrated
  - aj-report
  - rce
references:
  - local://vulhub/aj-report/CNVD-2024-15077/README.md
  - http://your-ip:9095`.
  - https://github.com/wy876/POC/blob/main/AJ-Report%E5%BC%80%E6%BA%90%E6%95%B0%E6%8D%AE%E5%A4%A7%E5%B1%8F%E5%AD%98%E5%9C%A8%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md
  - https://xz.aliyun.com/t/14460
trust_level: high
created_at: 2026-03-11T11:19:41.320917+00:00
updated_at: 2026-03-11T11:19:41.320917+00:00
---

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: Vulhub 漏洞复现指南
> 用途: AI 智能体可参考本指南中的靶场环境与 Payload 执行漏洞检测与验证。

## Overview
aj-report vulnerability validation playbook

Vulhub-based validation guidance for aj-report (N/A) with structured detection, bounded exploitation verification, and evidence capture.

## Applicability
Use only in authorized testing scope with legal approval.
Relevant identifier: N/A.

## Environment Preparation
1. Source reference: `vulhub/aj-report/CNVD-2024-15077/README.md`.
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
Key markers: N/A / aj-report / rce.

## Risk and Mitigation
Risk: may lead to unauthorized access, code execution, data exposure, or lateral movement.
Mitigation: patch affected components, enforce least privilege, reduce exposed attack surface, and enable monitoring + alerting.
