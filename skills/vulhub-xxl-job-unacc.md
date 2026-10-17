---
name: vulhub/xxl-job/unacc
description: Vulhub-based validation guidance for xxl-job (N/A) with structured detection, bounded exploitation verification, and evidence capture.
version: 2.1
source: vulhub/xxl-job/unacc/README.md
source_type: vulhub
cve: N/A
product: xxl-job
vuln_type: deserialization
severity: high
tags:
  - vulhub
  - auto-migrated
  - xxl-job
  - deserialization
references:
  - local://vulhub/xxl-job/unacc/README.md
  - http://your-ip:8080`
  - http://your-ip:9999`.
  - https://github.com/OneSourceCat/XxlJob-Hessian-RCE
  - https://landgrey.me/blog/18/
  - https://mp.weixin.qq.com/s/jzXIVrEl0vbjZxI4xlUm-g
trust_level: high
created_at: 2026-03-11T11:19:41.490599+00:00
updated_at: 2026-03-11T11:19:41.490599+00:00
---

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: Vulhub 漏洞复现指南
> 用途: AI 智能体可参考本指南中的靶场环境与 Payload 执行漏洞检测与验证。

## Overview
xxl-job vulnerability validation playbook

Vulhub-based validation guidance for xxl-job (N/A) with structured detection, bounded exploitation verification, and evidence capture.

## Applicability
Use only in authorized testing scope with legal approval.
Relevant identifier: N/A.

## Environment Preparation
1. Source reference: `vulhub/xxl-job/unacc/README.md`.
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
Key markers: N/A / xxl-job / deserialization.

## Risk and Mitigation
Risk: may lead to unauthorized access, code execution, data exposure, or lateral movement.
Mitigation: patch affected components, enforce least privilege, reduce exposed attack surface, and enable monitoring + alerting.
