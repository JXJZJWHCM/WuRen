---
name: vulhub/skywalking/8.3.0-sqli
description: Vulhub-based validation guidance for skywalking (N/A) with structured detection, bounded exploitation verification, and evidence capture.
version: 2.1
source: vulhub/skywalking/8.3.0-sqli/README.md
source_type: vulhub
cve: N/A
product: skywalking
vuln_type: sql_injection
severity: low
tags:
  - vulhub
  - auto-migrated
  - skywalking
  - sql_injection
references:
  - local://vulhub/skywalking/8.3.0-sqli/README.md
  - http://your-ip:8080`
  - https://github.com/apache/skywalking/commit/0bd81495965d801315dd7417bb17333ae0eccf3b#diff-ec87a1cdf66cdb37574d9eafd4d72d99ed94a38c4a8ff2aa9c7b8daeff502a2c
  - https://mp.weixin.qq.com/s/hB-r523_4cM0jZMBOt6Vhw
trust_level: high
created_at: 2026-03-11T11:19:41.451446+00:00
updated_at: 2026-03-11T11:19:41.451446+00:00
---

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: Vulhub 漏洞复现指南
> 用途: AI 智能体可参考本指南中的靶场环境与 Payload 执行漏洞检测与验证。

## Overview
skywalking vulnerability validation playbook

Vulhub-based validation guidance for skywalking (N/A) with structured detection, bounded exploitation verification, and evidence capture.

## Applicability
Use only in authorized testing scope with legal approval.
Relevant identifier: N/A.

## Environment Preparation
1. Source reference: `vulhub/skywalking/8.3.0-sqli/README.md`.
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
Key markers: N/A / skywalking / sql_injection.

## Risk and Mitigation
Risk: may lead to unauthorized access, code execution, data exposure, or lateral movement.
Mitigation: patch affected components, enforce least privilege, reduce exposed attack surface, and enable monitoring + alerting.
