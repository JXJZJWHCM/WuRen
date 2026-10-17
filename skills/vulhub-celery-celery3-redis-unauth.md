---
name: vulhub/celery/celery3_redis_unauth
description: Vulhub-based validation guidance for celery (N/A) with structured detection, bounded exploitation verification, and evidence capture.
version: 2.1
source: vulhub/celery/celery3_redis_unauth/README.md
source_type: vulhub
cve: N/A
product: celery
vuln_type: deserialization
severity: high
tags:
  - vulhub
  - auto-migrated
  - celery
  - deserialization
references:
  - local://vulhub/celery/celery3_redis_unauth/README.md
  - https://blog.csdn.net/SKI_12/article/details/85015803
  - https://docs.celeryproject.org/en/stable/userguide/calling.html#serializers
  - https://docs.celeryproject.org/en/stable/userguide/configuration.html
  - https://www.bookstack.cn/read/celery-3.1.7-zh/8d5b10e3439dbe1f.md#dhfmrk
  - https://www.jianshu.com/p/52552c075bc0
  - https://www.runoob.com/w3cnote/python-redis-intro.html
trust_level: high
created_at: 2026-03-11T11:19:41.327143+00:00
updated_at: 2026-03-11T11:19:41.327143+00:00
---

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: Vulhub 漏洞复现指南
> 用途: AI 智能体可参考本指南中的靶场环境与 Payload 执行漏洞检测与验证。

## Overview
celery vulnerability validation playbook

Vulhub-based validation guidance for celery (N/A) with structured detection, bounded exploitation verification, and evidence capture.

## Applicability
Use only in authorized testing scope with legal approval.
Relevant identifier: N/A.

## Environment Preparation
1. Source reference: `vulhub/celery/celery3_redis_unauth/README.md`.
2. Reproduce target environment in an isolated lab.
3. Prepare logging, snapshot, and rollback controls before execution.

## Detection Steps
1. Identify exposed service and version fingerprint.
2. Build minimal verification request based on vulnerable behavior.
3. Record response artifacts and confidence level.

## Exploitation Validation
Perform minimum-impact validation and keep execution bounded.
- `docker compose up -d`
- `docker compose logs celery`
- `docker compose exec celery ls -l /tmp`

## Evidence
Preserve request parameters, response snippets, command output, privilege context, and timestamps.
Key markers: N/A / celery / deserialization.

## Risk and Mitigation
Risk: may lead to unauthorized access, code execution, data exposure, or lateral movement.
Mitigation: patch affected components, enforce least privilege, reduce exposed attack surface, and enable monitoring + alerting.
