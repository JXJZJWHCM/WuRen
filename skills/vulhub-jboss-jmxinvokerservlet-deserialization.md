---
name: vulhub/jboss/CVE-2017-12149
description: Vulhub-based validation guidance for jboss (CVE-2017-12149) with structured detection, bounded exploitation verification, and evidence capture.
version: 2.1
source: vulhub/jboss/JMXInvokerServlet-deserialization/README.md
source_type: vulhub
cve: CVE-2017-12149
product: jboss
vuln_type: rce
severity: high
tags:
  - vulhub
  - auto-migrated
  - jboss
  - rce
  - CVE-2017-12149
references:
  - local://vulhub/jboss/JMXInvokerServlet-deserialization/README.md
  - http://www.freebuf.com/sectool/88908.html
  - http://your-ip:8080/`
  - https://download.vulhub.org/download/deserialization/DeserializeExploit.jar
  - https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  - https://github.com/frohoff/ysoserial
  - https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149
  - https://paper.seebug.org/312/
  - https://www.seebug.org/vuldb/ssvid-89723
trust_level: high
created_at: 2026-03-11T11:19:41.385371+00:00
updated_at: 2026-03-11T11:19:41.385371+00:00
---

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: Vulhub 漏洞复现指南
> 用途: AI 智能体可参考本指南中的靶场环境与 Payload 执行漏洞检测与验证。

## Overview
jboss CVE-2017-12149 validation playbook

Vulhub-based validation guidance for jboss (CVE-2017-12149) with structured detection, bounded exploitation verification, and evidence capture.

## Applicability
Use only in authorized testing scope with legal approval.
Relevant identifier: CVE-2017-12149.

## Environment Preparation
1. Source reference: `vulhub/jboss/JMXInvokerServlet-deserialization/README.md`.
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
Key markers: CVE-2017-12149 / jboss / rce.

## Risk and Mitigation
Risk: may lead to unauthorized access, code execution, data exposure, or lateral movement.
Mitigation: patch affected components, enforce least privilege, reduce exposed attack surface, and enable monitoring + alerting.
