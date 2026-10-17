---
name: learned/report/attck-owasp-evidence-contract-2026
description: Reporting contract with ATT&CK/OWASP mapping and explicit evidence-gap tagging.
version: 2.1
source: official-curated-2024-2026
source_type: learned_auto
cve: N/A
product: reporting
vuln_type: evidence_standard
severity: medium
tags:
  - learned-auto
  - report
  - evidence
  - attck
  - owasp
references:
  - https://attack.mitre.org/resources/updates/
  - https://owasp.org/Top10/
  - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  - https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
  - https://www.nist.gov/cyberframework
trust_level: high
created_at: 2026-03-11T11:00:50.359852+00:00
updated_at: 2026-03-11T11:00:50.359852+00:00
---

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: 自动化渗透测试专属技能包
> 用途: 扩展 AI 智能体的实战能力与外部工具调用规范。

## 概述
Reporting stage must convert multi-phase execution output into citable, reproducible, remediation-focused evidence.

## 适用条件
Use at pipeline completion or controlled interruption points.

## 环境准备
Prepare phase_summary, phase_evidence, phase_log, and unified severity rubric.

## 检测步骤
Map each conclusion to ATT&CK techniques and OWASP categories with confidence labels.

## 利用验证
If detection exists without exploitation proof, mark retries, blockers, and follow-up recommendations explicitly.

## 证据要点
Keep source links, command summaries, timeline entries, and remediation priorities together.

## 风险与修复
Main risk is non-reproducible reporting; mitigate with strict output schema validation.
