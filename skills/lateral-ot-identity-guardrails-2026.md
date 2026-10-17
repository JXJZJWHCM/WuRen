---
name: learned/lateral/ot-identity-guardrails-2026
description: Lateral movement validation with OT and identity guardrails from 2025-2026 advisories.
version: 2.1
source: official-curated-2024-2026
source_type: learned_auto
cve: N/A
product: ot-scada-identity
vuln_type: lateral_movement_methodology
severity: high
tags:
  - learned-auto
  - lateral
  - ot
  - scada
  - identity
  - apt
references:
  - https://www.fbi.gov/investigate/cyber/news/apt-and-cybercriminals-target-ot-and-scada-systems
  - https://www.ic3.gov/Alerts/2026
  - https://www.fbi.gov/file-repository/kimsuky-targets-people-and-organizations-using-social-engineering.pdf
  - https://www.fbi.gov/file-repository/united-front-work-department-targets-state-local-tribal-territorial-officials.pdf
trust_level: high
created_at: 2026-03-11T11:00:50.359852+00:00
updated_at: 2026-03-11T11:00:50.359852+00:00
---

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: 自动化渗透测试专属技能包
> 用途: 扩展 AI 智能体的实战能力与外部工具调用规范。

## 概述
Lateral stage should test whether segmentation and identity controls can stop chain progression.

## 适用条件
Use for authorized enterprise or critical-infrastructure validation with strict boundary controls.

## 环境准备
Prepare segment map, jump-path audit controls, identity policy matrix, and emergency rollback flow.

## 检测步骤
Test segmentation and identity boundaries first, then validate whether movement attempts are detected and contained.

## 利用验证
Do not execute destructive or out-of-scope movement; keep validation bounded to approved paths.

## 证据要点
Output a path graph with per-hop evidence, triggered controls, and uncovered blind spots.

## 风险与修复
Main risk is critical-service disruption; mitigate through maintenance windows and dual-operator approval.
