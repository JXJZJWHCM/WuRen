---
name: learned/recon/threat-intel-fusion-2026
description: Recon retrieval strategy fused with ATT&CK, OWASP, and annual threat intelligence.
version: 2.1
source: official-curated-2024-2026
source_type: learned_auto
cve: N/A
product: cross-domain
vuln_type: recon_methodology
severity: medium
tags:
  - learned-auto
  - recon
  - attck
  - owasp
  - threat-intel
references:
  - https://attack.mitre.org/resources/updates/
  - https://www.verizon.com/about/news/2025-data-breach-investigations-report
  - https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025
  - https://www.enisa.europa.eu/sites/default/files/2025-10/enisa-threat-landscape-2025_0.pdf
trust_level: high
created_at: 2026-03-11T11:00:50.359852+00:00
updated_at: 2026-03-11T11:00:50.359852+00:00
---

> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)
> 类别: 自动化渗透测试专属技能包
> 用途: 扩展 AI 智能体的实战能力与外部工具调用规范。

## 概述
Prioritize high-risk attack surface during recon: edge services, identity endpoints, third-party touchpoints, and cloud control planes.

## 适用条件
Use only in authorized assessments with explicit target scope and evidence retention requirements.

## 环境准备
Prepare inventory templates, baseline scanning outputs, and timeline normalization for evidence correlation.

## 检测步骤
Run layered enumeration (asset -> service -> version -> exposed function) and score targets by ATT&CK and OWASP relevance.

## 利用验证
Use minimum-impact verification only; avoid destructive behavior in recon stage.

## 证据要点
Capture discovery timestamp, fingerprint source, confidence score, and mapped risk category.

## 风险与修复
Main risks are scope drift and false positives; mitigate through scope locks and mandatory review checkpoints.
