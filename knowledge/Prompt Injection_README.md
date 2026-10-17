# Prompt Injection Security Baseline

> [!NOTE] 雾刃自动化渗透测试平台知识库 (WuRen Knowledge Base)
> 提供渗透测试方法论、ATT&CK框架与安全理论指导。

- Updated: 2026-03-11T11:17:11.773251+00:00

## Overview
Prompt injection risks target instruction hierarchy and tool invocation boundaries in AI systems.

## Threat Model
Model attacker control over user content, retrieved context, external tools, and response channels.

## Testing Focus
Validate system prompt protection, tool-call gating, retrieval poisoning resistance, and output policy enforcement.

## Evidence Contract
Capture prompt context, model output, tool traces, and policy decision logs with timestamps.

## Mitigation
Use strict policy layers, signed retrieval sources, least-privilege tools, and post-generation filters.
