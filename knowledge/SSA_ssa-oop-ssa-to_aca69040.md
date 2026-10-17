# SSA for Object-Oriented Flows

> [!NOTE] 雾刃自动化渗透测试平台知识库 (WuRen Knowledge Base)
> 提供渗透测试方法论、ATT&CK框架与安全理论指导。

- Updated: 2026-03-11T11:17:11.773251+00:00

## Overview
Model object state transitions in SSA to identify unsafe flow transitions.

## Method
Track constructor influence, mutable state edges, and sink reachability.

## Result
Emit findings with call path, state mutation point, and fix recommendation.
