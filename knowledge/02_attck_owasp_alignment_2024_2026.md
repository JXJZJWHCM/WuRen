# ATT&CK and OWASP Alignment Update (2024-2026)

> [!NOTE] 雾刃自动化渗透测试平台知识库 (WuRen Knowledge Base)
> 提供渗透测试方法论、ATT&CK框架与安全理论指导。

- Last updated: 2026-03-11
- Use case: unify detection, exploitation validation, lateral analysis, and reporting contracts.

## MITRE ATT&CK

- ATT&CK updates indicate Enterprise ATT&CK v18 (2025-10) as current on the updates page.
- Pipeline output should map phase evidence to ATT&CK techniques for traceable reporting.

## OWASP baseline

- OWASP Top 10 (Web) has a 2025 edition.
- OWASP API Security Top 10 latest stable edition remains 2023.
- OWASP Top 10 for LLM Applications has a 2025 edition (includes agentic abuse and prompt/system leakage concerns).

## Five-phase mapping suggestions

1. Recon: map discovery artifacts to ATT&CK Reconnaissance and Resource Development.
2. Exploit: map verified findings to OWASP risk classes and ATT&CK execution-related techniques.
3. Persistence: map sustained-access evidence to ATT&CK Persistence and Privilege Escalation.
4. Lateral: map movement and credential evidence to ATT&CK Lateral Movement/Credential Access.
5. Report: require ATT&CK technique IDs + OWASP categories + remediation priority.

## References

- https://attack.mitre.org/resources/updates/
- https://owasp.org/Top10/
- https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
