# APT and OT/SCADA Advisory Highlights (2025-2026)

> [!NOTE] 雾刃自动化渗透测试平台知识库 (WuRen Knowledge Base)
> 提供渗透测试方法论、ATT&CK框架与安全理论指导。

- Last updated: 2026-03-11
- Content type: official advisory synthesis; no unauthorized exploitation instructions.

## Current focus areas

- Threat actors continue targeting high-value OT/SCADA and critical-sector environments.
- 2026 FBI alerts keep emphasizing social engineering, tailored pretexting, and mission-focused targeting.
- Joint advisories indicate sustained credential and identity-driven intrusion patterns.

## Defensive validation baseline

1. Enforce network segmentation between IT and OT layers.
2. Harden remote access with MFA, session controls, and anomaly detection.
3. Track edge-exposed services and patch by exploitability and blast radius.
4. Preserve full authentication and administrative audit trails with time synchronization.
5. Test with an authorized full chain: discover -> exploit validation -> persistence risk check -> lateral path -> report.

## References

- https://www.fbi.gov/investigate/cyber/news/apt-and-cybercriminals-target-ot-and-scada-systems
- https://www.ic3.gov/Alerts/2026
- https://www.fbi.gov/file-repository/kimsuky-targets-people-and-organizations-using-social-engineering.pdf
- https://www.fbi.gov/file-repository/united-front-work-department-targets-state-local-tribal-territorial-officials.pdf
