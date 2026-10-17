# Threat Landscape Baseline (2024-2026)

> [!NOTE] 雾刃自动化渗透测试平台知识库 (WuRen Knowledge Base)
> 提供渗透测试方法论、ATT&CK框架与安全理论指导。

- Last updated: 2026-03-11
- Intended use: authorized security testing and defensive validation.

## 2024 highlights

- NIST CSF 2.0 introduced stronger governance integration across cybersecurity functions.
- ENISA 2024 continued to rank ransomware, supply-chain exposure, social engineering, and identity abuse as major risks.
- M-Trends 2024 reinforced that initial access and identity compromise remain central attack paths.

## 2025 highlights

- Verizon DBIR 2025 reported a notable increase in third-party involvement in breaches (news release cites 30%).
- M-Trends 2025 emphasized attacker focus on cloud control planes, identity, edge services, and long-dwell operations.
- ENISA Threat Landscape 2025 highlighted hybrid campaigns, geopolitical pressure, and AI-related risk expansion.

## 2026 (up to March) observable updates

- FBI 2026 alert stream continues to publish APT-oriented advisories.
- OT/SCADA guidance remains centered on segmentation, least privilege, remote access hardening, and log traceability.

## Direct platform implications (Agent + RAG)

1. Increase retrieval weights for identity/cloud/edge contexts during recon.
2. Require cross-phase evidence schema: command summary, output, timestamp, and confidence.
3. Add explicit third-party and dependency risk blocks in final reports.
4. Feed high-quality online findings into learned skills with trust and citation metadata.

## References

- https://www.nist.gov/cyberframework
- https://www.enisa.europa.eu/publications/enisa-threat-landscape-2024
- https://www.enisa.europa.eu/sites/default/files/2025-10/enisa-threat-landscape-2025_0.pdf
- https://www.verizon.com/about/news/2025-data-breach-investigations-report
- https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2024
- https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025
- https://www.ic3.gov/Alerts/2026
