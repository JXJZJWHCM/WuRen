import os
import json
import re
from datetime import datetime, timezone, timedelta
from loguru import logger
from typing import Dict, Any, List
from core.utils.time_sync import get_formatted_real_time

class ReportGenerator:
    """
    渗透测试报告生成器。
    负责将扫描结果、漏洞信息等数据整理并生成 Markdown 格式的报告。
    """

    def __init__(self, output_dir: str = "output/reports"):
        self.output_dir = output_dir
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        """确保输出目录存在"""
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
                logger.info(f"创建报告输出目录: {self.output_dir}")
            except OSError as e:
                logger.error(f"创建报告输出目录失败: {e}")
                raise

    @staticmethod
    def _sanitize_text(content: Any, max_chars: int = 8000) -> str:
        text = str(content or "")
        text = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\[TASK_COMPLETED\]", "", text, flags=re.IGNORECASE).strip()
        if len(text) > max_chars:
            return text[:max_chars].rstrip() + "..."
        return text

    def generate_report(self, project_id: str, data: Dict[str, Any]) -> str:
        """
        生成渗透测试报告。

        Args:
            project_id (str): 项目唯一标识符。
            data (Dict[str, Any]): 报告所需的数据，包含 recon results, vulnerabilities, shells 等。

        Returns:
            str: 生成的报告文件路径。
        """
        logger.info(f"开始生成项目 {project_id} 的报告...")

        report_content = self._build_markdown_content(project_id, data)
        
        filename = f"{project_id}_report.md"
        filepath = os.path.join(self.output_dir, filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report_content)
            logger.info(f"报告生成成功: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"写入报告文件失败: {e}")
            raise

    def _build_markdown_content(self, project_id: str, data: Dict[str, Any]) -> str:
        """构建 Markdown 内容"""
        
        # 提取数据，提供默认值
        executive_summary = self._sanitize_text(data.get("executive_summary", "本次渗透测试旨在评估目标系统的安全性，发现潜在的安全漏洞并提供修复建议。"))
        methodology = self._sanitize_text(data.get("methodology", "本次测试采用黑盒测试方法，结合自动化扫描与人工验证，覆盖信息收集、漏洞探测、利用与后渗透阶段。"))
        findings = data.get("findings", [])
        recommendations = self._sanitize_text(data.get("recommendations", "建议定期进行安全测试，及时修补已知漏洞，加强系统访问控制与日志审计。"))
        reference_review = data.get("reference_review", {})
        
        target_info = data.get("target_info", {})
        scan_time = get_formatted_real_time()

        md = []
        
        # 标题
        md.append(f"# 渗透测试报告 - {project_id}\n")
        md.append(f"**生成时间:** {scan_time}\n")
        if target_info:
            md.append("**目标信息:**\n")
            for key, value in target_info.items():
                if isinstance(value, (dict, list)):
                    md.append(f"- **{key}**:\n```json\n{json.dumps(value, indent=2, ensure_ascii=False)}\n```\n")
                else:
                    md.append(f"- **{key}**: {value}\n")
        
        md.append("---\n")

        # 1. Executive Summary
        md.append("## 1. 执行摘要 (Executive Summary)\n")
        md.append(f"{executive_summary}\n")

        # 2. Methodology
        md.append("## 2. 测试方法 (Methodology)\n")
        md.append(f"{methodology}\n")

        # 3. Findings
        md.append("## 3. 发现 (Findings)\n")
        if not findings:
            md.append("未发现明显漏洞。\n")
        else:
            for idx, finding in enumerate(findings, 1):
                title = finding.get("title", "未知漏洞")
                severity = finding.get("severity", "Unknown")
                description = self._sanitize_text(finding.get("description", "无描述"))
                remediation = self._sanitize_text(finding.get("remediation", "无修复建议"))
                
                md.append(f"### 3.{idx} {title} ({severity})\n")
                md.append(f"**描述:**\n{description}\n")
                md.append(f"**修复建议:**\n{remediation}\n")
                
                # 如果有 PoC 或证据，可以添加
                if "poc" in finding:
                    md.append(f"**PoC / 证据:**\n```\n{self._sanitize_text(finding['poc'])}\n```\n")

        # 4. Recommendations
        md.append("## 4. 建议 (Recommendations)\n")
        md.append(f"{recommendations}\n")

        if isinstance(reference_review, dict) and reference_review.get("enabled"):
            md.append("## 5. 参考链路校验 (Reference Review)\n")
            md.append(f"- **参考文件**: {self._sanitize_text(reference_review.get('reference_path', ''))}\n")
            md.append(f"- **状态**: {self._sanitize_text(reference_review.get('status', 'unknown'))}\n")
            chain_overview = self._sanitize_text(reference_review.get("chain_overview", ""), max_chars=1200)
            if chain_overview:
                md.append(f"- **参考主链**: {chain_overview}\n")
            summary = self._sanitize_text(reference_review.get("summary", ""), max_chars=2000)
            if summary:
                md.append(f"- **校验结论**: {summary}\n")
            missing_stages = reference_review.get("missing_stages", [])
            if isinstance(missing_stages, list) and missing_stages:
                md.append("- **缺失阶段**:\n")
                for item in missing_stages[:8]:
                    md.append(f"  - {self._sanitize_text(item, max_chars=200)}\n")

        return "\n".join(md)
