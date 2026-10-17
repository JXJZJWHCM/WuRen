import os
import re
from typing import Any, Dict, List


class ReferenceWalkthroughEvaluator:
    def __init__(self, enabled: bool = False, reference_path: str = ""):
        self.enabled = bool(enabled and str(reference_path or "").strip())
        self.reference_path = os.path.abspath(reference_path) if self.enabled else ""
        self._cached_reference: Dict[str, Any] | None = None

    def evaluate(self, *texts: str) -> Dict[str, Any]:
        reference = self._load_reference()
        if not reference.get("enabled"):
            return {"enabled": False, "status": "disabled", "summary": "未启用参考链路校验。"}

        actual_text = "\n".join(str(text or "") for text in texts if text).lower()
        stages = reference.get("stages", [])
        matched_stages: List[str] = []
        missing_stages: List[str] = []

        for stage in stages:
            match_terms = stage.get("match_terms", [])
            matched_count = sum(1 for term in match_terms if term in actual_text)
            if matched_count >= int(stage.get("min_match_count", 1)):
                matched_stages.append(stage.get("label", ""))
            else:
                missing_stages.append(stage.get("label", ""))

        constrained_terms = [
            "apparmor",
            "无法建立立足点",
            "无法建立持久化",
            "持久化 shell",
            "反弹 shell",
            "www-data",
            "命令注入",
            "rce",
            "uid=33",
        ]
        advanced_terms = [
            "ssrf",
            "webhook.php",
            "gopher",
            "127.0.0.1:9090",
            "9090",
            "daemon.py",
            "pyyaml",
            "反序列化",
            "root",
        ]
        missing_text = " ".join(missing_stages).lower()
        likely_stopped_early = bool(
            missing_stages
            and any(term in actual_text for term in constrained_terms)
            and (
                not any(term in actual_text for term in advanced_terms)
                or any(term in missing_text for term in ["ssrf", "webhook", "gopher", "9090", "yaml", "root", "反序列化"])
            )
        )

        status = "match" if not missing_stages else "mismatch"
        summary_parts = [
            f"参考链路共 {len(stages)} 个关键阶段，已覆盖 {len(matched_stages)} 个。",
        ]
        if missing_stages:
            summary_parts.append("缺失阶段：" + " -> ".join(missing_stages[:6]))
        if likely_stopped_early:
            summary_parts.append("检测到结果可能停留在受限中间立足点，尚未进入参考链路中的后续关键阶段。")

        return {
            "enabled": True,
            "status": status,
            "reference_path": reference.get("reference_path", ""),
            "chain_overview": reference.get("chain_overview", ""),
            "matched_stages": matched_stages,
            "missing_stages": missing_stages,
            "likely_stopped_early": likely_stopped_early,
            "summary": " ".join(part for part in summary_parts if part).strip(),
        }

    def _load_reference(self) -> Dict[str, Any]:
        if self._cached_reference is not None:
            return self._cached_reference
        if not self.enabled or not self.reference_path or not os.path.isfile(self.reference_path):
            self._cached_reference = {"enabled": False}
            return self._cached_reference

        with open(self.reference_path, "r", encoding="utf-8") as file:
            raw_content = file.read()

        lines = [line.strip() for line in raw_content.splitlines() if line.strip()]
        chain_overview = next((line for line in lines if "->" in line and len(line) <= 300), "")
        numbered_steps = [re.sub(r"^\d+\.\s*", "", line) for line in lines if re.match(r"^\d+\.\s+", line)]
        stage_labels = self._extract_stage_labels(chain_overview, numbered_steps)
        stages = [self._build_stage(label) for label in stage_labels]

        self._cached_reference = {
            "enabled": True,
            "reference_path": self.reference_path,
            "chain_overview": chain_overview,
            "stages": stages,
        }
        return self._cached_reference

    def _extract_stage_labels(self, chain_overview: str, numbered_steps: List[str]) -> List[str]:
        labels: List[str] = []
        if len(numbered_steps) >= 4:
            for item in numbered_steps[:8]:
                cleaned = item.strip()
                if cleaned and len(cleaned) <= 120:
                    labels.append(cleaned)
            return labels
        if chain_overview:
            labels.extend(part.strip(" `") for part in chain_overview.split("->") if part.strip())
        if len(labels) < 3:
            labels = []
            for item in numbered_steps[:8]:
                cleaned = item.strip()
                if cleaned and len(cleaned) <= 120:
                    labels.append(cleaned)
        if not labels:
            labels = ["初始入口", "认证或权限获取", "高价值利用链", "最终影响"]
        return labels

    def _build_stage(self, label: str) -> Dict[str, Any]:
        lowered = label.lower()
        if any(term in lowered for term in ["sql", "ticket.php", "注入"]):
            return {
                "label": label,
                "match_terms": ["ticket.php", "sql", "union"],
                "min_match_count": 2,
            }
        if any(term in lowered for term in ["管理员", "集成", "integrations", "users"]):
            return {
                "label": label,
                "match_terms": ["管理员", "integrations", "集成", "users", "secret_key", "账号"],
                "min_match_count": 2,
            }
        if any(term in lowered for term in ["登录后台", "admin 登录", "dashboard.php"]):
            return {
                "label": label,
                "match_terms": ["登录", "后台", "admin", "dashboard.php"],
                "min_match_count": 2,
            }
        if any(term in lowered for term in ["ssrf", "webhook", "127.0.0.1", "9090"]):
            return {
                "label": label,
                "match_terms": ["webhook.php", "ssrf", "127.0.0.1:9090", "gopher"],
                "min_match_count": 2,
            }
        if any(term in lowered for term in ["pyyaml", "反序列化", "daemon.py", "日志服务"]):
            return {
                "label": label,
                "match_terms": ["pyyaml", "反序列化", "daemon.py", "日志服务"],
                "min_match_count": 2,
            }
        if any(term in lowered for term in ["flag", "web 可访问目录", "root"]):
            return {
                "label": label,
                "match_terms": ["flag{", "root_flag.txt", "uploads/root_flag.txt", "chmod 644", "cp /root/flag.txt"],
                "min_match_count": 1,
            }
        match_terms = self._build_match_terms(label)
        min_match_count = 1
        if any(term in lowered for term in ["sql", "注入", "ticket.php"]):
            min_match_count = 2
        if any(term in lowered for term in ["管理员", "集成", "integrations", "users"]):
            min_match_count = 2
        if any(term in lowered for term in ["ssrf", "webhook", "127.0.0.1", "9090"]):
            min_match_count = 2
        if any(term in lowered for term in ["yaml", "pyyaml", "反序列化", "root", "flag"]):
            min_match_count = 2
        return {
            "label": label,
            "match_terms": match_terms,
            "min_match_count": min_match_count,
        }

    def _build_match_terms(self, label: str) -> List[str]:
        lowered = label.lower()
        terms: List[str] = [lowered]
        terms.extend(match.lower() for match in re.findall(r"`([^`]+)`", label))
        terms.extend(match.lower() for match in re.findall(r"[a-zA-Z0-9_./:-]{3,}", label))

        keyword_groups = {
            "sql": ["sql", "sqli", "union", "ticket.php", "工单", "注入"],
            "login": ["login", "登录", "admin", "dashboard.php", "后台"],
            "users": ["users", "账号", "管理员", "凭据", "hash", "integrations", "集成"],
            "ssrf": ["ssrf", "webhook.php", "gopher", "127.0.0.1", "内网请求", "9090"],
            "yaml": ["yaml", "pyyaml", "反序列化", "daemon.py", "日志服务"],
            "root": ["root", "提权", "权限提升", "flag", "uploads", "root_flag.txt"],
            "network": ["network_tools.php", "命令注入", "rce", "www-data"],
        }
        for trigger, extra_terms in keyword_groups.items():
            if trigger in lowered or any(extra in lowered for extra in extra_terms):
                terms.extend(extra_terms)

        unique_terms: List[str] = []
        seen = set()
        for term in terms:
            normalized = str(term or "").strip().lower()
            if len(normalized) < 2 or normalized in seen:
                continue
            seen.add(normalized)
            unique_terms.append(normalized)
        return unique_terms
