import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from loguru import logger


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_ALIAS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "middle": "MEDIUM",
    "moderate": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
}
WEB_LANG_HINTS = {"html", "css", "js", "javascript", "typescript", "vue", "php"}


class WebSourceAuditor:
    def __init__(self, rule_dir: str = "repo", yak_binary: str = "yak"):
        self.rule_dir = os.path.abspath(rule_dir)
        self.yak_binary = yak_binary

    @staticmethod
    def normalize_target_url(target: str) -> str:
        value = str(target or "").strip()
        if not value:
            raise ValueError("target is required")
        if not value.startswith(("http://", "https://")):
            value = f"http://{value}"
        return value

    @staticmethod
    def _normalize_array(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return []
            if "," in raw:
                return [item.strip() for item in raw.split(",") if item.strip()]
            return [raw]
        return [str(value).strip()] if str(value).strip() else []

    @staticmethod
    def _normalize_severity(raw: Any) -> str:
        key = str(raw or "info").strip().lower()
        return SEVERITY_ALIAS.get(key, "INFO")

    @staticmethod
    def _compile_or_fix_regex(pattern: str) -> Tuple[str, bool, Optional[str]]:
        text = str(pattern or "")
        if not text:
            return "", False, "empty pattern"
        try:
            re.compile(text)
            return text, False, None
        except re.error as error:
            fixed = re.escape(text)
            try:
                re.compile(fixed)
                return fixed, True, f"invalid regex auto-escaped: {error}"
            except re.error as second:
                return text, False, str(second)

    def _normalize_list_rule(self, item: Dict[str, Any], file_stem: str, index: int) -> Tuple[Dict[str, Any], List[str]]:
        fixes: List[str] = []
        normalized = dict(item or {})

        name = str(normalized.get("name") or normalized.get("RuleName") or "").strip()
        if not name:
            name = f"{file_stem}_{index + 1}"
            fixes.append("name set to default")
        normalized["name"] = name

        severity = self._normalize_severity(normalized.get("Severity") or normalized.get("severity"))
        if str(normalized.get("Severity") or "").strip() != severity:
            fixes.append("severity normalized")
        normalized["Severity"] = severity

        description = str(normalized.get("Description") or normalized.get("description") or "").strip()
        if not description:
            description = f"Auto-fixed rule description for {name}"
            fixes.append("description set to default")
        normalized["Description"] = description

        fixed_patterns: List[str] = []
        for pattern in self._normalize_array(normalized.get("patterns")):
            fixed, changed, issue = self._compile_or_fix_regex(pattern)
            if issue and changed:
                fixes.append(issue)
            if fixed:
                fixed_patterns.append(fixed)
        if normalized.get("patterns") != fixed_patterns:
            fixes.append("patterns normalized")
        normalized["patterns"] = fixed_patterns

        sources = self._normalize_array(normalized.get("sources"))
        sinks = self._normalize_array(normalized.get("sinks"))
        if normalized.get("sources") != sources:
            fixes.append("sources normalized")
        if normalized.get("sinks") != sinks:
            fixes.append("sinks normalized")
        normalized["sources"] = sources
        normalized["sinks"] = sinks

        return normalized, fixes

    def _normalize_static_config(self, config: Any) -> Tuple[Dict[str, List[str]], List[str]]:
        fixes: List[str] = []
        payload: Dict[str, Any] = config if isinstance(config, dict) else {}
        normalized = {
            "patterns": [],
            "sources": [],
            "sinks": [],
        }
        for key in ["patterns", "sources", "sinks"]:
            values = self._normalize_array(payload.get(key))
            if key == "patterns":
                fixed_patterns: List[str] = []
                for pattern in values:
                    fixed, changed, issue = self._compile_or_fix_regex(pattern)
                    if issue and changed:
                        fixes.append(issue)
                    if fixed:
                        fixed_patterns.append(fixed)
                values = fixed_patterns
            normalized[key] = values
            if payload.get(key) != values:
                fixes.append(f"StaticConfig.{key} normalized")
        return normalized, fixes

    def _normalize_dict_rule(self, item: Dict[str, Any], file_stem: str) -> Tuple[Dict[str, Any], List[str]]:
        fixes: List[str] = []
        normalized = dict(item or {})

        title = str(normalized.get("Title") or normalized.get("RuleName") or normalized.get("name") or "").strip()
        if not title:
            title = file_stem
            fixes.append("Title set to default")
        normalized["Title"] = title
        if not str(normalized.get("RuleName") or "").strip():
            normalized["RuleName"] = title
            fixes.append("RuleName set from Title")

        severity = self._normalize_severity(normalized.get("Severity") or normalized.get("severity"))
        if str(normalized.get("Severity") or "").strip() != severity:
            fixes.append("Severity normalized")
        normalized["Severity"] = severity

        content = str(normalized.get("Content") or "")
        if not content.strip():
            normalized["Content"] = f"# auto-filled empty content for {title}\n"
            fixes.append("Content auto-filled")

        rule_type = str(normalized.get("Type") or "").strip().lower()
        static_config, static_fixes = self._normalize_static_config(normalized.get("StaticConfig"))
        fixes.extend(static_fixes)
        has_static_signals = bool(static_config["patterns"] or static_config["sources"] or static_config["sinks"])

        if not rule_type:
            rule_type = "static_analysis" if has_static_signals else "sf"
            fixes.append("Type inferred")
        if rule_type not in {"sf", "static_analysis"}:
            rule_type = "sf"
            fixes.append("Type corrected to sf")
        normalized["Type"] = rule_type
        normalized["StaticConfig"] = static_config

        description = str(normalized.get("Description") or "").strip()
        if not description:
            normalized["Description"] = f"Auto-fixed rule description for {title}"
            fixes.append("Description set to default")

        language = str(normalized.get("Language") or "").strip().lower()
        if language and language not in WEB_LANG_HINTS:
            normalized.setdefault("_web_lang_hint", False)
        return normalized, fixes

    @staticmethod
    def _sha256_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    def validate_and_fix_rules(self, auto_fix: bool = True) -> Dict[str, Any]:
        rule_root = Path(self.rule_dir)
        if not rule_root.exists():
            raise FileNotFoundError(f"rule directory not found: {self.rule_dir}")

        details: List[Dict[str, Any]] = []
        fixed_files = 0
        parse_failed = 0
        rules_checked = 0
        rules_fixed = 0

        for file_path in sorted(rule_root.glob("*.json")):
            fixes: List[str] = []
            status = "ok"
            try:
                raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
                data = json.loads(raw_text)
            except Exception as error:
                parse_failed += 1
                details.append(
                    {
                        "file": str(file_path).replace("\\", "/"),
                        "status": "parse_failed",
                        "error": str(error),
                    }
                )
                continue

            changed = False
            normalized_data: Any = data
            if isinstance(data, list):
                out_items: List[Dict[str, Any]] = []
                for index, entry in enumerate(data):
                    rules_checked += 1
                    item = entry if isinstance(entry, dict) else {"name": f"{file_path.stem}_{index + 1}"}
                    normalized_item, item_fixes = self._normalize_list_rule(item, file_path.stem, index)
                    out_items.append(normalized_item)
                    if item_fixes:
                        rules_fixed += 1
                        fixes.extend(item_fixes)
                normalized_data = out_items
            elif isinstance(data, dict):
                rules_checked += 1
                normalized_data, item_fixes = self._normalize_dict_rule(data, file_path.stem)
                if item_fixes:
                    rules_fixed += 1
                    fixes.extend(item_fixes)
            else:
                parse_failed += 1
                details.append(
                    {
                        "file": str(file_path).replace("\\", "/"),
                        "status": "invalid_root",
                        "error": "rule file root must be object or array",
                    }
                )
                continue

            normalized_text = json.dumps(normalized_data, ensure_ascii=False, indent=2)
            if self._sha256_text(raw_text.strip()) != self._sha256_text(normalized_text.strip()):
                changed = True
                status = "fixed"
                if auto_fix:
                    file_path.write_text(normalized_text + "\n", encoding="utf-8")
                fixed_files += 1
            details.append(
                {
                    "file": str(file_path).replace("\\", "/"),
                    "status": status,
                    "changed": changed,
                    "fixes": sorted(set(fixes)),
                }
            )

        return {
            "rule_dir": str(rule_root).replace("\\", "/"),
            "auto_fix": auto_fix,
            "files_total": len(list(rule_root.glob("*.json"))),
            "files_fixed": fixed_files,
            "files_parse_failed": parse_failed,
            "rules_checked": rules_checked,
            "rules_fixed": rules_fixed,
            "details": details,
        }

    @staticmethod
    def _contains_any(source: str, terms: List[str]) -> bool:
        lowered = source.lower()
        return any(str(term or "").strip().lower() in lowered for term in terms if str(term or "").strip())

    def _evaluate_list_rule(self, rule: Dict[str, Any], source: str, file_path: str) -> Optional[Dict[str, Any]]:
        patterns = rule.get("patterns") or []
        sources = rule.get("sources") or []
        sinks = rule.get("sinks") or []

        pattern_hits: List[str] = []
        for pattern in patterns:
            try:
                match = re.search(pattern, source)
                if match:
                    snippet = source[max(0, match.start() - 60): match.end() + 120]
                    pattern_hits.append(snippet[:300])
            except re.error:
                continue

        source_sink_hit = bool(sources and sinks and self._contains_any(source, sources) and self._contains_any(source, sinks))
        if not pattern_hits and not source_sink_hit:
            return None

        evidence = pattern_hits[0] if pattern_hits else f"sources/sinks matched: {','.join(sources[:3])} -> {','.join(sinks[:3])}"
        return {
            "rule_file": file_path,
            "rule_name": rule.get("name") or "unnamed_rule",
            "severity": self._normalize_severity(rule.get("Severity")),
            "description": rule.get("Description") or "",
            "match_type": "pattern" if pattern_hits else "source_sink",
            "evidence": evidence,
        }

    @staticmethod
    def _is_web_relevant_dict_rule(rule: Dict[str, Any]) -> bool:
        language = str(rule.get("Language") or "").strip().lower()
        if language and language in WEB_LANG_HINTS:
            return True
        title = " ".join(
            [
                str(rule.get("Title") or ""),
                str(rule.get("RuleName") or ""),
                str(rule.get("Tag") or ""),
            ]
        ).lower()
        return any(token in title for token in ["web", "html", "css", "javascript", "xss", "dom"])

    def _evaluate_dict_rule(self, rule: Dict[str, Any], source: str, file_path: str) -> Optional[Dict[str, Any]]:
        if not self._is_web_relevant_dict_rule(rule):
            return None

        static_cfg = rule.get("StaticConfig") if isinstance(rule.get("StaticConfig"), dict) else {}
        list_style = {
            "name": rule.get("RuleName") or rule.get("Title") or "unnamed_rule",
            "patterns": static_cfg.get("patterns") or [],
            "sources": static_cfg.get("sources") or [],
            "sinks": static_cfg.get("sinks") or [],
            "Severity": rule.get("Severity") or "INFO",
            "Description": rule.get("Description") or "",
        }
        finding = self._evaluate_list_rule(list_style, source, file_path)
        if finding:
            finding["match_type"] = "static_config"
            return finding

        content = str(rule.get("Content") or "")
        if not content.strip():
            return None
        rough_tokens = [token for token in re.split(r"[^a-zA-Z0-9_\-/]+", content) if len(token) >= 7][:120]
        token_hits = [token for token in rough_tokens if token.lower() in source.lower()]
        if token_hits:
            return {
                "rule_file": file_path,
                "rule_name": rule.get("RuleName") or rule.get("Title") or "unnamed_rule",
                "severity": self._normalize_severity(rule.get("Severity")),
                "description": rule.get("Description") or "",
                "match_type": "content_token",
                "evidence": f"matched tokens: {', '.join(token_hits[:8])}",
            }
        return None

    def _run_yak(self, source_text: str, normalized_url: str) -> Dict[str, Any]:
        yak_path = shutil.which(self.yak_binary) or self.yak_binary
        if not shutil.which(self.yak_binary):
            return {
                "available": False,
                "invoked": False,
                "matched": False,
                "stdout": "",
                "stderr": "yak binary not found",
                "command": "",
                "returncode": 127,
            }

        with tempfile.TemporaryDirectory(prefix="web_audit_yak_") as temp_dir:
            source_path = os.path.join(temp_dir, "source.html")
            with open(source_path, "w", encoding="utf-8") as fp:
                fp.write(source_text)

            commands = [
                [yak_path, "sf", source_path],
                [yak_path, "ssa", source_path],
            ]
            for cmd in commands:
                try:
                    process = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                    stdout = str(process.stdout or "")
                    stderr = str(process.stderr or "")
                    matched = process.returncode == 0 and bool(re.search(r"(?i)(alert|vuln|risk|warning|cwe|cve)", stdout + "\n" + stderr))
                    return {
                        "available": True,
                        "invoked": True,
                        "matched": matched,
                        "stdout": stdout[:2000],
                        "stderr": stderr[:1200],
                        "command": " ".join(shlex.quote(part) for part in cmd),
                        "returncode": process.returncode,
                        "target": normalized_url,
                    }
                except Exception as error:
                    return {
                        "available": True,
                        "invoked": True,
                        "matched": False,
                        "stdout": "",
                        "stderr": str(error),
                        "command": " ".join(shlex.quote(part) for part in cmd),
                        "returncode": -1,
                    }

        return {
            "available": True,
            "invoked": False,
            "matched": False,
            "stdout": "",
            "stderr": "yak invocation skipped",
            "command": "",
            "returncode": 0,
        }

    def run_audit(
        self,
        target: str,
        auto_fix_rules: bool = True,
        use_yak: bool = True,
        timeout_seconds: int = 0,
    ) -> Dict[str, Any]:
        normalized_url = self.normalize_target_url(target)
        validation = self.validate_and_fix_rules(auto_fix=auto_fix_rules)
        tls_verify = True
        response: Optional[httpx.Response] = None
        request_error: Optional[Exception] = None
        client_timeout = None if int(timeout_seconds or 0) <= 0 else int(timeout_seconds)
        try:
            with httpx.Client(timeout=client_timeout, follow_redirects=True) as client:
                response = client.get(normalized_url)
        except Exception as error:
            request_error = error
        if response is None and request_error and "CERTIFICATE_VERIFY_FAILED" in str(request_error):
            logger.warning(f"TLS verify failed for {normalized_url}, retry with verify=False")
            tls_verify = False
            with httpx.Client(timeout=client_timeout, follow_redirects=True, verify=False) as client:
                response = client.get(normalized_url)
        if response is None:
            raise ValueError(f"target request failed: {request_error}")

        source = response.text or ""
        findings: List[Dict[str, Any]] = []
        total_rules = 0

        for file_path in sorted(Path(self.rule_dir).glob("*.json")):
            try:
                data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
            except Exception as error:
                logger.warning(f"Skip rule file {file_path}: {error}")
                continue
            safe_path = str(file_path).replace("\\", "/")
            if isinstance(data, list):
                for entry in data:
                    if not isinstance(entry, dict):
                        continue
                    total_rules += 1
                    finding = self._evaluate_list_rule(entry, source, safe_path)
                    if finding:
                        findings.append(finding)
            elif isinstance(data, dict):
                total_rules += 1
                finding = self._evaluate_dict_rule(data, source, safe_path)
                if finding:
                    findings.append(finding)

        yak_result = self._run_yak(source, normalized_url) if use_yak else {
            "available": False,
            "invoked": False,
            "matched": False,
            "stdout": "",
            "stderr": "yak disabled",
            "command": "",
            "returncode": 0,
        }

        severity_counter: Dict[str, int] = {key: 0 for key in SEVERITY_ORDER}
        for item in findings:
            severity = self._normalize_severity(item.get("severity"))
            severity_counter[severity] = severity_counter.get(severity, 0) + 1

        return {
            "target": normalized_url,
            "status_code": int(response.status_code),
            "tls_verify": tls_verify,
            "content_length": len(source),
            "rule_files": len(list(Path(self.rule_dir).glob("*.json"))),
            "rules_evaluated": total_rules,
            "findings_count": len(findings),
            "severity_count": severity_counter,
            "findings": findings,
            "yak": yak_result,
            "rule_validation": validation,
        }
