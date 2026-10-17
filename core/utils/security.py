import re
from typing import Any, Dict, List


_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PROMPT_INJECTION_PATTERNS = [
    (
        re.compile(r"\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|messages?)\b", re.IGNORECASE),
        "包含疑似“忽略前文指令”类注入语句",
    ),
    (
        re.compile(r"^\s*(?:system|developer|assistant|user)\s*:", re.IGNORECASE),
        "包含疑似角色指令片段",
    ),
    (
        re.compile(r"<\s*\/?\s*(?:system|developer|assistant|user)\s*>", re.IGNORECASE),
        "包含疑似角色标签",
    ),
    (
        re.compile(r"\b(?:system\s+prompt|prompt\s+injection)\b", re.IGNORECASE),
        "包含疑似提示注入关键词",
    ),
    (
        re.compile(r"\b(?:act|behave)\s+as\b", re.IGNORECASE),
        "包含疑似角色扮演指令",
    ),
    (
        re.compile(r"\b(?:bypass|override)\b[\s\S]{0,24}\b(?:safety|guardrails?|restrictions?|policy)\b", re.IGNORECASE),
        "包含疑似绕过限制的指令",
    ),
]
_SENSITIVE_TEXT_PATTERNS = [
    re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)([a-z0-9._\-+/=]+)"),
    re.compile(r"(?i)\b(x-api-key\s*:\s*)([^\s,;]+)"),
    re.compile(r"(?i)\b(api[_\- ]?key\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)\b(access[_\- ]?key\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)\b(secret\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)\b(password\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)\b(token\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r'(?i)("?(?:api[_\-]?key|access[_\-]?key|secret|password|token)"?\s*:\s*")([^"]+)(")'),
    re.compile(r"(?i)([?&](?:key|api_key|access_token|token)=)([^&#\s]+)"),
]


def mask_secret(secret: Any, keep_prefix: int = 4, keep_suffix: int = 4) -> str:
    value = str(secret or "")
    if not value:
        return ""
    if len(value) <= keep_prefix + keep_suffix:
        return "*" * len(value)
    middle_len = max(0, len(value) - keep_prefix - keep_suffix)
    return f"{value[:keep_prefix]}{'*' * middle_len}{value[-keep_suffix:]}"


def normalize_text_input(
    value: Any,
    *,
    field_name: str = "input",
    max_length: int = 4000,
    allow_newlines: bool = True,
    allow_empty: bool = False,
) -> str:
    text = str(value or "")
    text = _CONTROL_CHAR_PATTERN.sub("", text)
    if not allow_newlines:
        text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        text = re.sub(r"\s+", " ", text)
    else:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.strip()
    if not allow_empty and not text:
        raise ValueError(f"{field_name} 不能为空")
    if len(text) > int(max_length):
        raise ValueError(f"{field_name} 长度不能超过 {int(max_length)} 个字符")
    return text


def normalize_target_input(value: Any) -> str:
    return normalize_text_input(
        value,
        field_name="target",
        max_length=253,
        allow_newlines=False,
        allow_empty=False,
    )


def detect_prompt_injection(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    normalized = _CONTROL_CHAR_PATTERN.sub("", text).strip()
    for pattern, reason in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(normalized):
            return reason
    return ""


def redact_sensitive_text(value: Any, max_length: int | None = None) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = _CONTROL_CHAR_PATTERN.sub("", text)
    for pattern in _SENSITIVE_TEXT_PATTERNS:
        text = pattern.sub(lambda match: _mask_match_groups(match), text)
    if max_length is not None and int(max_length) > 0 and len(text) > int(max_length):
        text = text[: int(max_length)].rstrip() + "...(truncated)"
    return text


def redact_sensitive_data(
    data: Any,
    *,
    max_depth: int = 4,
    max_items: int = 60,
    string_max_length: int = 20000,
) -> Any:
    if max_depth <= 0:
        if isinstance(data, (dict, list, tuple, set)):
            return "[TRUNCATED]"
        if data is None or isinstance(data, (bool, int, float)):
            return data
        return redact_sensitive_text(data, max_length=string_max_length)
    if isinstance(data, dict):
        sanitized: Dict[str, Any] = {}
        for idx, (key, value) in enumerate(data.items()):
            if idx >= max_items:
                sanitized["__truncated__"] = f"Only first {max_items} items kept"
                break
            key_text = redact_sensitive_text(key, max_length=256)
            if _is_sensitive_key(key_text):
                sanitized[key_text] = mask_secret(value)
                continue
            sanitized[key_text] = redact_sensitive_data(
                value,
                max_depth=max_depth - 1,
                max_items=max_items,
                string_max_length=string_max_length,
            )
        return sanitized
    if isinstance(data, (list, tuple, set)):
        rows: List[Any] = []
        for idx, item in enumerate(list(data)):
            if idx >= max_items:
                rows.append(f"[TRUNCATED:{max_items}]")
                break
            rows.append(
                redact_sensitive_data(
                    item,
                    max_depth=max_depth - 1,
                    max_items=max_items,
                    string_max_length=string_max_length,
                )
            )
        return rows
    if data is None or isinstance(data, (bool, int, float)):
        return data
    return redact_sensitive_text(data, max_length=string_max_length)


def _mask_match_groups(match: re.Match[str]) -> str:
    groups = list(match.groups())
    if not groups:
        return mask_secret(match.group(0))
    if len(groups) == 2:
        return f"{groups[0]}{mask_secret(groups[1])}"
    if len(groups) >= 3:
        prefix = groups[0]
        secret = groups[1]
        suffix = groups[2]
        return f"{prefix}{mask_secret(secret)}{suffix}"
    return mask_secret(match.group(0))


def _is_sensitive_key(key: str) -> bool:
    lowered = str(key or "").strip().lower()
    return any(token in lowered for token in ("api_key", "apikey", "token", "secret", "password", "authorization", "access_key"))
