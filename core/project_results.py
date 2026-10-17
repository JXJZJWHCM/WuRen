import json
from typing import Any, Dict, List

LATERAL_MOVEMENT_TOOL_NAMES = frozenset({
    "scan_internal_network",
    "psexec",
    "wmiexec",
})

PERSISTENCE_TOOL_NAMES = frozenset({
    "add_cron_job",
    "add_registry_run_key",
})

_PERSISTENCE_KIND_MAP = {
    "add_cron_job": "cron_job",
    "add_registry_run_key": "registry_run_key",
}

_PERSISTENCE_PLATFORM_MAP = {
    "add_cron_job": "linux",
    "add_registry_run_key": "windows",
}


def _coerce_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _coerce_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _normalize_tool_name(item: Dict[str, Any]) -> str:
    return str(item.get("tool") or item.get("tool_name") or "").strip()


def _tool_identity(item: Dict[str, Any]) -> str:
    return json.dumps(
        {
            "tool": _normalize_tool_name(item),
            "arguments": item.get("arguments"),
            "result": _coerce_dict(item.get("result")).get("command"),
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _trim_text(value: Any, max_chars: int = 160) -> str:
    text = str(value or "").strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "..."


def _merge_tool_results(preferred: Any, derived: Any) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()
    for item in _coerce_list(preferred) + _coerce_list(derived):
        if not isinstance(item, dict):
            continue
        marker = _tool_identity(item)
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(item)
    return merged


def _build_lateral_line(item: Dict[str, Any]) -> str:
    tool_name = _normalize_tool_name(item)
    arguments = _coerce_dict(item.get("arguments"))
    result = _coerce_dict(item.get("result"))
    scope = arguments.get("target") or arguments.get("subnet") or arguments.get("user") or "unknown"
    command = _trim_text(result.get("command") or "")
    failure_reason = _trim_text(item.get("failure_reason") or item.get("error") or "")
    if failure_reason:
        return f"{tool_name}: 目标 {scope}，失败原因 {failure_reason}"
    if command:
        return f"{tool_name}: 目标 {scope}，已生成命令 {command}"
    if result.get("success") is True or result.get("returncode") == 0 or result.get("status") == 200:
        return f"{tool_name}: 目标 {scope}，执行成功"
    return f"{tool_name}: 目标 {scope}，已记录横向动作"


def build_lateral_movement_result(post_exploit_result: Any) -> Dict[str, Any]:
    stage_result = _coerce_dict(post_exploit_result)
    tool_results = [
        item
        for item in _coerce_list(stage_result.get("tool_results"))
        if isinstance(item, dict) and _normalize_tool_name(item) in LATERAL_MOVEMENT_TOOL_NAMES
    ]
    if not tool_results:
        return {}

    lines: List[str] = []
    seen = set()
    # 这里基于结构化工具结果生成横向摘要，避免依赖难以稳定切分的自由文本。
    for item in tool_results:
        line = _build_lateral_line(item)
        if not line:
            continue
        marker = line.lower()
        if marker in seen:
            continue
        seen.add(marker)
        lines.append(line)

    return {
        "content": "\n".join(lines),
        "tool_results": tool_results,
        "derived_from": "post_exploit_result",
    }


def build_persistence_objects(post_exploit_result: Any) -> List[Dict[str, Any]]:
    stage_result = _coerce_dict(post_exploit_result)
    objects: List[Dict[str, Any]] = []
    seen = set()
    for index, item in enumerate(_coerce_list(stage_result.get("tool_results"))):
        if not isinstance(item, dict):
            continue
        tool_name = _normalize_tool_name(item)
        if tool_name not in PERSISTENCE_TOOL_NAMES:
            continue
        arguments = _coerce_dict(item.get("arguments"))
        result = _coerce_dict(item.get("result"))
        command = str(result.get("command") or arguments.get("command") or "").strip()
        marker = json.dumps(
            {"tool": tool_name, "command": command, "arguments": arguments},
            ensure_ascii=False,
            sort_keys=True,
        )
        if marker in seen:
            continue
        seen.add(marker)
        summary = f"{tool_name}: {command or '已生成持久化动作'}"
        objects.append(
            {
                "id": f"{tool_name}:{index + 1}",
                "category": "persistence",
                "tool": tool_name,
                "kind": _PERSISTENCE_KIND_MAP.get(tool_name, "unknown"),
                "platform": _PERSISTENCE_PLATFORM_MAP.get(tool_name, "unknown"),
                "status": "failed" if item.get("ok") is False else "prepared",
                "command": command,
                "arguments": arguments,
                "summary": summary,
                "source_result": "post_exploit_result",
            }
        )
    return objects


def summarize_persistence_objects(objects: Any, limit: int = 5) -> str:
    lines: List[str] = []
    for item in _coerce_list(objects)[: max(1, int(limit))]:
        if not isinstance(item, dict):
            continue
        summary = _trim_text(item.get("summary") or item.get("command") or "")
        if not summary:
            continue
        lines.append(f"- {summary}")
    return "\n".join(lines)


def _merge_stage_result(preferred: Any, derived: Any) -> Dict[str, Any]:
    preferred_result = _coerce_dict(preferred)
    derived_result = _coerce_dict(derived)
    if not preferred_result:
        return derived_result
    if not derived_result:
        return preferred_result

    merged = dict(derived_result)
    merged.update(preferred_result)
    merged["tool_results"] = _merge_tool_results(
        preferred_result.get("tool_results"),
        derived_result.get("tool_results"),
    )
    if not merged.get("content"):
        merged["content"] = derived_result.get("content") or preferred_result.get("content") or ""
    return merged


def _merge_persistence_objects(preferred: Any, derived: Any) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()
    for item in _coerce_list(preferred) + _coerce_list(derived):
        if not isinstance(item, dict):
            continue
        marker = json.dumps(
            {
                "tool": item.get("tool"),
                "kind": item.get("kind"),
                "command": item.get("command"),
                "arguments": item.get("arguments"),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(item)
    return merged


def normalize_project_results(results: Any) -> Dict[str, Any]:
    normalized = dict(_coerce_dict(results))
    original_post_exploit_result = _coerce_dict(normalized.get("post_exploit_result"))
    post_exploit_result = dict(original_post_exploit_result)
    tool_results = _coerce_list(original_post_exploit_result.get("tool_results"))

    if post_exploit_result:
        retained_tool_results: List[Dict[str, Any]] = []
        for item in tool_results:
            if not isinstance(item, dict):
                continue
            tool_name = _normalize_tool_name(item)
            if tool_name in LATERAL_MOVEMENT_TOOL_NAMES or tool_name in PERSISTENCE_TOOL_NAMES:
                continue
            retained_tool_results.append(item)
        if tool_results:
            post_exploit_result = {
                **post_exploit_result,
                "tool_results": retained_tool_results,
            }
        normalized["post_exploit_result"] = post_exploit_result

    normalized["lateral_movement_result"] = _merge_stage_result(
        normalized.get("lateral_movement_result"),
        build_lateral_movement_result(original_post_exploit_result),
    )
    normalized["persistence_objects"] = _merge_persistence_objects(
        normalized.get("persistence_objects"),
        build_persistence_objects(original_post_exploit_result),
    )
    return normalized
