from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOOL_MATRIX_PATH = PROJECT_ROOT / "config" / "tool_matrix.yaml"
REQUIRED_TOP_LEVEL_KEYS = ("schema_version", "matrix_id", "baselines", "tools")
REQUIRED_TOOL_KEYS = (
    "standard_name",
    "display_name",
    "baseline",
    "category",
    "support",
    "install",
    "execution",
    "healthcheck",
)
REQUIRED_SECTION_KEYS = {
    "support": ("platforms",),
    "install": ("mode", "automated", "providers", "dependencies"),
    "execution": ("entry_type", "entrypoint", "path_hint"),
    "healthcheck": ("type",),
}


def normalize_tool_name(name: str) -> str:
    return str(name or "").strip()


def get_current_platform_key(platform_name: str | None = None) -> str:
    normalized = normalize_tool_name(platform_name or sys.platform).lower()
    if normalized.startswith("win"):
        return "windows"
    if normalized.startswith("darwin"):
        return "darwin"
    if normalized.startswith("linux"):
        return "linux"
    return normalized


@lru_cache(maxsize=4)
def _load_tool_matrix_cached(path: str) -> dict[str, Any]:
    matrix_path = Path(path)
    with matrix_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    validate_tool_matrix(data)
    return data


def load_tool_matrix(path: str | Path = DEFAULT_TOOL_MATRIX_PATH) -> dict[str, Any]:
    matrix_path = Path(path).resolve()
    return _load_tool_matrix_cached(str(matrix_path))


def validate_tool_matrix(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(data, dict):
        raise ValueError("工具矩阵必须是对象结构")

    missing_top_level_keys = [key for key in REQUIRED_TOP_LEVEL_KEYS if key not in data]
    if missing_top_level_keys:
        raise ValueError(f"工具矩阵缺少顶层字段: {', '.join(missing_top_level_keys)}")

    baselines = data["baselines"]
    tools = data["tools"]
    if not isinstance(baselines, dict) or not baselines:
        raise ValueError("工具矩阵 baselines 必须为非空对象")
    if not isinstance(tools, dict) or not tools:
        raise ValueError("工具矩阵 tools 必须为非空对象")

    for tool_id, tool_definition in tools.items():
        if not isinstance(tool_definition, dict):
            raise ValueError(f"工具 {tool_id} 定义必须是对象")

        missing_tool_keys = [key for key in REQUIRED_TOOL_KEYS if key not in tool_definition]
        if missing_tool_keys:
            raise ValueError(f"工具 {tool_id} 缺少字段: {', '.join(missing_tool_keys)}")

        if tool_definition["standard_name"] != tool_id:
            raise ValueError(f"工具 {tool_id} 的 standard_name 必须与键名一致")

        baseline = tool_definition["baseline"]
        if baseline not in baselines:
            raise ValueError(f"工具 {tool_id} 引用了未声明的 baseline: {baseline}")

        for section_name, required_keys in REQUIRED_SECTION_KEYS.items():
            section_value = tool_definition[section_name]
            if not isinstance(section_value, dict):
                raise ValueError(f"工具 {tool_id} 的 {section_name} 必须是对象")
            missing_section_keys = [key for key in required_keys if key not in section_value]
            if missing_section_keys:
                raise ValueError(
                    f"工具 {tool_id} 的 {section_name} 缺少字段: {', '.join(missing_section_keys)}"
                )

        platforms = tool_definition["support"]["platforms"]
        if not isinstance(platforms, dict) or not platforms:
            raise ValueError(f"工具 {tool_id} 的 support.platforms 必须为非空对象")

        aliases = tool_definition.get("aliases", [])
        if not isinstance(aliases, list):
            raise ValueError(f"工具 {tool_id} 的 aliases 必须是数组")
        if any(not normalize_tool_name(alias) for alias in aliases):
            raise ValueError(f"工具 {tool_id} 的 aliases 不允许包含空值")

        dependencies = tool_definition["install"]["dependencies"]
        if not isinstance(dependencies, list):
            raise ValueError(f"工具 {tool_id} 的 install.dependencies 必须是数组")

    return tools


def resolve_tool_name(tool_name: str, path: str | Path = DEFAULT_TOOL_MATRIX_PATH) -> str:
    tool_matrix = load_tool_matrix(path)
    requested_name = normalize_tool_name(tool_name)
    if not requested_name:
        raise KeyError("工具名不能为空")

    alias_index: dict[str, str] = {}
    for standard_name, tool_definition in tool_matrix["tools"].items():
        candidates = {standard_name}
        candidates.update(str(alias) for alias in tool_definition.get("aliases", []))

        entrypoint_name = Path(str(tool_definition["execution"].get("entrypoint") or "")).name
        if entrypoint_name:
            candidates.add(entrypoint_name)
            candidates.add(Path(entrypoint_name).stem)

        for candidate in candidates:
            normalized_candidate = normalize_tool_name(candidate)
            if not normalized_candidate:
                continue
            owner = alias_index.get(normalized_candidate)
            if owner and owner != standard_name:
                raise ValueError(f"工具别名冲突: {normalized_candidate}")
            alias_index[normalized_candidate] = standard_name

    try:
        return alias_index[requested_name]
    except KeyError as error:
        raise KeyError(f"未找到工具定义: {requested_name}") from error


def get_tool_definition(standard_name: str, path: str | Path = DEFAULT_TOOL_MATRIX_PATH) -> dict[str, Any]:
    tool_matrix = load_tool_matrix(path)
    resolved_name = resolve_tool_name(standard_name, path)
    return tool_matrix["tools"][resolved_name]


def list_tools_by_baseline(path: str | Path = DEFAULT_TOOL_MATRIX_PATH) -> dict[str, list[str]]:
    tool_matrix = load_tool_matrix(path)
    grouped_tools: dict[str, list[str]] = {baseline: [] for baseline in tool_matrix["baselines"]}
    for standard_name, tool_definition in tool_matrix["tools"].items():
        grouped_tools.setdefault(tool_definition["baseline"], []).append(standard_name)
    for standard_name_list in grouped_tools.values():
        standard_name_list.sort()
    return grouped_tools
