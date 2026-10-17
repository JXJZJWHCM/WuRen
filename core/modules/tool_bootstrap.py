from __future__ import annotations

from typing import Any


BOOTSTRAP_RESULT_STATUSES = ("available", "platform_limited", "failed", "manual")
MISSING_RESULT_STATUSES = tuple(status for status in BOOTSTRAP_RESULT_STATUSES if status != "available")


def build_bootstrap_payload(platform: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {status: 0 for status in BOOTSTRAP_RESULT_STATUSES}
    missing_tools = {status: [] for status in MISSING_RESULT_STATUSES}

    for item in results:
        status = str(item.get("status") or "")
        if status not in summary:
            raise ValueError(f"未知的工具准备状态: {status}")
        summary[status] += 1
        if status in missing_tools:
            missing_tools[status].append(
                {
                    "tool": item.get("tool"),
                    "message": item.get("message"),
                }
            )

    return {
        "platform": platform,
        "summary": summary,
        "missing_tools": missing_tools,
        "results": results,
    }
