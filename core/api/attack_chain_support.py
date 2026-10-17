from typing import Any, Dict, List


ATTACK_CHAIN_ORDER = [
    "recon",
    "vuln_analysis",
    "exploitation",
    "post_exploit",
    "lateral_movement",
    "report",
]

ATTACK_STAGE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "recon": {
        "tactic_id": "TA0043",
        "tactic_name": "侦察",
        "title": "资产侦察",
        "description": "确认目标暴露面、服务、指纹与可疑入口，为后续阶段提供事实基础。",
        "prerequisites": [],
        "requirements": [],
    },
    "vuln_analysis": {
        "tactic_id": "TA0001",
        "tactic_name": "初始访问",
        "title": "漏洞分析",
        "description": "基于侦察结果筛选可利用入口，形成可执行的漏洞假设与验证路径。",
        "prerequisites": ["recon"],
        "requirements": [],
    },
    "exploitation": {
        "tactic_id": "TA0001/TA0002",
        "tactic_name": "初始访问与执行",
        "title": "漏洞利用",
        "description": "对侦察阶段发现的攻击面进行验证与利用，获取初始立足点或执行能力。",
        "prerequisites": ["recon", "vuln_analysis"],
        "requirements": ["validated_vulnerability"],
    },
    "post_exploit": {
        "tactic_id": "TA0003/TA0004/TA0006",
        "tactic_name": "持久化、提权与凭据访问",
        "title": "后渗透",
        "description": "在已获得的立足点上执行信息收集、权限提升、持久化与凭据利用。",
        "prerequisites": ["exploitation"],
        "requirements": ["shell_foothold"],
    },
    "lateral_movement": {
        "tactic_id": "TA0008",
        "tactic_name": "横向移动",
        "title": "横向移动",
        "description": "复用已获得的凭据、路由或会话，探索并尝试进入其他主机或区域。",
        "prerequisites": ["post_exploit"],
        "requirements": ["shell_foothold"],
    },
    "report": {
        "tactic_id": "TA0009/TA0040",
        "tactic_name": "收集、影响评估与报告",
        "title": "报告输出",
        "description": "汇总阶段证据、结论与修复建议，生成结构化攻击链与报告。",
        "prerequisites": ["recon", "vuln_analysis", "exploitation"],
        "requirements": [],
    },
}

_PROGRESSED_STATUSES = {"running", "completed", "failed", "insufficient_evidence", "paused"}
_REPORT_ACCEPTABLE_PREREQ = {"completed", "insufficient_evidence", "failed", "error"}


def _stage_status(status_map: Dict[str, str], stage: str) -> str:
    return str(status_map.get(stage) or "pending").strip().lower() or "pending"


def _is_prerequisite_satisfied(prerequisite: str, consumer_stage: str, status_map: Dict[str, str]) -> bool:
    status = _stage_status(status_map, prerequisite)
    if consumer_stage == "report":
        return status in _REPORT_ACCEPTABLE_PREREQ
    return status == "completed"


def extract_validated_vulnerability_count(stage_payload: Dict[str, Any]) -> int:
    if not isinstance(stage_payload, dict):
        return 0
    count = 0
    tool_results = stage_payload.get("tool_results")
    if not isinstance(tool_results, list):
        return 0
    for tool_result in tool_results:
        if not isinstance(tool_result, dict):
            continue
        result = tool_result.get("result")
        if not isinstance(result, dict):
            continue
        vulnerabilities = result.get("vulnerabilities")
        if isinstance(vulnerabilities, list):
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                severity = str(vulnerability.get("severity") or "").strip().lower()
                if severity in {"high", "critical"}:
                    count += 1
        elif result.get("verified") is True or result.get("validated") is True or result.get("vulnerable") is True:
            count += 1
    return count


def build_sequence_constraints(
    stage_status_map: Dict[str, str],
    validated_vulnerability_count: int,
    active_shell_count: int,
) -> Dict[str, Any]:
    normalized_status_map = {
        stage: _stage_status(stage_status_map, stage)
        for stage in ATTACK_CHAIN_ORDER
    }
    stage_constraints: Dict[str, Dict[str, Any]] = {}
    violations: List[Dict[str, Any]] = []

    for index, stage in enumerate(ATTACK_CHAIN_ORDER):
        definition = ATTACK_STAGE_DEFINITIONS.get(stage, {})
        prerequisites = list(definition.get("prerequisites") or [])
        requirement_names = list(definition.get("requirements") or [])
        prerequisite_states: List[Dict[str, Any]] = []
        blocked_by: List[str] = []

        for prerequisite in prerequisites:
            satisfied = _is_prerequisite_satisfied(prerequisite, stage, normalized_status_map)
            prerequisite_states.append(
                {
                    "stage": prerequisite,
                    "status": normalized_status_map.get(prerequisite, "pending"),
                    "satisfied": satisfied,
                }
            )
            if not satisfied:
                blocked_by.append(f"前置阶段 {prerequisite} 未完成")

        if "validated_vulnerability" in requirement_names and validated_vulnerability_count <= 0:
            blocked_by.append("缺少高危/严重漏洞的结构化验证证据")
        if "shell_foothold" in requirement_names and active_shell_count <= 0:
            blocked_by.append("缺少可用的 Shell/Session 立足点")

        status = normalized_status_map.get(stage, "pending")
        unlock_ready = len(blocked_by) == 0
        stage_constraints[stage] = {
            "attack": {
                "tactic_id": definition.get("tactic_id", "TA0000"),
                "tactic_name": definition.get("tactic_name", "未知战术"),
                "title": definition.get("title", stage),
                "description": definition.get("description", ""),
            },
            "prerequisites": prerequisite_states,
            "unlock_state": {
                "ready": unlock_ready,
                "blocked_by": blocked_by,
                "requirements": requirement_names,
            },
            "structure": {
                "previous_phase": ATTACK_CHAIN_ORDER[index - 1] if index > 0 else None,
                "next_phase": ATTACK_CHAIN_ORDER[index + 1] if index + 1 < len(ATTACK_CHAIN_ORDER) else None,
            },
        }
        if status in _PROGRESSED_STATUSES and blocked_by:
            violations.append(
                {
                    "stage": stage,
                    "status": status,
                    "blocked_by": blocked_by,
                }
            )

    nodes = [
        {
            "phase": stage,
            "order": index + 1,
            "status": normalized_status_map.get(stage, "pending"),
            **stage_constraints.get(stage, {}),
        }
        for index, stage in enumerate(ATTACK_CHAIN_ORDER)
    ]
    edges = [
        {
            "from": ATTACK_CHAIN_ORDER[index],
            "to": ATTACK_CHAIN_ORDER[index + 1],
            "type": "sequential",
        }
        for index in range(len(ATTACK_CHAIN_ORDER) - 1)
    ]
    return {
        "order": list(ATTACK_CHAIN_ORDER),
        "validated_vulnerability_count": max(0, int(validated_vulnerability_count or 0)),
        "active_shell_count": max(0, int(active_shell_count or 0)),
        "stages": stage_constraints,
        "violations": violations,
        "graph": {
            "nodes": nodes,
            "edges": edges,
        },
    }
