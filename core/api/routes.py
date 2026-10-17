import asyncio
import html
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
import time
import uuid
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, Header, HTTPException, Query, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from loguru import logger
from pydantic import BaseModel, ConfigDict, Field, field_validator
import yaml
import httpx

from core.ai.coordinator import MultiAgentSystem
from core.ai.learning import SelfLearningPipeline
from core.ai.provider_catalog import (
    get_default_endpoint_key,
    get_provider_base_url,
    get_provider_catalog_payload,
    get_provider_default_failover_models,
    get_provider_default_model,
    get_provider_discovery,
    get_provider_endpoints,
    get_provider_label,
    get_provider_models,
    get_runtime_provider_base_url,
    is_provider_model_supported,
    list_supported_providers,
    migrate_ai_config,
    normalize_provider_config,
    normalize_provider_failover_order,
    normalize_provider_name,
    provider_allows_custom_base_url,
    provider_allows_custom_protocol,
    provider_requires_api_key,
    provider_supports_freeform_models,
    resolve_provider_protocol,
)
from core.api.storage import (
    cleanup_expired_download_tokens as db_cleanup_expired_download_tokens,
    cleanup_completed_export_jobs as db_cleanup_completed_export_jobs,
    close_webui_session as db_close_webui_session,
    count_project_events as db_count_project_events,
    consume_export_download_token as db_consume_export_download_token,
    create_project as db_create_project,
    create_export_download_token as db_create_export_download_token,
    create_export_job as db_create_export_job,
    delete_webui_sessions_by_project as db_delete_webui_sessions_by_project,
    delete_project as db_delete_project,
    delete_export_job as db_delete_export_job,
    get_project as db_get_project,
    get_export_job as db_get_export_job,
    get_setting as db_get_setting,
    list_webui_sessions as db_list_webui_sessions,
    init_storage,
    insert_export_cleanup_run as db_insert_export_cleanup_run,
    insert_export_job_audit as db_insert_export_job_audit,
    insert_event as db_insert_event,
    list_export_cleanup_runs as db_list_export_cleanup_runs,
    list_export_job_audit as db_list_export_job_audit,
    list_export_jobs as db_list_export_jobs,
    list_project_events as db_list_project_events,
    list_projects as db_list_projects,
    set_setting as db_set_setting,
    upsert_webui_session as db_upsert_webui_session,
    update_export_job as db_update_export_job,
    update_project as db_update_project,
)
from core.api.attack_chain_support import (
    ATTACK_CHAIN_ORDER,
    build_sequence_constraints,
    extract_validated_vulnerability_count,
)
from core.project_results import normalize_project_results, summarize_persistence_objects
from core.modules.cli_manager import CLIManager
from core.modules.report.generator import ReportGenerator
from core.modules.session_backend import SessionBackendExecutor
from core.modules.web_audit import WebSourceAuditor
from core.utils.security import detect_prompt_injection, mask_secret, normalize_target_input, normalize_text_input, redact_sensitive_data, redact_sensitive_text

router = APIRouter()
CONFIG_PATH = os.path.abspath("config/config.yaml")
SUPPORTED_AI_PROVIDERS = tuple(list_supported_providers())
AI_PROVIDER_DEFAULT_BASE_URL = {provider: get_provider_base_url(provider) for provider in SUPPORTED_AI_PROVIDERS}
AI_PROVIDER_DEFAULT_MODEL = {provider: get_provider_default_model(provider) for provider in SUPPORTED_AI_PROVIDERS}
AI_PROVIDER_MODEL_FALLBACKS = {provider: get_provider_default_failover_models(provider) for provider in SUPPORTED_AI_PROVIDERS}

# Initialize the MAS globally (it loads prompts and engine)
try:
    mas = MultiAgentSystem(CONFIG_PATH)
except Exception as e:
    logger.error(f"Failed to initialize MultiAgentSystem: {e}")
    mas = None
try:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fp:
        _route_cfg = yaml.safe_load(fp) or {}
except Exception:
    _route_cfg = {}
_paths_cfg = _route_cfg.get("paths") or {}
learner = SelfLearningPipeline(
    knowledge_dir=_paths_cfg.get("knowledge_base", "knowledge"),
    skills_dir=_paths_cfg.get("skills", "skills"),
)
web_auditor = WebSourceAuditor(rule_dir=_paths_cfg.get("audit_rules", "repo"))

# Initialize SQLite storage
init_storage()


# Data Models
class ProjectCreate(BaseModel):
    target: str
    description: str = ""

    @field_validator("target")
    @classmethod
    def _validate_target(cls, value: str) -> str:
        return normalize_target_input(value)

    @field_validator("description")
    @classmethod
    def _validate_description(cls, value: str) -> str:
        normalized = normalize_text_input(
            value,
            field_name="description",
            max_length=4000,
            allow_newlines=True,
            allow_empty=True,
        )
        if normalized:
            reason = detect_prompt_injection(normalized)
            if reason:
                raise ValueError(f"description {reason}")
        return normalized


class Project(ProjectCreate):
    id: str
    status: str  # pending, running, paused, stopped, completed, failed
    phase: str = "pending"  # pending, recon, exploit, post_exploit, report, completed, failed
    progress: float = 0.0
    created_at: float = 0.0
    results: Dict[str, Any] = Field(default_factory=dict)


class ProjectEvent(BaseModel):
    id: int
    type: str
    project_id: Optional[str] = None
    phase: Optional[str] = None
    status: Optional[str] = None
    progress: Optional[float] = None
    level: Optional[str] = None
    timestamp: Optional[float] = None
    message: str = ""
    agent: Optional[str] = None
    reasoning_content: Optional[str] = None
    ai_content: Optional[str] = None
    tool_name: Optional[str] = None
    tool_arguments: Optional[Any] = None
    tool_command: Optional[str] = None
    tool_help_command: Optional[str] = None
    tool_help_excerpt: Optional[str] = None
    tool_result_excerpt: Optional[str] = None
    tool_error: Optional[str] = None
    failure_level: Optional[str] = None
    failure_reason: Optional[str] = None
    failure_action: Optional[str] = None
    retry_recommendation: Optional[str] = None
    usage: Optional[Dict[str, Any]] = None
    usage_total: Optional[Dict[str, Any]] = None


class ExportJobStatus(BaseModel):
    job_id: str
    project_id: str
    status: str
    format: str
    created_at: float
    completed_at: Optional[float] = None
    download_url: Optional[str] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 0
    created_by: str = "system"
    last_action_by: Optional[str] = None


class ExportPolicy(BaseModel):
    retention_hours: int = 24
    max_retries: int = 2
    auto_retry_failed: bool = True


class ExportJobBatchDelete(BaseModel):
    job_ids: List[str]


class ExportJobAudit(BaseModel):
    id: int
    job_id: str
    project_id: str
    action: str
    actor: str
    timestamp: float
    detail: Optional[str] = None


class CLIExecuteRequest(BaseModel):
    command: str = Field(min_length=1)
    timeout: int = Field(default=0, ge=0)
    cwd: Optional[str] = Field(default=None)
    project_id: Optional[str] = Field(default=None, max_length=64)
    session_id: Optional[str] = Field(default=None, max_length=128)

    @field_validator("command")
    @classmethod
    def _validate_command(cls, value: str) -> str:
        return normalize_text_input(value, field_name="command", max_length=2000, allow_newlines=False)

    @field_validator("cwd")
    @classmethod
    def _validate_cwd(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return normalize_text_input(value, field_name="cwd", max_length=512, allow_newlines=False)


class FileOperationRequest(BaseModel):
    action: str = Field(description="list/read/write/delete")
    path: str = Field(default=".")
    content: Optional[str] = None
    recursive: bool = False
    max_entries: int = Field(default=200, ge=1, le=2000)
    project_id: Optional[str] = Field(default=None, max_length=64)
    session_id: Optional[str] = Field(default=None, max_length=128)


class LibFileUpsertRequest(BaseModel):
    lib_type: str
    path: str
    content: str
    overwrite: bool = True


class ApiKeyUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str = "deepseek"
    endpoint_key: Optional[str] = Field(default=None, max_length=64)
    api_key: Optional[str] = Field(default=None, max_length=512)
    base_url: Optional[str] = Field(default=None, max_length=1024)
    protocol: Optional[str] = Field(default=None, max_length=64)
    model: Optional[str] = Field(default=None, max_length=128)
    failover_models: Optional[List[str]] = Field(default=None)
    default_provider: Optional[str] = Field(default=None, max_length=64)
    provider_failover_order: Optional[List[str]] = Field(default=None)

    @field_validator("provider", "endpoint_key", "protocol", "model", "default_provider")
    @classmethod
    def _validate_plain_text_fields(cls, value: Optional[str], info) -> Optional[str]:
        if value is None:
            return value
        return normalize_text_input(value, field_name=info.field_name, max_length=256, allow_newlines=False)

    @field_validator("api_key", "base_url")
    @classmethod
    def _validate_secret_like_fields(cls, value: Optional[str], info) -> Optional[str]:
        if value is None:
            return value
        return normalize_text_input(value, field_name=info.field_name, max_length=1024, allow_newlines=False)


class AccessKeyUpdateRequest(BaseModel):
    access_key: str = Field(min_length=8, max_length=256)

class ProviderVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Optional[str] = Field(default=None, max_length=64)
    endpoint_key: Optional[str] = Field(default=None, max_length=64)
    api_key: Optional[str] = Field(default=None, max_length=512)
    base_url: Optional[str] = Field(default=None, max_length=1024)
    protocol: Optional[str] = Field(default=None, max_length=64)
    model: Optional[str] = Field(default=None, max_length=128)

    @field_validator("provider", "endpoint_key", "protocol", "model")
    @classmethod
    def _validate_plain_text_fields(cls, value: Optional[str], info) -> Optional[str]:
        if value is None:
            return value
        return normalize_text_input(value, field_name=info.field_name, max_length=256, allow_newlines=False)

    @field_validator("api_key", "base_url")
    @classmethod
    def _validate_secret_like_fields(cls, value: Optional[str], info) -> Optional[str]:
        if value is None:
            return value
        return normalize_text_input(value, field_name=info.field_name, max_length=1024, allow_newlines=False)


class SessionOpenRequest(BaseModel):
    shell_id: Optional[str] = None
    name: Optional[str] = Field(default=None, max_length=128)
    cwd: Optional[str] = Field(default=".")


class SessionCloseRequest(BaseModel):
    reason: Optional[str] = Field(default="manual")

class ToolsListResponse(BaseModel):
    tools: List[str]


class SessionBackendUpdateRequest(BaseModel):
    mode: str = Field(default="workspace")
    msf_binary: Optional[str] = Field(default="msfconsole", max_length=256)


class SessionHealthCheckRequest(BaseModel):
    command: Optional[str] = Field(default=None, max_length=1024)
    timeout: int = Field(default=20, ge=3, le=120)


class SessionCommandRequest(BaseModel):
    command: str = Field(min_length=1)
    timeout: int = Field(default=120, ge=0, le=3600)
    cwd: Optional[str] = Field(default=None, max_length=512)

    @field_validator("command")
    @classmethod
    def _validate_command(cls, value: str) -> str:
        return normalize_text_input(value, field_name="command", max_length=2000, allow_newlines=False)

    @field_validator("cwd")
    @classmethod
    def _validate_cwd(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return normalize_text_input(value, field_name="cwd", max_length=512, allow_newlines=False)


class SessionFileOperationRequest(BaseModel):
    action: str = Field(description="list/read/write/delete")
    path: str = Field(default=".")
    content: Optional[str] = None
    recursive: bool = False
    max_entries: int = Field(default=200, ge=1, le=2000)


class LearningSyncRequest(BaseModel):
    topic: str = Field(min_length=1, max_length=200)
    urls: List[str] = Field(default_factory=list)
    content: Optional[str] = Field(default=None, max_length=20000)

    @field_validator("topic")
    @classmethod
    def _validate_topic(cls, value: str) -> str:
        return normalize_text_input(value, field_name="topic", max_length=200, allow_newlines=False)

    @field_validator("content")
    @classmethod
    def _validate_content(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return normalize_text_input(value, field_name="content", max_length=20000, allow_newlines=True)


class WebAuditRulesValidateRequest(BaseModel):
    auto_fix: bool = True


class WebAuditRunRequest(BaseModel):
    target: str = Field(min_length=1)
    auto_fix_rules: bool = True
    use_yak: bool = True
    timeout_seconds: int = Field(default=0, ge=0)

    @field_validator("target")
    @classmethod
    def _validate_target(cls, value: str) -> str:
        return normalize_target_input(value)


# Runtime task storage
running_tasks: Dict[str, asyncio.Task] = {}
tasks_lock = asyncio.Lock()
DEFAULT_EXPORT_POLICY = {
    "retention_hours": 24,
    "max_retries": 2,
    "auto_retry_failed": True,
}
cleanup_worker_task: Optional[asyncio.Task] = None
exploitdb_sync_task: Optional[asyncio.Task] = None
webui_sessions: Dict[str, Dict[str, Any]] = {}
session_health_cache: Dict[str, Dict[str, Any]] = {}
sessions_restored = False

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)
PROJECT_ROOT = os.path.abspath(".")
def _build_lib_base_map() -> Dict[str, str]:
    default_paths = {
        "fingerprints": "fingerprints",
        "plugins": "plugins",
        "vuldb": "vuldb",
        "knowledge": "knowledge",
        "skills": "skills",
        "poc_exp": "poc_exp",
        "custom_tools": "tools",
        "prompts": "core/ai/prompts_data",
        "audit_rules": "repo",
    }
    try:
        if os.path.isfile(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as fp:
                cfg = yaml.safe_load(fp) or {}
            path_cfg = cfg.get("paths") or {}
            default_paths["fingerprints"] = path_cfg.get("fingerprints", default_paths["fingerprints"])
            default_paths["plugins"] = path_cfg.get("plugins", default_paths["plugins"])
            default_paths["vuldb"] = path_cfg.get("vuldb", default_paths["vuldb"])
            default_paths["knowledge"] = path_cfg.get("knowledge_base", default_paths["knowledge"])
            default_paths["skills"] = path_cfg.get("skills", default_paths["skills"])
            default_paths["poc_exp"] = path_cfg.get("poc_exp", default_paths["poc_exp"])
            default_paths["custom_tools"] = path_cfg.get("custom_tools", default_paths["custom_tools"])
            default_paths["prompts"] = path_cfg.get("prompts", default_paths["prompts"])
            default_paths["audit_rules"] = path_cfg.get("audit_rules", default_paths["audit_rules"])
    except Exception as error:
        logger.warning(f"Load config paths failed, use default lib paths: {error}")
    normalized_paths: Dict[str, str] = {}
    for key, value in default_paths.items():
        resolved = os.path.abspath(value)
        if key == "audit_rules" and os.path.isfile(resolved):
            resolved = os.path.abspath(os.path.dirname(resolved))
        normalized_paths[key] = resolved
    return normalized_paths


LIB_BASE_MAP = _build_lib_base_map()
PROJECT_STATUSES = {"pending", "running", "paused", "stopped", "completed", "failed", "insufficient_evidence"}
CORE_PHASES = ["recon", "exploit", "post_exploit", "report"]
ATTACK_CHAIN_STAGES = list(ATTACK_CHAIN_ORDER)
ATTACK_PHASE_LABELS = {
    "planning": ("TA0043", "侦察准备"),
    "dispatch": ("TA0043", "侦察准备"),
    "recon": ("TA0043", "侦察"),
    "exploit": ("TA0001/TA0002", "初始访问与执行"),
    "post_exploit": ("TA0003/TA0004/TA0006/TA0007/TA0008", "后渗透与横向"),
    "aggregation": ("TA0009", "收集与汇总"),
    "verification": ("TA0009", "证据验证"),
    "report": ("TA0040", "影响评估与报告"),
    "completed": ("TA0040", "完成"),
    "failed": ("TA0040", "失败"),
}


def _model_dump(model: BaseModel) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _normalize_status(value: str, default: str = "pending") -> str:
    normalized = str(value or default).strip().lower()
    if normalized == "error":
        normalized = "failed"
    return normalized if normalized in PROJECT_STATUSES else default


def _project_or_404(project_id: str) -> Dict[str, Any]:
    project = db_get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def _resolve_workspace_path(raw_path: str) -> str:
    candidate = raw_path or "."
    if os.path.isabs(candidate):
        resolved = os.path.abspath(candidate)
    else:
        resolved = os.path.abspath(os.path.join(PROJECT_ROOT, candidate))
    normalized_root = os.path.normcase(PROJECT_ROOT)
    normalized_resolved = os.path.normcase(resolved)
    if normalized_resolved != normalized_root and not normalized_resolved.startswith(normalized_root + os.sep):
        raise HTTPException(status_code=400, detail="Path is outside workspace")
    return resolved


def _session_root(project_id: str, session_id: str) -> str:
    root = os.path.abspath(os.path.join("output", "sessions", project_id, session_id))
    os.makedirs(root, exist_ok=True)
    return root


def _get_live_project_shells(project_id: str) -> List[Dict[str, Any]]:
    project = _project_or_404(project_id)
    results = project.get("results") or {}
    return _extract_shells_from_results(project_id, results if isinstance(results, dict) else {})


def _resolve_session(project_id: str, session_id: str) -> Dict[str, Any]:
    key = f"{project_id}:{session_id}"
    session = webui_sessions.get(key)
    if not session or session.get("status") != "active":
        raise HTTPException(status_code=404, detail="Session not found")
    session["last_active_at"] = time.time()
    _persist_webui_session(session)
    return session


def _resolve_session_path(project_id: Optional[str], session_id: Optional[str], requested_path: str) -> str:
    if not project_id or not session_id:
        return _resolve_workspace_path(requested_path)
    session = _resolve_session(project_id, session_id)
    base = _session_root(project_id, session_id)
    raw_path = requested_path or session.get("cwd") or "."
    if os.path.isabs(raw_path):
        raise HTTPException(status_code=400, detail="Absolute path is not allowed in session mode")
    resolved = os.path.abspath(os.path.join(base, raw_path))
    normalized_base = os.path.normcase(base)
    normalized_resolved = os.path.normcase(resolved)
    if normalized_resolved != normalized_base and not normalized_resolved.startswith(normalized_base + os.sep):
        raise HTTPException(status_code=400, detail="Path is outside session workspace")
    return resolved


def _resolve_lib_path(lib_type: str, rel_path: str = "") -> str:
    raw_type = (lib_type or "").strip().lower()
    alias_map = {
        "knowledge_base": "knowledge",
        "skill": "skills",
        "skill_lib": "skills",
        "vulnerability": "vuldb",
        "repo": "audit_rules",
        "rules": "audit_rules",
    }
    normalized_type = alias_map.get(raw_type, raw_type)
    base_dir = LIB_BASE_MAP.get(normalized_type)
    if not base_dir:
        raise HTTPException(status_code=400, detail="Unsupported lib_type")
    os.makedirs(base_dir, exist_ok=True)
    if not rel_path:
        return os.path.abspath(base_dir)
    safe_rel = rel_path.replace("\\", "/").lstrip("/")
    resolved = os.path.abspath(os.path.join(base_dir, safe_rel))
    normalized_base = os.path.normcase(os.path.abspath(base_dir))
    normalized_resolved = os.path.normcase(resolved)
    if normalized_resolved != normalized_base and not normalized_resolved.startswith(normalized_base + os.sep):
        raise HTTPException(status_code=400, detail="Path is outside library scope")
    return resolved


def _mask_secret(secret: str) -> str:
    return mask_secret(secret)


def _normalize_provider_name(provider: str) -> str:
    return normalize_provider_name(provider)


def _is_placeholder_api_key(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return True
    if text in {"smoke-test-key", "your-api-key", "api-key", "none", "null"}:
        return True
    return text.startswith("test-key-")


def _provider_is_configured_for_runtime(provider: str, provider_config: Optional[Dict[str, Any]] = None) -> bool:
    runtime = _provider_runtime_config(provider, provider_config or {})
    if provider_requires_api_key(provider) and _is_placeholder_api_key(str(runtime.get("api_key") or "").strip()):
        return False
    if provider_allows_custom_base_url(provider) and not str(runtime.get("base_url") or "").strip():
        return False
    return bool(str(runtime.get("model") or "").strip())


def _configured_provider_chain(config: Dict[str, Any]) -> List[str]:
    ai_config = config.get("ai", {}) or {}
    default_provider = _normalize_provider_name(ai_config.get("default_provider", "deepseek"))
    provider_order = normalize_provider_failover_order(ai_config.get("provider_failover_order"), default_provider)
    providers = ai_config.get("providers", {}) or {}
    chain: List[str] = []
    for provider_name in provider_order:
        provider_config = providers.get(provider_name, {}) or {}
        if not _provider_is_configured_for_runtime(provider_name, provider_config):
            continue
        if provider_name not in chain:
            chain.append(provider_name)
    return chain


def _classify_provider_verify_result(result: Dict[str, Any]) -> str:
    if not isinstance(result, dict):
        return "unknown"
    if not bool(result.get("api_key_configured")):
        return "api_key_missing"
    if bool(result.get("reachable")) and bool(result.get("model_exists")):
        return "ok"
    if bool(result.get("reachable")) and not bool(result.get("model_exists")):
        return "model_mismatch"
    text = str(result.get("error") or "").lower()
    if "401" in text or "403" in text or "unauthorized" in text or "invalid api key" in text:
        return "auth_error"
    if "timeout" in text or "timed out" in text:
        return "network_timeout"
    if "name or service not known" in text or "nodename nor servname" in text or "getaddrinfo" in text:
        return "dns_error"
    if "connection" in text or "ssl" in text or "certificate" in text:
        return "network_error"
    return "unknown"


def _provider_protocol(provider: str, provider_config: Optional[Dict[str, Any]] = None) -> str:
    return resolve_provider_protocol(provider, provider_config or {})


def _provider_runtime_config(provider: str, provider_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    normalized_provider = _normalize_provider_name(provider)
    normalized_config, warnings = normalize_provider_config(normalized_provider, provider_config or {})
    endpoint_key = str(normalized_config.get("endpoint_key") or get_default_endpoint_key(normalized_provider)).strip()
    runtime = dict(normalized_config)
    runtime["provider"] = normalized_provider
    runtime["label"] = get_provider_label(normalized_provider)
    runtime["endpoint_key"] = endpoint_key
    runtime["base_url"] = get_runtime_provider_base_url(normalized_provider, normalized_config)
    runtime["protocol"] = resolve_provider_protocol(normalized_provider, normalized_config)
    runtime["discovery"] = get_provider_discovery(normalized_provider)
    runtime["requires_api_key"] = provider_requires_api_key(normalized_provider)
    runtime["migration_warnings"] = warnings
    available_models = list(runtime.get("discovered_models") or get_provider_models(normalized_provider, endpoint_key))
    if provider_supports_freeform_models(normalized_provider):
        merged_models: List[str] = []
        for item in [runtime.get("model"), *(runtime.get("failover_models") or []), *available_models]:
            text = str(item or "").strip()
            if text and text not in merged_models:
                merged_models.append(text)
        available_models = merged_models
    runtime["available_models"] = available_models
    return runtime


def _error_with_response(error: Exception) -> str:
    if isinstance(error, httpx.HTTPStatusError) and error.response is not None:
        body = redact_sensitive_text(str(error.response.text or "").strip(), max_length=500)
        if body:
            return f"{redact_sensitive_text(error)} | {body}"
    return redact_sensitive_text(error)


async def _fetch_provider_models(provider: str, provider_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    runtime = _provider_runtime_config(provider, provider_config)
    normalized_provider = runtime["provider"]
    protocol = str(runtime.get("protocol") or "unknown")
    api_key = str(runtime.get("api_key") or "").strip()
    base_url = str(runtime.get("base_url") or "").strip()
    requires_api_key = bool(runtime.get("requires_api_key"))
    result: Dict[str, Any] = {
        "provider": normalized_provider,
        "label": runtime.get("label"),
        "endpoint_key": runtime.get("endpoint_key"),
        "protocol": protocol,
        "base_url": base_url,
        "model": str(runtime.get("model") or ""),
        "models": list(dict.fromkeys(runtime.get("available_models") or [])),
        "source": "catalog",
        "migration_warnings": list(runtime.get("migration_warnings") or []),
        "error": None,
    }
    if str(runtime.get("discovery") or "") != "remote_models":
        return result
    if requires_api_key and _is_placeholder_api_key(api_key):
        result["error"] = "api_key is missing or still set to a placeholder"
        return result
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            if normalized_provider == "ollama":
                ollama_root = base_url.rstrip("/")
                if ollama_root.endswith("/v1"):
                    ollama_root = ollama_root[: -len("/v1")]
                response = await client.get(f"{ollama_root}/api/tags")
                response.raise_for_status()
                payload = response.json()
                models = [str(item.get("name") or "").strip() for item in (payload.get("models") or []) if str(item.get("name") or "").strip()]
            elif protocol == "openai-compatible":
                headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
                response = await client.get(
                    f"{base_url.rstrip('/')}/models",
                    headers=headers or None,
                )
                response.raise_for_status()
                payload = response.json()
                models = [str(item.get("id") or "").strip() for item in (payload.get("data") or []) if str(item.get("id") or "").strip()]
            elif protocol == "google-official":
                response = await client.get(f"{base_url.rstrip('/')}/models", params={"key": api_key})
                response.raise_for_status()
                payload = response.json()
                models = []
                for item in (payload.get("models") or []):
                    name = str(item.get("name") or "").strip()
                    model_name = name.split("/")[-1] if "/" in name else name
                    if model_name:
                        models.append(model_name)
            elif protocol == "anthropic-official":
                response = await client.get(
                    f"{base_url.rstrip('/')}/models",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": str(runtime.get("anthropic_version") or "2023-06-01"),
                    },
                )
                response.raise_for_status()
                payload = response.json()
                models = [str(item.get("id") or "").strip() for item in (payload.get("data") or []) if str(item.get("id") or "").strip()]
            else:
                result["error"] = "unsupported provider protocol"
                return result
            if models:
                result["models"] = list(dict.fromkeys(models))
                result["source"] = "remote"
            return result
    except Exception as error:
        result["error"] = _error_with_response(error)
        return result


async def _verify_provider_config(provider: str, provider_config: Dict[str, Any]) -> Dict[str, Any]:
    normalized_provider = _normalize_provider_name(provider)
    runtime = _provider_runtime_config(normalized_provider, provider_config)
    protocol = str(runtime.get("protocol") or "unknown")
    api_key = str(runtime.get("api_key") or "").strip()
    base_url = str(runtime.get("base_url") or "")
    model = str(runtime.get("model") or "")
    requires_api_key = bool(runtime.get("requires_api_key"))
    result: Dict[str, Any] = {
        "provider": normalized_provider,
        "label": runtime.get("label"),
        "endpoint_key": runtime.get("endpoint_key"),
        "protocol": protocol,
        "base_url": base_url,
        "model": model,
        "api_key_configured": (not requires_api_key) or (not _is_placeholder_api_key(api_key)),
        "migration_warnings": list(runtime.get("migration_warnings") or []),
        "reachable": False,
        "model_exists": False,
        "models_sample": [],
    }
    if requires_api_key and _is_placeholder_api_key(api_key):
        result["error"] = "api_key is missing or still set to a placeholder"
        result["status"] = _classify_provider_verify_result(result)
        return result
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            if normalized_provider == "ollama":
                response = await client.post(
                    f"{base_url.rstrip('/')}/chat/completions",
                    headers={"Content-Type": "application/json"},
                    json={
                        "model": model,
                        "max_tokens": 16,
                        "messages": [{"role": "user", "content": "ping"}],
                    },
                )
                response.raise_for_status()
                result["reachable"] = True
                fetched = await _fetch_provider_models(normalized_provider, provider_config)
                result["models_sample"] = list(fetched.get("models") or [])[:20]
                result["model_exists"] = bool(model)
                result["status"] = _classify_provider_verify_result(result)
                return result
            if str(runtime.get("discovery") or "") == "remote_models" and protocol == "openai-compatible" and normalized_provider not in {"custom"}:
                response = await client.get(
                    f"{base_url.rstrip('/')}/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                response.raise_for_status()
                payload = response.json()
                models = [str(item.get("id") or "").strip() for item in (payload.get("data") or []) if str(item.get("id") or "").strip()]
                result["reachable"] = True
                result["models_sample"] = models[:20]
                result["model_exists"] = model in models if model else False
                result["status"] = _classify_provider_verify_result(result)
                return result
            if str(runtime.get("discovery") or "") == "remote_models" and protocol == "google-official" and normalized_provider not in {"custom"}:
                response = await client.get(f"{base_url.rstrip('/')}/models", params={"key": api_key})
                response.raise_for_status()
                payload = response.json()
                models = []
                for item in (payload.get("models") or []):
                    raw_name = str(item.get("name") or "").strip()
                    model_name = raw_name.split("/")[-1] if "/" in raw_name else raw_name
                    if model_name:
                        models.append(model_name)
                result["reachable"] = True
                result["models_sample"] = models[:20]
                result["model_exists"] = model in models if model else False
                result["status"] = _classify_provider_verify_result(result)
                return result
            if str(runtime.get("discovery") or "") == "remote_models" and protocol == "anthropic-official" and normalized_provider not in {"custom"}:
                response = await client.get(
                    f"{base_url.rstrip('/')}/models",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": str(runtime.get("anthropic_version") or "2023-06-01"),
                    },
                )
                response.raise_for_status()
                payload = response.json()
                models = [str(item.get("id") or "").strip() for item in (payload.get("data") or []) if str(item.get("id") or "").strip()]
                result["reachable"] = True
                result["models_sample"] = models[:20]
                result["model_exists"] = model in models if model else False
                result["status"] = _classify_provider_verify_result(result)
                return result
            if protocol == "openai-compatible":
                headers = {
                    "Content-Type": "application/json",
                }
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"
                response = await client.post(
                    f"{base_url.rstrip('/')}/chat/completions",
                    headers=headers,
                    json={
                        "model": model,
                        "max_tokens": 16,
                        "messages": [{"role": "user", "content": "ping"}],
                    },
                )
                response.raise_for_status()
                result["reachable"] = True
                result["models_sample"] = list(runtime.get("available_models") or [])[:20]
                result["model_exists"] = bool(model)
                result["status"] = _classify_provider_verify_result(result)
                return result
            if protocol == "google-official":
                response = await client.post(
                    f"{base_url.rstrip('/')}/models/{model}:generateContent",
                    params={"key": api_key},
                    json={
                        "contents": [{"role": "user", "parts": [{"text": "ping"}]}],
                        "generationConfig": {"maxOutputTokens": 16},
                    },
                )
                response.raise_for_status()
                result["reachable"] = True
                result["models_sample"] = list(runtime.get("available_models") or [])[:20]
                result["model_exists"] = bool(model)
                result["status"] = _classify_provider_verify_result(result)
                return result
            if protocol == "anthropic-official":
                messages_url = base_url if base_url.rstrip("/").endswith("/messages") else f"{base_url.rstrip('/')}/messages"
                response = await client.post(
                    messages_url,
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": str(runtime.get("anthropic_version") or "2023-06-01"),
                        "content-type": "application/json",
                    },
                    json={
                        "model": model,
                        "max_tokens": 16,
                        "messages": [{"role": "user", "content": "ping"}],
                    },
                )
                response.raise_for_status()
                result["reachable"] = True
                result["models_sample"] = [model] if model else []
                result["model_exists"] = bool(model)
                result["status"] = _classify_provider_verify_result(result)
                return result
            result["error"] = "unsupported provider protocol"
            result["status"] = _classify_provider_verify_result(result)
            return result
    except httpx.HTTPStatusError as error:
        if error.response is not None and error.response.status_code in {400, 404, 422}:
            result["reachable"] = True
            result["models_sample"] = list(runtime.get("available_models") or [])[:20]
            result["model_exists"] = False
            result["error"] = _error_with_response(error)
            result["status"] = _classify_provider_verify_result(result)
            return result
        result["error"] = _error_with_response(error)
        result["status"] = _classify_provider_verify_result(result)
        return result
    except Exception as error:
        result["error"] = _error_with_response(error)
        result["status"] = _classify_provider_verify_result(result)
        return result


async def _check_loaded_ai_models(config: Dict[str, Any]) -> Dict[str, Any]:
    ai_config = config.get("ai", {}) or {}
    providers = ai_config.get("providers", {}) or {}
    loaded_models: List[Dict[str, Any]] = []
    failed_models: List[Dict[str, Any]] = []
    configured_count = 0
    for provider_name in SUPPORTED_AI_PROVIDERS:
        provider_config = providers.get(provider_name, {}) or {}
        if not _provider_is_configured_for_runtime(provider_name, provider_config):
            continue
        configured_count += 1
        verify_result = await _verify_provider_config(provider_name, provider_config or {})
        verify_result["checked_at"] = time.time()
        record = {
            "provider": verify_result.get("provider"),
            "endpoint_key": verify_result.get("endpoint_key"),
            "protocol": verify_result.get("protocol"),
            "base_url": verify_result.get("base_url"),
            "model": verify_result.get("model"),
            "status": verify_result.get("status"),
            "error": verify_result.get("error"),
        }
        if bool(verify_result.get("reachable")):
            loaded_models.append(record)
        else:
            failed_models.append(record)
    return {
        "checked_at": time.time(),
        "configured_count": configured_count,
        "loaded_count": len(loaded_models),
        "loaded_models": loaded_models,
        "failed_models": failed_models,
    }


@router.get("/tools", response_model=ToolsListResponse)
def list_built_in_tools():
    return {"tools": []}

@router.post("/tools/upload")
async def upload_built_in_tool(file: UploadFile = File(...)):
    raise HTTPException(status_code=410, detail="内置工具上传能力已下线，请使用系统 CLI 工具")

@router.delete("/tools/{filename}")
def delete_built_in_tool(filename: str):
    raise HTTPException(status_code=410, detail="内置工具删除能力已下线，请使用系统 CLI 工具")

def _get_admin_access_key() -> str:
    configured = str(db_get_setting("webui_access_key", "") or "").strip()
    if configured:
        return configured
    return str(os.getenv("WRAPT_WEBUI_ACCESS_KEY", "") or "").strip()


def _require_admin_access(x_admin_key: Optional[str]) -> None:
    expected = _get_admin_access_key()
    if not expected:
        return
    provided = str(x_admin_key or "").strip()
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid X-Admin-Key")


def _require_admin_when_configured(x_admin_key: Optional[str]) -> None:
    if _get_admin_access_key():
        _require_admin_access(x_admin_key)


def _audit_operation(
    project_id: Optional[str],
    phase: str,
    status: str,
    message: str,
    level: str = "INFO",
) -> None:
    try:
        db_insert_event(
            {
                "project_id": project_id,
                "type": "audit",
                "phase": phase,
                "status": status,
                "level": level,
                "message": message,
                "timestamp": time.time(),
            }
        )
    except Exception as error:
        logger.warning(f"Audit event insert failed: {error}")


def _load_yaml_config(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def _save_yaml_config(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        yaml.safe_dump(data, file, allow_unicode=True, sort_keys=False)


def _get_session_backend_settings() -> Dict[str, str]:
    mode = str(db_get_setting("session_backend_mode", "workspace") or "workspace").strip().lower()
    msf_binary = str(db_get_setting("session_backend_msf_binary", "msfconsole") or "msfconsole").strip()
    if mode not in {"workspace", "msf"}:
        mode = "workspace"
    if not msf_binary:
        msf_binary = "msfconsole"
    return {"mode": mode, "msf_binary": msf_binary}


def _build_session_executor(session: Optional[Dict[str, Any]] = None) -> SessionBackendExecutor:
    settings = _get_session_backend_settings()
    mode = session.get("backend_mode") if session and session.get("backend_mode") else settings["mode"]
    return SessionBackendExecutor(mode=mode, msf_binary=settings["msf_binary"])


def _session_cache_key(project_id: str, session_id: str) -> str:
    return f"{project_id}:{session_id}"


def _persist_webui_session(session: Dict[str, Any]) -> Dict[str, Any]:
    persisted = db_upsert_webui_session(session)
    key = _session_cache_key(str(persisted.get("project_id")), str(persisted.get("session_id")))
    webui_sessions[key] = persisted
    return persisted


def _restore_webui_sessions() -> None:
    restored = db_list_webui_sessions(status="active")
    for session in restored:
        project_id = str(session.get("project_id") or "")
        session_id = str(session.get("session_id") or "")
        if not project_id or not session_id:
            continue
        key = _session_cache_key(project_id, session_id)
        webui_sessions[key] = session
        if session.get("health_status") or session.get("health_checked_at"):
            session_health_cache[key] = {
                "healthy": str(session.get("health_status") or "").lower() == "online",
                "status": session.get("health_status") or "unknown",
                "reason": session.get("health_reason") or "",
                "checked_at": session.get("health_checked_at") or time.time(),
                "returncode": session.get("last_returncode"),
                "command": session.get("last_command"),
            }


def _snapshot_command_output(value: str, max_len: int = 0) -> str:
    text = redact_sensitive_text(value)
    if max_len is None or int(max_len) <= 0:
        return text
    return text if len(text) <= max_len else text[:max_len] + "...(truncated)"


def _sanitize_event_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = redact_sensitive_data(event or {}, max_depth=5, max_items=80, string_max_length=20000)
    if not isinstance(payload, dict):
        return {"type": "log", "message": redact_sensitive_text(payload)}
    if payload.get("timestamp") == "":
        payload["timestamp"] = None
    if payload.get("progress") == "":
        payload["progress"] = None
    if "message" in payload:
        payload["message"] = redact_sensitive_text(payload.get("message"), max_length=20000)
    return payload


def _record_session_health(
    project_id: str,
    session_id: str,
    healthy: bool,
    reason: str,
    returncode: Optional[int] = None,
    command: Optional[str] = None,
) -> Dict[str, Any]:
    now = time.time()
    payload = {
        "healthy": bool(healthy),
        "status": "online" if healthy else "offline",
        "reason": reason,
        "checked_at": now,
        "returncode": returncode,
        "command": command,
    }
    session_health_cache[_session_cache_key(project_id, session_id)] = payload
    session = webui_sessions.get(_session_cache_key(project_id, session_id))
    if session:
        session["health_status"] = payload["status"]
        session["health_checked_at"] = now
        session["health_reason"] = reason
        _persist_webui_session(session)
    return payload


async def _refresh_session_heartbeat(project_id: str, session: Dict[str, Any], force: bool = False) -> Dict[str, Any]:
    session_id = str(session.get("session_id") or "")
    if not session_id:
        return {"status": "unknown", "reason": "missing_session_id", "checked_at": time.time()}
    key = _session_cache_key(project_id, session_id)
    cached = session_health_cache.get(key)
    now = time.time()
    if cached and not force and now - float(cached.get("checked_at") or 0) < 30:
        return cached
    backend_mode = str(session.get("backend_mode") or "workspace")
    if backend_mode == "msf":
        executor = _build_session_executor(session)
        ready, reason = await executor.verify_session(shell_id=session.get("shell_id"), timeout=20)
        return _record_session_health(project_id, session_id, ready, reason, 0 if ready else 1, "heartbeat:verify_session")
    return _record_session_health(project_id, session_id, True, "workspace_session", 0, "heartbeat:workspace")


def _extract_shells_from_results(project_id: str, results: Dict[str, Any]) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    seen_ids = set()

    def visit(node: Any, depth: int = 0):
        if depth > 6:
            return
        if isinstance(node, dict):
            lower_keys = {str(key).lower() for key in node.keys()}
            is_shell_candidate = (
                "shell" in "".join(lower_keys)
                or ("id" in lower_keys and ("target" in lower_keys or "ip" in lower_keys))
                or ("session" in lower_keys and "status" in lower_keys)
            )
            if is_shell_candidate:
                shell_id = str(
                    node.get("id")
                    or node.get("shell_id")
                    or node.get("session")
                    or node.get("sid")
                    or f"shell-{len(found) + 1}"
                )
                if shell_id not in seen_ids:
                    seen_ids.add(shell_id)
                    found.append(
                        {
                            "id": shell_id,
                            "project_id": project_id,
                            "target": node.get("target") or node.get("ip") or node.get("host"),
                            "type": node.get("type") or node.get("shell_type") or "unknown",
                            "user": node.get("user") or node.get("username"),
                            "status": node.get("status") or "active",
                            "last_seen": node.get("last_seen") or time.time(),
                            "raw": node,
                        }
                    )
            for value in node.values():
                visit(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:200]:
                visit(item, depth + 1)

    visit(results)
    return found


def _append_session_history(session: Dict[str, Any], history_key: str, entry: Dict[str, Any], limit: int = 40) -> None:
    """维护会话历史，便于重启后继续追踪最近命令与文件操作。"""
    current = session.get(history_key)
    if not isinstance(current, list):
        current = []
    current.append(entry)
    session[history_key] = current[-max(1, int(limit)) :]


def _record_session_command(
    session: Dict[str, Any],
    command: str,
    cwd: str,
    returncode: int,
    duration: float,
    stdout: str,
    stderr: str,
    backend_meta: Dict[str, Any],
) -> None:
    now = time.time()
    safe_command = redact_sensitive_text(command, max_length=2000)
    safe_cwd = redact_sensitive_text(cwd, max_length=512)
    session["last_command"] = safe_command
    session["last_command_at"] = now
    session["last_returncode"] = returncode
    session["last_duration_seconds"] = duration
    session["last_stdout_excerpt"] = _snapshot_command_output(stdout, max_len=800)
    session["last_stderr_excerpt"] = _snapshot_command_output(stderr, max_len=800)
    _append_session_history(
        session,
        "command_history",
        {
            "timestamp": now,
            "command": safe_command,
            "cwd": safe_cwd,
            "returncode": returncode,
            "duration_seconds": duration,
            "stdout_excerpt": session["last_stdout_excerpt"],
            "stderr_excerpt": session["last_stderr_excerpt"],
            "backend_mode": backend_meta.get("mode"),
        },
    )
    _persist_webui_session(session)


def _record_session_file_operation(
    session: Dict[str, Any],
    action: str,
    raw_path: str,
    resolved_path: str,
    result: Dict[str, Any],
    backend_mode: str,
) -> None:
    now = time.time()
    _append_session_history(
        session,
        "file_history",
        {
            "timestamp": now,
            "action": action,
            "path": raw_path,
            "resolved_path": resolved_path,
            "backend_mode": backend_mode,
            "ok": "error" not in result,
        },
    )
    session["last_active_at"] = now
    _persist_webui_session(session)


def _file_operation_error_to_http(error: str) -> HTTPException:
    text = str(error or "").strip() or "File operation failed"
    lowered = text.lower()
    if "not found" in lowered:
        return HTTPException(status_code=404, detail=text)
    return HTTPException(status_code=400, detail=text)


def _resolve_file_operation_target(
    request_path: str,
    project_id: Optional[str],
    session: Optional[Dict[str, Any]],
) -> str:
    if session and str(session.get("backend_mode") or "workspace").strip().lower() == "msf":
        target = str(request_path or "").strip() or "."
        return target
    return _resolve_session_path(project_id, session.get("session_id") if session else None, request_path)


async def _execute_cli_for_session(
    *,
    project_id: Optional[str],
    session: Optional[Dict[str, Any]],
    command: str,
    cwd: str,
    timeout: int,
) -> Dict[str, Any]:
    started_at = time.time()
    safe_command = redact_sensitive_text(command, max_length=2000)
    safe_cwd = redact_sensitive_text(cwd, max_length=512)
    executor = _build_session_executor(session)
    stdout, stderr, returncode, backend_meta = await executor.execute(
        command=command,
        timeout=None if timeout <= 0 else timeout,
        cwd=cwd,
        shell_id=(session or {}).get("shell_id"),
        retries=1,
    )
    duration = round(time.time() - started_at, 4)
    if session and project_id:
        _record_session_command(session, command, cwd, returncode, duration, stdout, stderr, backend_meta)
        _record_session_health(
            project_id=project_id,
            session_id=str(session.get("session_id") or ""),
            healthy=returncode == 0,
            reason="command_ok" if returncode == 0 else "command_failed",
            returncode=returncode,
            command=safe_command,
        )
    return {
        "command": safe_command,
        "cwd": safe_cwd,
        "project_id": project_id,
        "session_id": (session or {}).get("session_id"),
        "timeout": timeout,
        "returncode": returncode,
        "stdout": redact_sensitive_text(stdout),
        "stderr": redact_sensitive_text(stderr),
        "duration_seconds": duration,
        "timed_out": returncode == -1 and "timed out" in (stderr or "").lower(),
        "backend": backend_meta,
    }


async def _execute_file_operation(
    *,
    action: str,
    path: str,
    content: Optional[str],
    recursive: bool,
    max_entries: int,
    project_id: Optional[str],
    session: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    target_path = _resolve_file_operation_target(path, project_id, session)
    if session:
        executor = _build_session_executor(session)
        result = await executor.execute_file_op(
            action=action,
            path=target_path,
            content=content,
            recursive=recursive,
            max_entries=max_entries,
            shell_id=session.get("shell_id"),
        )
        if "error" in result:
            raise _file_operation_error_to_http(str(result.get("error") or ""))
        _record_session_file_operation(
            session=session,
            action=action,
            raw_path=path,
            resolved_path=target_path,
            result=result,
            backend_mode=str(executor.mode),
        )
        return {
            **result,
            "project_id": project_id,
            "session_id": session.get("session_id"),
            "backend": {"mode": executor.mode},
        }

    if action == "list":
        if not os.path.isdir(target_path):
            raise HTTPException(status_code=400, detail="Path is not a directory")
        rows: List[Dict[str, Any]] = []
        entries = sorted(os.scandir(target_path), key=lambda item: (not item.is_dir(), item.name.lower()))
        for entry in entries[:max_entries]:
            stat = entry.stat()
            rows.append(
                {
                    "name": entry.name,
                    "path": os.path.abspath(entry.path),
                    "is_dir": entry.is_dir(),
                    "size": int(stat.st_size),
                    "modified_at": float(stat.st_mtime),
                }
            )
        return {"action": action, "path": target_path, "project_id": project_id, "session_id": None, "count": len(rows), "items": rows}

    if action == "read":
        if not os.path.isfile(target_path):
            raise HTTPException(status_code=404, detail="File not found")
        with open(target_path, "r", encoding="utf-8", errors="replace") as file:
            content_value = file.read()
        return {"action": action, "path": target_path, "project_id": project_id, "session_id": None, "content": content_value}

    if action == "write":
        if content is None:
            raise HTTPException(status_code=400, detail="content is required for write action")
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as file:
            file.write(content)
        return {"action": action, "path": target_path, "project_id": project_id, "session_id": None, "bytes": len(content.encode('utf-8'))}

    if action == "delete":
        if not os.path.exists(target_path):
            return {"action": action, "path": target_path, "project_id": project_id, "session_id": None, "deleted": False}
        if os.path.isdir(target_path):
            if not recursive:
                raise HTTPException(status_code=400, detail="Directory delete requires recursive=true")
            for root, dirs, files in os.walk(target_path, topdown=False):
                for filename in files:
                    os.remove(os.path.join(root, filename))
                for dirname in dirs:
                    os.rmdir(os.path.join(root, dirname))
            os.rmdir(target_path)
        else:
            os.remove(target_path)
        return {"action": action, "path": target_path, "project_id": project_id, "session_id": None, "deleted": True}

    raise HTTPException(status_code=400, detail="Unsupported action, use list/read/write/delete")


def _extract_tool_names(stage_payload: Any) -> List[str]:
    names: List[str] = []
    if not isinstance(stage_payload, dict):
        return names
    for tool_call in stage_payload.get("tool_calls") or []:
        function_data = tool_call.get("function") if isinstance(tool_call, dict) else None
        name = ""
        if isinstance(function_data, dict):
            name = str(function_data.get("name") or "").strip()
        if not name and isinstance(tool_call, dict):
            name = str(tool_call.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    for tool_result in stage_payload.get("tool_results") or []:
        if not isinstance(tool_result, dict):
            continue
        name = str(tool_result.get("tool") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def _strip_think_blocks(content: str) -> str:
    text = str(content or "")
    text = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\[TASK_COMPLETED\]", "", text, flags=re.IGNORECASE)
    return text.strip()


def _sanitize_report_text(content: str, max_chars: int = 6000) -> str:
    text = _strip_think_blocks(content).strip()
    if len(text) > max_chars:
        return text[:max_chars].rstrip() + "..."
    return text


def _attack_label_for_phase(phase: str) -> str:
    tactic, name = ATTACK_PHASE_LABELS.get(str(phase or "").strip().lower(), ("TA0000", "未知阶段"))
    return f"{name} ({tactic})"


def _summarize_event_messages(events: List[Dict[str, Any]], limit: int = 3) -> str:
    if not events:
        return ""
    snippets: List[str] = []
    for event in events[-limit:]:
        message = _sanitize_report_text(str(event.get("message") or "").replace("\n", " "), max_chars=280)
        if not message:
            continue
        tool_name = str(event.get("tool_name") or "").strip()
        if tool_name and tool_name not in message:
            message = f"{tool_name}: {message}"
        snippets.append(message)
    return "；".join(snippets)


def _extract_stage_payload_from_events(project_id: str, stage: str) -> Dict[str, Any]:
    phase_aliases = {
        "recon": {"recon"},
        "vuln_analysis": {"exploit"},
        "exploitation": {"exploit"},
        "post_exploit": {"post_exploit"},
        "lateral_movement": {"post_exploit"},
        "report": {"report"},
    }
    expected_phases = phase_aliases.get(stage, {stage})
    events = db_list_project_events(project_id, limit=800, offset=0)
    stage_events = [item for item in events if str(item.get("phase") or "") in expected_phases]
    tool_names: List[str] = []
    for item in stage_events:
        tool_name = str(item.get("tool_name") or "").strip()
        if tool_name and tool_name not in tool_names:
            tool_names.append(tool_name)
    return {
        "content": _summarize_event_messages(stage_events),
        "tool_results": [{"tool": name} for name in tool_names],
    }


def _build_inline_stage_snapshot(phase: str, status: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    content = str(payload.get("content") or "")
    tool_results = payload.get("tool_results", []) if isinstance(payload.get("tool_results"), list) else []
    key_facts: List[str] = []
    for row in content.replace("\r", "\n").split("\n"):
        text = row.lstrip("-•* ").strip()
        if not text:
            continue
        key_facts.append(text[:140] + "..." if len(text) > 140 else text)
        if len(key_facts) >= 4:
            break
    evidences: List[str] = []
    for item in tool_results[:8]:
        if not isinstance(item, dict):
            continue
        tool_name = str(item.get("tool") or item.get("tool_name") or "unknown_tool")
        evidences.append(tool_name)
    return {
        "phase": phase,
        "status": status,
        "key_facts": key_facts,
        "hypotheses": [],
        "evidences": evidences,
        "next_actions": [],
    }


def _derive_phase_status_from_events(project_id: str) -> Dict[str, str]:
    events = db_list_project_events(project_id, limit=1200, offset=0)
    status: Dict[str, str] = {}
    mapping = {
        "recon": "recon",
        "exploit": "exploit",
        "post_exploit": "post_exploit",
        "report": "report",
    }
    for item in events:
        phase = str(item.get("phase") or "").strip()
        mapped = mapping.get(phase)
        if not mapped:
            continue
        current = _normalize_status(str(item.get("status") or "running"), default="running")
        if current == "insufficient_evidence":
            status[mapped] = "insufficient_evidence"
            continue
        if current in {"failed", "error"}:
            status[mapped] = "failed"
            continue
        if status.get(mapped) not in {"failed", "insufficient_evidence"}:
            status[mapped] = "completed" if current == "completed" else "running"
    project = db_get_project(project_id) or {}
    project_status = _normalize_status(str(project.get("status") or "pending"), default="pending")
    project_phase = str(project.get("phase") or "").strip()
    if project_status in {"completed", "insufficient_evidence", "failed"}:
        for phase in ("recon", "exploit", "post_exploit", "report"):
            current = str(status.get(phase) or "").strip()
            if not current:
                if project_status == "failed" and (project_phase == phase or phase == "report"):
                    status[phase] = "failed"
                elif project_status == "insufficient_evidence" and phase in {"exploit", "post_exploit"}:
                    status[phase] = "insufficient_evidence"
                else:
                    status[phase] = "completed"
                continue
            if current == "running":
                if project_status == "insufficient_evidence" and phase in {"exploit", "post_exploit"}:
                    status[phase] = "insufficient_evidence"
                elif project_status == "failed" and (project_phase == phase or phase == "report"):
                    status[phase] = "failed"
                else:
                    status[phase] = "completed"
    return status


def _extract_usage_from_events(project_id: str) -> Dict[str, float]:
    events = db_list_project_events(project_id, limit=5000, offset=0)
    usage_total: Dict[str, float] = {}
    usage_by_agent: Dict[str, Dict[str, float]] = {}
    usage_score_by_agent: Dict[str, float] = {}
    for item in events:
        raw = item.get("usage_total")
        if not isinstance(raw, dict):
            continue
        parsed = {str(key): float(value) for key, value in raw.items() if isinstance(value, (int, float))}
        if not parsed:
            continue
        agent = str(item.get("agent") or item.get("phase") or f"event-{item.get('id')}")
        score = float(parsed.get("total_tokens") or sum(parsed.values()))
        previous = float(usage_score_by_agent.get(agent, -1.0))
        if score >= previous:
            usage_score_by_agent[agent] = score
            usage_by_agent[agent] = parsed
    if usage_by_agent:
        for usage in usage_by_agent.values():
            for key, value in usage.items():
                usage_total[key] = float(usage_total.get(key, 0.0)) + float(value)
        return usage_total
    for item in events:
        raw = item.get("usage_total")
        if not isinstance(raw, dict):
            continue
        for key, value in raw.items():
            if isinstance(value, (int, float)):
                usage_total[str(key)] = max(float(value), float(usage_total.get(str(key), 0.0)))
    return usage_total


def _coerce_terminal_phase_status(phase_status: Dict[str, str], project_status: str, project_phase: str) -> Dict[str, str]:
    normalized = dict(phase_status or {})
    terminal = _normalize_status(project_status, default="pending")
    phase = str(project_phase or "").strip()
    if terminal not in {"completed", "insufficient_evidence", "failed"}:
        return normalized
    for key in ("recon", "exploit", "post_exploit", "report"):
        current = str(normalized.get(key) or "").strip()
        if not current or current == "running":
            if terminal == "insufficient_evidence" and key in {"exploit", "post_exploit"}:
                normalized[key] = "insufficient_evidence"
            elif terminal == "failed" and (phase == key or key == "report"):
                normalized[key] = "failed"
            else:
                normalized[key] = "completed"
    return normalized


def _build_report_quality_checks(
    phase_status: Dict[str, str],
    findings: List[Dict[str, Any]],
    evidence_gap_checklist: List[str],
    usage_summary: Dict[str, Any],
) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    checks.append(
        {
            "name": "phase_status_present",
            "passed": bool(isinstance(phase_status, dict) and phase_status),
            "message": "阶段状态已生成" if isinstance(phase_status, dict) and phase_status else "阶段状态缺失",
        }
    )
    checks.append(
        {
            "name": "findings_present",
            "passed": bool(isinstance(findings, list) and findings),
            "message": "发现项已生成" if isinstance(findings, list) and findings else "发现项缺失",
        }
    )
    evidence_gate_active = str((phase_status or {}).get("exploit") or "") == "insufficient_evidence" or str((phase_status or {}).get("post_exploit") or "") == "insufficient_evidence"
    checks.append(
        {
            "name": "evidence_gate_consistency",
            "passed": (not evidence_gate_active) or bool(evidence_gap_checklist),
            "message": "证据门禁清单一致" if (not evidence_gate_active) or bool(evidence_gap_checklist) else "证据门禁触发但缺少清单",
        }
    )
    checks.append(
        {
            "name": "usage_summary_present",
            "passed": bool(isinstance(usage_summary, dict) and usage_summary),
            "message": "用量摘要已生成" if isinstance(usage_summary, dict) and usage_summary else "用量摘要缺失",
        }
    )
    passed_count = sum(1 for item in checks if item.get("passed") is True)
    return {
        "total": len(checks),
        "passed": passed_count,
        "failed": len(checks) - passed_count,
        "items": checks,
    }


def _summarize_verification_result(verification_result: Dict[str, Any], evidence_gate_active: bool) -> str:
    if not isinstance(verification_result, dict):
        verification_result = {}
    status = str(verification_result.get("status") or "Unknown").strip()
    suggestions = verification_result.get("suggestions")
    suggestion_items = suggestions if isinstance(suggestions, list) else []
    if evidence_gate_active:
        base = "当前存在待验证线索，报告将保持审慎表述，并把缺少复现实证的内容降级展示。"
    elif status.lower() == "pass":
        base = "自动化验证通过，报告已基于工具证据和验证结果生成。"
    elif status.lower() in {"fail", "unknown", "error"}:
        base = "自动化验证未通过，报告已按审慎原则降级为线索与失败原因汇总。"
    else:
        base = "自动化验证已完成。"
    if suggestion_items:
        return f"{base}\n\n验证建议：{'; '.join(str(item) for item in suggestion_items[:3])}"
    return base


def _markdown_to_readable_html(markdown_text: str, title: str) -> str:
    lines = str(markdown_text or "").splitlines()
    html_lines: List[str] = []
    in_list = False
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if stripped.startswith("### "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h3>{html.escape(stripped[4:])}</h3>")
            continue
        if stripped.startswith("## "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h2>{html.escape(stripped[3:])}</h2>")
            continue
        if stripped.startswith("# "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h1>{html.escape(stripped[2:])}</h1>")
            continue
        if stripped == "---":
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append("<hr />")
            continue
        if stripped.startswith("- "):
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{html.escape(stripped[2:])}</li>")
            continue
        if in_list:
            html_lines.append("</ul>")
            in_list = False
        if stripped:
            safe = html.escape(stripped).replace("**", "")
            html_lines.append(f"<p>{safe}</p>")
    if in_list:
        html_lines.append("</ul>")
    content = "\n".join(html_lines)
    return (
        "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font-family:Segoe UI,Arial,sans-serif;background:#f8fafc;color:#0f172a;margin:0}"
        ".wrap{max-width:1080px;margin:24px auto;padding:0 16px}.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px}"
        "h1,h2,h3{line-height:1.4}p{line-height:1.75;margin:10px 0}li{line-height:1.7;margin:4px 0}hr{border:none;border-top:1px solid #e2e8f0;margin:16px 0}</style>"
        "</head><body><div class='wrap'><div class='card'>"
        f"{content}</div></div></body></html>"
    )


def _build_attack_chain(project: Dict[str, Any]) -> List[Dict[str, Any]]:
    stages = CORE_PHASES
    current_phase = str(project.get("phase") or "pending")
    current_status = _normalize_status(str(project.get("status") or "pending"))
    progress = float(project.get("progress") or 0.0)
    results = project.get("results") or {}
    phase_status = results.get("phase_status", {}) if isinstance(results, dict) else {}
    if isinstance(phase_status, dict):
        phase_status = _coerce_terminal_phase_status(phase_status, str(project.get("status") or ""), str(project.get("phase") or ""))
    progress_hint = {"recon": 0.30, "exploit": 0.50, "post_exploit": 0.70, "report": 0.95}
    current_index = stages.index(current_phase) if current_phase in stages else -1
    chain: List[Dict[str, Any]] = []
    for index, stage in enumerate(stages):
        stage_status = _normalize_status(str(phase_status.get(stage) or ""), default="")
        if not stage_status:
            if stage == current_phase and current_status in {"running", "paused"}:
                stage_status = current_status
            elif current_status == "completed" and index <= current_index:
                stage_status = "completed"
            elif current_status == "failed" and stage == current_phase:
                stage_status = "failed"
            elif index < current_index:
                stage_status = "completed"
            elif progress >= progress_hint.get(stage, 1.0):
                stage_status = "completed"
            else:
                stage_status = "pending"
        chain.append(
            {
                "stage": stage,
                "order": index + 1,
                "status": stage_status,
                "is_current": stage == current_phase,
            }
        )
    return chain


def _calculate_stage_progress_percent(status: str, overall_progress: Any) -> int:
    normalized_status = str(status or "pending").lower()
    if normalized_status == "completed":
        return 100
    if normalized_status in ("running", "paused"):
        try:
            p_val = float(overall_progress if overall_progress is not None else 0.0)
            percent = int(round(p_val * 100))
            return max(10, min(percent, 95))
        except (ValueError, TypeError):
            return 50
    if normalized_status in ("failed", "insufficient_evidence", "error"):
        return 100
    return 0

def _build_attack_chain_stages(project_id: str, project: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = normalize_project_results(project.get("results") if isinstance(project.get("results"), dict) else {})
    phase_status = results.get("phase_status", {}) if isinstance(results, dict) else {}
    if isinstance(phase_status, dict):
        phase_status = _coerce_terminal_phase_status(phase_status, str(project.get("status") or ""), str(project.get("phase") or ""))
    current_phase = str(project.get("phase") or "pending")
    current_status = _normalize_status(str(project.get("status") or "pending"))
    stage_source_map = {
        "recon": "recon_result",
        "vuln_analysis": "exploit_result",
        "exploitation": "exploit_result",
        "post_exploit": "post_exploit_result",
        "lateral_movement": "lateral_movement_result",
        "report": "report_result",
    }
    stage_snapshot_key_map = {
        "recon": "recon",
        "vuln_analysis": "exploit",
        "exploitation": "exploit",
        "post_exploit": "post_exploit",
        "lateral_movement": "lateral_movement",
        "report": "report",
    }
    cognitive_snapshot = results.get("cognitive_snapshot", {}) if isinstance(results, dict) else {}
    stage_snapshots = cognitive_snapshot.get("stage_snapshots", {}) if isinstance(cognitive_snapshot, dict) else {}
    events = db_list_project_events(project_id, limit=1200, offset=0)
    shells = _extract_shells_from_results(project_id, results if isinstance(results, dict) else {})
    shell_ids = [str(item.get("id")) for item in shells if item.get("id")]
    active_shell_count = sum(1 for item in shells if str(item.get("status") or "active").lower() != "closed")
    exploit_payload = results.get("exploit_result", {}) if isinstance(results, dict) else {}
    if not isinstance(exploit_payload, dict) or (not exploit_payload.get("content") and not exploit_payload.get("tool_results")):
        exploit_payload = _extract_stage_payload_from_events(project_id, "exploitation")
    validated_vulnerability_count = extract_validated_vulnerability_count(exploit_payload if isinstance(exploit_payload, dict) else {})
    phase_aliases = {
        "recon": {"recon"},
        "vuln_analysis": {"exploit"},
        "exploitation": {"exploit"},
        "post_exploit": {"post_exploit"},
        "lateral_movement": {"post_exploit"},
        "report": {"report"},
    }
    stages: List[Dict[str, Any]] = []
    for order, stage in enumerate(ATTACK_CHAIN_STAGES, start=1):
        stage_payload = results.get(stage_source_map.get(stage, ""), {}) if isinstance(results, dict) else {}
        if not isinstance(stage_payload, dict) or (not stage_payload.get("content") and not stage_payload.get("tool_results")):
            stage_payload = _extract_stage_payload_from_events(project_id, stage)
        content = ""
        if isinstance(stage_payload, dict):
            content = str(stage_payload.get("content") or "")
        stage_tools = _extract_tool_names(stage_payload)
        summary = content.strip().replace("\n", " ")
        if len(summary) > 180:
            summary = summary[:180] + "..."
        raw_status = ""
        if stage == "vuln_analysis":
            raw_status = str(phase_status.get("exploit") or "")
        elif stage == "exploitation":
            raw_status = str(phase_status.get("exploit") or "")
        elif stage == "lateral_movement":
            raw_status = str(phase_status.get("post_exploit") or "")
        else:
            raw_status = str(phase_status.get(stage) or "")
        status = _normalize_status(raw_status, default="pending") if raw_status else "pending"
        if current_phase == "exploit" and stage in {"vuln_analysis", "exploitation"} and current_status in {"running", "paused"}:
            status = current_status
        if current_phase == "post_exploit" and stage == "lateral_movement" and current_status in {"running", "paused"}:
            status = current_status
        if current_status == "failed" and (
            (current_phase == "exploit" and stage in {"vuln_analysis", "exploitation"})
            or (current_phase == "post_exploit" and stage in {"post_exploit", "lateral_movement"})
            or current_phase == stage
        ):
            status = "failed"
        stage_events = [item for item in events if str(item.get("phase") or "") in phase_aliases.get(stage, {stage})]
        last_event_at = 0.0
        if stage_events:
            last_event_at = max(float(item.get("timestamp") or 0.0) for item in stage_events)
        stage_snapshot = stage_snapshots.get(stage_snapshot_key_map.get(stage, ""), {}) if isinstance(stage_snapshots, dict) else {}
        if stage == "lateral_movement" and (not isinstance(stage_snapshot, dict) or not stage_snapshot):
            stage_snapshot = stage_snapshots.get("post_exploit", {}) if isinstance(stage_snapshots, dict) else {}
        if not isinstance(stage_snapshot, dict):
            stage_snapshot = {}
        if not stage_snapshot:
            stage_snapshot = _build_inline_stage_snapshot(stage, status, stage_payload if isinstance(stage_payload, dict) else {})
        stages.append(
            {
                "order": order,
                "phase": stage,
                "name": stage,
                "status": status,
                "tools": stage_tools,
                "shells": shell_ids if stage in {"exploitation", "post_exploit", "lateral_movement"} else [],
                "summary": summary or "-",
                "event_count": len(stage_events),
                "last_event_at": last_event_at,
                "progress_percent": _calculate_stage_progress_percent(status, project.get("progress")),
                "evidence": {
                    "result_key": stage_source_map.get(stage, ""),
                    "has_content": bool(content.strip()),
                    "tool_count": len(stage_tools),
                    "validated_vulnerability_count": validated_vulnerability_count if stage in {"vuln_analysis", "exploitation"} else 0,
                    "active_shell_count": active_shell_count if stage in {"exploitation", "post_exploit", "lateral_movement"} else 0,
                },
                "cognitive_snapshot": stage_snapshot,
            }
        )
    stage_status_map = {str(item.get("phase")): str(item.get("status") or "pending") for item in stages}
    constraints = build_sequence_constraints(
        stage_status_map=stage_status_map,
        validated_vulnerability_count=validated_vulnerability_count,
        active_shell_count=active_shell_count,
    )
    for item in stages:
        phase = str(item.get("phase") or "")
        stage_constraint = constraints.get("stages", {}).get(phase, {})
        item["attack"] = stage_constraint.get("attack", {})
        item["prerequisites"] = stage_constraint.get("prerequisites", [])
        item["unlock_state"] = stage_constraint.get("unlock_state", {"ready": True, "blocked_by": [], "requirements": []})
        structure = stage_constraint.get("structure", {})
        item["structure"] = {
            **structure,
            "node_id": f"{project_id}:{phase}",
        }
    return stages


def _is_valid_target(target: str) -> bool:
    if not target or not target.strip():
        return False
    normalized_target = target.strip()
    if any(character.isspace() for character in normalized_target):
        return False

    if "://" in normalized_target or "/" in normalized_target or "?" in normalized_target:
        return False
    hostname = normalized_target

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    if DOMAIN_REGEX.match(hostname):
        return True

    return False


def _get_export_policy() -> Dict[str, Any]:
    policy = db_get_setting("export_policy", DEFAULT_EXPORT_POLICY)
    if not isinstance(policy, dict):
        policy = dict(DEFAULT_EXPORT_POLICY)
    retention_hours = int(policy.get("retention_hours", DEFAULT_EXPORT_POLICY["retention_hours"]))
    max_retries = int(policy.get("max_retries", DEFAULT_EXPORT_POLICY["max_retries"]))
    auto_retry_failed = bool(policy.get("auto_retry_failed", DEFAULT_EXPORT_POLICY["auto_retry_failed"]))
    normalized = {
        "retention_hours": max(1, min(720, retention_hours)),
        "max_retries": max(0, min(5, max_retries)),
        "auto_retry_failed": auto_retry_failed,
    }
    if normalized != policy:
        db_set_setting("export_policy", normalized)
    return normalized


def _get_download_secret() -> str:
    secret = db_get_setting("export_download_secret", "")
    if not isinstance(secret, str) or not secret:
        secret = secrets.token_hex(32)
        db_set_setting("export_download_secret", secret)
    return secret


def _build_download_signature(job_id: str, project_id: str, expires: int, actor: str) -> str:
    payload = f"{job_id}:{project_id}:{expires}:{actor}".encode("utf-8")
    secret = _get_download_secret().encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def _assert_job_actor_access(job: Dict[str, Any], actor: str) -> None:
    normalized_actor = (actor or "").strip() or "ui"
    created_by = str(job.get("created_by") or "system")
    if created_by == normalized_actor:
        return
    raise HTTPException(status_code=403, detail="Actor has no permission for this export job")


def _audit_export_job(job_id: str, project_id: str, action: str, actor: str, detail: Optional[str] = None) -> None:
    try:
        db_insert_export_job_audit(
            job_id=job_id,
            project_id=project_id,
            action=action,
            actor=actor or "system",
            detail=detail,
        )
    except Exception as error:
        logger.warning(f"Failed to write export audit log: {error}")


def _build_export_content(
    project: Dict[str, Any],
    events: List[Dict[str, Any]],
    export_format: str,
    filters: Dict[str, Any],
) -> Dict[str, str]:
    if export_format == "json":
        payload = {
            "project": {
                "id": project["id"],
                "target": project["target"],
                "status": project["status"],
                "phase": project["phase"],
            },
            "filters": filters,
            "events": events,
        }
        return {
            "content": json.dumps(payload, ensure_ascii=False, indent=2),
            "media_type": "application/json",
            "extension": "json",
        }

    if export_format == "csv":
        csv_lines = ["timestamp,type,level,phase,status,progress,message"]
        for event in events:
            ts = (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event["timestamp"]))
                if event.get("timestamp")
                else ""
            )
            progress_text = (
                f"{float(event['progress']):.4f}" if event.get("progress") is not None else ""
            )
            message = str(event.get("message", "")).replace('"', '""').replace("\n", " ")
            csv_lines.append(
                f"\"{ts}\",\"{event.get('type') or ''}\",\"{event.get('level') or ''}\",\"{event.get('phase') or ''}\",\"{event.get('status') or ''}\",\"{progress_text}\",\"{message}\""
            )
        return {
            "content": "\n".join(csv_lines),
            "media_type": "text/csv; charset=utf-8",
            "extension": "csv",
        }

    lines = [
        f"# 项目事件导出 - {project['target']} ({project['id']})",
        "",
        f"- 当前状态: {project['status']}",
        f"- 当前阶段: {project['phase']}",
        f"- 导出数量: {len(events)}",
        "",
        "| 时间 | 类型 | 级别 | 阶段 | 状态 | 进度 | 消息 |",
        "|---|---|---|---|---|---|---|",
    ]
    for event in events:
        ts = (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event["timestamp"]))
            if event.get("timestamp")
            else "-"
        )
        progress_text = (
            f"{int(float(event['progress']) * 100)}%"
            if event.get("progress") is not None
            else "-"
        )
        message = str(event.get("message", "")).replace("\n", " ").replace("|", "\\|")
        lines.append(
            f"| {ts} | {event.get('type') or '-'} | {event.get('level') or '-'} | {event.get('phase') or '-'} | {event.get('status') or '-'} | {progress_text} | {message} |"
        )
    return {
        "content": "\n".join(lines),
        "media_type": "text/markdown; charset=utf-8",
        "extension": "md",
    }


def _start_export_job(
    project: Dict[str, Any],
    project_id: str,
    export_format: str,
    limit: int,
    type: Optional[str],
    level: Optional[str],
    phase: Optional[str],
    start_ts: Optional[float],
    end_ts: Optional[float],
    q: Optional[str],
    actor: str = "system",
) -> Dict[str, Any]:
    policy = _get_export_policy()
    max_retries = int(policy["max_retries"])
    filters = {
        "type": type,
        "level": level,
        "phase": phase,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "q": q,
        "limit": limit,
    }
    job_id = str(uuid.uuid4())
    created_at = time.time()
    job_payload = {
        "job_id": job_id,
        "project_id": project_id,
        "status": "queued",
        "format": export_format,
        "created_at": created_at,
        "completed_at": None,
        "error": None,
        "retry_count": 0,
        "max_retries": max_retries,
        "filters": filters,
        "created_by": actor or "system",
        "last_action_by": actor or "system",
    }
    job_record = db_create_export_job(job_payload)
    _audit_export_job(job_id, project_id, "create", actor, f"format={export_format}, limit={limit}")

    async def run_export_job():
        retry_count = 0
        while True:
            try:
                db_update_export_job(job_id, status="running", retry_count=retry_count, error=None, last_action_by=actor or "system")
                _audit_export_job(job_id, project_id, "start", actor, f"retry={retry_count}")
                events = db_list_project_events(
                    project_id,
                    limit=limit,
                    offset=0,
                    event_type=type,
                    level=level,
                    phase=phase,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    keyword=q,
                )
                export_data = _build_export_content(
                    project,
                    events,
                    export_format,
                    filters,
                )
                export_dir = os.path.abspath("output/exports")
                os.makedirs(export_dir, exist_ok=True)
                output_path = os.path.join(export_dir, f"{project_id}_{job_id}.{export_data['extension']}")
                with open(output_path, "w", encoding="utf-8") as file:
                    file.write(export_data["content"])
                db_update_export_job(
                    job_id,
                    status="completed",
                    completed_at=time.time(),
                    download_path=output_path,
                    media_type=export_data["media_type"],
                    error=None,
                    retry_count=retry_count,
                    last_action_by=actor or "system",
                )
                _audit_export_job(job_id, project_id, "complete", actor, f"events={len(events)}")
                return
            except Exception as error:
                should_retry = bool(policy.get("auto_retry_failed", True)) and retry_count < max_retries
                if not should_retry:
                    db_update_export_job(
                        job_id,
                        status="failed",
                        completed_at=time.time(),
                        error=str(error),
                        retry_count=retry_count,
                        last_action_by=actor or "system",
                    )
                    _audit_export_job(job_id, project_id, "failed", actor, str(error))
                    return
                retry_count += 1
                db_update_export_job(
                    job_id,
                    status="queued",
                    error=f"Auto retry {retry_count}/{max_retries} after error: {error}",
                    retry_count=retry_count,
                    last_action_by="system:auto-retry",
                )
                _audit_export_job(job_id, project_id, "auto_retry", "system:auto-retry", f"retry={retry_count}/{max_retries}")
                await asyncio.sleep(1)

    asyncio.create_task(run_export_job())
    return job_record


# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_text(self, message: str):
        if not isinstance(message, str):
            message = str(message)
        message = redact_sensitive_text(message)
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

    async def broadcast_event(self, event: Dict[str, Any]):
        event_payload = _sanitize_event_payload(event)
        if event_payload.get("timestamp") is None:
            event_payload["timestamp"] = time.time()
        if event_payload.get("type") in {"log", "phase", "status"}:
            try:
                db_insert_event(event_payload)
            except Exception as error:
                logger.error(f"Failed to persist event: {error}")

        payload = json.dumps(event_payload, ensure_ascii=False)
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                pass


manager = ConnectionManager()


# Custom Loguru Sink
class LogSink:
    @staticmethod
    def _normalize_level(raw_level: Any) -> str:
        if hasattr(raw_level, "name"):
            return str(getattr(raw_level, "name") or "INFO").upper()
        text = str(raw_level or "INFO")
        match = re.search(r"name='([^']+)'", text)
        if match:
            return str(match.group(1)).upper()
        return text.upper()

    def write(self, message):
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                record = getattr(message, "record", None)
                if record:
                    event = {
                        "type": "log",
                        "project_id": None,
                        "phase": "system",
                        "status": "running",
                        "progress": None,
                        "level": self._normalize_level(record.get("level", "INFO")),
                        "timestamp": time.time(),
                        "message": record.get("message", str(message)).strip(),
                    }
                else:
                    event = {
                        "type": "log",
                        "project_id": None,
                        "phase": "system",
                        "status": "running",
                        "progress": None,
                        "level": "INFO",
                        "timestamp": time.time(),
                        "message": str(message).strip(),
                    }
                loop.create_task(manager.broadcast_event(event))
        except RuntimeError:
            pass
        except Exception:
            pass


log_sink = LogSink()


async def _cleanup_worker_loop():
    while True:
        try:
            policy = _get_export_policy()
            await cleanup_export_jobs(
                max_age_hours=int(policy["retention_hours"]),
                project_id=None,
                actor="system:scheduler",
                x_admin_key=_get_admin_access_key(),
            )
            db_cleanup_expired_download_tokens()
        except Exception as error:
            logger.warning(f"Cleanup worker failed: {error}")
        await asyncio.sleep(300)


async def _run_exploitdb_sync_process():
    """
    实际执行 Exploit-DB 同步脚本并返回结果。
    """
    logger.info("Starting Exploit-DB sync task...")
    script_path = os.path.abspath(os.path.join("tools", "exploitdb_sync.py"))
    if not os.path.exists(script_path):
        logger.warning(f"Exploit-DB sync script not found at {script_path}")
        return False, "Sync script not found."
        
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable, script_path,
            cwd=PROJECT_ROOT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            err_msg = stderr.decode('utf-8', errors='ignore')
            logger.error(f"Exploit-DB sync failed: {err_msg}")
            return False, err_msg
        else:
            msg = stdout.decode('utf-8', errors='ignore')
            logger.info(f"Exploit-DB sync finished: {msg}")
            return True, msg
    except Exception as error:
        logger.error(f"Exploit-DB sync process error: {error}")
        return False, str(error)


async def _exploitdb_sync_worker_loop():
    while True:
        try:
            now = time.localtime()
            # 每天早上 9 点更新 (9:00 - 9:05 之间触发)
            if now.tm_hour == 9 and 0 <= now.tm_min <= 5:
                await _run_exploitdb_sync_process()
                # 睡 10 分钟避免重复触发
                await asyncio.sleep(600)
            else:
                # 每隔 1 分钟检查一次时间
                await asyncio.sleep(60)
        except Exception as error:
            logger.error(f"Exploit-DB sync worker error: {error}")
            await asyncio.sleep(60)


async def _restore_sessions_health_checks() -> None:
    for session in list(webui_sessions.values()):
        try:
            if session.get("status") != "active":
                continue
            project_id = str(session.get("project_id") or "")
            if not project_id:
                continue
            await _refresh_session_heartbeat(project_id, session, force=True)
        except Exception as error:
            logger.warning(f"Restore session health check failed: {error}")


async def start_background_jobs():
    global cleanup_worker_task, exploitdb_sync_task, sessions_restored
    if not sessions_restored:
        _restore_webui_sessions()
        asyncio.create_task(_restore_sessions_health_checks())
        sessions_restored = True
    if not cleanup_worker_task or cleanup_worker_task.done():
        cleanup_worker_task = asyncio.create_task(_cleanup_worker_loop())
    if not exploitdb_sync_task or exploitdb_sync_task.done():
        exploitdb_sync_task = asyncio.create_task(_exploitdb_sync_worker_loop())


async def stop_background_jobs():
    global cleanup_worker_task, exploitdb_sync_task
    if cleanup_worker_task and not cleanup_worker_task.done():
        cleanup_worker_task.cancel()
        try:
            await cleanup_worker_task
        except asyncio.CancelledError:
            pass
    cleanup_worker_task = None

    if exploitdb_sync_task and not exploitdb_sync_task.done():
        exploitdb_sync_task.cancel()
        try:
            await exploitdb_sync_task
        except asyncio.CancelledError:
            pass
    exploitdb_sync_task = None


@router.post("/projects", response_model=Project)
async def create_project(project_in: ProjectCreate):
    if not _is_valid_target(project_in.target):
        raise HTTPException(status_code=400, detail="Invalid target format")

    project_id = str(uuid.uuid4())
    project_payload = {
        "id": project_id,
        "status": "pending",
        "phase": "pending",
        "progress": 0.0,
        "created_at": time.time(),
        **_model_dump(project_in),
        "results": {},
    }
    created_project = db_create_project(project_payload)
    logger.info(f"Created project: {redact_sensitive_text(project_in.target)} (ID: {project_id})")
    return Project(**created_project)


@router.get("/projects", response_model=List[Project])
async def list_projects():
    projects = db_list_projects()
    return [Project(**project) for project in projects]


@router.get("/projects/{project_id}", response_model=Project)
async def get_project(project_id: str):
    project = _project_or_404(project_id)
    return Project(**project)


@router.get("/projects/{project_id}/events", response_model=List[ProjectEvent])
async def get_project_events(
    project_id: str,
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    type: Optional[str] = Query(default=None),
    level: Optional[str] = Query(default=None),
    phase: Optional[str] = Query(default=None),
    start_ts: Optional[float] = Query(default=None),
    end_ts: Optional[float] = Query(default=None),
    q: Optional[str] = Query(default=None),
    response: Response = None,
):
    _project_or_404(project_id)
    total = db_count_project_events(
        project_id,
        event_type=type,
        level=level,
        phase=phase,
        start_ts=start_ts,
        end_ts=end_ts,
        keyword=q,
    )
    events = db_list_project_events(
        project_id,
        limit=limit,
        offset=offset,
        event_type=type,
        level=level,
        phase=phase,
        start_ts=start_ts,
        end_ts=end_ts,
        keyword=q,
    )
    if response is not None:
        response.headers["X-Total-Count"] = str(total)
        response.headers["X-Offset"] = str(offset)
        response.headers["X-Limit"] = str(limit)
    return [ProjectEvent(**_sanitize_event_payload(event)) for event in events]


@router.get("/projects/{project_id}/events/export")
async def export_project_events(
    project_id: str,
    format: str = Query(default="json"),
    limit: int = Query(default=2000, ge=1, le=20000),
    type: Optional[str] = Query(default=None),
    level: Optional[str] = Query(default=None),
    phase: Optional[str] = Query(default=None),
    start_ts: Optional[float] = Query(default=None),
    end_ts: Optional[float] = Query(default=None),
    q: Optional[str] = Query(default=None),
):
    project = _project_or_404(project_id)
    events = db_list_project_events(
        project_id,
        limit=limit,
        offset=0,
        event_type=type,
        level=level,
        phase=phase,
        start_ts=start_ts,
        end_ts=end_ts,
        keyword=q,
    )
    events = [_sanitize_event_payload(event) for event in events]

    export_format = format.lower().strip()
    if export_format not in {"json", "md", "csv"}:
        raise HTTPException(status_code=400, detail="format must be json, md or csv")
    export_data = _build_export_content(
        project,
        events,
        export_format,
        {
            "type": type,
            "level": level,
            "phase": phase,
            "start_ts": start_ts,
            "end_ts": end_ts,
            "q": q,
            "limit": limit,
        },
    )
    filename = f"{project_id}_events.{export_data['extension']}"
    return Response(
        content=export_data["content"],
        media_type=export_data["media_type"],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/projects/{project_id}/events/export/jobs", response_model=ExportJobStatus)
async def create_export_job(
    project_id: str,
    format: str = Query(default="json"),
    limit: int = Query(default=5000, ge=1, le=50000),
    type: Optional[str] = Query(default=None),
    level: Optional[str] = Query(default=None),
    phase: Optional[str] = Query(default=None),
    start_ts: Optional[float] = Query(default=None),
    end_ts: Optional[float] = Query(default=None),
    q: Optional[str] = Query(default=None),
    actor: str = Query(default="ui"),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    project = _project_or_404(project_id)
    export_format = format.lower().strip()
    if export_format not in {"json", "md", "csv"}:
        raise HTTPException(status_code=400, detail="format must be json, md or csv")
    job_record = _start_export_job(
        project=project,
        project_id=project_id,
        export_format=export_format,
        limit=limit,
        type=type,
        level=level,
        phase=phase,
        start_ts=start_ts,
        end_ts=end_ts,
        q=q,
        actor=actor,
    )
    return ExportJobStatus(
        job_id=job_record["job_id"],
        project_id=job_record["project_id"],
        status=job_record["status"],
        format=job_record["format"],
        created_at=job_record["created_at"],
        completed_at=job_record["completed_at"],
        download_url=None,
        error=job_record["error"],
        retry_count=job_record.get("retry_count", 0),
        max_retries=job_record.get("max_retries", 0),
        created_by=job_record.get("created_by", "system"),
        last_action_by=job_record.get("last_action_by"),
    )


@router.get("/projects/{project_id}/events/export/jobs/{job_id}", response_model=ExportJobStatus)
async def get_export_job_status(
    project_id: str,
    job_id: str,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    _project_or_404(project_id)
    job = db_get_export_job(job_id)
    if not job or job.get("project_id") != project_id:
        raise HTTPException(status_code=404, detail="Export job not found")
    return ExportJobStatus(
        job_id=job["job_id"],
        project_id=job["project_id"],
        status=job["status"],
        format=job["format"],
        created_at=job["created_at"],
        completed_at=job["completed_at"],
        download_url=(
            f"/api/projects/{project_id}/events/export/jobs/{job_id}/download"
            if job.get("status") == "completed"
            else None
        ),
        error=job.get("error"),
        retry_count=job.get("retry_count", 0),
        max_retries=job.get("max_retries", 0),
        created_by=job.get("created_by", "system"),
        last_action_by=job.get("last_action_by"),
    )


@router.get("/projects/{project_id}/events/export/jobs/{job_id}/signed-url")
async def get_export_job_signed_url(
    project_id: str,
    job_id: str,
    actor: str = Query(default="ui"),
    ttl_seconds: int = Query(default=300, ge=30, le=3600),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    _project_or_404(project_id)
    job = db_get_export_job(job_id)
    if not job or job.get("project_id") != project_id:
        raise HTTPException(status_code=404, detail="Export job not found")
    if job.get("status") != "completed":
        raise HTTPException(status_code=409, detail="Export job is not completed")
    _assert_job_actor_access(job, actor)
    expires = int(time.time()) + int(ttl_seconds)
    token = secrets.token_urlsafe(24)
    db_create_export_download_token(
        token=token,
        job_id=job_id,
        project_id=project_id,
        actor=actor,
        expires_at=float(expires),
    )
    sig = _build_download_signature(job_id=job_id, project_id=project_id, expires=expires, actor=actor)
    url = f"/api/projects/{project_id}/events/export/jobs/{job_id}/download?actor={actor}&expires={expires}&token={token}&sig={sig}"
    return {"url": url, "expires": expires, "token": token}


@router.post("/projects/{project_id}/events/export/jobs/{job_id}/retry", response_model=ExportJobStatus)
async def retry_export_job(
    project_id: str,
    job_id: str,
    actor: str = Query(default="ui"),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    project = _project_or_404(project_id)
    existing = db_get_export_job(job_id)
    if not existing or existing.get("project_id") != project_id:
        raise HTTPException(status_code=404, detail="Export job not found")
    _assert_job_actor_access(existing, actor)
    new_job = _start_export_job(
        project=project,
        project_id=project_id,
        export_format=existing["format"],
        limit=50000,
        type=None,
        level=None,
        phase=None,
        start_ts=None,
        end_ts=None,
        q=None,
        actor=actor,
    )
    db_update_export_job(job_id, last_action_by=actor)
    _audit_export_job(job_id, project_id, "manual_retry", actor, f"new_job={new_job['job_id']}")
    return ExportJobStatus(
        job_id=new_job["job_id"],
        project_id=new_job["project_id"],
        status=new_job["status"],
        format=new_job["format"],
        created_at=new_job["created_at"],
        completed_at=new_job["completed_at"],
        download_url=None,
        error=new_job["error"],
        retry_count=new_job.get("retry_count", 0),
        max_retries=new_job.get("max_retries", 0),
        created_by=new_job.get("created_by", "system"),
        last_action_by=new_job.get("last_action_by"),
    )


@router.get("/projects/{project_id}/events/export/jobs/{job_id}/download")
async def download_export_job_file(
    project_id: str,
    job_id: str,
    actor: str = Query(default="ui"),
    expires: Optional[int] = Query(default=None),
    token: Optional[str] = Query(default=None),
    sig: Optional[str] = Query(default=None),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    _project_or_404(project_id)
    job = db_get_export_job(job_id)
    if not job or job.get("project_id") != project_id:
        raise HTTPException(status_code=404, detail="Export job not found")
    if job.get("status") != "completed":
        raise HTTPException(status_code=409, detail="Export job is not completed")
    if expires is not None and sig and token:
        if int(time.time()) > int(expires):
            raise HTTPException(status_code=401, detail="Signed URL expired")
        expected = _build_download_signature(job_id=job_id, project_id=project_id, expires=int(expires), actor=actor)
        if not hmac.compare_digest(expected, sig):
            raise HTTPException(status_code=401, detail="Invalid signed URL")
        consumed = db_consume_export_download_token(token=token)
        if not consumed:
            raise HTTPException(status_code=401, detail="Invalid or already used download token")
        if consumed["job_id"] != job_id or consumed["project_id"] != project_id or consumed["actor"] != actor:
            raise HTTPException(status_code=401, detail="Download token mismatch")
    else:
        _assert_job_actor_access(job, actor)
    output_path = job.get("download_path")
    if not output_path or not os.path.exists(output_path):
        raise HTTPException(status_code=404, detail="Export file not found")
    filename = os.path.basename(output_path)
    with open(output_path, "r", encoding="utf-8") as file:
        content = file.read()
    return Response(
        content=content,
        media_type=job.get("media_type") or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/projects/{project_id}/events/export/jobs/{job_id}")
async def delete_export_job(
    project_id: str,
    job_id: str,
    actor: str = Query(default="ui"),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    _project_or_404(project_id)
    job = db_get_export_job(job_id)
    if not job or job.get("project_id") != project_id:
        raise HTTPException(status_code=404, detail="Export job not found")
    _assert_job_actor_access(job, actor)
    output_path = job.get("download_path")
    if output_path and os.path.exists(output_path):
        try:
            os.remove(output_path)
        except Exception as error:
            logger.warning(f"Failed to remove export file {output_path}: {error}")
    db_delete_export_job(job_id)
    _audit_export_job(job_id, project_id, "delete", actor, "single delete")
    return {"message": "Export job deleted"}


@router.get("/export/jobs")
async def list_export_jobs(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    project_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    jobs = db_list_export_jobs(limit=limit, offset=offset, project_id=project_id, status=status)
    return jobs


@router.get("/export/jobs/{job_id}/audit", response_model=List[ExportJobAudit])
async def get_export_job_audit(
    job_id: str,
    actor: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    start_ts: Optional[float] = Query(default=None),
    end_ts: Optional[float] = Query(default=None),
    q: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    rows = db_list_export_job_audit(
        job_id=job_id,
        actor=actor,
        action=action,
        start_ts=start_ts,
        end_ts=end_ts,
        q=q,
        limit=limit,
        offset=offset,
    )
    return [ExportJobAudit(**row) for row in rows]


@router.get("/export/audit", response_model=List[ExportJobAudit])
async def list_export_audit(
    project_id: Optional[str] = Query(default=None),
    actor: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    start_ts: Optional[float] = Query(default=None),
    end_ts: Optional[float] = Query(default=None),
    q: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    rows = db_list_export_job_audit(
        project_id=project_id,
        actor=actor,
        action=action,
        start_ts=start_ts,
        end_ts=end_ts,
        q=q,
        limit=limit,
        offset=offset,
    )
    return [ExportJobAudit(**row) for row in rows]


@router.post("/mtools/upload")
async def upload_mtool(
    file: UploadFile = File(...),
    x_admin_key: str = Header(default=None, alias="X-Admin-Key")
):
    """
    上传自定义 Python 工具（.py 或 .zip）。
    如果上传的是 .zip，会自动解压到 mtools 目录下。
    """
    _require_admin_when_configured(x_admin_key)
    
    mtools_dir = os.path.abspath("mtools")
    os.makedirs(mtools_dir, exist_ok=True)
    
    filename = file.filename
    if not filename:
        raise HTTPException(status_code=400, detail="No filename provided")
        
    file_path = os.path.join(mtools_dir, filename)
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # 如果是 ZIP 包，则解压
        if filename.endswith(".zip"):
            extract_dir = os.path.join(mtools_dir, filename[:-4])
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            os.remove(file_path)  # 解压后删除压缩包
            return {"status": "success", "message": f"Tool unzipped to {extract_dir}"}
            
        return {"status": "success", "message": f"Tool {filename} uploaded successfully"}
    except Exception as e:
        logger.error(f"Failed to upload tool: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mtools/list")
async def list_mtools(x_admin_key: str = Header(default=None, alias="X-Admin-Key")):
    """列出当前已安装的所有自定义工具"""
    _require_admin_when_configured(x_admin_key)
    mtools_dir = os.path.abspath("mtools")
    os.makedirs(mtools_dir, exist_ok=True)
    
    tools = []
    for item in os.listdir(mtools_dir):
        item_path = os.path.join(mtools_dir, item)
        if os.path.isfile(item_path) and item.endswith(".py"):
            tools.append({"name": item, "type": "script"})
        elif os.path.isdir(item_path):
            # Check if there is a main.py or similar
            entry = "main.py" if os.path.exists(os.path.join(item_path, "main.py")) else ""
            tools.append({"name": item, "type": "package", "entry": entry})
            
    return {"status": "success", "tools": tools}


@router.get("/export/audit/export")
async def export_audit_records(
    format: str = Query(default="json"),
    project_id: Optional[str] = Query(default=None),
    actor: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    start_ts: Optional[float] = Query(default=None),
    end_ts: Optional[float] = Query(default=None),
    q: Optional[str] = Query(default=None),
    limit: int = Query(default=2000, ge=1, le=20000),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    rows = db_list_export_job_audit(
        project_id=project_id,
        actor=actor,
        action=action,
        start_ts=start_ts,
        end_ts=end_ts,
        q=q,
        limit=limit,
        offset=0,
    )
    export_format = format.lower().strip()
    if export_format not in {"json", "csv"}:
        raise HTTPException(status_code=400, detail="format must be json or csv")
    if export_format == "json":
        payload = {
            "filters": {
                "project_id": project_id,
                "actor": actor,
                "action": action,
                "start_ts": start_ts,
                "end_ts": end_ts,
                "q": q,
                "limit": limit,
            },
            "items": rows,
        }
        return Response(
            content=json.dumps(payload, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="export_audit.json"'},
        )
    csv_lines = ["id,job_id,project_id,action,actor,timestamp,detail"]
    for row in rows:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(row["timestamp"])))
        detail = str(row.get("detail", "") or "").replace('"', '""').replace("\n", " ")
        csv_lines.append(
            f"{row['id']},\"{row['job_id']}\",\"{row['project_id']}\",\"{row['action']}\",\"{row['actor']}\",\"{ts}\",\"{detail}\""
        )
    return Response(
        content="\n".join(csv_lines),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="export_audit.csv"'},
    )


@router.get("/export/policy", response_model=ExportPolicy)
async def get_export_policy(x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_when_configured(x_admin_key)
    return ExportPolicy(**_get_export_policy())


@router.put("/export/policy", response_model=ExportPolicy)
async def update_export_policy(
    policy: ExportPolicy,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    payload = {
        "retention_hours": max(1, min(720, policy.retention_hours)),
        "max_retries": max(0, min(5, policy.max_retries)),
        "auto_retry_failed": bool(policy.auto_retry_failed),
    }
    db_set_setting("export_policy", payload)
    return ExportPolicy(**payload)


@router.post("/export/jobs/batch-delete")
async def batch_delete_export_jobs(
    request: ExportJobBatchDelete,
    actor: str = Query(default="ui"),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    removed_jobs = 0
    removed_files = 0
    for job_id in request.job_ids:
        job = db_get_export_job(job_id)
        if not job:
            continue
        _assert_job_actor_access(job, actor)
        output_path = job.get("download_path")
        if output_path and os.path.exists(output_path):
            try:
                os.remove(output_path)
                removed_files += 1
            except Exception as error:
                logger.warning(f"Failed to remove export file {output_path}: {error}")
        if db_delete_export_job(job_id):
            removed_jobs += 1
            _audit_export_job(job_id, job["project_id"], "batch_delete", actor, "batch delete")
    return {"message": "Batch delete completed", "removed_jobs": removed_jobs, "removed_files": removed_files}


@router.post("/export/jobs/cleanup")
async def cleanup_export_jobs(
    max_age_hours: Optional[int] = Query(default=None, ge=1, le=720),
    project_id: Optional[str] = Query(default=None),
    actor: str = Query(default="system:cleanup"),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    policy = _get_export_policy()
    effective_hours = max_age_hours if max_age_hours is not None else int(policy["retention_hours"])
    before_ts = time.time() - effective_hours * 3600
    jobs = db_list_export_jobs(limit=10000, offset=0, project_id=project_id, status="completed")
    removed_files = 0
    for job in jobs:
        completed_at = job.get("completed_at")
        if completed_at is None or completed_at > before_ts:
            continue
        output_path = job.get("download_path")
        if output_path and os.path.exists(output_path):
            try:
                os.remove(output_path)
                removed_files += 1
            except Exception as error:
                logger.warning(f"Failed to remove export file {output_path}: {error}")
    removed_jobs = db_cleanup_completed_export_jobs(before_ts=before_ts, project_id=project_id)
    db_cleanup_expired_download_tokens(before_ts=time.time())
    db_insert_export_cleanup_run(
        actor=actor or "system:cleanup",
        project_id=project_id,
        max_age_hours=effective_hours,
        removed_jobs=removed_jobs,
        removed_files=removed_files,
        timestamp=time.time(),
    )
    if removed_jobs > 0:
        _audit_export_job("*", project_id or "*", "cleanup", actor, f"removed_jobs={removed_jobs}, removed_files={removed_files}")
    return {
        "message": "Cleanup completed",
        "removed_jobs": removed_jobs,
        "removed_files": removed_files,
        "before_ts": before_ts,
    }


@router.get("/export/cleanup/runs")
async def list_cleanup_runs(
    project_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    return db_list_export_cleanup_runs(limit=limit, offset=offset, project_id=project_id)


@router.get("/export/metrics")
async def get_export_metrics(
    project_id: Optional[str] = Query(default=None),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    jobs = db_list_export_jobs(limit=100000, offset=0, project_id=project_id)
    cleanup_runs = db_list_export_cleanup_runs(limit=10000, offset=0, project_id=project_id)
    status_counts = {"queued": 0, "running": 0, "completed": 0, "failed": 0}
    for job in jobs:
        status = str(job.get("status") or "queued")
        status_counts[status] = status_counts.get(status, 0) + 1
    removed_jobs_total = sum(int(item.get("removed_jobs") or 0) for item in cleanup_runs)
    removed_files_total = sum(int(item.get("removed_files") or 0) for item in cleanup_runs)
    return {
        "project_id": project_id,
        "jobs_total": len(jobs),
        "status_counts": status_counts,
        "cleanup_runs_total": len(cleanup_runs),
        "cleanup_removed_jobs_total": removed_jobs_total,
        "cleanup_removed_files_total": removed_files_total,
    }


@router.post("/projects/{project_id}/start")
async def start_project(project_id: str, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_access(x_admin_key)
    project = _project_or_404(project_id)
    project_status = _normalize_status(project["status"])
    if project_status == "running":
        return {"message": "Project is already running"}
    if not _is_valid_target(project["target"]):
        raise HTTPException(status_code=400, detail="Invalid project target")

    if not mas:
        raise HTTPException(
            status_code=500,
            detail="AI System not initialized properly. Check config/API Key.",
        )

    is_resume = project_status == "paused"
    existing_results = project.get("results") if isinstance(project.get("results"), dict) else {}
    phase_to_resume = str(project.get("phase") or "recon")
    if phase_to_resume in {"paused", "stopped", "pending", "completed", "failed", "error"}:
        phase_to_resume = "recon"
    update_payload: Dict[str, Any] = {
        "status": "running",
        "phase": phase_to_resume if is_resume else "recon",
        "progress": float(project.get("progress") or 0.05) if is_resume else 0.05,
    }
    if not is_resume:
        update_payload["results"] = {}
    project = db_update_project(project_id, **update_payload)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    phase_progress_map = {
        "planning": 0.10,
        "dispatch": 0.20,
        "recon": 0.30,
        "exploit": 0.50,
        "post_exploit": 0.70,
        "aggregation": 0.80,
        "verification": 0.90,
        "report": 0.95,
        "completed": 1.00,
        "failed": 1.00,
    }

    async def emit_event(
        event_type: str,
        pid: str,
        phase: str,
        status: str,
        progress: Optional[float],
        level: str,
        message: str,
        extra: Optional[Dict[str, Any]] = None,
    ):
        payload = {
            "type": event_type,
            "project_id": pid,
            "phase": phase,
            "status": status,
            "progress": progress,
            "level": level,
            "timestamp": time.time(),
            "message": message,
        }
        if isinstance(extra, dict):
            payload.update(extra)
        await manager.broadcast_event(payload)

    async def progress_callback(phase: str, progress: Optional[float], status: str = "running"):
        latest_project = db_get_project(project_id)
        if not latest_project:
            return
        if latest_project["status"] not in {"running", "insufficient_evidence"}:
            return

        base_progress = progress if progress is not None else phase_progress_map.get(phase, 0.0)
        next_progress = max(0.0, min(float(base_progress), 1.0))
        current_progress = max(0.0, min(float(latest_project.get("progress") or 0.0), 1.0))
        normalized_status = _normalize_status(status, default="running")
        if normalized_status in {"running", "paused"}:
            next_progress = max(current_progress, next_progress)
        if normalized_status == "completed":
            next_progress = 1.0
        updated_project = db_update_project(
            project_id,
            phase=phase,
            progress=next_progress,
            status=status,
        )
        if not updated_project:
            return
        await emit_event(
            event_type="phase",
            pid=project_id,
            phase=phase,
            status=status,
            progress=updated_project["progress"],
            level="INFO",
            message=f"ATT&CK阶段: {_attack_label_for_phase(phase)}，进度 {int(updated_project['progress'] * 100)}%",
        )

    async def agent_event_callback(event_payload: Dict[str, Any]):
        latest_project = db_get_project(project_id)
        raw_phase = str(event_payload.get("phase") or "").strip()
        runtime_phase = str(latest_project["phase"] if latest_project else "recon")
        mapped_phase = runtime_phase if raw_phase in {"tools", "ai_output", "ai_thinking", "ai_tools"} else (raw_phase or runtime_phase)
        progress = latest_project["progress"] if latest_project else phase_progress_map.get(mapped_phase, 0.0)
        phase = mapped_phase
        status = str(event_payload.get("status") or "running")
        level = str(event_payload.get("level") or "INFO")
        message = str(event_payload.get("message") or "AI运行事件")
        payload = dict(event_payload or {})
        if payload.get("ai_content"):
            payload["ai_content"] = _sanitize_report_text(str(payload.get("ai_content") or ""), max_chars=20000)
        if payload.get("reasoning_content"):
            payload["reasoning_content"] = _sanitize_report_text(str(payload.get("reasoning_content") or ""), max_chars=20000)
        tool_name = str(payload.get("tool_name") or "").strip()
        if raw_phase == "tools" and tool_name:
            if "异常归因" in message:
                failure_reason = str(payload.get("failure_reason") or "工具执行失败").strip()
                message = f"ATT&CK-{_attack_label_for_phase(phase)} | 工具失败: {tool_name} | 原因: {failure_reason[:180]}"
            elif "执行完成" in message:
                message = f"ATT&CK-{_attack_label_for_phase(phase)} | 工具执行: {tool_name}"
            elif "预检" in message:
                message = f"ATT&CK-{_attack_label_for_phase(phase)} | 工具预检: {tool_name}"
        payload["message"] = message
        payload = _sanitize_event_payload(payload)
        await emit_event(
            event_type="log",
            pid=project_id,
            phase=phase,
            status=status,
            progress=progress,
            level=level,
            message=message,
            extra=payload,
        )

    async def run_scan(pid: str, target: str):
        logger.info(f"项目 {pid} 开始扫描目标: {target}")
        latest_project = db_get_project(pid)
        if not latest_project:
            return
        await emit_event(
            event_type="status",
            pid=pid,
            phase=latest_project["phase"],
            status="running",
            progress=latest_project["progress"],
            level="INFO",
            message=f"任务启动，目标: {target}",
        )
        try:
            latest_project = db_get_project(pid)
            if not latest_project or latest_project["status"] not in {"running", "insufficient_evidence"}:
                await emit_event(
                    event_type="status",
                    pid=pid,
                    phase=latest_project["phase"] if latest_project else "stopped",
                    status=latest_project["status"] if latest_project else "stopped",
                    progress=latest_project["progress"] if latest_project else 0.0,
                    level="WARNING",
                    message="任务在执行前被中止",
                )
                return

            results = await mas.start_project(
                pid,
                target,
                project_description=str(project.get("description") or ""),
                progress_callback=progress_callback,
                event_callback=agent_event_callback,
                resume_state=existing_results if is_resume else None,
                resume_from_phase=phase_to_resume if is_resume else None,
            )

            latest_project = db_get_project(pid)
            if latest_project and latest_project["status"] in {"running", "insufficient_evidence"}:
                phase_status = results.get("phase_status", {}) if isinstance(results, dict) else {}
                final_status = "completed"
                if isinstance(phase_status, dict):
                    if any(str(phase_status.get(item) or "") in {"failed", "error"} for item in ("recon", "exploit", "post_exploit", "report")):
                        final_status = "failed"
                    elif any(str(phase_status.get(item) or "") == "insufficient_evidence" for item in ("exploit", "post_exploit")):
                        final_status = "insufficient_evidence"
                final_phase = "completed" if final_status != "failed" else "failed"
                db_update_project(
                    pid,
                    status=final_status,
                    phase=final_phase,
                    progress=1.0,
                    results=results,
                )
                logger.success(f"项目 {pid} 扫描完成，状态: {final_status}")
                await emit_event(
                    event_type="status",
                    pid=pid,
                    phase=final_phase,
                    status=final_status,
                    progress=1.0,
                    level="SUCCESS" if final_status == "completed" else ("WARNING" if final_status == "insufficient_evidence" else "ERROR"),
                    message="任务执行完成" if final_status == "completed" else ("任务执行完成，但证据不足" if final_status == "insufficient_evidence" else "任务执行失败"),
                )
        except asyncio.CancelledError:
            latest_project = db_get_project(pid)
            if latest_project:
                await emit_event(
                    event_type="status",
                    pid=pid,
                    phase=latest_project["phase"],
                    status=latest_project["status"],
                    progress=latest_project["progress"],
                    level="WARNING",
                    message=f"任务已取消，当前状态: {latest_project['status']}",
                )
            raise
        except Exception as e:
            latest_project = db_get_project(pid)
            db_update_project(
                pid,
                status="failed",
                phase="failed",
                progress=latest_project["progress"] if latest_project else 0.0,
                results={
                    "phase_status": {
                        "recon": "unknown",
                        "exploit": "unknown",
                        "post_exploit": "unknown",
                        "report": "failed",
                    },
                    "report_path": "",
                },
            )
            logger.error(f"项目 {pid} 执行失败: {e}")
            await emit_event(
                event_type="status",
                pid=pid,
                phase="failed",
                status="failed",
                progress=latest_project["progress"] if latest_project else 0.0,
                level="ERROR",
                message=f"任务执行失败: {e}",
            )
        finally:
            async with tasks_lock:
                if pid in running_tasks:
                    del running_tasks[pid]

    async with tasks_lock:
        existing_task = running_tasks.get(project_id)
        if existing_task and not existing_task.done():
            return {"message": "Project is already running"}
        task = asyncio.create_task(run_scan(project_id, project["target"]))
        running_tasks[project_id] = task

    _audit_operation(project_id, "project_control", "success", f"project {project_id} {'resumed' if is_resume else 'started'}")
    return {"message": "Project resumed" if is_resume else "Project started"}


@router.post("/projects/{project_id}/stop")
async def stop_project(project_id: str, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_access(x_admin_key)
    project = _project_or_404(project_id)
    if _normalize_status(project["status"]) not in {"running", "paused"}:
        return {"message": "Project is not running"}

    updated_project = db_update_project(project_id, status="stopped", phase="stopped")
    logger.info(f"Stopping project {project_id}...")

    async with tasks_lock:
        if project_id in running_tasks:
            running_tasks[project_id].cancel()
            del running_tasks[project_id]

    await manager.broadcast_event(
        {
            "type": "status",
            "project_id": project_id,
            "phase": "stopped",
            "status": "stopped",
            "progress": updated_project["progress"] if updated_project else project["progress"],
            "level": "WARNING",
            "timestamp": time.time(),
            "message": "任务已中止",
        }
    )
    _audit_operation(project_id, "project_control", "success", f"project {project_id} stopped")
    return {"message": "Project stopping..."}


@router.post("/projects/{project_id}/pause")
async def pause_project(project_id: str, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_access(x_admin_key)
    project = _project_or_404(project_id)
    if _normalize_status(project["status"]) != "running":
        return {"message": "Project is not running"}

    updated_project = db_update_project(project_id, status="paused")
    logger.info(f"Pausing project {project_id}...")

    async with tasks_lock:
        if project_id in running_tasks:
            running_tasks[project_id].cancel()
            del running_tasks[project_id]

    await manager.broadcast_event(
        {
            "type": "status",
            "project_id": project_id,
            "phase": project.get("phase") or "paused",
            "status": "paused",
            "progress": updated_project["progress"] if updated_project else project["progress"],
            "level": "WARNING",
            "timestamp": time.time(),
            "message": "任务已暂停",
        }
    )
    _audit_operation(project_id, "project_control", "success", f"project {project_id} paused")
    return {"message": "Project paused"}


@router.post("/projects/{project_id}/continue")
async def continue_project(project_id: str, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_access(x_admin_key)
    project = _project_or_404(project_id)
    if _normalize_status(project["status"]) != "paused":
        return {"message": "Project is not paused"}
    return await start_project(project_id, x_admin_key=x_admin_key)


@router.delete("/projects/{project_id}")
async def delete_project(project_id: str, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_access(x_admin_key)
    project = _project_or_404(project_id)

    if project["status"] == "running":
        db_update_project(project_id, status="stopped", phase="stopped")
        async with tasks_lock:
            if project_id in running_tasks:
                running_tasks[project_id].cancel()
                del running_tasks[project_id]
    session_keys = [key for key, value in webui_sessions.items() if value.get("project_id") == project_id]
    for key in session_keys:
        webui_sessions.pop(key, None)
        session_health_cache.pop(key, None)
    db_delete_webui_sessions_by_project(project_id)

    db_delete_project(project_id)
    try:
        if mas and hasattr(mas, "cleanup_project_memory"):
            mas.cleanup_project_memory(project_id)
    except Exception as error:
        logger.warning(f"Failed to cleanup project memory for {project_id}: {error}")
    logger.info(f"Deleted project {project_id}")
    _audit_operation(project_id, "project_control", "success", f"project {project_id} deleted")
    return {"message": "Project deleted"}


@router.post("/webui/projects/{project_id}/control/start")
async def webui_start_project(project_id: str, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    return await start_project(project_id, x_admin_key=x_admin_key)


@router.post("/webui/projects/{project_id}/control/pause")
async def webui_pause_project(project_id: str, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    return await pause_project(project_id, x_admin_key=x_admin_key)


@router.post("/webui/projects/{project_id}/control/stop")
async def webui_stop_project(project_id: str, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    return await stop_project(project_id, x_admin_key=x_admin_key)


@router.post("/webui/projects/{project_id}/control/continue")
async def webui_continue_project(project_id: str, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    return await continue_project(project_id, x_admin_key=x_admin_key)


@router.get("/webui/projects/{project_id}/attack-chain")
async def webui_attack_chain(project_id: str):
    project = _project_or_404(project_id)
    results = normalize_project_results(project.get("results") if isinstance(project.get("results"), dict) else {})
    phase_status = results.get("phase_status", {}) if isinstance(results, dict) else {}
    phase_status = _coerce_terminal_phase_status(
        phase_status if isinstance(phase_status, dict) else {},
        str(project.get("status") or ""),
        str(project.get("phase") or ""),
    )
    usage_summary = results.get("usage_summary", {}) if isinstance(results, dict) else {}
    if not isinstance(usage_summary, dict) or not usage_summary:
        usage_summary = _extract_usage_from_events(project_id)
    cognitive_snapshot = results.get("cognitive_snapshot", {}) if isinstance(results, dict) else {}
    if not isinstance(cognitive_snapshot, dict):
        cognitive_snapshot = {}
    stages = _build_attack_chain_stages(project_id, project)
    sequence_constraints = build_sequence_constraints(
        stage_status_map={str(item.get("phase")): str(item.get("status") or "pending") for item in stages},
        validated_vulnerability_count=max(
            [int(item.get("evidence", {}).get("validated_vulnerability_count") or 0) for item in stages] or [0]
        ),
        active_shell_count=max(
            [int(item.get("evidence", {}).get("active_shell_count") or 0) for item in stages] or [0]
        ),
    )
    return {
        "project_id": project_id,
        "target": project.get("target"),
        "status": project.get("status"),
        "phase": project.get("phase"),
        "progress": project.get("progress"),
        "stages": stages,
        "chain": _build_attack_chain(project),
        "phase_status": phase_status,
        "usage_summary": usage_summary,
        "cognitive_snapshot": cognitive_snapshot,
        "sequence_constraints": sequence_constraints,
        "attack_graph": sequence_constraints.get("graph", {}),
        "stage_counts": {
            "completed": sum(1 for item in stages if str(item.get("status")) == "completed"),
            "running": sum(1 for item in stages if str(item.get("status")) == "running"),
            "failed": sum(1 for item in stages if str(item.get("status")) in {"failed", "error"}),
            "insufficient_evidence": sum(1 for item in stages if str(item.get("status")) == "insufficient_evidence"),
        },
    }


@router.get("/webui/projects/{project_id}/shells")
async def webui_list_shells(project_id: str):
    project = _project_or_404(project_id)
    results = project.get("results") or {}
    shells = _extract_shells_from_results(project_id, results if isinstance(results, dict) else {})
    return {"project_id": project_id, "count": len(shells), "items": shells}


@router.get("/webui/session-backend")
async def webui_get_session_backend():
    return _get_session_backend_settings()


@router.put("/webui/session-backend")
async def webui_update_session_backend(
    request: SessionBackendUpdateRequest,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    mode = (request.mode or "workspace").strip().lower()
    if mode not in {"workspace", "msf"}:
        raise HTTPException(status_code=400, detail="mode must be workspace or msf")
    msf_binary = (request.msf_binary or "msfconsole").strip()
    if not msf_binary:
        msf_binary = "msfconsole"
    db_set_setting("session_backend_mode", mode)
    db_set_setting("session_backend_msf_binary", msf_binary)
    return {"mode": mode, "msf_binary": msf_binary}


@router.get("/webui/msf/sessions")
async def webui_probe_msf_sessions():
    settings = _get_session_backend_settings()
    executor = SessionBackendExecutor(mode="msf", msf_binary=settings["msf_binary"])
    result = await executor.probe_sessions()
    return {
        "mode": settings["mode"],
        "msf_binary": settings["msf_binary"],
        "ok": result["ok"],
        "returncode": result["returncode"],
        "sessions": result["sessions"],
        "stderr": result["stderr"],
    }


@router.get("/webui/projects/{project_id}/sessions")
async def webui_list_sessions(project_id: str):
    _project_or_404(project_id)
    shells = _get_live_project_shells(project_id)
    shell_sessions: List[Dict[str, Any]] = []
    for shell in shells:
        shell_id = str(shell.get("session_id") or shell.get("id") or "")
        if not shell_id:
            continue
        shell_sessions.append(
            {
                "session_id": shell_id,
                "project_id": project_id,
                "status": "active",
                "name": shell.get("user") or shell.get("host") or "shell",
                "type": "shell",
                "host": shell.get("host"),
                "shell_id": shell_id,
                "backend_mode": _get_session_backend_settings()["mode"],
                "source": "project_results",
                "source_shell": shell.get("raw"),
            }
        )
    manual_sessions: List[Dict[str, Any]] = []
    for item in webui_sessions.values():
        if item.get("project_id") != project_id or item.get("status") != "active":
            continue
        heartbeat = await _refresh_session_heartbeat(project_id, item, force=False)
        manual_sessions.append(
            {
                "session_id": item["session_id"],
                "project_id": item["project_id"],
                "status": item["status"],
                "name": item.get("name", "manual"),
                "type": item.get("type", "workspace"),
                "cwd": item.get("cwd"),
                "shell_id": item.get("shell_id"),
                "source": "manual",
                "created_at": item.get("created_at"),
                "last_active_at": item.get("last_active_at"),
                "backend_mode": item.get("backend_mode", _get_session_backend_settings()["mode"]),
                "health_status": heartbeat.get("status", "unknown"),
                "health_reason": heartbeat.get("reason", ""),
                "health_checked_at": heartbeat.get("checked_at"),
                "last_command": item.get("last_command"),
                "last_command_at": item.get("last_command_at"),
                "last_returncode": item.get("last_returncode"),
                "last_duration_seconds": item.get("last_duration_seconds"),
                "workspace_root": item.get("workspace_root"),
                "source_shell": item.get("source_shell"),
                "history_counts": {
                    "commands": len(item.get("command_history") or []),
                    "files": len(item.get("file_history") or []),
                },
            }
        )
    return {"project_id": project_id, "count": len(shell_sessions) + len(manual_sessions), "items": shell_sessions + manual_sessions}


@router.post("/webui/projects/{project_id}/sessions/open")
async def webui_open_session(
    project_id: str,
    request: SessionOpenRequest,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    _project_or_404(project_id)
    backend_settings = _get_session_backend_settings()
    matched_shell = None
    if request.shell_id:
        matched_shell = next((item for item in _get_live_project_shells(project_id) if str(item.get("id") or "") == str(request.shell_id)), None)
    
    # Only verify MSF session if the backend mode is MSF AND the shell is explicitly marked as an MSF shell type.
    # Otherwise, treat it as a generic/custom shell (like NC, AI POC) which runs in workspace mode.
    shell_type = str(matched_shell.get("type") or "").lower() if matched_shell else ""
    is_msf_shell = "msf" in shell_type or "meterpreter" in shell_type
    
    if backend_settings["mode"] == "msf" and request.shell_id and is_msf_shell:
        probe_executor = SessionBackendExecutor(mode="msf", msf_binary=backend_settings["msf_binary"])
        ready, reason = await probe_executor.verify_session(request.shell_id)
        if not ready:
            raise HTTPException(status_code=400, detail=f"MSF shell session invalid: {reason}")
            
    # Determine the backend mode for this specific session
    session_backend_mode = "msf" if (backend_settings["mode"] == "msf" and is_msf_shell) else "workspace"
    
    session_id = str(uuid.uuid4())
    workspace = _session_root(project_id, session_id)
    rel_cwd = (request.cwd or ".").replace("\\", "/").lstrip("/")
    if rel_cwd:
        cwd = os.path.abspath(os.path.join(workspace, rel_cwd))
        if not cwd.startswith(workspace):
            raise HTTPException(status_code=400, detail="Invalid cwd")
        os.makedirs(cwd, exist_ok=True)
    else:
        cwd = workspace
    payload = {
        "session_id": session_id,
        "project_id": project_id,
        "status": "active",
        "type": "workspace" if session_backend_mode == "workspace" else "msf",
        "shell_id": request.shell_id,
        "name": request.name or "manual-session",
        "cwd": cwd,
        "created_at": time.time(),
        "last_active_at": time.time(),
        "backend_mode": session_backend_mode,
        "workspace_root": workspace,
        "source": "manual",
        "source_shell": matched_shell.get("raw") if isinstance(matched_shell, dict) else None,
        "command_history": [],
        "file_history": [],
    }
    persisted = _persist_webui_session(payload)
    return persisted


@router.post("/webui/projects/{project_id}/sessions/sync-msf")
async def webui_sync_msf_sessions(
    project_id: str,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    _project_or_404(project_id)
    settings = _get_session_backend_settings()
    executor = SessionBackendExecutor(mode="msf", msf_binary=settings["msf_binary"])
    result = await executor.probe_sessions()
    created: List[Dict[str, Any]] = []
    if result["ok"]:
        for msf in result["sessions"]:
            sid = str(msf.get("id") or "").strip()
            if not sid:
                continue
            exists = None
            for item in webui_sessions.values():
                if item.get("project_id") == project_id and item.get("shell_id") == sid and item.get("status") == "active":
                    exists = item
                    break
            if exists:
                continue
            session_id = str(uuid.uuid4())
            workspace = _session_root(project_id, session_id)
            payload = {
                "session_id": session_id,
                "project_id": project_id,
                "status": "active",
                "type": "workspace",
                "shell_id": sid,
                "name": f"msf-{sid}",
                "cwd": workspace,
                "created_at": time.time(),
                "last_active_at": time.time(),
                "backend_mode": "msf",
                "workspace_root": workspace,
                "source": "msf_sync",
                "msf_meta": msf,
                "command_history": [],
                "file_history": [],
            }
            persisted = _persist_webui_session(payload)
            created.append(persisted)
    return {
        "project_id": project_id,
        "ok": result["ok"],
        "created_count": len(created),
        "created": created,
        "sessions_found": result["sessions"],
        "stderr": result["stderr"],
    }


@router.post("/webui/projects/{project_id}/sessions/{session_id}/close")
async def webui_close_session(
    project_id: str,
    session_id: str,
    request: SessionCloseRequest,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    session = _resolve_session(project_id, session_id)
    session["status"] = "closed"
    session["closed_at"] = time.time()
    session["close_reason"] = request.reason or "manual"
    db_close_webui_session(session_id, session["close_reason"])
    _persist_webui_session(session)
    session_health_cache.pop(_session_cache_key(project_id, session_id), None)
    return {"session_id": session_id, "project_id": project_id, "status": "closed"}


@router.get("/webui/projects/{project_id}/sessions/{session_id}/status")
async def webui_get_session_status(project_id: str, session_id: str):
    session = _resolve_session(project_id, session_id)
    heartbeat = await _refresh_session_heartbeat(project_id, session, force=False)
    return {
        "session_id": session_id,
        "project_id": project_id,
        "backend_mode": session.get("backend_mode"),
        "shell_id": session.get("shell_id"),
        "health": heartbeat,
        "last_command": session.get("last_command"),
        "last_command_at": session.get("last_command_at"),
        "last_returncode": session.get("last_returncode"),
        "last_duration_seconds": session.get("last_duration_seconds"),
        "last_stdout_excerpt": session.get("last_stdout_excerpt"),
        "last_stderr_excerpt": session.get("last_stderr_excerpt"),
        "workspace_root": session.get("workspace_root"),
        "source_shell": session.get("source_shell"),
        "command_history": session.get("command_history", [])[-10:],
        "file_history": session.get("file_history", [])[-10:],
    }


@router.post("/webui/projects/{project_id}/sessions/{session_id}/health-check")
async def webui_health_check_session(
    project_id: str,
    session_id: str,
    request: SessionHealthCheckRequest,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    session = _resolve_session(project_id, session_id)
    backend_mode = str(session.get("backend_mode") or "workspace")
    command = request.command or ("echo health-check" if backend_mode == "workspace" else "sysinfo")
    executor = _build_session_executor(session)
    stdout, stderr, returncode, backend_meta = await executor.execute(
        command=command,
        timeout=request.timeout,
        cwd=session.get("cwd") or PROJECT_ROOT,
        shell_id=session.get("shell_id"),
        retries=1,
    )
    healthy = returncode == 0
    heartbeat = _record_session_health(
        project_id=project_id,
        session_id=session_id,
        healthy=healthy,
        reason="command_ok" if healthy else "command_failed",
        returncode=returncode,
        command=command,
    )
    _record_session_command(session, command, session.get("cwd") or PROJECT_ROOT, returncode, 0.0, stdout, stderr, backend_meta)
    return {
        "session_id": session_id,
        "project_id": project_id,
        "command": command,
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "backend": backend_meta,
        "health": heartbeat,
    }


@router.post("/webui/projects/{project_id}/sessions/{session_id}/command")
async def webui_execute_session_command(
    project_id: str,
    session_id: str,
    request: SessionCommandRequest,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_access(x_admin_key)
    session = _resolve_session(project_id, session_id)
    command = request.command.strip()
    if not command:
        raise HTTPException(status_code=400, detail="Command cannot be empty")
    backend_mode = str(session.get("backend_mode") or "workspace").strip().lower()
    cwd = session.get("cwd") or PROJECT_ROOT
    if backend_mode != "msf":
        cwd = _resolve_session_path(project_id, session_id, request.cwd or "")
        if not os.path.isdir(cwd):
            raise HTTPException(status_code=400, detail="cwd does not exist")
    result = await _execute_cli_for_session(
        project_id=project_id,
        session=session,
        command=command,
        cwd=str(cwd),
        timeout=request.timeout,
    )
    _audit_operation(project_id, "cli", "success", f"session cli execute: {command[:120]}")
    return result


@router.post("/webui/cli/execute")
async def webui_execute_cli(request: CLIExecuteRequest, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_access(x_admin_key)
    command = request.command.strip()
    if not command:
        raise HTTPException(status_code=400, detail="Command cannot be empty")
    session = _resolve_session(request.project_id, request.session_id) if request.project_id and request.session_id else None
    cwd = request.cwd or "."
    if session and str(session.get("backend_mode") or "workspace").strip().lower() != "msf":
        cwd = _resolve_session_path(request.project_id, request.session_id, request.cwd or "")
        if not os.path.isdir(cwd):
            raise HTTPException(status_code=400, detail="cwd does not exist")
    elif not session:
        cwd = _resolve_session_path(request.project_id, request.session_id, request.cwd or ".")
        if not os.path.isdir(cwd):
            raise HTTPException(status_code=400, detail="cwd does not exist")
    result = await _execute_cli_for_session(
        project_id=request.project_id,
        session=session,
        command=command,
        cwd=cwd,
        timeout=request.timeout,
    )
    _audit_operation(request.project_id, "cli", "success", f"cli execute: {command[:120]}")
    return result


@router.post(
    "/webui/files/ops",
    responses={
        400: {"description": "Unsupported action or invalid path"},
        401: {"description": "Invalid X-Admin-Key"},
        404: {"description": "File not found"},
    },
)
async def webui_file_ops(request: FileOperationRequest, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_access(x_admin_key)
    action = (request.action or "").strip().lower()
    session = _resolve_session(request.project_id, request.session_id) if request.project_id and request.session_id else None
    result = await _execute_file_operation(
        action=action,
        path=request.path,
        content=request.content,
        recursive=request.recursive,
        max_entries=request.max_entries,
        project_id=request.project_id,
        session=session,
    )
    _audit_operation(request.project_id, "file_ops", "success", f"file {action}: {request.path}")
    return result


@router.post("/webui/projects/{project_id}/sessions/{session_id}/files")
async def webui_session_file_ops(
    project_id: str,
    session_id: str,
    request: SessionFileOperationRequest,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_access(x_admin_key)
    session = _resolve_session(project_id, session_id)
    action = (request.action or "").strip().lower()
    result = await _execute_file_operation(
        action=action,
        path=request.path,
        content=request.content,
        recursive=request.recursive,
        max_entries=request.max_entries,
        project_id=project_id,
        session=session,
    )
    _audit_operation(project_id, "file_ops", "success", f"session file {action}: {request.path}")
    return result


@router.post("/webui/files/upload")
async def webui_upload_file(
    project_id: str = Form(...),
    session_id: str = Form(...),
    path: str = Form(...),
    file: UploadFile = File(...),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    session = _resolve_session(project_id, session_id)
    executor = _build_session_executor(session)
    shell_id = session.get("shell_id")
    data = await file.read()
    if executor.mode == "workspace":
        target_path = _resolve_session_path(project_id, session_id, path)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "wb") as output:
            output.write(data)
        _record_session_file_operation(session, "upload", path, target_path, {"bytes": len(data)}, "workspace")
        return {"project_id": project_id, "session_id": session_id, "path": target_path, "filename": file.filename, "bytes": len(data)}
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Only text files can be uploaded to MSF currently") from exc
    result = await executor.execute_file_op(
        action="write",
        path=path,
        content=content,
        shell_id=shell_id,
    )
    if "error" in result:
        raise _file_operation_error_to_http(str(result["error"]))
    _record_session_file_operation(session, "upload", path, path, result, "msf")
    return {"project_id": project_id, "session_id": session_id, "path": path, "filename": file.filename, "bytes": len(data)}


@router.get("/webui/files/download")
async def webui_download_file(
    project_id: str = Query(...),
    session_id: str = Query(...),
    path: str = Query(...),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)

    # 统一使用会话解析函数，确保无效 project/session 返回稳定的 4xx
    session = _resolve_session(project_id, session_id)
    executor = _build_session_executor(session)
    shell_id = session.get("shell_id")

    if executor.mode == "workspace":
        try:
            target_path = _resolve_session_path(project_id, session_id, path)
        except HTTPException:
            # 已明确的业务异常（如路径越界、会话不存在）直接透传
            raise
        except (ValueError, OSError) as exc:
            # 兜底处理非法路径输入，避免落到 500
            raise HTTPException(status_code=400, detail=f"Invalid path: {exc}") from exc
        if not os.path.isfile(target_path):
            raise HTTPException(status_code=404, detail="File not found")
        _record_session_file_operation(session, "download", path, target_path, {"downloaded": True}, "workspace")
        return FileResponse(path=target_path, filename=os.path.basename(target_path))
    result = await executor.execute_file_op(
        action="read",
        path=path,
        shell_id=shell_id,
    )
    if "error" in result:
        raise _file_operation_error_to_http(str(result["error"]))
    _record_session_file_operation(session, "download", path, path, result, "msf")
    content = result.get("content", "")
    return Response(
        content=content.encode("utf-8"),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(path)}"'}
    )


@router.post("/webui/projects/{project_id}/reports/generate")
async def webui_generate_report(project_id: str):
    project = _project_or_404(project_id)
    existing_report_path = os.path.abspath(f"output/reports/{project_id}_report.md")
    if os.path.exists(existing_report_path) and os.path.getsize(existing_report_path) > 0:
        results = normalize_project_results(project.get("results") or {})
        if isinstance(results, dict):
            results["report_path"] = existing_report_path
            db_update_project(project_id, results=results)
        return {"project_id": project_id, "report_path": existing_report_path}

    results = normalize_project_results(project.get("results") or {})
    findings: List[Dict[str, Any]] = []
    recon_result = results.get("recon_result", {}) if isinstance(results, dict) else {}
    exploit_result = results.get("exploit_result", {}) if isinstance(results, dict) else {}
    post_exploit_result = results.get("post_exploit_result", {}) if isinstance(results, dict) else {}
    lateral_movement_result = results.get("lateral_movement_result", {}) if isinstance(results, dict) else {}
    persistence_objects = results.get("persistence_objects", []) if isinstance(results, dict) else []
    verification_result = results.get("final_verification", {}) if isinstance(results, dict) else {}
    report_result = results.get("report_result", {}) if isinstance(results, dict) else {}
    usage_summary = results.get("usage_summary", {}) if isinstance(results, dict) else {}
    evidence_gap_checklist = results.get("evidence_gap_checklist", []) if isinstance(results, dict) else []
    phase_status = results.get("phase_status", {}) if isinstance(results, dict) else {}
    if not isinstance(phase_status, dict) or not phase_status:
        phase_status = _derive_phase_status_from_events(project_id)
    phase_status = _coerce_terminal_phase_status(
        phase_status if isinstance(phase_status, dict) else {},
        str(project.get("status") or ""),
        str(project.get("phase") or ""),
    )
    if not isinstance(usage_summary, dict) or not usage_summary:
        usage_summary = _extract_usage_from_events(project_id)
    if not isinstance(evidence_gap_checklist, list):
        evidence_gap_checklist = []
    if isinstance(phase_status, dict):
        for phase_name, phase_result in phase_status.items():
            normalized_phase_result = _normalize_status(str(phase_result), default=str(phase_result))
            severity = "High" if normalized_phase_result in {"failed", "error"} else "Info"
            findings.append(
                {
                    "title": f"{phase_name} 阶段状态",
                    "severity": severity,
                    "description": f"阶段 {phase_name} 当前状态: {normalized_phase_result}",
                    "remediation": "请结合阶段日志和任务详情进行复核与修复。",
                }
            )
    exploit_text = _sanitize_report_text(str(exploit_result.get("content") or "").strip())
    post_exploit_text = _sanitize_report_text(str(post_exploit_result.get("content") or "").strip())
    lateral_movement_text = _sanitize_report_text(str(lateral_movement_result.get("content") or "").strip())
    exploit_tool_results = exploit_result.get("tool_results", []) if isinstance(exploit_result, dict) else []
    post_exploit_tool_results = post_exploit_result.get("tool_results", []) if isinstance(post_exploit_result, dict) else []
    validated_vulns: List[str] = []
    if isinstance(exploit_tool_results, list):
        for item in exploit_tool_results:
            if not isinstance(item, dict):
                continue
            result = item.get("result")
            if not isinstance(result, dict):
                continue
            vulnerabilities = result.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                continue
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                name = str(vuln.get("name") or vuln.get("template_id") or "").strip()
                severity = str(vuln.get("severity") or "").strip().lower()
                matched_at = str(vuln.get("matched_at") or vuln.get("matched-at") or "").strip()
                if name and severity in {"high", "critical"}:
                    validated_vulns.append(f"{name} @ {matched_at or 'unknown'}")
    if not exploit_text:
        exploit_text = _sanitize_report_text(_extract_stage_payload_from_events(project_id, "exploitation").get("content", ""))
    if not post_exploit_text:
        post_exploit_text = _sanitize_report_text(_extract_stage_payload_from_events(project_id, "post_exploit").get("content", ""))
    if not lateral_movement_text:
        lateral_movement_text = _sanitize_report_text(_extract_stage_payload_from_events(project_id, "lateral_movement").get("content", ""))
    if validated_vulns:
        findings.append(
            {
                "title": "Validated Vulnerabilities",
                "severity": "High",
                "description": "\n".join(validated_vulns),
                "remediation": "请优先修复已被工具验证的高危与严重漏洞。",
            }
        )
    if exploit_text:
        exploit_severity = "High" if validated_vulns else "Info"
        exploit_remediation = (
            "建议立即复现并修复高风险漏洞，落实补丁和访问控制策略。"
            if validated_vulns
            else "当前仅为未验证线索，需补充工具级证据后再下高风险结论。"
        )
        findings.append(
            {
                "title": "Exploitation Findings",
                "severity": exploit_severity,
                "description": exploit_text,
                "remediation": exploit_remediation,
            }
        )
    if post_exploit_text and (post_exploit_tool_results or not lateral_movement_text):
        findings.append(
            {
                "title": "Post-Exploitation Findings",
                "severity": "Medium",
                "description": post_exploit_text,
                "remediation": "建议最小权限化并加固横向移动相关主机与凭据管理。",
            }
        )
    if lateral_movement_text:
        findings.append(
            {
                "title": "Lateral Movement Findings",
                "severity": "Medium",
                "description": lateral_movement_text,
                "remediation": "建议收敛横向路径、轮换共享凭据，并限制远程管理面暴露。",
            }
        )
    persistence_summary = summarize_persistence_objects(persistence_objects)
    if persistence_summary:
        findings.append(
            {
                "title": "Persistence Objects",
                "severity": "Medium",
                "description": persistence_summary,
                "remediation": "建议移除异常启动项或计划任务，并复核受影响主机的长期驻留风险。",
            }
        )
    if not findings:
        findings.append(
            {
                "title": "Evidence Gap",
                "severity": "Info",
                "description": "当前未提取到可验证漏洞证据，建议补充扫描和复测后再生成结论。",
                "remediation": "先完成工具级证据采集，再进行利用与报告生成。",
            }
        )
    # 恢复证据门禁，作为警告显示，但不阻断报告生成
    evidence_gate_active = str((phase_status or {}).get("exploit") or "") == "insufficient_evidence" or str((phase_status or {}).get("post_exploit") or "") == "insufficient_evidence"
    if evidence_gate_active and not evidence_gap_checklist:
        evidence_gap_checklist = [
            "补充端口与服务识别证据（open_ports/services）。",
            "补充漏洞验证证据（high/critical）。",
            "证据补齐后再进入后渗透阶段。",
        ]
    if evidence_gate_active:
        findings.append(
            {
                "title": "Evidence Gap Checklist (证据缺口清单)",
                "severity": "Warning",
                "description": "系统检测到部分阶段缺乏结构化的工具级证据验证，但已根据 AI 的推演生成报告。缺口如下：\n" + "\n".join([f"- {item}" for item in evidence_gap_checklist]),
                "remediation": "建议在后续复测中按清单补齐相关工具的扫描证据。",
            }
        )
    usage_text = ""
    if isinstance(usage_summary, dict) and usage_summary:
        usage_text = "Token统计: " + ", ".join(
            [f"{key}={int(float(value))}" for key, value in usage_summary.items() if isinstance(value, (int, float))]
        )
    failure_events = db_list_project_events(project_id, limit=1200, offset=0, level="WARNING")
    failure_events += db_list_project_events(project_id, limit=1200, offset=0, level="ERROR")
    failure_reasons: List[str] = []
    for item in failure_events[-20:]:
        message = _sanitize_report_text(str(item.get("message") or ""), max_chars=180)
        if not message:
            continue
        if message not in failure_reasons:
            failure_reasons.append(message)
    failure_summary = "；".join(failure_reasons[:5])
    executive_summary = (
        _summarize_verification_result(verification_result, evidence_gate_active)
        or _summarize_event_messages(db_list_project_events(project_id, limit=300, offset=0), limit=6)
        or f"项目 {project_id} 当前状态 {project.get('status')}，阶段 {project.get('phase')}。"
    )
    if failure_summary:
        executive_summary = f"{executive_summary}\n\n未成功利用的主要原因：{failure_summary}"
    methodology = "通过自动化多智能体流程执行侦察、利用、后渗透与报告环节。"
    recommendations = (
        _sanitize_report_text(str(report_result.get("content") or "").strip())
        or "建议复核高风险发现并进行补丁修复、最小权限化与日志监控。"
    )
    
    # 移除原本在 evidence_gate_active 为 True 时粗暴覆盖 executive_summary 等字段的逻辑

    report_quality_checks = _build_report_quality_checks(
        phase_status=phase_status,
        findings=findings,
        evidence_gap_checklist=evidence_gap_checklist,
        usage_summary=usage_summary,
    )
    payload = {
        "executive_summary": executive_summary,
        "methodology": methodology,
        "findings": findings,
        "recommendations": recommendations,
        "quality_checks": report_quality_checks,
        "target_info": {
            "target": project.get("target"),
            "description": project.get("description", ""),
            "project_status": project.get("status"),
            "phase_status": phase_status,
            "usage_summary": usage_summary,
            "usage_text": usage_text,
            "recon_excerpt": _sanitize_report_text(str(recon_result.get("content") or ""), max_chars=2000),
            "lateral_movement_excerpt": lateral_movement_text,
            "persistence_objects": persistence_objects,
            "evidence_gate_active": evidence_gate_active,
            "evidence_gap_checklist": evidence_gap_checklist,
        },
    }
    generator = ReportGenerator(output_dir=os.path.abspath("output/reports"))
    report_path = os.path.abspath(generator.generate_report(project_id, payload))
    merged_results = dict(results) if isinstance(results, dict) else {}
    merged_results["phase_status"] = phase_status
    merged_results["usage_summary"] = usage_summary
    merged_results["evidence_gap_checklist"] = evidence_gap_checklist
    merged_results["report_quality_checks"] = report_quality_checks
    merged_results["report_path"] = report_path
    db_update_project(project_id, results=merged_results)
    return {"project_id": project_id, "report_path": report_path}


@router.get("/webui/projects/{project_id}/reports/latest")
async def webui_get_latest_report(project_id: str):
    project = _project_or_404(project_id)
    project_results = normalize_project_results(project.get("results") if isinstance(project.get("results"), dict) else {})
    report_path = project_results.get("report_path")
    if not report_path:
        fallback_report_path = os.path.abspath(f"output/reports/{project_id}_report.md")
        if os.path.exists(fallback_report_path):
            report_path = fallback_report_path
            if isinstance(project_results, dict):
                project_results["report_path"] = report_path
                db_update_project(project_id, results=project_results)
    if not report_path:
        raise HTTPException(status_code=404, detail="Report path not found")
    abs_report_path = os.path.abspath(report_path)
    if not os.path.exists(abs_report_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    with open(abs_report_path, "r", encoding="utf-8", errors="replace") as file:
        content = file.read()
    phase_status = project_results.get("phase_status", {}) if isinstance(project_results, dict) else {}
    evidence_gate_active = (
        str((phase_status or {}).get("exploit") or "") == "insufficient_evidence"
        or str((phase_status or {}).get("post_exploit") or "") == "insufficient_evidence"
    )
    return {
        "project_id": project_id,
        "report_path": abs_report_path,
        "content": content,
        "evidence_gate_active": evidence_gate_active,
        "evidence_gap_checklist": project_results.get("evidence_gap_checklist", []) if isinstance(project_results, dict) else [],
        "report_quality_checks": project_results.get("report_quality_checks", {}) if isinstance(project_results, dict) else {},
    }


@router.get("/webui/projects/{project_id}/reports/download")
async def webui_download_report(
    project_id: str,
    fmt: str = Query(default="md", pattern="^(md|json|html)$"),
):
    project = _project_or_404(project_id)
    project_results = normalize_project_results(project.get("results") if isinstance(project.get("results"), dict) else {})
    report_path = project_results.get("report_path")
    if not report_path:
        fallback_report_path = os.path.abspath(f"output/reports/{project_id}_report.md")
        if os.path.exists(fallback_report_path):
            report_path = fallback_report_path
            if isinstance(project_results, dict):
                project_results["report_path"] = report_path
                db_update_project(project_id, results=project_results)
    if not report_path:
        raise HTTPException(status_code=404, detail="Report path not found")
    abs_report_path = os.path.abspath(report_path)
    if not os.path.exists(abs_report_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    with open(abs_report_path, "r", encoding="utf-8", errors="replace") as file:
        markdown_content = file.read()
    if fmt == "md":
        return Response(
            content=markdown_content,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{project_id}_report.md"'},
        )
    if fmt == "json":
        payload = {
            "project_id": project_id,
            "target": project.get("target"),
            "status": project.get("status"),
            "phase": project.get("phase"),
            "report_path": abs_report_path,
            "phase_status": project_results.get("phase_status", {}),
            "usage_summary": project_results.get("usage_summary", {}),
            "lateral_movement_result": project_results.get("lateral_movement_result", {}),
            "persistence_objects": project_results.get("persistence_objects", []),
            "evidence_gap_checklist": project_results.get("evidence_gap_checklist", []),
            "report_quality_checks": project_results.get("report_quality_checks", {}),
            "markdown": markdown_content,
        }
        return Response(
            content=json.dumps(payload, ensure_ascii=False, indent=2),
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{project_id}_report.json"'},
        )
    title = f"渗透测试报告 - {project_id}"
    html_content = _markdown_to_readable_html(markdown_content, title)
    return Response(
        content=html_content,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{project_id}_report.html"'},
    )


@router.get(
    "/webui/libs/files",
    responses={
        400: {"description": "Unsupported lib_type or invalid path"},
    },
)
async def webui_list_lib_files(
    lib_type: str = Query(...),
    path: str = Query(default=""),
    recursive: bool = Query(default=False),
    limit: int = Query(default=500, ge=1, le=5000),
):
    target = _resolve_lib_path(lib_type, path)
    if not os.path.isdir(target):
        raise HTTPException(status_code=400, detail="Path is not a directory")
    items: List[Dict[str, Any]] = []
    if recursive:
        base = Path(target)
        for entry in sorted(base.rglob("*"))[:limit]:
            stat = entry.stat()
            items.append(
                {
                    "path": str(entry.relative_to(base)).replace("\\", "/"),
                    "is_dir": entry.is_dir(),
                    "size": int(stat.st_size),
                    "modified_at": float(stat.st_mtime),
                }
            )
    else:
        for entry in sorted(os.scandir(target), key=lambda item: (not item.is_dir(), item.name.lower()))[:limit]:
            stat = entry.stat()
            items.append(
                {
                    "path": entry.name.replace("\\", "/"),
                    "is_dir": entry.is_dir(),
                    "size": int(stat.st_size),
                    "modified_at": float(stat.st_mtime),
                }
            )
    return {"lib_type": lib_type, "path": target, "count": len(items), "items": items}


@router.get("/webui/libs/file")
async def webui_read_lib_file(lib_type: str = Query(...), path: str = Query(...)):
    file_path = _resolve_lib_path(lib_type, path)
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Library file not found")
    with open(file_path, "r", encoding="utf-8", errors="replace") as file:
        content = file.read()
    return {"lib_type": lib_type, "path": file_path, "content": content}


@router.put("/webui/libs/file")
async def webui_upsert_lib_file(
    request: LibFileUpsertRequest,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    file_path = _resolve_lib_path(request.lib_type, request.path)
    if os.path.exists(file_path) and not request.overwrite:
        raise HTTPException(status_code=409, detail="File already exists")
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(request.content)
    return {"lib_type": request.lib_type, "path": file_path, "bytes": len(request.content.encode("utf-8"))}


@router.delete("/webui/libs/file")
async def webui_delete_lib_file(
    lib_type: str = Query(...),
    path: str = Query(...),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    file_path = _resolve_lib_path(lib_type, path)
    if not os.path.exists(file_path):
        return {"lib_type": lib_type, "path": file_path, "deleted": False}
    if os.path.isdir(file_path):
        for root, dirs, files in os.walk(file_path, topdown=False):
            for filename in files:
                os.remove(os.path.join(root, filename))
            for dirname in dirs:
                os.rmdir(os.path.join(root, dirname))
        os.rmdir(file_path)
    else:
        os.remove(file_path)
    return {"lib_type": lib_type, "path": file_path, "deleted": True}


@router.post("/webui/web-audit/rules/validate")
async def webui_validate_web_audit_rules(
    request: WebAuditRulesValidateRequest,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_access(x_admin_key)
    try:
        summary = web_auditor.validate_and_fix_rules(auto_fix=bool(request.auto_fix))
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"rule validation failed: {error}") from error
    _audit_operation(None, "web_audit", "success", f"web audit rules validated, fixed_files={summary.get('files_fixed', 0)}")
    return summary


@router.post("/webui/web-audit/run")
async def webui_run_web_audit(
    request: WebAuditRunRequest,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_access(x_admin_key)
    try:
        result = web_auditor.run_audit(
            target=request.target,
            auto_fix_rules=bool(request.auto_fix_rules),
            use_yak=bool(request.use_yak),
            timeout_seconds=int(request.timeout_seconds),
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except FileNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"web audit failed: {error}") from error

    _audit_operation(
        None,
        "web_audit",
        "success",
        f"web audit run target={result.get('target')}, findings={result.get('findings_count', 0)}",
    )
    return result


@router.post("/webui/learning/sync")
async def webui_learning_sync(request: LearningSyncRequest, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_access(x_admin_key)
    topic = request.topic.strip()
    if not topic:
        raise HTTPException(status_code=400, detail="topic is required")
    results: List[Dict[str, Any]] = []
    if request.content and request.content.strip():
        text_result = learner.ingest_text(topic=topic, text=request.content.strip(), source="manual_input")
        results.append({"source": "manual_input", **text_result})
    url_result = {"topic": topic, "total": 0, "saved_count": 0, "duplicate_count": 0, "results": []}
    if request.urls:
        url_result = learner.ingest_urls(topic=topic, urls=request.urls)
        results.extend(url_result["results"])
    payload = {
        "topic": topic,
        "saved_count": sum(1 for item in results if item.get("saved")),
        "duplicate_count": sum(1 for item in results if item.get("duplicate")),
        "error_count": sum(1 for item in results if item.get("error")),
        "results": results,
        "url_summary": {
            "total": url_result.get("total", 0),
            "saved_count": url_result.get("saved_count", 0),
            "duplicate_count": url_result.get("duplicate_count", 0),
        },
    }
    _audit_operation(None, "learning", "success", f"learning sync topic={topic}, saved={payload['saved_count']}, duplicated={payload['duplicate_count']}")
    return payload


@router.get("/webui/learning/history")
async def webui_learning_history(
    keyword: Optional[str] = Query(default=None),
    item_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    keyword = keyword if isinstance(keyword, str) else None
    item_type = item_type if isinstance(item_type, str) else None
    return learner.list_history(keyword=keyword, item_type=item_type, limit=limit, offset=offset)


@router.get("/webui/settings/providers/catalog")
async def webui_get_provider_catalog(x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_when_configured(x_admin_key)
    payload = get_provider_catalog_payload()
    payload["checked_at"] = time.time()
    return payload


@router.get("/webui/settings/apikey")
async def webui_get_apikey_status(
    provider: Optional[str] = Query(default=None, max_length=64),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    config = migrate_ai_config(_load_yaml_config(CONFIG_PATH))
    ai_config = config.get("ai", {}) or {}
    default_provider = _normalize_provider_name(ai_config.get("default_provider", "deepseek"))
    if default_provider not in AI_PROVIDER_DEFAULT_BASE_URL:
        default_provider = "deepseek"
    target_provider = _normalize_provider_name(provider or default_provider)
    if target_provider not in AI_PROVIDER_DEFAULT_BASE_URL:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {target_provider}")
    provider_config = ai_config.get("providers", {}).get(target_provider, {})
    runtime = _provider_runtime_config(target_provider, provider_config)
    api_key = str(runtime.get("api_key") or "")
    updated_at = db_get_setting("api_key_last_updated_at", None)
    return {
        "provider": target_provider,
        "default_provider": default_provider,
        "provider_failover_order": normalize_provider_failover_order(ai_config.get("provider_failover_order"), default_provider),
        "configured_provider_chain": _configured_provider_chain(config),
        "endpoint_key": runtime.get("endpoint_key"),
        "is_configured": _provider_is_configured_for_runtime(target_provider, provider_config),
        "api_key_masked": _mask_secret(api_key) if api_key else "",
        "model": runtime.get("model"),
        "base_url": runtime.get("base_url"),
        "protocol": runtime.get("protocol"),
        "failover_models": runtime.get("failover_models", []),
        "migration_warnings": list(runtime.get("migration_warnings") or []),
        "updated_at": updated_at,
    }


@router.post("/webui/settings/providers/verify")
async def webui_verify_provider_settings(request: ProviderVerifyRequest, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_when_configured(x_admin_key)
    config = migrate_ai_config(_load_yaml_config(CONFIG_PATH))
    ai_config = config.get("ai", {}) or {}
    providers = ai_config.get("providers", {}) or {}
    target = _normalize_provider_name(request.provider or ai_config.get("default_provider", "deepseek"))
    if target not in AI_PROVIDER_DEFAULT_BASE_URL:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {target}")
    provider_config = dict(providers.get(target, {}) or {})
    if request.api_key is not None:
        provider_config["api_key"] = str(request.api_key or "").strip()
    if request.base_url is not None:
        provider_config["base_url"] = str(request.base_url or "").strip()
    if request.protocol is not None:
        provider_config["protocol"] = str(request.protocol or "").strip()
    if request.endpoint_key is not None:
        provider_config["endpoint_key"] = str(request.endpoint_key or "").strip()
    if request.model is not None:
        provider_config["model"] = str(request.model or "").strip()
        provider_config["reasoner_model"] = str(request.model or "").strip()
    result = await _verify_provider_config(target, provider_config)
    result["checked_at"] = time.time()
    result["effective_config_source"] = "request" if any(
        item is not None for item in (request.api_key, request.base_url, request.protocol, request.endpoint_key, request.model)
    ) else "config"
    return result


@router.post("/webui/settings/providers/verify-all")
async def webui_verify_all_provider_settings(x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_when_configured(x_admin_key)
    config = migrate_ai_config(_load_yaml_config(CONFIG_PATH))
    ai_config = config.get("ai", {}) or {}
    providers = ai_config.get("providers", {}) or {}
    results: List[Dict[str, Any]] = []
    for name in SUPPORTED_AI_PROVIDERS:
        provider_config = providers.get(name, {}) or {}
        verify_result = await _verify_provider_config(name, provider_config)
        verify_result["checked_at"] = time.time()
        results.append(verify_result)
    reachable = sum(1 for item in results if bool(item.get("reachable")))
    model_ok = sum(1 for item in results if bool(item.get("model_exists")))
    return {
        "checked_at": time.time(),
        "total": len(results),
        "reachable": reachable,
        "model_match": model_ok,
        "results": results,
    }


@router.get("/webui/settings/providers/models")
async def webui_get_provider_models(
    provider: Optional[str] = Query(default=None, max_length=64),
    endpoint_key: Optional[str] = Query(default=None, max_length=64),
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    _require_admin_when_configured(x_admin_key)
    config = migrate_ai_config(_load_yaml_config(CONFIG_PATH))
    ai_config = config.get("ai", {}) or {}
    providers = ai_config.get("providers", {}) or {}
    target = _normalize_provider_name(provider or ai_config.get("default_provider", "deepseek"))
    if target not in AI_PROVIDER_DEFAULT_BASE_URL:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {target}")
    provider_config = dict(providers.get(target, {}) or {})
    if endpoint_key is not None:
        provider_config["endpoint_key"] = str(endpoint_key or "").strip()
    result = await _fetch_provider_models(target, provider_config)
    result["checked_at"] = time.time()
    return result


@router.get("/webui/settings/providers/models/all")
async def webui_get_all_provider_models(x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_when_configured(x_admin_key)
    config = migrate_ai_config(_load_yaml_config(CONFIG_PATH))
    ai_config = config.get("ai", {}) or {}
    providers = ai_config.get("providers", {}) or {}
    results: List[Dict[str, Any]] = []
    for name in SUPPORTED_AI_PROVIDERS:
        provider_config = providers.get(name, {}) or {}
        item = await _fetch_provider_models(name, provider_config)
        item["checked_at"] = time.time()
        results.append(item)
    return {
        "checked_at": time.time(),
        "total": len(results),
        "results": results,
    }


@router.put("/webui/settings/apikey")
async def webui_update_apikey(request: ApiKeyUpdateRequest, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_access(x_admin_key)
    provider = _normalize_provider_name(request.provider or "deepseek")
    if provider not in AI_PROVIDER_DEFAULT_BASE_URL:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")

    endpoint_options = get_provider_endpoints(provider)
    endpoint_key = str(request.endpoint_key or get_default_endpoint_key(provider)).strip()
    if endpoint_key not in endpoint_options:
        raise HTTPException(status_code=400, detail=f"Unsupported endpoint option: {endpoint_key}")

    api_key = str(request.api_key or "").strip()
    if provider_requires_api_key(provider) and not api_key:
        raise HTTPException(status_code=400, detail="API key is required for this provider")
    if provider == "custom" and not str(request.base_url or "").strip():
        raise HTTPException(status_code=400, detail="Base URL is required for custom provider")
    if provider_allows_custom_base_url(provider):
        raw_base_url = str(request.base_url or "").strip()
        if raw_base_url and not re.match(r"^https?://", raw_base_url, re.IGNORECASE):
            raise HTTPException(status_code=400, detail="Base URL must start with http:// or https://")

    candidate_config = {
        "api_key": api_key,
        "endpoint_key": endpoint_key,
    }
    if provider_allows_custom_base_url(provider):
        candidate_config["base_url"] = str(request.base_url or "").strip()
    if provider_allows_custom_protocol(provider):
        candidate_config["protocol"] = str(request.protocol or "").strip()

    discovered_models: List[str] = []
    validation_models = list(get_provider_models(provider, endpoint_key))
    if get_provider_discovery(provider) == "remote_models" and (not provider_requires_api_key(provider) or not _is_placeholder_api_key(candidate_config["api_key"])):
        fetched = await _fetch_provider_models(provider, candidate_config)
        if fetched.get("source") == "remote" and isinstance(fetched.get("models"), list):
            discovered_models = [str(item or "").strip() for item in fetched.get("models") if str(item or "").strip()]
            if discovered_models:
                validation_models = list(dict.fromkeys(discovered_models))
    validation_model_set = set(validation_models)

    default_model = get_provider_default_model(provider, endpoint_key)
    if default_model not in validation_model_set and validation_models:
        default_model = validation_models[0]
    model = str(request.model or default_model).strip()
    if not model:
        raise HTTPException(status_code=400, detail="Model is required")
    if not provider_supports_freeform_models(provider) and model not in validation_model_set:
        raise HTTPException(status_code=400, detail=f"Model '{model}' is not in the official catalog for {provider}/{endpoint_key}")

    normalized_failover_models: List[str] = []
    invalid_failovers: List[str] = []
    for item in (request.failover_models or []):
        name = str(item or "").strip()
        if not name or name == model:
            continue
        if not provider_supports_freeform_models(provider) and name not in validation_model_set:
            invalid_failovers.append(name)
            continue
        if name not in normalized_failover_models:
            normalized_failover_models.append(name)
    if invalid_failovers:
        raise HTTPException(status_code=400, detail=f"Failover models are not in the official catalog: {', '.join(invalid_failovers)}")

    config = migrate_ai_config(_load_yaml_config(CONFIG_PATH))
    ai_config = config.setdefault("ai", {})
    providers = ai_config.setdefault("providers", {})
    current_default_provider = _normalize_provider_name(ai_config.get("default_provider", "deepseek"))
    if current_default_provider not in AI_PROVIDER_DEFAULT_BASE_URL:
        current_default_provider = "deepseek"
    next_default_provider = _normalize_provider_name(request.default_provider or current_default_provider)
    if next_default_provider not in AI_PROVIDER_DEFAULT_BASE_URL:
        raise HTTPException(status_code=400, detail=f"Unsupported default provider: {next_default_provider}")

    existing = dict(providers.get(provider, {}) or {})
    existing["api_key"] = api_key
    existing["endpoint_key"] = endpoint_key
    existing["model"] = model
    existing["reasoner_model"] = model
    existing["failover_models"] = normalized_failover_models
    if provider_allows_custom_base_url(provider):
        existing["base_url"] = str(request.base_url or "").strip()
    if provider_allows_custom_protocol(provider):
        existing["protocol"] = str(request.protocol or "").strip()
    if discovered_models:
        existing["discovered_models"] = validation_models
    else:
        existing.pop("discovered_models", None)
    provider_config, migration_warnings = normalize_provider_config(provider, existing)
    providers[provider] = provider_config
    ai_config["default_provider"] = next_default_provider
    ai_config["provider_failover_order"] = normalize_provider_failover_order(
        request.provider_failover_order if request.provider_failover_order is not None else ai_config.get("provider_failover_order"),
        next_default_provider,
    )

    config = migrate_ai_config(config)
    _save_yaml_config(CONFIG_PATH, config)
    global mas
    try:
        if mas and hasattr(mas, "aclose"):
            await mas.aclose()
        mas = MultiAgentSystem(CONFIG_PATH)
        engine_status = "reloaded"
    except Exception as error:
        logger.error(f"Failed to reload MultiAgentSystem after API key update: {error}")
        engine_status = f"reload_failed: {error}"
    loaded_result = await _check_loaded_ai_models(config)
    db_set_setting("api_key_last_updated_at", time.time())
    _audit_operation(None, "settings", "success", f"api key updated for provider={provider}, endpoint_key={endpoint_key}")
    runtime = _provider_runtime_config(provider, provider_config)
    return {
        "provider": provider,
        "default_provider": config.get("ai", {}).get("default_provider"),
        "provider_failover_order": list(config.get("ai", {}).get("provider_failover_order") or []),
        "configured_provider_chain": _configured_provider_chain(config),
        "endpoint_key": runtime.get("endpoint_key"),
        "api_key_masked": _mask_secret(api_key) if api_key else "",
        "base_url": runtime.get("base_url"),
        "protocol": runtime.get("protocol"),
        "model": runtime.get("model"),
        "failover_models": runtime.get("failover_models", []),
        "migration_warnings": migration_warnings,
        "engine_status": engine_status,
        "load_test_triggered": True,
        "loaded_models_result": loaded_result,
        "updated_at": time.time(),
    }


@router.put("/webui/settings/access-key")
async def webui_update_access_key(request: AccessKeyUpdateRequest, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    _require_admin_access(x_admin_key)
    db_set_setting("webui_access_key", request.access_key)
    db_set_setting("webui_access_key_updated_at", time.time())
    _audit_operation(None, "settings", "success", "webui access key updated")
    return {"access_key_masked": _mask_secret(request.access_key), "updated_at": time.time()}


@router.get("/webui/settings/access-key")
async def webui_get_access_key_status():
    access_key = _get_admin_access_key()
    updated_at = db_get_setting("webui_access_key_updated_at", None)
    return {"enabled": bool(access_key), "masked": _mask_secret(access_key) if access_key else "", "updated_at": updated_at}


@router.get("/webui/audit-metrics")
async def webui_audit_metrics(
    project_id: Optional[str] = Query(default=None),
    hours: int = Query(default=24, ge=1, le=168),
):
    now = time.time()
    start_ts = now - hours * 3600
    projects = db_list_projects()
    filtered_projects = [item for item in projects if (not project_id or item["id"] == project_id)]
    status_counts: Dict[str, int] = {}
    for project in filtered_projects:
        status = str(project.get("status") or "pending")
        status_counts[status] = status_counts.get(status, 0) + 1

    event_level_counts: Dict[str, int] = {}
    event_total = 0
    for project in filtered_projects:
        events = db_list_project_events(
            project["id"],
            limit=20000,
            offset=0,
            start_ts=start_ts,
            end_ts=now,
        )
        event_total += len(events)
        for event in events:
            level = str(event.get("level") or "INFO")
            event_level_counts[level] = event_level_counts.get(level, 0) + 1

    export_jobs = db_list_export_jobs(limit=100000, offset=0, project_id=project_id)
    cleanup_runs = db_list_export_cleanup_runs(limit=2000, offset=0, project_id=project_id)
    export_audit_rows = db_list_export_job_audit(
        project_id=project_id,
        start_ts=start_ts,
        end_ts=now,
        limit=2000,
        offset=0,
    )
    return {
        "time_window_hours": hours,
        "project_id": project_id,
        "projects_total": len(filtered_projects),
        "project_status_counts": status_counts,
        "events_total": event_total,
        "event_level_counts": event_level_counts,
        "export_jobs_total": len(export_jobs),
        "export_cleanup_runs_total": len(cleanup_runs),
        "export_audit_total": len(export_audit_rows),
        "export_audit_recent": export_audit_rows[:20],
    }


@router.post("/system/exploitdb/sync")
async def manual_exploitdb_sync(
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    """
    Manually trigger Exploit-DB synchronization via Git.
    """
    _require_admin_when_configured(x_admin_key)
    success, message = await _run_exploitdb_sync_process()
    if not success:
        raise HTTPException(status_code=500, detail=f"Sync failed: {message}")
    return {"message": "Exploit-DB sync completed successfully", "details": message}


@router.websocket("/logs")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
