import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

from loguru import logger
from core.project_results import normalize_project_results
from core.utils.security import redact_sensitive_data, redact_sensitive_text

DATABASE_PATH = os.path.abspath("output/projects/projects.db")
LEGACY_PROJECTS_JSON_PATH = os.path.abspath("output/projects/projects.json")
_db_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _safe_json_loads(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _safe_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return float(default)
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return float(default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _safe_optional_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _row_to_project(row: sqlite3.Row) -> Dict[str, Any]:
    results = normalize_project_results(_safe_json_loads(row["results_json"], {}))
    return {
        "id": row["id"],
        "target": row["target"],
        "description": row["description"] or "",
        "status": row["status"],
        "phase": row["phase"],
        "progress": _safe_float(row["progress"]),
        "created_at": _safe_float(row["created_at"]),
        "results": results,
    }


def _row_to_event(row: sqlite3.Row) -> Dict[str, Any]:
    extra = _safe_json_loads(row["extra_json"] if "extra_json" in row.keys() else "{}", {})
    if not isinstance(extra, dict):
        extra = {}
    payload = {
        "id": int(row["id"]),
        "type": row["event_type"],
        "project_id": row["project_id"],
        "phase": row["phase"],
        "status": row["status"],
        "progress": _safe_optional_float(row["progress"]),
        "level": row["level"],
        "timestamp": _safe_optional_float(row["timestamp"]),
        "message": redact_sensitive_text(row["message"] or "", max_length=20000),
        **extra,
    }
    sanitized = redact_sensitive_data(payload, max_depth=5, max_items=80, string_max_length=20000)
    return sanitized if isinstance(sanitized, dict) else payload


def init_storage() -> None:
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    with _db_lock:
        with _connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    progress REAL NOT NULL DEFAULT 0.0,
                    created_at REAL NOT NULL,
                    results_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT,
                    event_type TEXT NOT NULL,
                    phase TEXT,
                    status TEXT,
                    progress REAL,
                    level TEXT,
                    timestamp REAL NOT NULL,
                    message TEXT NOT NULL DEFAULT '',
                    extra_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
                )
                """
            )
            event_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(events)").fetchall()
            }
            if "extra_json" not in event_columns:
                connection.execute("ALTER TABLE events ADD COLUMN extra_json TEXT NOT NULL DEFAULT '{}'")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects(created_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_project_time ON events(project_id, timestamp DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS export_jobs (
                    job_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    format TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    completed_at REAL,
                    download_path TEXT,
                    media_type TEXT,
                    error TEXT,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    max_retries INTEGER NOT NULL DEFAULT 2,
                    filters_json TEXT,
                    created_by TEXT NOT NULL DEFAULT 'system',
                    last_action_by TEXT
                )
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(export_jobs)").fetchall()
            }
            if "retry_count" not in columns:
                connection.execute("ALTER TABLE export_jobs ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0")
            if "max_retries" not in columns:
                connection.execute("ALTER TABLE export_jobs ADD COLUMN max_retries INTEGER NOT NULL DEFAULT 2")
            if "filters_json" not in columns:
                connection.execute("ALTER TABLE export_jobs ADD COLUMN filters_json TEXT")
            if "created_by" not in columns:
                connection.execute("ALTER TABLE export_jobs ADD COLUMN created_by TEXT NOT NULL DEFAULT 'system'")
            if "last_action_by" not in columns:
                connection.execute("ALTER TABLE export_jobs ADD COLUMN last_action_by TEXT")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_export_jobs_project ON export_jobs(project_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_export_jobs_status ON export_jobs(status)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS export_job_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    detail TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_export_audit_job_time ON export_job_audit(job_id, timestamp DESC)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS export_cleanup_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL,
                    project_id TEXT,
                    max_age_hours INTEGER NOT NULL,
                    removed_jobs INTEGER NOT NULL,
                    removed_files INTEGER NOT NULL,
                    timestamp REAL NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_export_cleanup_time ON export_cleanup_runs(timestamp DESC)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS export_download_tokens (
                    token TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_export_download_tokens_expiry ON export_download_tokens(expires_at)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS webui_sessions (
                    session_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    session_type TEXT NOT NULL,
                    shell_id TEXT,
                    name TEXT,
                    cwd TEXT,
                    backend_mode TEXT,
                    health_status TEXT,
                    health_reason TEXT,
                    health_checked_at REAL,
                    created_at REAL NOT NULL,
                    last_active_at REAL,
                    closed_at REAL,
                    close_reason TEXT,
                    last_command TEXT,
                    last_command_at REAL,
                    last_returncode INTEGER,
                    last_duration_seconds REAL,
                    last_stdout_excerpt TEXT,
                    last_stderr_excerpt TEXT,
                    extra_json TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_webui_sessions_project ON webui_sessions(project_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_webui_sessions_status ON webui_sessions(status)"
            )
            connection.commit()
    migrate_legacy_projects_json()


def migrate_legacy_projects_json() -> int:
    if not os.path.exists(LEGACY_PROJECTS_JSON_PATH):
        return 0
    try:
        with open(LEGACY_PROJECTS_JSON_PATH, "r", encoding="utf-8") as file:
            legacy_data = json.load(file)
    except Exception as error:
        logger.warning(f"Failed to load legacy projects JSON for migration: {error}")
        return 0

    if not isinstance(legacy_data, list) or not legacy_data:
        return 0

    inserted = 0
    with _db_lock:
        with _connect() as connection:
            existing_ids = {
                row["id"]
                for row in connection.execute("SELECT id FROM projects").fetchall()
            }
            for item in legacy_data:
                if not isinstance(item, dict):
                    continue
                project_id = str(item.get("id", "")).strip()
                target = str(item.get("target", "")).strip()
                if not project_id or not target or project_id in existing_ids:
                    continue
                payload = {
                    "id": project_id,
                    "target": target,
                    "description": str(item.get("description", "") or ""),
                    "status": str(item.get("status", "pending") or "pending"),
                    "phase": str(item.get("phase", "pending") or "pending"),
                    "progress": _safe_float(item.get("progress", 0.0)),
                    "created_at": _safe_float(item.get("created_at", time.time()), time.time()),
                    "results_json": json.dumps(normalize_project_results(item.get("results", {})), ensure_ascii=False),
                }
                connection.execute(
                    """
                    INSERT INTO projects(id, target, description, status, phase, progress, created_at, results_json)
                    VALUES (:id, :target, :description, :status, :phase, :progress, :created_at, :results_json)
                    """,
                    payload,
                )
                existing_ids.add(project_id)
                inserted += 1
            connection.commit()
    if inserted > 0:
        logger.info(f"Migrated {inserted} legacy projects from projects.json to SQLite.")
    return inserted


def create_project(project: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "id": project["id"],
        "target": project["target"],
        "description": project.get("description", "") or "",
        "status": project.get("status", "pending"),
        "phase": project.get("phase", "pending"),
        "progress": _safe_float(project.get("progress", 0.0)),
        "created_at": _safe_float(project.get("created_at", time.time()), time.time()),
        "results_json": json.dumps(normalize_project_results(project.get("results", {})), ensure_ascii=False),
    }
    with _db_lock:
        with _connect() as connection:
            connection.execute(
                """
                INSERT INTO projects(id, target, description, status, phase, progress, created_at, results_json)
                VALUES (:id, :target, :description, :status, :phase, :progress, :created_at, :results_json)
                """,
                payload,
            )
            connection.commit()
    return get_project(payload["id"])  # type: ignore[return-value]


def list_projects() -> List[Dict[str, Any]]:
    with _db_lock:
        with _connect() as connection:
            rows = connection.execute(
                """
                SELECT id, target, description, status, phase, progress, created_at, results_json
                FROM projects
                ORDER BY created_at DESC
                """
            ).fetchall()
    return [_row_to_project(row) for row in rows]


def get_project(project_id: str) -> Optional[Dict[str, Any]]:
    with _db_lock:
        with _connect() as connection:
            row = connection.execute(
                """
                SELECT id, target, description, status, phase, progress, created_at, results_json
                FROM projects
                WHERE id = ?
                """,
                (project_id,),
            ).fetchone()
    if not row:
        return None
    return _row_to_project(row)


def update_project(project_id: str, **updates: Any) -> Optional[Dict[str, Any]]:
    if not updates:
        return get_project(project_id)

    set_clauses: List[str] = []
    parameters: List[Any] = []

    for key in ["target", "description", "status", "phase", "progress"]:
        if key in updates:
            set_clauses.append(f"{key} = ?")
            parameters.append(updates[key])
    if "results" in updates:
        set_clauses.append("results_json = ?")
        parameters.append(json.dumps(normalize_project_results(updates["results"] or {}), ensure_ascii=False))

    if not set_clauses:
        return get_project(project_id)

    parameters.append(project_id)
    with _db_lock:
        with _connect() as connection:
            connection.execute(
                f"UPDATE projects SET {', '.join(set_clauses)} WHERE id = ?",
                tuple(parameters),
            )
            connection.commit()
    return get_project(project_id)


def delete_project(project_id: str) -> bool:
    with _db_lock:
        with _connect() as connection:
            connection.execute("DELETE FROM events WHERE project_id = ?", (project_id,))
            cursor = connection.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            connection.commit()
            return cursor.rowcount > 0


def insert_event(event: Dict[str, Any]) -> Dict[str, Any]:
    known_keys = {
        "id",
        "type",
        "project_id",
        "phase",
        "status",
        "progress",
        "level",
        "timestamp",
        "message",
    }
    sanitized_event = redact_sensitive_data(event or {}, max_depth=5, max_items=80, string_max_length=20000)
    sanitized_event = sanitized_event if isinstance(sanitized_event, dict) else {"message": redact_sensitive_text(sanitized_event)}
    extra_payload = {
        str(key): value
        for key, value in sanitized_event.items()
        if key not in known_keys
    }
    payload = {
        "project_id": sanitized_event.get("project_id"),
        "event_type": sanitized_event.get("type", "status"),
        "phase": sanitized_event.get("phase"),
        "status": sanitized_event.get("status"),
        "progress": _safe_optional_float(sanitized_event.get("progress")),
        "level": sanitized_event.get("level"),
        "timestamp": _safe_float(sanitized_event.get("timestamp", time.time()), time.time()),
        "message": redact_sensitive_text(sanitized_event.get("message", ""), max_length=20000),
        "extra_json": json.dumps(extra_payload, ensure_ascii=False),
    }

    with _db_lock:
        with _connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO events(project_id, event_type, phase, status, progress, level, timestamp, message, extra_json)
                VALUES (:project_id, :event_type, :phase, :status, :progress, :level, :timestamp, :message, :extra_json)
                """,
                payload,
            )
            connection.commit()
            event_id = cursor.lastrowid

            row = connection.execute(
                """
                SELECT id, project_id, event_type, phase, status, progress, level, timestamp, message, extra_json
                FROM events
                WHERE id = ?
                """,
                (event_id,),
            ).fetchone()

    if not row:
        logger.warning("Failed to fetch event row after insert.")
        return {"id": -1, **payload, "type": payload["event_type"]}
    return _row_to_event(row)


def list_project_events(
    project_id: str,
    limit: int = 500,
    offset: int = 0,
    event_type: Optional[str] = None,
    level: Optional[str] = None,
    phase: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    keyword: Optional[str] = None,
) -> List[Dict[str, Any]]:
    if limit <= 0 or offset < 0:
        return []
    conditions: List[str] = ["project_id = ?"]
    parameters: List[Any] = [project_id]
    if event_type:
        conditions.append("event_type = ?")
        parameters.append(event_type)
    if level:
        conditions.append("level = ?")
        parameters.append(level)
    if phase:
        conditions.append("phase = ?")
        parameters.append(phase)
    if start_ts is not None:
        conditions.append("timestamp >= ?")
        parameters.append(float(start_ts))
    if end_ts is not None:
        conditions.append("timestamp <= ?")
        parameters.append(float(end_ts))
    if keyword:
        conditions.append("message LIKE ?")
        parameters.append(f"%{keyword.strip()}%")
    parameters.append(int(limit))
    parameters.append(int(offset))
    with _db_lock:
        with _connect() as connection:
            rows = connection.execute(
                """
                SELECT id, project_id, event_type, phase, status, progress, level, timestamp, message, extra_json
                FROM events
                WHERE """ + " AND ".join(conditions) + """
                ORDER BY id ASC
                LIMIT ?
                OFFSET ?
                """,
                tuple(parameters),
            ).fetchall()
    return [_row_to_event(row) for row in rows]


def count_project_events(
    project_id: str,
    event_type: Optional[str] = None,
    level: Optional[str] = None,
    phase: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    keyword: Optional[str] = None,
) -> int:
    conditions: List[str] = ["project_id = ?"]
    parameters: List[Any] = [project_id]
    if event_type:
        conditions.append("event_type = ?")
        parameters.append(event_type)
    if level:
        conditions.append("level = ?")
        parameters.append(level)
    if phase:
        conditions.append("phase = ?")
        parameters.append(phase)
    if start_ts is not None:
        conditions.append("timestamp >= ?")
        parameters.append(float(start_ts))
    if end_ts is not None:
        conditions.append("timestamp <= ?")
        parameters.append(float(end_ts))
    if keyword:
        conditions.append("message LIKE ?")
        parameters.append(f"%{keyword.strip()}%")
    with _db_lock:
        with _connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(1) AS total
                FROM events
                WHERE """ + " AND ".join(conditions),
                tuple(parameters),
            ).fetchone()
    return int(row["total"]) if row else 0


def create_export_job(job: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "job_id": job["job_id"],
        "project_id": job["project_id"],
        "status": job["status"],
        "format": job["format"],
        "created_at": float(job.get("created_at", time.time())),
        "completed_at": job.get("completed_at"),
        "download_path": job.get("download_path"),
        "media_type": job.get("media_type"),
        "error": job.get("error"),
        "retry_count": int(job.get("retry_count", 0)),
        "max_retries": int(job.get("max_retries", 2)),
        "filters_json": json.dumps(job.get("filters", {}), ensure_ascii=False),
        "created_by": str(job.get("created_by", "system") or "system"),
        "last_action_by": job.get("last_action_by"),
    }
    with _db_lock:
        with _connect() as connection:
            connection.execute(
                """
                INSERT INTO export_jobs(job_id, project_id, status, format, created_at, completed_at, download_path, media_type, error, retry_count, max_retries, filters_json, created_by, last_action_by)
                VALUES (:job_id, :project_id, :status, :format, :created_at, :completed_at, :download_path, :media_type, :error, :retry_count, :max_retries, :filters_json, :created_by, :last_action_by)
                """,
                payload,
            )
            connection.commit()
    return get_export_job(payload["job_id"])  # type: ignore[return-value]


def update_export_job(job_id: str, **updates: Any) -> Optional[Dict[str, Any]]:
    if not updates:
        return get_export_job(job_id)
    set_clauses: List[str] = []
    parameters: List[Any] = []
    for key in ["status", "format", "created_at", "completed_at", "download_path", "media_type", "error", "retry_count", "max_retries", "created_by", "last_action_by"]:
        if key in updates:
            set_clauses.append(f"{key} = ?")
            parameters.append(updates[key])
    if "filters" in updates:
        set_clauses.append("filters_json = ?")
        parameters.append(json.dumps(updates["filters"], ensure_ascii=False))
    if not set_clauses:
        return get_export_job(job_id)
    parameters.append(job_id)
    with _db_lock:
        with _connect() as connection:
            connection.execute(
                f"UPDATE export_jobs SET {', '.join(set_clauses)} WHERE job_id = ?",
                tuple(parameters),
            )
            connection.commit()
    return get_export_job(job_id)


def get_export_job(job_id: str) -> Optional[Dict[str, Any]]:
    with _db_lock:
        with _connect() as connection:
            row = connection.execute(
                """
                SELECT job_id, project_id, status, format, created_at, completed_at, download_path, media_type, error, retry_count, max_retries, filters_json, created_by, last_action_by
                FROM export_jobs
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
    if not row:
        return None
    return {
        "job_id": row["job_id"],
        "project_id": row["project_id"],
        "status": row["status"],
        "format": row["format"],
        "created_at": float(row["created_at"]),
        "completed_at": float(row["completed_at"]) if row["completed_at"] is not None else None,
        "download_path": row["download_path"],
        "media_type": row["media_type"],
        "error": row["error"],
        "retry_count": int(row["retry_count"] or 0),
        "max_retries": int(row["max_retries"] or 0),
        "filters": _safe_json_loads(row["filters_json"], {}),
        "created_by": row["created_by"] or "system",
        "last_action_by": row["last_action_by"],
    }


def list_export_jobs(limit: int = 50, offset: int = 0, project_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    conditions: List[str] = []
    parameters: List[Any] = []
    if project_id:
        conditions.append("project_id = ?")
        parameters.append(project_id)
    if status:
        conditions.append("status = ?")
        parameters.append(status)
    parameters.extend([int(limit), int(offset)])
    with _db_lock:
        with _connect() as connection:
            rows = connection.execute(
                """
                SELECT job_id, project_id, status, format, created_at, completed_at, download_path, media_type, error, retry_count, max_retries, filters_json, created_by, last_action_by
                FROM export_jobs
                """ + (("WHERE " + " AND ".join(conditions)) if conditions else "") + """
                ORDER BY created_at DESC
                LIMIT ?
                OFFSET ?
                """,
                tuple(parameters),
            ).fetchall()
    result: List[Dict[str, Any]] = []
    for row in rows:
        result.append({
            "job_id": row["job_id"],
            "project_id": row["project_id"],
            "status": row["status"],
            "format": row["format"],
            "created_at": float(row["created_at"]),
            "completed_at": float(row["completed_at"]) if row["completed_at"] is not None else None,
            "download_path": row["download_path"],
            "media_type": row["media_type"],
            "error": row["error"],
            "retry_count": int(row["retry_count"] or 0),
            "max_retries": int(row["max_retries"] or 0),
            "filters": _safe_json_loads(row["filters_json"], {}),
            "created_by": row["created_by"] or "system",
            "last_action_by": row["last_action_by"],
        })
    return result


def delete_export_job(job_id: str) -> bool:
    with _db_lock:
        with _connect() as connection:
            cursor = connection.execute("DELETE FROM export_jobs WHERE job_id = ?", (job_id,))
            connection.commit()
            return cursor.rowcount > 0


def cleanup_completed_export_jobs(before_ts: float, project_id: Optional[str] = None) -> int:
    conditions: List[str] = ["status = ?", "completed_at IS NOT NULL", "completed_at <= ?"]
    parameters: List[Any] = ["completed", float(before_ts)]
    if project_id:
        conditions.append("project_id = ?")
        parameters.append(project_id)
    with _db_lock:
        with _connect() as connection:
            cursor = connection.execute(
                "DELETE FROM export_jobs WHERE " + " AND ".join(conditions),
                tuple(parameters),
            )
            connection.commit()
            return int(cursor.rowcount or 0)


def get_setting(key: str, default: Any) -> Any:
    with _db_lock:
        with _connect() as connection:
            row = connection.execute(
                "SELECT value_json FROM system_settings WHERE key = ?",
                (key,),
            ).fetchone()
    if not row:
        return default
    return _safe_json_loads(row["value_json"], default)


def set_setting(key: str, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False)
    with _db_lock:
        with _connect() as connection:
            connection.execute(
                """
                INSERT INTO system_settings(key, value_json)
                VALUES(?, ?)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json
                """,
                (key, payload),
            )
            connection.commit()


def insert_export_job_audit(job_id: str, project_id: str, action: str, actor: str, detail: Optional[str] = None, timestamp: Optional[float] = None) -> Dict[str, Any]:
    payload = {
        "job_id": job_id,
        "project_id": project_id,
        "action": action,
        "actor": actor,
        "timestamp": float(timestamp or time.time()),
        "detail": detail,
    }
    with _db_lock:
        with _connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO export_job_audit(job_id, project_id, action, actor, timestamp, detail)
                VALUES(:job_id, :project_id, :action, :actor, :timestamp, :detail)
                """,
                payload,
            )
            connection.commit()
            row = connection.execute(
                "SELECT id, job_id, project_id, action, actor, timestamp, detail FROM export_job_audit WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
    return {
        "id": int(row["id"]),
        "job_id": row["job_id"],
        "project_id": row["project_id"],
        "action": row["action"],
        "actor": row["actor"],
        "timestamp": float(row["timestamp"]),
        "detail": row["detail"],
    }


def list_export_job_audit(
    job_id: Optional[str] = None,
    project_id: Optional[str] = None,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    q: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    conditions: List[str] = []
    parameters: List[Any] = []
    if job_id:
        conditions.append("job_id = ?")
        parameters.append(job_id)
    if project_id:
        conditions.append("project_id = ?")
        parameters.append(project_id)
    if actor:
        conditions.append("actor = ?")
        parameters.append(actor)
    if action:
        conditions.append("action = ?")
        parameters.append(action)
    if start_ts is not None:
        conditions.append("timestamp >= ?")
        parameters.append(float(start_ts))
    if end_ts is not None:
        conditions.append("timestamp <= ?")
        parameters.append(float(end_ts))
    if q:
        conditions.append("detail LIKE ?")
        parameters.append(f"%{q.strip()}%")
    parameters.extend([int(limit), int(offset)])
    with _db_lock:
        with _connect() as connection:
            rows = connection.execute(
                """
                SELECT id, job_id, project_id, action, actor, timestamp, detail
                FROM export_job_audit
                """ + (("WHERE " + " AND ".join(conditions)) if conditions else "") + """
                ORDER BY id DESC
                LIMIT ?
                OFFSET ?
                """,
                tuple(parameters),
            ).fetchall()
    result: List[Dict[str, Any]] = []
    for row in rows:
        result.append(
            {
                "id": int(row["id"]),
                "job_id": row["job_id"],
                "project_id": row["project_id"],
                "action": row["action"],
                "actor": row["actor"],
                "timestamp": float(row["timestamp"]),
                "detail": row["detail"],
            }
        )
    return result


def insert_export_cleanup_run(actor: str, project_id: Optional[str], max_age_hours: int, removed_jobs: int, removed_files: int, timestamp: Optional[float] = None) -> Dict[str, Any]:
    payload = {
        "actor": actor,
        "project_id": project_id,
        "max_age_hours": int(max_age_hours),
        "removed_jobs": int(removed_jobs),
        "removed_files": int(removed_files),
        "timestamp": float(timestamp or time.time()),
    }
    with _db_lock:
        with _connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO export_cleanup_runs(actor, project_id, max_age_hours, removed_jobs, removed_files, timestamp)
                VALUES(:actor, :project_id, :max_age_hours, :removed_jobs, :removed_files, :timestamp)
                """,
                payload,
            )
            connection.commit()
            row = connection.execute(
                """
                SELECT id, actor, project_id, max_age_hours, removed_jobs, removed_files, timestamp
                FROM export_cleanup_runs
                WHERE id = ?
                """,
                (cursor.lastrowid,),
            ).fetchone()
    return {
        "id": int(row["id"]),
        "actor": row["actor"],
        "project_id": row["project_id"],
        "max_age_hours": int(row["max_age_hours"]),
        "removed_jobs": int(row["removed_jobs"]),
        "removed_files": int(row["removed_files"]),
        "timestamp": float(row["timestamp"]),
    }


def list_export_cleanup_runs(limit: int = 100, offset: int = 0, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conditions: List[str] = []
    parameters: List[Any] = []
    if project_id:
        conditions.append("project_id = ?")
        parameters.append(project_id)
    parameters.extend([int(limit), int(offset)])
    with _db_lock:
        with _connect() as connection:
            rows = connection.execute(
                """
                SELECT id, actor, project_id, max_age_hours, removed_jobs, removed_files, timestamp
                FROM export_cleanup_runs
                """ + (("WHERE " + " AND ".join(conditions)) if conditions else "") + """
                ORDER BY id DESC
                LIMIT ?
                OFFSET ?
                """,
                tuple(parameters),
            ).fetchall()
    result: List[Dict[str, Any]] = []
    for row in rows:
        result.append(
            {
                "id": int(row["id"]),
                "actor": row["actor"],
                "project_id": row["project_id"],
                "max_age_hours": int(row["max_age_hours"]),
                "removed_jobs": int(row["removed_jobs"]),
                "removed_files": int(row["removed_files"]),
                "timestamp": float(row["timestamp"]),
            }
        )
    return result


def create_export_download_token(token: str, job_id: str, project_id: str, actor: str, expires_at: float) -> None:
    payload = {
        "token": token,
        "job_id": job_id,
        "project_id": project_id,
        "actor": actor,
        "expires_at": float(expires_at),
        "consumed_at": None,
    }
    with _db_lock:
        with _connect() as connection:
            connection.execute(
                """
                INSERT INTO export_download_tokens(token, job_id, project_id, actor, expires_at, consumed_at)
                VALUES(:token, :job_id, :project_id, :actor, :expires_at, :consumed_at)
                """,
                payload,
            )
            connection.commit()


def consume_export_download_token(token: str) -> Optional[Dict[str, Any]]:
    now = time.time()
    with _db_lock:
        with _connect() as connection:
            row = connection.execute(
                """
                SELECT token, job_id, project_id, actor, expires_at, consumed_at
                FROM export_download_tokens
                WHERE token = ?
                """,
                (token,),
            ).fetchone()
            if not row:
                return None
            if row["consumed_at"] is not None:
                return None
            if float(row["expires_at"]) < now:
                return None
            connection.execute(
                "UPDATE export_download_tokens SET consumed_at = ? WHERE token = ? AND consumed_at IS NULL",
                (now, token),
            )
            connection.commit()
            updated = connection.execute(
                """
                SELECT token, job_id, project_id, actor, expires_at, consumed_at
                FROM export_download_tokens
                WHERE token = ?
                """,
                (token,),
            ).fetchone()
    if not updated or updated["consumed_at"] is None:
        return None
    return {
        "token": updated["token"],
        "job_id": updated["job_id"],
        "project_id": updated["project_id"],
        "actor": updated["actor"],
        "expires_at": float(updated["expires_at"]),
        "consumed_at": float(updated["consumed_at"]),
    }


def cleanup_expired_download_tokens(before_ts: Optional[float] = None) -> int:
    threshold = float(before_ts if before_ts is not None else time.time())
    with _db_lock:
        with _connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM export_download_tokens
                WHERE expires_at <= ? OR (consumed_at IS NOT NULL AND consumed_at <= ?)
                """,
                (threshold, threshold),
            )
            connection.commit()
            return int(cursor.rowcount or 0)


def _row_to_webui_session(row: sqlite3.Row) -> Dict[str, Any]:
    payload = {
        "session_id": row["session_id"],
        "project_id": row["project_id"],
        "status": row["status"],
        "type": row["session_type"],
        "shell_id": row["shell_id"],
        "name": row["name"],
        "cwd": row["cwd"],
        "backend_mode": row["backend_mode"],
        "health_status": row["health_status"],
        "health_reason": row["health_reason"],
        "health_checked_at": _safe_optional_float(row["health_checked_at"]),
        "created_at": _safe_float(row["created_at"]),
        "last_active_at": _safe_optional_float(row["last_active_at"]),
        "closed_at": _safe_optional_float(row["closed_at"]),
        "close_reason": redact_sensitive_text(row["close_reason"] or "", max_length=500),
        "last_command": redact_sensitive_text(row["last_command"] or "", max_length=2000),
        "last_command_at": _safe_optional_float(row["last_command_at"]),
        "last_returncode": _safe_optional_int(row["last_returncode"]),
        "last_duration_seconds": _safe_optional_float(row["last_duration_seconds"]),
        "last_stdout_excerpt": redact_sensitive_text(row["last_stdout_excerpt"] or "", max_length=1200),
        "last_stderr_excerpt": redact_sensitive_text(row["last_stderr_excerpt"] or "", max_length=1200),
        **_safe_json_loads(row["extra_json"], {}),
    }
    sanitized = redact_sensitive_data(payload, max_depth=5, max_items=80, string_max_length=5000)
    return sanitized if isinstance(sanitized, dict) else payload


def upsert_webui_session(session: Dict[str, Any]) -> Dict[str, Any]:
    sanitized_session = redact_sensitive_data(session or {}, max_depth=5, max_items=80, string_max_length=5000)
    sanitized_session = sanitized_session if isinstance(sanitized_session, dict) else {}
    payload = {
        "session_id": sanitized_session["session_id"],
        "project_id": sanitized_session["project_id"],
        "status": sanitized_session.get("status", "active"),
        "session_type": sanitized_session.get("type", "workspace"),
        "shell_id": sanitized_session.get("shell_id"),
        "name": sanitized_session.get("name"),
        "cwd": sanitized_session.get("cwd"),
        "backend_mode": sanitized_session.get("backend_mode"),
        "health_status": sanitized_session.get("health_status"),
        "health_reason": sanitized_session.get("health_reason"),
        "health_checked_at": _safe_optional_float(sanitized_session.get("health_checked_at")),
        "created_at": _safe_float(sanitized_session.get("created_at", time.time()), time.time()),
        "last_active_at": _safe_optional_float(sanitized_session.get("last_active_at")),
        "closed_at": _safe_optional_float(sanitized_session.get("closed_at")),
        "close_reason": sanitized_session.get("close_reason"),
        "last_command": sanitized_session.get("last_command"),
        "last_command_at": _safe_optional_float(sanitized_session.get("last_command_at")),
        "last_returncode": _safe_optional_int(sanitized_session.get("last_returncode")),
        "last_duration_seconds": _safe_optional_float(sanitized_session.get("last_duration_seconds")),
        "last_stdout_excerpt": sanitized_session.get("last_stdout_excerpt"),
        "last_stderr_excerpt": sanitized_session.get("last_stderr_excerpt"),
        "extra_json": json.dumps(
            {
                "source": sanitized_session.get("source"),
                "msf_meta": sanitized_session.get("msf_meta"),
                "workspace_root": sanitized_session.get("workspace_root"),
                "source_shell": sanitized_session.get("source_shell"),
                "command_history": sanitized_session.get("command_history", []),
                "file_history": sanitized_session.get("file_history", []),
            },
            ensure_ascii=False,
        ),
    }
    with _db_lock:
        with _connect() as connection:
            connection.execute(
                """
                INSERT INTO webui_sessions(
                    session_id, project_id, status, session_type, shell_id, name, cwd, backend_mode,
                    health_status, health_reason, health_checked_at, created_at, last_active_at, closed_at,
                    close_reason, last_command, last_command_at, last_returncode, last_duration_seconds,
                    last_stdout_excerpt, last_stderr_excerpt, extra_json
                )
                VALUES(
                    :session_id, :project_id, :status, :session_type, :shell_id, :name, :cwd, :backend_mode,
                    :health_status, :health_reason, :health_checked_at, :created_at, :last_active_at, :closed_at,
                    :close_reason, :last_command, :last_command_at, :last_returncode, :last_duration_seconds,
                    :last_stdout_excerpt, :last_stderr_excerpt, :extra_json
                )
                ON CONFLICT(session_id) DO UPDATE SET
                    project_id=excluded.project_id,
                    status=excluded.status,
                    session_type=excluded.session_type,
                    shell_id=excluded.shell_id,
                    name=excluded.name,
                    cwd=excluded.cwd,
                    backend_mode=excluded.backend_mode,
                    health_status=excluded.health_status,
                    health_reason=excluded.health_reason,
                    health_checked_at=excluded.health_checked_at,
                    created_at=excluded.created_at,
                    last_active_at=excluded.last_active_at,
                    closed_at=excluded.closed_at,
                    close_reason=excluded.close_reason,
                    last_command=excluded.last_command,
                    last_command_at=excluded.last_command_at,
                    last_returncode=excluded.last_returncode,
                    last_duration_seconds=excluded.last_duration_seconds,
                    last_stdout_excerpt=excluded.last_stdout_excerpt,
                    last_stderr_excerpt=excluded.last_stderr_excerpt,
                    extra_json=excluded.extra_json
                """,
                payload,
            )
            connection.commit()
            row = connection.execute(
                "SELECT * FROM webui_sessions WHERE session_id = ?",
                (payload["session_id"],),
            ).fetchone()
    return _row_to_webui_session(row) if row else session


def list_webui_sessions(project_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    conditions: List[str] = []
    parameters: List[Any] = []
    if project_id:
        conditions.append("project_id = ?")
        parameters.append(project_id)
    if status:
        conditions.append("status = ?")
        parameters.append(status)
    with _db_lock:
        with _connect() as connection:
            rows = connection.execute(
                "SELECT * FROM webui_sessions "
                + (("WHERE " + " AND ".join(conditions)) if conditions else "")
                + " ORDER BY created_at ASC",
                tuple(parameters),
            ).fetchall()
    return [_row_to_webui_session(row) for row in rows]


def get_webui_session(session_id: str) -> Optional[Dict[str, Any]]:
    with _db_lock:
        with _connect() as connection:
            row = connection.execute(
                "SELECT * FROM webui_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
    return _row_to_webui_session(row) if row else None


def close_webui_session(session_id: str, reason: Optional[str] = None) -> Optional[Dict[str, Any]]:
    now = time.time()
    with _db_lock:
        with _connect() as connection:
            connection.execute(
                """
                UPDATE webui_sessions
                SET status = 'closed', closed_at = ?, close_reason = COALESCE(?, close_reason), last_active_at = ?
                WHERE session_id = ?
                """,
                (now, reason, now, session_id),
            )
            connection.commit()
            row = connection.execute("SELECT * FROM webui_sessions WHERE session_id = ?", (session_id,)).fetchone()
    return _row_to_webui_session(row) if row else None


def delete_webui_sessions_by_project(project_id: str) -> int:
    with _db_lock:
        with _connect() as connection:
            cursor = connection.execute("DELETE FROM webui_sessions WHERE project_id = ?", (project_id,))
            connection.commit()
            return int(cursor.rowcount or 0)

