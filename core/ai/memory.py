import datetime
import json
import os
import shutil
from typing import Any, Dict, List, Optional
from loguru import logger


class MemoryManager:
    def __init__(self, base_dir: str = "output/memory"):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)
        logger.info(f"MemoryManager 初始化完成，目录: {self.base_dir}")

    def _project_dir(self, project_id: str) -> str:
        pid = (project_id or "global").strip() or "global"
        path = os.path.join(self.base_dir, pid)
        os.makedirs(path, exist_ok=True)
        return path

    def _long_term_path(self, project_id: str) -> str:
        return os.path.join(self._project_dir(project_id), "long_term.json")

    def _short_term_path(self, project_id: str, agent_id: str) -> str:
        safe_agent_id = (agent_id or "default_agent").strip().replace("/", "_").replace("\\", "_")
        agents_dir = os.path.join(self._project_dir(project_id), "agents")
        os.makedirs(agents_dir, exist_ok=True)
        return os.path.join(agents_dir, f"{safe_agent_id}.json")

    def _agents_dir(self, project_id: str) -> str:
        path = os.path.join(self._project_dir(project_id), "agents")
        os.makedirs(path, exist_ok=True)
        return path

    def _load_memory(self, path: str) -> List[Dict[str, Any]]:
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as file:
                data = json.load(file)
            return data if isinstance(data, list) else []
        except Exception as error:
            logger.warning(f"加载记忆文件失败 {path}: {error}")
            return []

    def _save_memory(self, path: str, memory: List[Dict[str, Any]]) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as file:
            json.dump(memory, file, ensure_ascii=False, indent=2)

    def add_memory(
        self,
        content: str,
        role: str = "user",
        memory_type: str = "short_term",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        metadata = metadata or {}
        project_id = str(metadata.get("project_id") or "global")
        agent_id = str(metadata.get("agent_id") or metadata.get("agent") or "default_agent")
        entry = {
            "role": role,
            "content": content,
            "metadata": metadata,
            "timestamp": datetime.datetime.now().isoformat(),
        }
        if memory_type == "long_term":
            path = self._long_term_path(project_id)
        else:
            path = self._short_term_path(project_id, agent_id)
        memory = self._load_memory(path)
        memory.append(entry)
        self._save_memory(path, memory)

    def get_memory(
        self,
        memory_type: str = "short_term",
        limit: int = 10,
        project_id: str = "global",
        agent_id: str = "default_agent",
    ) -> List[Dict[str, Any]]:
        path = self._long_term_path(project_id) if memory_type == "long_term" else self._short_term_path(project_id, agent_id)
        memory = self._load_memory(path)
        return memory[-limit:] if limit > 0 else memory

    def clear_memory(
        self,
        memory_type: str = "short_term",
        project_id: str = "global",
        agent_id: str = "default_agent",
    ) -> None:
        path = self._long_term_path(project_id) if memory_type == "long_term" else self._short_term_path(project_id, agent_id)
        self._save_memory(path, [])

    def get_recent_short_term_across_agents(
        self,
        project_id: str = "global",
        exclude_agent_id: Optional[str] = None,
        limit_per_agent: int = 2,
        limit_total: int = 12,
    ) -> List[Dict[str, Any]]:
        agents_dir = self._agents_dir(project_id)
        if not os.path.isdir(agents_dir):
            return []
        excluded = str(exclude_agent_id or "").strip().replace("/", "_").replace("\\", "_")
        merged: List[Dict[str, Any]] = []
        for file_name in sorted(os.listdir(agents_dir)):
            if not file_name.lower().endswith(".json"):
                continue
            agent_id = file_name[:-5]
            if excluded and agent_id == excluded:
                continue
            path = os.path.join(agents_dir, file_name)
            items = self._load_memory(path)
            for entry in items[-max(1, int(limit_per_agent)):]:
                payload = dict(entry)
                metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
                payload["metadata"] = {**metadata, "agent_id": metadata.get("agent_id") or agent_id}
                merged.append(payload)
        merged.sort(key=lambda item: str(item.get("timestamp") or ""))
        if limit_total > 0:
            return merged[-limit_total:]
        return merged

    def cleanup_project(self, project_id: str) -> bool:
        path = os.path.join(self.base_dir, str(project_id))
        if not os.path.exists(path):
            return False
        shutil.rmtree(path, ignore_errors=True)
        return True
