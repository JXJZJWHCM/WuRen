import importlib.util
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Dict, Any

import yaml
from loguru import logger

from core.modules.cli_manager import CLIManager
from core.modules.tool_matrix import (
    DEFAULT_TOOL_MATRIX_PATH,
    PROJECT_ROOT,
    get_current_platform_key,
    get_tool_definition,
    normalize_tool_name,
    resolve_tool_name,
)


class ToolRuntimeError(RuntimeError):
    def __init__(
        self,
        *,
        requested_tool: str,
        status: str,
        message: str,
        standard_name: Optional[str] = None,
        display_name: Optional[str] = None,
        platform: Optional[str] = None,
        support_state: Optional[str] = None,
        install_mode: Optional[str] = None,
    ):
        super().__init__(message)
        self.requested_tool = requested_tool
        self.status = status
        self.message = message
        self.standard_name = standard_name
        self.display_name = display_name
        self.platform = platform
        self.support_state = support_state
        self.install_mode = install_mode

    def to_result(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "status": self.status,
            "message": self.message,
            "requested_tool": self.requested_tool,
            "standard_name": self.standard_name,
            "display_name": self.display_name,
            "platform": self.platform,
            "support_state": self.support_state,
            "install_mode": self.install_mode,
        }
        return {key: value for key, value in result.items() if value is not None}

class ToolManager:
    """
    Cross-platform manager for executing penetration testing tools.
    Replaces the old KaliToolWrapper.
    Uses system-level CLI tools and project-declared scripts/modules.
    """

    def __init__(
        self,
        config_path: str = "config/config.yaml",
        tool_matrix_path: str = str(DEFAULT_TOOL_MATRIX_PATH),
    ):
        """
        Initialize the ToolManager.

        Args:
            config_path (str): Path to configuration file.
        """
        self.project_root = PROJECT_ROOT
        self.tool_matrix_path = Path(tool_matrix_path).resolve()
        self.platform_key = get_current_platform_key()

        self.cli_manager = CLIManager()
        self.default_nuclei_templates = self._resolve_default_nuclei_templates(config_path)

    @staticmethod
    def _resolve_default_nuclei_templates(config_path: str) -> str:
        default_root = "vuldb"
        try:
            if os.path.isfile(config_path):
                with open(config_path, "r", encoding="utf-8") as fp:
                    cfg = yaml.safe_load(fp) or {}
                path_cfg = cfg.get("paths") or {}
                configured = str(path_cfg.get("vuldb") or "").strip()
                if configured:
                    default_root = configured
        except Exception as error:
            logger.warning(f"Failed to load config path for vuldb, fallback to {default_root}: {error}")
        resolved = os.path.abspath(default_root)
        os.makedirs(resolved, exist_ok=True)
        return resolved

    @staticmethod
    def _format_command(parts: list[str]) -> str:
        cleaned_parts = [str(item) for item in parts if str(item or "").strip()]
        if os.name == "nt":
            return subprocess.list2cmdline(cleaned_parts)
        return shlex.join(cleaned_parts)

    def _resolve_nuclei_template_arg(self, template_path: Optional[str]) -> Optional[str]:
        def resolve_single(item: str) -> str:
            raw = str(item or "").strip()
            if not raw:
                return ""
            if raw.startswith(("http://", "https://")):
                return raw
            if os.path.isabs(raw):
                return raw
            if self.default_nuclei_templates:
                candidate = os.path.abspath(os.path.join(self.default_nuclei_templates, raw))
                if os.path.exists(candidate) or not os.path.exists(raw):
                    return candidate
            return os.path.abspath(raw)

        if template_path and str(template_path).strip():
            items = [resolve_single(part) for part in str(template_path).split(",") if str(part).strip()]
            return ",".join(item for item in items if item)

        return self.default_nuclei_templates or None

    def _tool_error(
        self,
        *,
        requested_tool: str,
        status: str,
        message: str,
        definition: Optional[Dict[str, Any]] = None,
        standard_name: Optional[str] = None,
        support_state: Optional[str] = None,
    ) -> ToolRuntimeError:
        tool_definition = definition or {}
        install_meta = tool_definition.get("install") if isinstance(tool_definition, dict) else {}
        install_mode = install_meta.get("mode") if isinstance(install_meta, dict) else None
        return ToolRuntimeError(
            requested_tool=requested_tool,
            status=status,
            message=message,
            standard_name=standard_name,
            display_name=tool_definition.get("display_name") if isinstance(tool_definition, dict) else None,
            platform=self.platform_key,
            support_state=support_state,
            install_mode=install_mode,
        )

    def _resolve_declared_tool(self, tool_name: str) -> tuple[str, Dict[str, Any]]:
        requested_tool = normalize_tool_name(tool_name)
        if not requested_tool:
            raise self._tool_error(
                requested_tool=requested_tool,
                status="undeclared",
                message="工具名不能为空",
            )

        try:
            standard_name = resolve_tool_name(requested_tool, self.tool_matrix_path)
            definition = get_tool_definition(standard_name, self.tool_matrix_path)
        except KeyError as error:
            raise self._tool_error(
                requested_tool=requested_tool,
                status="undeclared",
                message=f"工具 {requested_tool} 未在 config/tool_matrix.yaml 中声明，已拒绝执行",
            ) from error
        return standard_name, definition

    def _ensure_platform_supported(self, requested_tool: str, standard_name: str, definition: Dict[str, Any]) -> None:
        platforms = definition.get("support", {}).get("platforms", {})
        support_state = str(platforms.get(self.platform_key, "unsupported") or "unsupported")
        if support_state == "supported":
            return
        raise self._tool_error(
            requested_tool=requested_tool,
            status="platform_limited",
            message=f"工具 {standard_name} 当前平台不可直接执行，平台状态为 {support_state}",
            definition=definition,
            standard_name=standard_name,
            support_state=support_state,
        )

    def _resolve_project_path(self, raw_path: str) -> Path:
        candidate = Path(str(raw_path))
        if candidate.is_absolute():
            return candidate
        return self.project_root / candidate

    @staticmethod
    def _candidate_extensions(entry_type: str) -> list[str]:
        if entry_type in {"native_binary", "binary", "binary_bundle", "system_binary", "launcher_script"}:
            return [".exe", ".bat", ".cmd", ".ps1", ""]
        return [""]

    def _resolve_entry_command(
        self,
        requested_tool: str,
        standard_name: str,
        definition: Dict[str, Any],
    ) -> tuple[str, Optional[str], Optional[str]]:
        execution = definition.get("execution", {})
        entry_type = str(execution.get("entry_type") or "").strip()
        entrypoint = str(execution.get("entrypoint") or "").strip()
        path_hint = str(execution.get("path_hint") or "").strip()
        requested_name = normalize_tool_name(requested_tool)
        lookup_names = [requested_name, standard_name, Path(entrypoint).stem, Path(entrypoint).name]

        if entry_type == "python_module":
            module_root = None
            if path_hint and "/" in path_hint:
                candidate_root = self._resolve_project_path(path_hint)
                if candidate_root.exists():
                    module_root = str(candidate_root)
            if module_root is None and importlib.util.find_spec(entrypoint) is None:
                raise self._tool_error(
                    requested_tool=requested_name,
                    status="failed" if definition.get("install", {}).get("automated", True) else "manual",
                    message=f"工具 {standard_name} 已声明但未检测到可执行 Python 模块 {entrypoint}",
                    definition=definition,
                    standard_name=standard_name,
                )
            return self._format_command([sys.executable, "-m", entrypoint]), module_root, None

        if entry_type == "python_script":
            candidate_path = self._resolve_project_path(entrypoint)
            if candidate_path.is_file():
                return self._format_command([sys.executable, str(candidate_path)]), str(candidate_path.parent), str(candidate_path)

        if entry_type == "java_archive":
            candidate_path = self._resolve_project_path(entrypoint)
            if candidate_path.is_file():
                return self._format_command(["java", "-jar", str(candidate_path)]), str(candidate_path.parent), str(candidate_path)

        if entry_type == "shell_script":
            candidate_path = self._resolve_project_path(entrypoint)
            if candidate_path.is_file():
                return self._format_command(["bash", str(candidate_path)]), str(candidate_path.parent), str(candidate_path)

        if "/" in entrypoint or "\\" in entrypoint:
            candidate_path = self._resolve_project_path(entrypoint)
            if candidate_path.is_file():
                if entry_type == "launcher_script":
                    return self._format_command([str(candidate_path)]), str(candidate_path.parent), str(candidate_path)
                return self._format_command([str(candidate_path)]), str(candidate_path.parent), str(candidate_path)

        if path_hint == "system_path" or entry_type == "system_binary":
            resolved_binary = shutil.which(entrypoint)
            if resolved_binary:
                return self._format_command([resolved_binary]), None, resolved_binary
        if entrypoint:
            resolved_binary = shutil.which(entrypoint)
            if resolved_binary:
                return self._format_command([resolved_binary]), None, resolved_binary
        for candidate_name in lookup_names:
            if not candidate_name:
                continue
            resolved_binary = shutil.which(candidate_name)
            if resolved_binary:
                return self._format_command([resolved_binary]), None, resolved_binary

        if path_hint and "/" in path_hint:
            base_path = self._resolve_project_path(path_hint)
            if base_path.is_file():
                return self._format_command([str(base_path)]), str(base_path.parent), str(base_path)
            if base_path.is_dir():
                entrypoint_name = Path(entrypoint).name or standard_name
                for extension in self._candidate_extensions(entry_type):
                    candidate_path = base_path / f"{entrypoint_name}{extension}"
                    if candidate_path.is_file():
                        if entry_type == "shell_script":
                            return self._format_command(["bash", str(candidate_path)]), str(candidate_path.parent), str(candidate_path)
                        return self._format_command([str(candidate_path)]), str(candidate_path.parent), str(candidate_path)

        missing_status = "failed" if definition.get("install", {}).get("automated", True) else "manual"
        raise self._tool_error(
            requested_tool=requested_name,
            status=missing_status,
            message=f"工具 {standard_name} 已声明但当前运行环境不可用，未解析到有效执行入口",
            definition=definition,
            standard_name=standard_name,
        )

    def inspect_tool(self, tool_name: str) -> Dict[str, Any]:
        requested_tool = normalize_tool_name(tool_name)
        try:
            standard_name, definition = self._resolve_declared_tool(requested_tool)
            self._ensure_platform_supported(requested_tool, standard_name, definition)
            command, cwd, resolved_path = self._resolve_entry_command(requested_tool, standard_name, definition)
            result: Dict[str, Any] = {
                "status": "available",
                "requested_tool": requested_tool,
                "standard_name": standard_name,
                "display_name": definition.get("display_name"),
                "platform": self.platform_key,
                "support_state": "supported",
                "install_mode": definition.get("install", {}).get("mode"),
                "command": command,
                "cwd": cwd,
                "resolved_path": resolved_path,
            }
            return {key: value for key, value in result.items() if value is not None}
        except ToolRuntimeError as error:
            return error.to_result()

    def _get_tool_path(self, tool_name: str) -> str:
        inspection = self.inspect_tool(tool_name)
        if inspection.get("status") != "available":
            raise self._tool_error(
                requested_tool=str(inspection.get("requested_tool") or tool_name),
                status=str(inspection.get("status") or "failed"),
                message=str(inspection.get("message") or f"工具 {tool_name} 当前不可用"),
                standard_name=inspection.get("standard_name"),
                support_state=inspection.get("support_state"),
            )
        return str(inspection["command"])

    async def _execute_named_tool(
        self,
        tool_name: str,
        arguments: str = "",
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        inspection = self.inspect_tool(tool_name)
        if inspection.get("status") != "available":
            raise self._tool_error(
                requested_tool=str(inspection.get("requested_tool") or tool_name),
                status=str(inspection.get("status") or "failed"),
                message=str(inspection.get("message") or f"工具 {tool_name} 当前不可用"),
                standard_name=inspection.get("standard_name"),
                support_state=inspection.get("support_state"),
            )

        command = str(inspection["command"])
        extra_arguments = str(arguments or "").strip()
        if extra_arguments:
            command = f"{command} {extra_arguments}"
        effective_timeout = 300 if timeout is None else timeout
        stdout, stderr, returncode = await self.cli_manager.execute_command(
            command,
            timeout=effective_timeout,
            cwd=inspection.get("cwd"),
        )
        inspection["command"] = command
        inspection["stdout"] = stdout
        inspection["stderr"] = stderr
        inspection["returncode"] = returncode
        return inspection

    async def nmap(self, target: str, options: str = "-sV") -> str:
        result = await self._execute_named_tool("nmap", f"{options} {target}")
        command = result["command"]
        logger.info(f"Running Nmap: {command}")
        stdout = str(result["stdout"])
        stderr = str(result["stderr"])
        returncode = int(result["returncode"])
        if returncode != 0:
            logger.error(f"Nmap failed: {stderr}")
        return stdout

    async def sqlmap(self, url: str, options: str = "--batch") -> str:
        result = await self._execute_named_tool("sqlmap", f'-u "{url}" {options}')
        command = result["command"]
        logger.info(f"Running Sqlmap: {command}")
        stdout = str(result["stdout"])
        stderr = str(result["stderr"])
        returncode = int(result["returncode"])
        if returncode != 0:
            logger.error(f"Sqlmap failed: {stderr}")
        return stdout

    async def nuclei(self, target: str, template_path: Optional[str] = None, options: str = "") -> str:
        resolved_templates = self._resolve_nuclei_template_arg(template_path)
        arguments = f"-u {target} {options}".strip()
        if resolved_templates:
            arguments += f" -t {shlex.quote(resolved_templates)}"

        result = await self._execute_named_tool("nuclei", arguments)
        command = result["command"]
        logger.info(f"Running Nuclei: {command}")
        stdout = str(result["stdout"])
        stderr = str(result["stderr"])
        returncode = int(result["returncode"])
        if returncode != 0:
            logger.error(f"Nuclei failed: {stderr}")
        return stdout

    async def hydra(self, target: str, service: str, user_list: str, pass_list: str, options: str = "") -> str:
        result = await self._execute_named_tool("hydra", f"-L {user_list} -P {pass_list} {options} {target} {service}")
        command = result["command"]
        logger.info(f"Running Hydra: {command}")
        stdout = str(result["stdout"])
        stderr = str(result["stderr"])
        returncode = int(result["returncode"])
        if returncode != 0:
            logger.error(f"Hydra failed: {stderr}")
        return stdout

    async def msfconsole(self, command_str: str) -> str:
        result = await self._execute_named_tool("msfconsole", f'-q -x "{command_str}; exit"')
        command = result["command"]
        logger.info(f"Running msfconsole: {command}")
        stdout = str(result["stdout"])
        stderr = str(result["stderr"])
        returncode = int(result["returncode"])
        if returncode != 0:
            logger.error(f"msfconsole failed: {stderr}")
        return stdout

    async def run_tool(self, tool_name: str, arguments: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Run any generic tool from the tools directory.
        """
        if tool_name == "mysql" and "--batch" not in arguments and "-B" not in arguments:
            arguments = f"--batch {arguments}"

        inspection = self.inspect_tool(tool_name)
        if inspection.get("status") != "available":
            inspection.setdefault("stdout", "")
            inspection.setdefault("stderr", "")
            inspection["returncode"] = -1
            inspection["command"] = None
            return inspection

        command = str(inspection["command"])
        normalized_arguments = str(arguments or "").strip()
        if normalized_arguments:
            command = f"{command} {normalized_arguments}"

        if timeout is None:
            timeout = 300

        logger.info(f"Running generic tool: {command}")
        stdout, stderr, returncode = await self.cli_manager.execute_command(
            command,
            timeout=timeout,
            cwd=inspection.get("cwd"),
        )

        inspection["stdout"] = stdout
        inspection["stderr"] = stderr
        inspection["returncode"] = returncode
        inspection["command"] = command
        return inspection
