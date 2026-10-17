import os
import shlex
import re
from typing import Any, Dict, List, Optional, Tuple

from core.modules.cli_manager import CLIManager


class SessionBackendExecutor:
    def __init__(self, mode: str = "workspace", msf_binary: Optional[str] = None):
        normalized = (mode or "workspace").strip().lower()
        self.mode = normalized if normalized in {"workspace", "msf"} else "workspace"
        self.msf_binary = msf_binary or "msfconsole"

    async def execute(
        self,
        command: str,
        timeout: Optional[int],
        cwd: str,
        shell_id: Optional[str] = None,
        retries: int = 1,
    ) -> Tuple[str, str, int, Dict[str, Any]]:
        if self.mode == "msf":
            wrapped = self._wrap_msf_command(command=command, shell_id=shell_id)
            stdout, stderr, code = await self._run_msf_command(wrapped=wrapped, timeout=timeout)
            meta: Dict[str, Any] = {"mode": "msf", "wrapped_command": wrapped, "retry_count": 0}
            if code != 0 and retries > 0:
                msf_ready, reason = await self.verify_session(shell_id=shell_id)
                meta["session_ready"] = msf_ready
                meta["session_check"] = reason
                if msf_ready:
                    stdout, stderr, code = await self._run_msf_command(wrapped=wrapped, timeout=timeout)
                    meta["retry_count"] = 1
            return stdout, stderr, code, meta
        stdout, stderr, code = await CLIManager.execute_command(
            command=command,
            timeout=timeout,
            cwd=cwd,
        )
        return stdout, stderr, code, {"mode": "workspace", "wrapped_command": command}

    async def probe_sessions(self, timeout: int = 20) -> Dict[str, Any]:
        wrapped = f"{self.msf_binary} -q -x {shlex.quote('sessions -l; exit')}"
        stdout, stderr, code = await CLIManager.execute_command(command=wrapped, timeout=timeout, cwd=os.path.abspath("."))
        sessions = self._parse_sessions(stdout)
        return {"ok": code == 0, "returncode": code, "stdout": stdout, "stderr": stderr, "sessions": sessions}

    async def verify_session(self, shell_id: Optional[str], timeout: int = 20) -> Tuple[bool, str]:
        sid = (shell_id or "").strip()
        if not sid:
            return False, "missing_shell_id"
        result = await self.probe_sessions(timeout=timeout)
        if not result["ok"]:
            return False, "msf_unavailable"
        for item in result["sessions"]:
            if str(item.get("id")) == sid:
                return True, "session_found"
        return False, "session_not_found"

    async def _run_msf_command(self, wrapped: str, timeout: Optional[int]) -> Tuple[str, str, int]:
        return await CLIManager.execute_command(command=wrapped, timeout=timeout, cwd=os.path.abspath("."))

    def _parse_sessions(self, stdout: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        pattern = re.compile(r"^\s*(\d+)\s+([^\s]+)\s+([^\s]+)\s+([^\s].*?)\s{2,}(.+?)\s{2,}(.+?)\s*$")
        for line in (stdout or "").splitlines():
            text = line.strip()
            if not text or text.startswith("Active sessions") or text.startswith("="):
                continue
            match = pattern.match(line)
            if match:
                rows.append(
                    {
                        "id": match.group(1),
                        "name": match.group(2),
                        "type": match.group(3),
                        "information": match.group(4).strip(),
                        "connection": match.group(5).strip(),
                        "via": match.group(6).strip(),
                    }
                )
                continue
            if text and text[0].isdigit():
                parts = re.split(r"\s{2,}", text)
                if len(parts) >= 4:
                    head = parts[0].split()
                    sid = head[0]
                    rows.append(
                        {
                            "id": sid,
                            "name": head[1] if len(head) > 1 else "session",
                            "type": head[2] if len(head) > 2 else "unknown",
                            "information": " ".join(head[3:]) if len(head) > 3 else "",
                            "connection": parts[-2],
                            "via": parts[-1],
                        }
                    )
        return rows

    def _wrap_msf_command(self, command: str, shell_id: Optional[str]) -> str:
        sid = (shell_id or "").strip()
        if sid:
            payload = f"sessions -i {sid} -C {shlex.quote(command)}; exit"
        else:
            payload = f"{command}; exit"
        return f"{self.msf_binary} -q -x {shlex.quote(payload)}"

    async def execute_file_op(self, action: str, path: str, content: Optional[str] = None, recursive: bool = False, max_entries: int = 200, shell_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute file operations either locally or remotely via MSF"""
        if self.mode == "workspace":
            return await self._local_file_op(action, path, content, recursive, max_entries)
        else:
            return await self._msf_file_op(action, path, content, recursive, max_entries, shell_id)

    async def _local_file_op(self, action: str, path: str, content: Optional[str], recursive: bool, max_entries: int) -> Dict[str, Any]:
        if action == "list":
            if not os.path.isdir(path):
                return {"error": "Path is not a directory"}
            rows = []
            entries = sorted(os.scandir(path), key=lambda item: (not item.is_dir(), item.name.lower()))
            for entry in entries[:max_entries]:
                stat = entry.stat()
                rows.append({
                    "name": entry.name,
                    "path": os.path.abspath(entry.path),
                    "is_dir": entry.is_dir(),
                    "size": int(stat.st_size),
                    "modified_at": float(stat.st_mtime),
                })
            return {"action": action, "path": path, "count": len(rows), "items": rows}
            
        if action == "read":
            if not os.path.isfile(path):
                return {"error": "File not found"}
            with open(path, "r", encoding="utf-8", errors="replace") as file:
                return {"action": action, "path": path, "content": file.read()}
                
        if action == "write":
            if content is None:
                return {"error": "Content is required for write action"}
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(path, "w", encoding="utf-8") as file:
                file.write(content)
            return {"action": action, "path": path, "bytes": len(content.encode('utf-8'))}
            
        if action == "delete":
            if not os.path.exists(path):
                return {"action": action, "path": path, "deleted": False}
            if os.path.isdir(path):
                if not recursive:
                    return {"error": "Directory delete requires recursive=true"}
                import shutil
                shutil.rmtree(path)
            else:
                os.remove(path)
            return {"action": action, "path": path, "deleted": True}
            
        return {"error": "Unsupported action"}

    async def _msf_file_op(self, action: str, path: str, content: Optional[str], recursive: bool, max_entries: int, shell_id: Optional[str]) -> Dict[str, Any]:
        """Handle file operations on a remote MSF session"""
        if not shell_id:
            return {"error": "shell_id is required for MSF file operations"}
            
        # Verify session first
        msf_ready, reason = await self.verify_session(shell_id=shell_id)
        if not msf_ready:
            return {"error": f"MSF session not ready: {reason}"}
            
        if action == "list":
            cmd = f"ls {shlex.quote(path)}"
            stdout, stderr, code, _ = await self.execute(cmd, timeout=30, cwd=".", shell_id=shell_id)
            if code != 0 or "Error" in stdout:
                return {"error": f"Failed to list directory: {stdout or stderr}"}
                
            rows = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("Listing") or line.startswith("Mode") or line.startswith("----"):
                    continue
                parts = line.split(maxsplit=5)
                if len(parts) >= 6:
                    is_dir = parts[0].startswith('d')
                    rows.append({
                        "name": parts[5],
                        "path": f"{path.rstrip('/')}/{parts[5]}",
                        "is_dir": is_dir,
                        "size": int(parts[1]) if parts[1].isdigit() else 0,
                        "modified_at": 0.0 # Remote MSF parsing might not yield easy timestamps
                    })
            return {"action": action, "path": path, "count": len(rows), "items": rows[:max_entries]}
            
        if action == "read":
            cmd = f"cat {shlex.quote(path)}"
            stdout, stderr, code, _ = await self.execute(cmd, timeout=30, cwd=".", shell_id=shell_id)
            if code != 0:
                return {"error": f"Failed to read file: {stderr}"}
            return {"action": action, "path": path, "content": stdout}
            
        if action == "write":
            if content is None:
                return {"error": "Content is required"}
            
            # Since MSF console doesn't have a direct 'write text to file' command,
            # we write to a local temp file and upload it via MSF's 'upload' command
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as temp:
                temp.write(content)
                temp_path = temp.name
                
            try:
                cmd = f"upload {shlex.quote(temp_path)} {shlex.quote(path)}"
                stdout, stderr, code, _ = await self.execute(cmd, timeout=60, cwd=".", shell_id=shell_id)
                if code != 0 or "failed" in stdout.lower():
                    return {"error": f"Failed to write file: {stdout or stderr}"}
                return {"action": action, "path": path, "bytes": len(content.encode('utf-8'))}
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                    
        if action == "delete":
            cmd = f"rm {shlex.quote(path)}"
            stdout, stderr, code, _ = await self.execute(cmd, timeout=30, cwd=".", shell_id=shell_id)
            if code != 0:
                return {"error": f"Failed to delete file: {stderr}"}
            return {"action": action, "path": path, "deleted": True}
            
        return {"error": "Unsupported action for MSF"}
