import asyncio
import shlex
import shutil
import time
from typing import Tuple, Optional
from loguru import logger

class CLIManager:
    """
    Manager for executing CLI commands asynchronously.
    """

    def __init__(self):
        pass

    @staticmethod
    def _is_bruteforce_command(command: str) -> bool:
        lowered = str(command or "").lower()
        keywords = ["hydra", "medusa", "ncrack", "patator", "crowbar", "brutespray", "wpscan --passwords"]
        return any(item in lowered for item in keywords)

    @staticmethod
    async def execute_command(command: str, timeout: Optional[int] = None, cwd: Optional[str] = None) -> Tuple[str, str, int]:
        """
        Execute a shell command asynchronously.

        Args:
            command (str): The command string to execute.
            timeout (Optional[int]): Maximum time in seconds to wait for the command. None/0 means no limit.

        Returns:
            Tuple[str, str, int]: (stdout, stderr, returncode).
            If a timeout occurs, returncode will be -1.
        """
        logger.info(f"Executing command: {command}")
        start_time = time.time()
        safe_timeout: Optional[int]
        if timeout is None or int(timeout) <= 0:
            safe_timeout = None
        else:
            safe_timeout = int(timeout)
        
        try:
            # Create subprocess
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )

            try:
                # Wait for command to complete with timeout
                if safe_timeout is None:
                    stdout_data, stderr_data = await process.communicate()
                else:
                    stdout_data, stderr_data = await asyncio.wait_for(process.communicate(), timeout=safe_timeout)
                
                # Try to decode with utf-8, fallback to system encoding or replace
                try:
                    stdout = stdout_data.decode('utf-8').strip()
                    stderr = stderr_data.decode('utf-8').strip()
                except UnicodeDecodeError:
                    # Fallback for Windows or other encodings
                    import locale
                    encoding = locale.getpreferredencoding()
                    stdout = stdout_data.decode(encoding, errors='replace').strip()
                    stderr = stderr_data.decode(encoding, errors='replace').strip()

                returncode = process.returncode
                
                execution_time = time.time() - start_time
                logger.info(f"Command finished in {execution_time:.2f}s with return code {returncode}")
                
                if returncode != 0:
                    logger.warning(f"Command failed with return code {returncode}")
                    logger.debug(f"Stderr: {stderr}")

                return stdout, stderr, returncode

            except asyncio.TimeoutError:
                logger.error(f"Command timed out after {safe_timeout}s: {command}")
                try:
                    process.kill()
                    await process.wait() 
                except ProcessLookupError:
                    pass
                return "", f"Command timed out after {safe_timeout}s", -1

        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            return "", str(e), -1
