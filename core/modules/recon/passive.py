import asyncio
import socket
from typing import Dict, Any, List, Optional
from loguru import logger
from core.modules.tool_manager import ToolManager

class PassiveRecon:
    """
    Passive reconnaissance module.
    """
    def __init__(self):
        self.tool_manager = ToolManager()

    async def dns_lookup(self, target: str) -> Dict[str, Any]:
        """
        Perform DNS lookup to retrieve A, AAAA, MX, and NS records.

        Args:
            target (str): The domain name.

        Returns:
            Dict[str, Any]: Dictionary containing DNS records.
        """
        logger.info(f"Performing DNS lookup for {target}...")
        results = {
            "a": [],
            "aaaa": [],
            "mx": [],
            "ns": [],
            "txt": []
        }

        # Use dig for more comprehensive results if available, otherwise fallback to socket
        try:
            # Run specific queries
            for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
                result = await self.tool_manager.cli_manager.execute_command(f"dig {target} {record_type} +short", timeout=10)
                stdout = result[0]
                if stdout:
                    lines = stdout.strip().split('\n')
                    results[record_type.lower()] = [line for line in lines if line]

        except Exception as e:
            logger.warning(f"dig command failed or not found. Falling back to socket: {e}")
            try:
                # Basic A record lookup
                ip = socket.gethostbyname(target)
                results["a"].append(ip)
            except socket.gaierror as err:
                logger.error(f"DNS lookup failed: {err}")

        logger.info(f"DNS lookup complete for {target}.")
        return results

    async def whois_lookup(self, target: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup.

        Args:
            target (str): The domain name.

        Returns:
            Dict[str, Any]: WHOIS information.
        """
        logger.info(f"Performing WHOIS lookup for {target}...")
        
        try:
            result = await self.tool_manager.cli_manager.execute_command(f"whois {target}", timeout=15)
            stdout = result[0]
            stderr = result[1]
            returncode = result[2]
            
            if returncode != 0:
                logger.error(f"WHOIS command failed: {stderr}")
                return {"error": stderr}
            
            output = stdout
            # Basic parsing of WHOIS output
            info = {}
            for line in output.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    info[key.strip()] = value.strip()
            
            return info

        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            return {"error": str(e)}

    async def search_engines(self, target: str, engine: str = "fofa") -> Dict[str, Any]:
        """
        Placeholder for FOFA/Shodan search.

        Args:
            target (str): The query string.
            engine (str): 'fofa' or 'shodan'.

        Returns:
            Dict[str, Any]: Search results.
        """
        logger.info(f"Searching {engine} for {target} (Placeholder)...")
        # TODO: Implement API calls if keys are available
        return {"message": "Not implemented yet", "engine": engine, "target": target}
