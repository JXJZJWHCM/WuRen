import os
import json
import re
import shlex
import asyncio
import aiohttp
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from loguru import logger
from core.modules.tool_manager import ToolManager

class ActiveRecon:
    """
    Active reconnaissance module wrapping local cross-platform tools.
    """

    def __init__(self):
        self.tool_manager = ToolManager()
        self.fingerprints_dir = "fingerprints"

    @staticmethod
    def _safe_contains(haystack: str, needle: str) -> bool:
        return str(needle or "").lower() in str(haystack or "").lower()

    def _match_rule_clause(self, clause: str, body: str, headers: Dict[str, Any], status: int) -> bool:
        text = str(clause or "").strip()
        if not text:
            return False
        if text.startswith("header_") and "=\"" in text and text.endswith('"'):
            header_expr, expected = text.split("=\"", 1)
            header_name = header_expr[7:].strip()
            expected = expected[:-1]
            actual = str(headers.get(header_name) or "")
            return bool(actual) and self._safe_contains(actual, expected)
        if text.startswith("body=\"") and text.endswith('"'):
            expected = text[6:-1]
            return self._safe_contains(body, expected)
        if text.startswith("title=\"") and text.endswith('"'):
            expected = text[7:-1]
            match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.I | re.S)
            title = (match.group(1).strip() if match else "")
            return self._safe_contains(title, expected)
        if text.startswith("status=\"") and text.endswith('"'):
            expected = text[8:-1].strip()
            return expected.isdigit() and int(expected) == int(status)
        return False

    def _rule_matches(self, rule: str, body: str, headers: Dict[str, Any], status: int) -> bool:
        expression = str(rule or "").strip()
        if not expression:
            return False
        or_groups = [item.strip() for item in expression.split("||") if item.strip()]
        for group in or_groups:
            and_clauses = [item.strip() for item in group.split("&&") if item.strip()]
            if and_clauses and all(self._match_rule_clause(item, body, headers, status) for item in and_clauses):
                return True
        return False

    async def _match_fingerprints(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Match target URL against local fingerprint JSON definitions.
        """
        matched = []
        if not os.path.exists(self.fingerprints_dir):
            return matched
            
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False)) as session:
                async with session.get(target_url, timeout=10) as response:
                    body = await response.text(errors='ignore')
                    headers = response.headers
                    status = response.status
        except Exception as e:
            logger.warning(f"Failed to fetch {target_url} for fingerprinting: {e}")
            return matched

        # Read and check fingerprints
        for root, _, files in os.walk(self.fingerprints_dir):
            for file in files:
                if not file.endswith('.json'):
                    continue
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        fp_data = json.load(f)
                        
                    rule = str(fp_data.get("指纹规则", ""))
                    name = str(fp_data.get("指纹名称", file))
                    
                    if not rule:
                        continue
                        
                    if self._rule_matches(rule, body, headers, status):
                        matched.append({
                            "name": name,
                            "vendor": fp_data.get("vendor", ""),
                            "product": fp_data.get("product", ""),
                            "version": fp_data.get("version", ""),
                            "rule_matched": rule,
                            "status_code": status,
                        })
                except Exception as e:
                    logger.debug(f"Error parsing fingerprint {file}: {e}")
                    continue
                    
        return matched

    async def port_scan(self, target: str) -> List[int]:
        """
        Perform a port scan using Nmap to find open ports.

        Args:
            target (str): The target IP or hostname.

        Returns:
            List[int]: A list of open ports.
        """
        logger.info(f"Starting port scan on {target}...")
        # Use -p- to scan all ports, -T4 for speed, --open to show only open ports
        # -oX - outputs XML to stdout for easier parsing
        options = "-p- -T4 --open -oX -"
        stdout = await self.tool_manager.nmap(target, options=options)

        open_ports = []
        try:
            root = ET.fromstring(stdout)
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    port_id = port.get("portid")
                    if port_id:
                        open_ports.append(int(port_id))
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML output: {e}")
            # Fallback to regex parsing if XML fails (e.g. if nmap isn't installed or fails)
            # This is a basic fallback
            for line in stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split("/")
                    if parts[0].isdigit():
                        open_ports.append(int(parts[0]))
        
        logger.info(f"Found {len(open_ports)} open ports on {target}.")
        return sorted(open_ports)

    async def service_scan(self, target: str, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """
        Perform a service version detection scan using Nmap.

        Args:
            target (str): The target IP or hostname.
            ports (List[int], optional): Specific ports to scan. If None, scans common ports.

        Returns:
            List[Dict[str, Any]]: A list of services with details.
        """
        logger.info(f"Starting service scan on {target}...")
        
        port_opt = ""
        if ports:
            port_opt = f"-p {','.join(map(str, ports))}"
        else:
            port_opt = "-F" # Fast scan if no ports specified

        # -sV for version detection, -oX - for XML output
        options = f"{port_opt} -sV -oX -"
        stdout = await self.tool_manager.nmap(target, options=options)

        services = []
        try:
            root = ET.fromstring(stdout)
            for port in root.findall(".//port"):
                service_data = {
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "state": port.find("state").get("state"),
                    "service": "unknown",
                    "product": "",
                    "version": ""
                }
                
                service_elem = port.find("service")
                if service_elem is not None:
                    service_data["service"] = service_elem.get("name", "unknown")
                    service_data["product"] = service_elem.get("product", "")
                    service_data["version"] = service_elem.get("version", "")
                
                services.append(service_data)
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML output: {e}")
        
        logger.info(f"Identified {len(services)} services on {target}.")
        return services

    async def web_fingerprint(self, target: str) -> List[Dict[str, Any]]:
        """
        Perform web fingerprinting using Nuclei (and potentially others).

        Args:
            target (str): The target URL or IP.

        Returns:
            List[Dict[str, Any]]: A list of identified technologies/vulnerabilities.
        """
        logger.info(f"Starting web fingerprinting on {target}...")
        
        # Use nuclei with technology detection templates
        # -json to get JSON output
        options = "-json" 
        # We might want to specify templates, e.g., -t technologies/
        # But for now, let's stick to default or minimal options to avoid long scans
        # If the user has specific templates, they can be added here.
        # Assuming 'technologies' is a valid tag or template dir in standard nuclei install
        # But to be safe, we'll just run default nuclei which includes tech detection
        
        # Ensure target has protocol if missing
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        # 1. Run custom local fingerprint matching
        local_fps = await self._match_fingerprints(target)

        tool = self.tool_manager._get_tool_path("nuclei")
        command = (
            f"{shlex.quote(str(tool))} "
            f"-u {shlex.quote(str(target))} "
            f"{options} "
            f"-t {shlex.quote(str(self.tool_manager.default_nuclei_templates))}"
        )
        stdout, stderr, returncode = await self.tool_manager.cli_manager.execute_command(command)
        
        results = []
        # Add local fingerprints first
        for fp in local_fps[:30]:
            results.append({
                "template_id": "local-fingerprint",
                "name": fp["name"],
                "severity": "info",
                "matched_at": target,
                "tags": ["fingerprint", fp["vendor"], fp["product"]],
                "source": "local-rules",
                "confidence": "medium",
            })
        if returncode == 0:
            for line in stdout.splitlines():
                try:
                    if line.strip():
                        data = json.loads(line)
                        results.append({
                            "template_id": data.get("template-id"),
                            "name": data.get("info", {}).get("name"),
                            "severity": data.get("info", {}).get("severity"),
                            "matched_at": data.get("matched-at"),
                            "tags": data.get("info", {}).get("tags"),
                            "source": "nuclei",
                            "confidence": "high",
                        })
                except json.JSONDecodeError:
                    continue
        else:
            logger.error(f"Nuclei failed: {str(stderr or '')[:500]}")
                
        logger.info(f"Fingerprinting complete. Found {len(results)} items.")
        return results
