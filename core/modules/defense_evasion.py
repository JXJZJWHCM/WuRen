import asyncio
from typing import Dict, Any, Optional, List
from loguru import logger
import aiohttp
from core.modules.tool_manager import ToolManager

class DefenseEvasionManager:
    """
    Manager for recognizing and bypassing target defense systems.
    """
    def __init__(self, tool_manager: ToolManager):
        self.tool_manager = tool_manager

    async def detect_waf(self, target: str) -> Dict[str, Any]:
        """
        Identify the target's WAF (Web Application Firewall).
        """
        logger.info(f"Detecting WAF on {target}...")
        
        # Use wafw00f
        try:
            # -a for all checks, -o for output file (but we want to parse stdout)
            result = await self.tool_manager.run_tool("wafw00f", target, timeout=60)
            stdout = result.get("stdout", "")
            
            # Simple parsing for wafw00f output
            if "is behind" in stdout:
                waf_name = stdout.split("is behind")[1].split(".")[0].strip()
                return {"waf_detected": True, "waf_name": waf_name, "raw_output": stdout}
            elif "No WAF detected" in stdout:
                return {"waf_detected": False, "waf_name": None, "raw_output": stdout}
            else:
                return {"waf_detected": False, "waf_name": "unknown", "raw_output": stdout}
        except Exception as e:
            logger.error(f"WAF detection failed: {e}")
            return {"error": str(e)}

    async def find_bypass_strategies(self, waf_name: str, attack_type: str) -> List[str]:
        """
        Search for known bypass strategies for a given WAF and attack type.
        (Integration with search engine would be best here)
        """
        logger.info(f"Searching bypass strategies for {waf_name} and {attack_type}...")
        
        # This could be integrated with a search engine like WebSearch or a local KB
        # For now, return some generic advice based on attack type
        common_bypasses = {
            "SQLI": [
                "Using case-insensitive keywords (e.g., sELecT)",
                "Using comment syntax (e.g., /*!50000select*/)",
                "Encoding payloads (URL, Hex, Double URL, Unicode)",
                "Using whitespace alternatives (e.g., %0a, %0b, %0c, %a0)",
                "Using concatenation (e.g., 'SEL' || 'ECT')",
                "HTTP Parameter Contamination (HPP)"
            ],
            "XSS": [
                "Encoding tags (e.g., <img src=x onerror=alert(1)> -> %3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E)",
                "Using obscure event handlers (e.g., onpointerover, onfocusin)",
                "Using non-standard tags (e.g., <svg>, <details>)",
                "Using base64 encoding",
                "Breaking out of quotes or tags"
            ],
            "RCE": [
                "Using command concatenation (e.g., ; | & &&)",
                "Using environment variables (e.g., ${IFS}, $u)",
                "Using globbing (e.g., /bin/c?t /etc/p?sswd)",
                "Using hex/octal encoding for command strings",
                "Using base64 encoded commands"
            ]
        }
        
        strategies = common_bypasses.get(attack_type.upper(), ["No specific bypass strategies found. Try encoding and manual experimentation."])
        return strategies

    async def test_bypass_feasibility(self, target: str, payload: str, attack_type: str) -> Dict[str, Any]:
        """
        Tests if a specific bypass payload is feasible (e.g., doesn't trigger 403/406).
        """
        logger.info(f"Testing bypass feasibility on {target} with payload: {payload}")
        
        try:
            async with aiohttp.ClientSession() as session:
                # Assuming target is a URL. If it's a domain, need to prepend http://
                url = target if target.startswith("http") else f"http://{target}"
                
                # Test with the payload. This is a very basic check.
                # In real scenario, would need to know which parameter to inject into.
                async with session.get(url, params={"test_param": payload}, timeout=10, verify_ssl=False) as response:
                    status = response.status
                    body = await response.text(errors='ignore')
                    
                    if status in [403, 406, 501]:
                        return {"feasible": False, "status": status, "reason": "Blocked by WAF"}
                    else:
                        return {"feasible": True, "status": status, "reason": "Request accepted"}
        except Exception as e:
            logger.error(f"Bypass feasibility test failed: {e}")
            return {"error": str(e)}
