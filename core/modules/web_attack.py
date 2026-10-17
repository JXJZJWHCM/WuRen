import asyncio
from typing import Dict, Any, Optional, List
import aiohttp
from loguru import logger
import json

class WebAttackManager:
    """
    Manager for advanced Web attacks including browser automation and request manipulation.
    """
    def __init__(self):
        self.browser = None
        self.playwright = None

    async def _ensure_browser(self):
        if not self.browser:
            try:
                from playwright.async_api import async_playwright
                self.playwright = await async_playwright().start()
                self.browser = await self.playwright.chromium.launch(headless=True)
                logger.info("Playwright browser started.")
            except ImportError:
                logger.warning("Playwright not installed. Browser automation will be unavailable.")
                return False
            except Exception as e:
                logger.error(f"Failed to start Playwright browser: {e}")
                return False
        return True

    async def browser_action(self, url: str, action: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform an autonomous browser action (navigate, click, type, screenshot, etc.)
        """
        if not await self._ensure_browser():
            return {"error": "Browser automation not available (Playwright missing or failed)."}

        context = await self.browser.new_context()
        page = await context.new_page()
        result = {"success": False, "data": None}

        try:
            logger.info(f"Performing browser action: {action} on {url}")
            await page.goto(url, wait_until="networkidle")

            if action == "screenshot":
                path = params.get("path", "screenshot.png") if params else "screenshot.png"
                await page.screenshot(path=path)
                result = {"success": True, "path": path}
            elif action == "get_content":
                content = await page.content()
                # 截断过长的 HTML，避免大模型上下文溢出 (保留前 50000 字符)
                if len(content) > 50000:
                    content = content[:50000] + "\n...[HTML Truncated due to length]..."
                result = {"success": True, "content": content}
            elif action == "click":
                selector = params.get("selector") if params else None
                if selector:
                    await page.click(selector)
                    await page.wait_for_load_state("networkidle")
                    result = {"success": True, "current_url": page.url}
            elif action == "type":
                selector = params.get("selector")
                text = params.get("text")
                if selector and text:
                    await page.type(selector, text)
                    result = {"success": True}
            elif action == "intercept_requests":
                # Basic intercept logic
                requests = []
                page.on("request", lambda request: requests.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": request.headers
                }))
                await page.goto(url, wait_until="networkidle")
                result = {"success": True, "requests": requests}
            
            await context.close()
        except Exception as e:
            logger.error(f"Browser action failed: {e}")
            result = {"success": False, "error": str(e)}
        
        return result

    async def replay_request(self, method: str, url: str, headers: Dict[str, str], body: Optional[str] = None) -> Dict[str, Any]:
        """
        Manually replay/modify and send an HTTP request.
        """
        logger.info(f"Replaying {method} request to {url}")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, headers=headers, data=body, verify_ssl=False) as response:
                    res_body = await response.text(errors='ignore')
                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "body": res_body
                    }
        except Exception as e:
            logger.error(f"Request replay failed: {e}")
            return {"error": str(e)}

    async def close(self):
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
