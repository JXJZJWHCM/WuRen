from core.ai.engine import DeepSeekEngine
from loguru import logger
import json
from typing import Dict, Any

class ArtifactVerifier:
    """
    工件验证器。
    使用 AI 引擎验证 PoC 代码或生成的报告内容是否合理、有效且安全。
    """

    def __init__(self, engine: DeepSeekEngine):
        """
        初始化验证器。

        Args:
            engine (DeepSeekEngine): AI 引擎实例。
        """
        self.engine = engine

    async def verify_artifact(self, content: str, type: str = "poc") -> Dict[str, Any]:
        """
        验证工件（PoC 或报告）。

        Args:
            content (str): 待验证的内容（代码或文本）。
            type (str): 工件类型，"poc" 或 "report"。

        Returns:
            Dict[str, Any]: 验证结果，包含 status (Pass/Fail) 和 suggestions。
        """
        logger.info(f"正在验证 {type} 工件...")
        
        if type == "poc":
            prompt = self._get_poc_verification_prompt(content)
        elif type == "report":
            prompt = self._get_report_verification_prompt(content)
        else:
            raise ValueError(f"不支持的工件类型: {type}")

        messages = [
            {"role": "system", "content": "你是一个专业的安全代码审计和渗透测试报告审查专家。你的任务是验证提供的工件是否符合安全标准、逻辑正确且无明显错误。"},
            {"role": "user", "content": prompt}
        ]

        try:
            # 使用 JSON 模式获取结构化输出
            response = await self.engine.chat(messages, json_mode=True)
            
            result_content = response.get("content", "{}")
            try:
                result = json.loads(result_content)
            except json.JSONDecodeError:
                logger.warning("AI 返回的不是有效的 JSON，尝试手动解析")
                # 简单的回退处理，如果 AI 没有返回 JSON
                result = {
                    "status": "Unknown",
                    "suggestions": [result_content],
                    "raw_response": result_content
                }

            status = str(result.get("status") or "Unknown")
            suggestions = result.get("suggestions")
            suggestion_items = suggestions if isinstance(suggestions, list) else []
            if status.lower() == "pass":
                result["content"] = "自动化验证通过，结果可进入最终报告。"
            elif suggestion_items:
                result["content"] = f"自动化验证状态 {status}。主要建议：{'; '.join(str(item) for item in suggestion_items[:3])}"
            else:
                result["content"] = f"自动化验证状态 {status}。"
            
            logger.info(f"{type} 验证完成: {result.get('status', 'Unknown')}")
            return result

        except Exception as e:
            logger.error(f"验证过程发生错误: {e}")
            return {
                "status": "Error",
                "suggestions": [f"验证过程发生异常: {str(e)}"],
                "content": f"自动化验证异常: {str(e)}",
            }

    def _get_poc_verification_prompt(self, content: str) -> str:
        return f"""
请审查以下 PoC (Proof of Concept) 代码。
重点检查：
1. 代码逻辑是否正确，能否实现预期的漏洞验证功能。
2. 是否存在语法错误或明显的运行时错误。
3. 是否包含恶意代码或对系统造成不可逆破坏的操作（应仅限于验证）。
4. 代码可读性和注释是否充分。

PoC 内容:
```
{content}
```

请以 JSON 格式返回结果，格式如下：
{{
    "status": "Pass" 或 "Fail",
    "suggestions": ["建议1", "建议2", ...]
}}
如果代码存在严重问题或无法运行，请标记为 Fail。
"""

    def _get_report_verification_prompt(self, content: str) -> str:
        return f"""
请审查以下渗透测试报告内容。
重点检查：
1. 报告结构是否清晰（摘要、方法、发现、建议）。
2. 漏洞描述是否准确，严重程度评级是否合理。
3. 修复建议是否具体可行。
4. 是否存在敏感信息泄露（如未脱敏的密码、密钥等）。
5. 语言是否专业、通顺。

报告内容:
```
{content}
```

请以 JSON 格式返回结果，格式如下：
{{
    "status": "Pass" 或 "Fail",
    "suggestions": ["建议1", "建议2", ...]
}}
如果报告存在严重遗漏或误导性信息，请标记为 Fail。
"""
