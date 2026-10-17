import os
import re
from typing import Dict, Any, Optional
from loguru import logger
from core.ai.engine import DeepSeekEngine
from core.modules.tool_manager import ToolManager

class AIToolGenerator:
    """
    Module for AI to autonomously write and save general penetration testing tools.
    """

    def __init__(self, engine: DeepSeekEngine, tools_dir: str = "tools/custom"):
        self.engine = engine
        self.tools_dir = os.path.abspath(tools_dir)
        os.makedirs(self.tools_dir, exist_ok=True)
        self.tool_manager = ToolManager()

    async def generate_tool(self, requirement_description: str, tool_name: str, language: str = "python") -> str:
        """
        Generate a script based on requirements and save it to the custom tools directory.

        Args:
            requirement_description (str): Description of what the tool should do.
            tool_name (str): The desired name for the tool (without extension).
            language (str): The programming language to use (python, java, go, php).

        Returns:
            str: Path to the generated tool.
        """
        language = language.lower()
        if language not in ["python", "java", "go", "php"]:
            language = "python"
            
        ext_map = {
            "python": "py",
            "java": "java",
            "go": "go",
            "php": "php"
        }
        ext = ext_map[language]

        logger.info(f"Generating custom tool '{tool_name}.{ext}' in {language} for requirement: {requirement_description}")

        system_prompt = (
            f"You are an expert penetration testing tool developer. "
            f"Your task is to write a highly reliable, cross-platform {language.capitalize()} script based on the user's requirements. "
            f"The script must use command line arguments if necessary, handle exceptions gracefully, "
            f"and print output clearly. Do NOT write malicious code that harms the local system. "
            f"Return ONLY the raw {language.capitalize()} code enclosed in ```{language}\n ... \n``` blocks."
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Please write a {language.capitalize()} tool named {tool_name}. Requirement: {requirement_description}"}
        ]

        response = await self.engine.chat(messages=messages)
        content = response.get("content", "")

        # Extract code block
        match = re.search(fr"```{language}\s*(.*?)\s*```", content, re.DOTALL | re.IGNORECASE)
        if match:
            code = match.group(1).strip()
        else:
            # Fallback if no block found
            code = content.strip()
            code = code.removeprefix(f"```{language}").removesuffix("```").strip()

        if not code:
            raise ValueError(f"Failed to extract {language.capitalize()} code from AI response.")

        # Save to tools/custom/
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', tool_name)
        if language == "java":
            # Java files often need to match the class name
            safe_name = safe_name.capitalize()
            if "public class " in code:
                class_match = re.search(r"public\s+class\s+([A-Za-z0-9_]+)", code)
                if class_match:
                    safe_name = class_match.group(1)

        file_path = os.path.join(self.tools_dir, f"{safe_name}.{ext}")
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code)

        logger.info(f"Custom tool '{safe_name}.{ext}' generated and saved to {file_path}")
        return file_path
