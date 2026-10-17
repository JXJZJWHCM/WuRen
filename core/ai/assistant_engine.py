import json
from typing import Any, Awaitable, Callable, Dict, List, Optional

from core.ai.engine import DeepSeekEngine


class DeepSeekAssistantEngine:
    def __init__(self, engine: DeepSeekEngine):
        self.engine = engine

    async def run_multi_round(
        self,
        history: List[Dict[str, Any]],
        user_input: str,
        thinking_mode: Optional[bool] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        messages = list(history)
        messages.append({"role": "user", "content": user_input})
        response = await self.engine.chat(
            messages=messages,
            thinking_mode=thinking_mode,
            model=model or self.engine.get_default_model(thinking_mode),
        )
        if not isinstance(response, dict):
            raise RuntimeError("run_multi_round 仅支持非流式响应")
        next_history = self.engine.append_assistant_message(messages, response, include_reasoning=False)
        return {"response": response, "messages": next_history}

    async def run_json_output(
        self,
        messages: List[Dict[str, Any]],
        thinking_mode: Optional[bool] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        response = await self.engine.chat(
            messages=messages,
            json_mode=True,
            thinking_mode=thinking_mode,
            model=model or self.engine.get_default_model(thinking_mode),
        )
        if not isinstance(response, dict):
            raise RuntimeError("run_json_output 仅支持非流式响应")
        payload = response.get("content") or "{}"
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"raw": payload}
        return {"response": response, "json": parsed}

    async def run_prefix_completion(
        self,
        user_prompt: str,
        assistant_prefix: str,
        stop: Optional[List[str]] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        messages = [
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_prefix},
        ]
        response = await self.engine.chat(
            messages=messages,
            prefix_completion=True,
            stop=stop or [],
            thinking_mode=False,
            model=model or self.engine.model,
        )
        if not isinstance(response, dict):
            raise RuntimeError("run_prefix_completion 仅支持非流式响应")
        return response

    async def run_tool_calls(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        tool_executor: Callable[[Dict[str, Any]], Awaitable[Any]],
        thinking_mode: Optional[bool] = None,
        model: Optional[str] = None,
        strict_mode: bool = False,
    ) -> Dict[str, Any]:
        async def _tool_executor_wrapper(tool_call: Dict[str, Any]) -> str:
            output = await tool_executor(tool_call)
            if isinstance(output, str):
                return output
            return json.dumps(output, ensure_ascii=False)

        prepared_tools = self.enable_strict_tool_calls(tools) if strict_mode else tools
        return await self.engine.run_tool_call_loop(
            messages=messages,
            tools=prepared_tools,
            tool_executor=_tool_executor_wrapper,
            thinking_mode=thinking_mode,
            model=model or self.engine.get_default_model(thinking_mode),
            use_beta=strict_mode,
        )

    @staticmethod
    def enable_strict_tool_calls(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        strict_tools: List[Dict[str, Any]] = []
        for item in tools:
            tool = dict(item)
            function_data = dict(tool.get("function") or {})
            parameters = dict(function_data.get("parameters") or {})
            if parameters.get("type") == "object":
                parameters.setdefault("additionalProperties", False)
                properties = parameters.get("properties")
                if isinstance(properties, dict):
                    required = parameters.get("required")
                    if not isinstance(required, list):
                        parameters["required"] = list(properties.keys())
            function_data["parameters"] = parameters
            function_data["strict"] = True
            tool["function"] = function_data
            strict_tools.append(tool)
        return strict_tools
