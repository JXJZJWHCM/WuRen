import os
import yaml
import json
import uuid
import inspect
import asyncio
from copy import deepcopy
from typing import Optional, Dict, Any, AsyncGenerator, Union, List, Callable, Awaitable
import httpx
from openai import AsyncOpenAI, OpenAIError
from loguru import logger

from core.ai.provider_catalog import (
    OPENAI_COMPATIBLE_PROVIDERS,
    get_provider_auth_headers,
    get_provider_beta_base_url,
    get_provider_default_model,
    get_provider_default_reasoner_model,
    get_provider_messages_path,
    get_runtime_provider_base_url,
    is_supported_provider,
    normalize_provider_config,
    normalize_provider_failover_order,
    normalize_provider_name,
    provider_allows_custom_base_url,
    provider_requires_api_key,
    resolve_provider_protocol,
)

_GLOBAL_SEMAPHORES: Dict[str, asyncio.Semaphore] = {}

REASONING_CONTENT_PASSTHROUGH_PROVIDERS = {"deepseek", "xiaomi", "moonshot"}
REASONING_DETAILS_PASSTHROUGH_PROVIDERS = {"minimax"}
MAX_CONTEXT_CHARS_BY_PROVIDER = {
    "ollama": 60000,
    "custom": 90000,
}
DEFAULT_MAX_CONTEXT_CHARS = 180000
DEFAULT_CONTEXT_KEEP_RECENT_BLOCKS = 8
DEFAULT_CONTEXT_MESSAGE_MAX_CHARS = 24000

def _get_semaphore(key: str, limit: int) -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    loop_id = id(loop)
    sem_key = f"{key}_{loop_id}"
    if sem_key not in _GLOBAL_SEMAPHORES:
        _GLOBAL_SEMAPHORES[sem_key] = asyncio.Semaphore(limit)
    return _GLOBAL_SEMAPHORES[sem_key]


class DeepSeekEngine:
    OPENAI_COMPATIBLE_PROVIDERS = OPENAI_COMPATIBLE_PROVIDERS

    def __init__(
        self,
        config_path: str = "config/config.yaml",
        *,
        config_data: Optional[Dict[str, Any]] = None,
        provider_override: Optional[str] = None,
        allow_provider_failover: bool = True,
        shared_http_client: Optional[Any] = None,
    ):
        self.config_path = config_path
        self.config = deepcopy(config_data) if config_data is not None else self._load_config(config_path)
        self.allow_provider_failover = bool(allow_provider_failover)
        ai_section = self.config.get("ai", {}) or {}
        requested_default = normalize_provider_name(ai_section.get("default_provider", "deepseek"))
        self.default_provider = requested_default if is_supported_provider(requested_default) else "deepseek"
        requested_provider = normalize_provider_name(provider_override or self.default_provider)
        self.provider = requested_provider if is_supported_provider(requested_provider) else "deepseek"
        if self.provider != requested_provider:
            logger.warning(f"Unsupported AI provider configured: {requested_provider}; fallback to deepseek")
        self.provider_failover_order = normalize_provider_failover_order(
            ai_section.get("provider_failover_order"),
            self.default_provider,
        )
        providers_cfg = ai_section.get("providers", {})
        self.providers_config: Dict[str, Dict[str, Any]] = {}
        for provider_name, provider_config in (providers_cfg or {}).items():
            normalized_name = normalize_provider_name(provider_name)
            if not is_supported_provider(normalized_name):
                continue
            normalized_config, _ = normalize_provider_config(normalized_name, provider_config or {})
            self.providers_config[normalized_name] = normalized_config
        self.ai_config, self.migration_warnings = normalize_provider_config(self.provider, self.providers_config.get(self.provider, {}))
        self.endpoint_key = str(self.ai_config.get("endpoint_key") or "")

        self.api_key = str(self.ai_config.get("api_key") or "").strip()
        self.base_url = self._sanitize_endpoint(get_runtime_provider_base_url(self.provider, self.ai_config))
        self.model = str(self.ai_config.get("model") or get_provider_default_model(self.provider, self.endpoint_key) or "")
        self.reasoner_model = str(
            self.ai_config.get("reasoner_model") or get_provider_default_reasoner_model(self.provider, self.endpoint_key) or self.model
        )
        self.failover_models = self._parse_failover_models(self.ai_config.get("failover_models"), primary=self.model)
        self.temperature = float(self.ai_config.get("temperature", 0.5))
        self.max_tokens = self._safe_int(self.ai_config.get("max_tokens"), 4096)
        self.max_tokens_chat = self._safe_int(self.ai_config.get("max_tokens_chat"), 8192)
        self.max_tokens_reasoner = self._safe_int(self.ai_config.get("max_tokens_reasoner"), 32768)
        self.timeout = self._safe_timeout(self.ai_config.get("timeout", 0))
        self.thinking_default = bool(self.ai_config.get("thinking_default", True))
        self.thinking_mode_type = str(self.ai_config.get("thinking_type", "enabled"))
        self.reasoning_effort = str(self.ai_config.get("reasoning_effort") or "high").strip()
        self.context_max_chars = self._safe_int(
            self.ai_config.get("context_max_chars"),
            MAX_CONTEXT_CHARS_BY_PROVIDER.get(self.provider, DEFAULT_MAX_CONTEXT_CHARS),
        )
        self.context_keep_recent_blocks = max(
            1,
            self._safe_int(self.ai_config.get("context_keep_recent_blocks"), DEFAULT_CONTEXT_KEEP_RECENT_BLOCKS),
        )
        self.context_message_max_chars = max(
            4096,
            self._safe_int(self.ai_config.get("context_message_max_chars"), DEFAULT_CONTEXT_MESSAGE_MAX_CHARS),
        )
        default_beta_url = self.base_url if provider_allows_custom_base_url(self.provider) else get_provider_beta_base_url(self.provider, self.endpoint_key)
        self.beta_base_url = str(default_beta_url or self.base_url)
        self.anthropic_version = str(self.ai_config.get("anthropic_version") or "2023-06-01")
        self.anthropic_beta = str(self.ai_config.get("anthropic_beta") or "").strip()

        self._owns_http_client = shared_http_client is None
        self.client: Optional[AsyncOpenAI] = None
        self.beta_client: Optional[AsyncOpenAI] = None
        self.http_client = shared_http_client if shared_http_client is not None else httpx.AsyncClient(timeout=self.timeout or 120)

        self._initialize_provider_clients()
        logger.info(
            f"AI engine initialized provider={self.provider} model={self.model} protocol={self._provider_protocol()}"
        )

    async def aclose(self) -> None:
        try:
            if self.client:
                if hasattr(self.client, "aclose"):
                    await self.client.aclose()
                elif hasattr(self.client, "close"):
                    close_method = self.client.close()
                    if inspect.iscoroutine(close_method):
                        await close_method
        except Exception as e:
            logger.warning(f"client cleanup failed: {e}")
        finally:
            self.client = None

        try:
            if self.beta_client:
                if hasattr(self.beta_client, "aclose"):
                    await self.beta_client.aclose()
                elif hasattr(self.beta_client, "close"):
                    close_method = self.beta_client.close()
                    if inspect.iscoroutine(close_method):
                        await close_method
        except Exception as e:
            logger.warning(f"beta_client cleanup failed: {e}")
        finally:
            self.beta_client = None

        try:
            if self._owns_http_client and self.http_client:
                await self.http_client.aclose()
        except Exception as e:
            logger.warning(f"http_client cleanup failed: {e}")
        finally:
            if self._owns_http_client:
                self.http_client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.aclose()

    @staticmethod
    def _sanitize_endpoint(value: Any) -> str:
        text = str(value or "").strip()
        return text.strip("`").strip("'").strip('"').strip()

    def _load_config(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            logger.error(f"Config file not found: {path}")
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"Failed to load config file {path}: {e}")
            return {}

    def _initialize_provider_clients(self) -> None:
        if self._provider_protocol() != "openai-compatible":
            return
        if provider_requires_api_key(self.provider) and not self.api_key:
            logger.warning(f"{self.provider} API key is not configured in config.yaml or WebUI settings.")
            return
        client_api_key = self.api_key or "ollama"
        default_headers = {"Accept-Encoding": "identity"}
        default_headers.update(get_provider_auth_headers(self.provider, self.endpoint_key, self.api_key))
        self.client = AsyncOpenAI(api_key=client_api_key, base_url=self.base_url, timeout=self.timeout, default_headers=default_headers)
        beta_url = self.beta_base_url if self.provider == "deepseek" else self.base_url
        self.beta_client = AsyncOpenAI(api_key=client_api_key, base_url=beta_url, timeout=self.timeout, default_headers=default_headers)

    @staticmethod
    def _is_placeholder_api_key(value: Any) -> bool:
        text = str(value or "").strip().lower()
        if not text:
            return True
        if text in {"smoke-test-key", "your-api-key", "api-key", "none", "null"}:
            return True
        return text.startswith("test-key-")

    def _configured_provider_candidates(self) -> List[str]:
        candidates: List[str] = []
        for provider_name in normalize_provider_failover_order(self.provider_failover_order, self.provider):
            provider_config = self.providers_config.get(provider_name, {})
            api_key = str(provider_config.get("api_key") or "").strip()
            model = str(provider_config.get("model") or "").strip()
            if provider_requires_api_key(provider_name) and self._is_placeholder_api_key(api_key):
                continue
            if provider_allows_custom_base_url(provider_name) and not str(get_runtime_provider_base_url(provider_name, provider_config) or "").strip():
                continue
            if not model:
                continue
            if provider_name in candidates:
                continue
            candidates.append(provider_name)
        if self.provider not in candidates and (not provider_requires_api_key(self.provider) or not self._is_placeholder_api_key(self.api_key)) and str(self.model or "").strip():
            candidates.insert(0, self.provider)
        return candidates or [self.provider]

    def _spawn_provider_engine(self, provider_name: str) -> "DeepSeekEngine":
        child = DeepSeekEngine(
            self.config_path,
            config_data=self.config,
            provider_override=provider_name,
            allow_provider_failover=False,
            shared_http_client=self.http_client,
        )
        return child

    @staticmethod
    def _safe_int(value: Any, default: int) -> int:
        try:
            return int(value)
        except Exception:
            return int(default)

    @staticmethod
    def _safe_timeout(raw_timeout: Any) -> Optional[int]:
        try:
            timeout = int(raw_timeout or 0)
            return None if timeout <= 0 else timeout
        except Exception:
            return None

    def _provider_protocol(self) -> str:
        return resolve_provider_protocol(self.provider, self.ai_config)

    @staticmethod
    def _parse_failover_models(raw: Any, primary: str) -> List[str]:
        values: List[str] = []
        if isinstance(raw, list):
            values = [str(item or "").strip() for item in raw]
        elif isinstance(raw, str):
            values = [segment.strip() for segment in raw.split(",")]
        normalized: List[str] = []
        primary_name = str(primary or "").strip()
        for model in values:
            if not model:
                continue
            if model == primary_name:
                continue
            if model in normalized:
                continue
            normalized.append(model)
        return normalized

    @staticmethod
    def _message_text(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            chunks: List[str] = []
            for item in value:
                if isinstance(item, str):
                    chunks.append(item)
                elif isinstance(item, dict):
                    if item.get("type") == "text" and item.get("text") is not None:
                        chunks.append(str(item.get("text") or ""))
                    elif item.get("text") is not None:
                        chunks.append(str(item.get("text") or ""))
                    elif item.get("content") is not None:
                        chunks.append(str(item.get("content") or ""))
                elif item is not None:
                    chunks.append(str(item))
            return "\n".join(chunk for chunk in chunks if chunk)
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _trim_text(value: Any, max_chars: int) -> str:
        text = DeepSeekEngine._message_text(value)
        if max_chars <= 0 or len(text) <= max_chars:
            return text
        keep_head = max_chars // 2
        keep_tail = max_chars - keep_head
        return (
            text[:keep_head]
            + f"\n\n[context compacted: omitted {len(text) - max_chars} characters]\n\n"
            + text[-keep_tail:]
        )

    def _message_size(self, message: Dict[str, Any]) -> int:
        try:
            return len(json.dumps(message, ensure_ascii=False, default=str))
        except Exception:
            return len(str(message or ""))

    def _build_context_blocks(self, messages: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], List[List[Dict[str, Any]]]]:
        system_messages: List[Dict[str, Any]] = []
        blocks: List[List[Dict[str, Any]]] = []
        current_block: List[Dict[str, Any]] = []
        for message in messages:
            role = str(message.get("role") or "").strip().lower()
            if role in {"system", "developer"}:
                if current_block:
                    blocks.append(current_block)
                    current_block = []
                system_messages.append(message)
                continue
            if role == "user" and current_block:
                blocks.append(current_block)
                current_block = []
            current_block.append(message)
        if current_block:
            blocks.append(current_block)
        return system_messages, blocks

    def _compact_summary_message(self, dropped_blocks: List[List[Dict[str, Any]]]) -> Dict[str, str]:
        snippets: List[str] = []
        for block in dropped_blocks[-6:]:
            for message in block:
                role = str(message.get("role") or "message").strip().lower()
                if role == "tool":
                    continue
                text = self._message_text(message.get("content")).strip().replace("\r", " ").replace("\n", " ")
                if not text:
                    continue
                snippets.append(f"{role}: {text[:260]}")
                break
        summary = "Earlier conversation was compacted to fit the active model context window."
        if snippets:
            summary += " Recent omitted turns: " + " | ".join(snippets)
        return {"role": "system", "content": summary[:2400]}

    def _compact_messages_for_context(
        self,
        messages: List[Dict[str, Any]],
        keep_reasoning_content: bool,
        keep_reasoning_details: bool,
    ) -> List[Dict[str, Any]]:
        prepared = [self._sanitize_message_for_provider(item, keep_reasoning_content, keep_reasoning_details) for item in messages]
        prepared = [item for item in prepared if item]
        if not prepared:
            return []
        if self.context_max_chars <= 0:
            return prepared
        total_size = sum(self._message_size(item) for item in prepared)
        if total_size <= self.context_max_chars:
            return prepared

        system_messages, blocks = self._build_context_blocks(prepared)
        compacted_systems: List[Dict[str, Any]] = []
        for message in system_messages:
            item = dict(message)
            if "content" in item:
                item["content"] = self._trim_text(item.get("content"), self.context_message_max_chars)
            compacted_systems.append(item)

        reserved_size = sum(self._message_size(item) for item in compacted_systems) + 2400
        budget = max(1000, self.context_max_chars - reserved_size)
        kept_blocks: List[List[Dict[str, Any]]] = []
        kept_size = 0
        for block in reversed(blocks):
            block_size = sum(self._message_size(item) for item in block)
            if kept_blocks and len(kept_blocks) >= self.context_keep_recent_blocks and kept_size + block_size > budget:
                break
            if kept_blocks and kept_size + block_size > budget:
                break
            kept_blocks.insert(0, block)
            kept_size += block_size

        if not kept_blocks and blocks:
            kept_blocks = [blocks[-1]]

        dropped_count = max(0, len(blocks) - len(kept_blocks))
        dropped_blocks = blocks[:dropped_count]
        flattened: List[Dict[str, Any]] = []
        flattened.extend(compacted_systems)
        if dropped_blocks:
            flattened.append(self._compact_summary_message(dropped_blocks))
        for block in kept_blocks:
            for message in block:
                item = dict(message)
                if "content" in item and self._message_size(item) > self.context_message_max_chars:
                    item["content"] = self._trim_text(item.get("content"), self.context_message_max_chars)
                flattened.append(item)
        logger.info(
            f"AI context compacted provider={self.provider} messages={len(prepared)}->{len(flattened)} "
            f"chars={total_size}->{sum(self._message_size(item) for item in flattened)}"
        )
        return flattened

    def _provider_allows_reasoning_content(self, model: str, use_thinking_mode: bool, has_tools: bool, messages: List[Dict[str, Any]]) -> bool:
        if not use_thinking_mode:
            return False
        if self.provider not in REASONING_CONTENT_PASSTHROUGH_PROVIDERS:
            return False
        model_name = str(model or "").strip()
        if self.provider == "deepseek" and model_name in {"deepseek-chat", "deepseek-reasoner"}:
            return False
        if has_tools:
            return True
        return any(str(item.get("reasoning_content") or "").strip() for item in messages if isinstance(item, dict))

    def _provider_allows_reasoning_details(self, use_thinking_mode: bool) -> bool:
        return use_thinking_mode and self.provider in REASONING_DETAILS_PASSTHROUGH_PROVIDERS

    def _sanitize_message_for_provider(
        self,
        message: Dict[str, Any],
        keep_reasoning_content: bool,
        keep_reasoning_details: bool,
    ) -> Dict[str, Any]:
        if not isinstance(message, dict):
            return {}
        allowed_keys = {
            "role",
            "content",
            "name",
            "tool_call_id",
            "tool_calls",
            "function_call",
            "prefix",
            "partial",
        }
        item = {key: deepcopy(value) for key, value in message.items() if key in allowed_keys}
        if keep_reasoning_content and message.get("reasoning_content"):
            item["reasoning_content"] = str(message.get("reasoning_content") or "")
        if keep_reasoning_details and isinstance(message.get("reasoning_details"), list):
            item["reasoning_details"] = deepcopy(message.get("reasoning_details") or [])
        return item

    def _prepare_messages_for_openai_request(
        self,
        messages: List[Dict[str, Any]],
        resolved_model: str,
        use_thinking_mode: bool,
        has_tools: bool,
    ) -> List[Dict[str, Any]]:
        keep_reasoning_content = self._provider_allows_reasoning_content(resolved_model, use_thinking_mode, has_tools, messages)
        keep_reasoning_details = self._provider_allows_reasoning_details(use_thinking_mode)
        return self._compact_messages_for_context(messages, keep_reasoning_content, keep_reasoning_details)

    def _openai_max_tokens_param(self) -> str:
        if self.provider in {"openai", "xiaomi", "moonshot"}:
            return "max_completion_tokens"
        return "max_tokens"

    @staticmethod
    def _call_supports_param(callable_obj: Any, param_name: str) -> bool:
        try:
            parameters = inspect.signature(callable_obj).parameters
        except Exception:
            return True
        if param_name in parameters:
            return True
        return any(item.kind == inspect.Parameter.VAR_KEYWORD for item in parameters.values())

    def _resolve_openai_request_model(
        self,
        candidate_model: str,
        normalized_tools: List[Dict[str, Any]],
    ) -> str:
        resolved = str(candidate_model or "").strip()
        # DeepSeek 官方文档中，tool calling 应走支持工具调用的 chat 模型；
        # deepseek-reasoner 仅适合纯推理场景，否则多轮工具链容易触发 400。
        if self.provider == "deepseek" and resolved in {"deepseek-chat", "deepseek-reasoner"}:
            return "deepseek-v4-flash"
        return resolved

    def _resolve_openai_temperature(self, use_model: str) -> Optional[float]:
        model_name = str(use_model or "").strip()
        if self.provider == "minimax":
            # MiniMax OpenAI 兼容接口要求 temperature ∈ (0, 1]；
            # 这里做轻量钳制，避免默认 0.0 直接触发参数错误。
            return min(max(float(self.temperature), 0.01), 1.0)
        if self.provider in {"openai", "zhipu", "qwen"}:
            return self.temperature
        if "reasoner" not in model_name:
            return self.temperature
        return None

    def _build_openai_extra_body(
        self,
        use_thinking_mode: bool,
        extra_body: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        payload = dict(extra_body or {})
        if use_thinking_mode:
            if self.provider == "deepseek":
                payload.setdefault("thinking", {"type": self.thinking_mode_type})
            elif self.provider == "zhipu":
                payload.setdefault("thinking", {"type": self.thinking_mode_type})
            elif self.provider == "xiaomi":
                payload.setdefault("thinking", {"type": self.thinking_mode_type})
            elif self.provider == "moonshot":
                payload.setdefault("thinking", {"type": self.thinking_mode_type})
            elif self.provider == "minimax":
                payload.setdefault("reasoning_split", True)
        if self.provider == "qwen":
            # DashScope 的混合思考模型建议显式传递 enable_thinking，
            # 这样在思考/非思考两种模式下都能保持请求契约一致。
            payload.setdefault("enable_thinking", bool(use_thinking_mode))
        return payload

    def _model_candidates(self, preferred_model: str) -> List[str]:
        first = str(preferred_model or self.model).strip()
        candidates: List[str] = []
        if first:
            candidates.append(first)
        for fallback in self.failover_models:
            if fallback and fallback not in candidates:
                candidates.append(fallback)
        return candidates or [self.model]

    @staticmethod
    def _build_failover_handoff_message(
        from_target: str,
        to_target: str,
        error: Exception,
        messages: List[Dict[str, Any]],
    ) -> str:
        latest_user = ""
        for item in reversed(messages):
            if str(item.get("role") or "").strip().lower() == "user":
                latest_user = str(item.get("content") or "").strip()
                if latest_user:
                    break
        latest_user = latest_user[:700] if latest_user else "Continue the current task from the existing context."
        err_text = str(error or "")
        if len(err_text) > 240:
            err_text = err_text[:240] + "..."
        return (
            f"System handoff: the model switched automatically from {from_target} to {to_target}. "
            f"Reason: {err_text}. Continue from the existing context without restarting the workflow. "
            f"Current user task: {latest_user}"
        )

    @staticmethod
    def _is_gateway_bad_response(error: Exception) -> bool:
        text = str(error or "").lower()
        return "gzip: invalid header" in text or "bad_response_body" in text

    @staticmethod
    def _is_transient_gateway_status(error: Exception) -> bool:
        text = str(error or "").lower()
        if hasattr(error, "response") and error.response is not None:
            status = getattr(error.response, "status_code", 0)
            if status in {502, 503, 504}:
                return True
        return "bad_response_status_code" in text or " 504 " in f" {text} " or "gateway timeout" in text or " 502 " in f" {text} " or "bad gateway" in text or " 503 " in f" {text} " or "service unavailable" in text

    @staticmethod
    def _is_empty_json_body_error(error: Exception) -> bool:
        text = str(error or "").lower()
        # OpenAI 兼容网关在返回空 body 时，常见异常文本为:
        # "Expecting value: line 1 column 1 (char 0)"
        return "expecting value: line 1 column 1 (char 0)" in text

    async def _fallback_chat_completion_no_compression(self, kwargs: Dict[str, Any], use_thinking_mode: bool) -> Dict[str, Any]:
        payload = dict(kwargs or {})
        extra_body = payload.pop("extra_body", None)
        if isinstance(extra_body, dict):
            payload.update(extra_body)
        if payload.get("stream"):
            raise RuntimeError("The no-compression fallback does not support streaming responses.")
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept-Encoding": "identity",
        }
        response = await self.http_client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        try:
            data = response.json()
        except Exception:
            return {"content": str(response.text or ""), "role": "assistant", "usage": {}}
        return self._handle_response(data, use_thinking_mode)

    async def chat(
        self, 
        messages: list,
        stream: bool = False,
        json_mode: bool = False,
        thinking_mode: Optional[bool] = None,
        model: Optional[str] = None,
        tools: Optional[list] = None,
        tool_choice: Optional[Union[str, dict]] = None,
        stop: Optional[List[str]] = None,
        prefix_completion: bool = False,
        extra_body: Optional[Dict[str, Any]] = None,
        use_beta: bool = False,
    ) -> Union[Dict[str, Any], AsyncGenerator[str, None]]:
        if not self.allow_provider_failover:
            return await self._chat_current_provider(
                messages=messages,
                stream=stream,
                json_mode=json_mode,
                thinking_mode=thinking_mode,
                model=model,
                tools=tools,
                tool_choice=tool_choice,
                stop=stop,
                prefix_completion=prefix_completion,
                extra_body=extra_body,
                use_beta=use_beta,
            )

        provider_candidates = self._configured_provider_candidates()
        last_error: Optional[Exception] = None
        last_provider: Optional[str] = None
        last_model: Optional[str] = None

        for idx, candidate_provider in enumerate(provider_candidates):
            candidate_engine = self if candidate_provider == self.provider else self._spawn_provider_engine(candidate_provider)
            candidate_messages = [dict(item) for item in messages]
            candidate_model = model if idx == 0 else None
            effective_model_label = str(candidate_model or candidate_engine.get_default_model(thinking_mode) or "").strip()

            if idx > 0 and last_error is not None and last_provider and last_model:
                handoff = self._build_failover_handoff_message(
                    f"{last_provider}/{last_model}",
                    f"{candidate_engine.provider}/{effective_model_label}",
                    last_error,
                    candidate_messages,
                )
                candidate_messages.append({"role": "system", "content": handoff})
                logger.warning(
                    f"Automatic provider failover: {last_provider}/{last_model} -> "
                    f"{candidate_engine.provider}/{effective_model_label}"
                )

            try:
                response = await candidate_engine._chat_current_provider(
                    messages=candidate_messages,
                    stream=stream,
                    json_mode=json_mode,
                    thinking_mode=thinking_mode,
                    model=candidate_model,
                    tools=tools,
                    tool_choice=tool_choice,
                    stop=stop,
                    prefix_completion=prefix_completion,
                    extra_body=extra_body,
                    use_beta=use_beta,
                )
                if idx > 0 and isinstance(response, dict) and last_provider and last_model:
                    response["provider_failover"] = {
                        "activated": True,
                        "from_provider": last_provider,
                        "from_model": last_model,
                        "to_provider": candidate_engine.provider,
                        "to_model": response.get("model") or effective_model_label,
                        "attempt_index": idx + 1,
                    }
                    response["content"] = (
                        f"[provider failover from={last_provider}/{last_model} "
                        f"to={candidate_engine.provider}/{response.get('model') or effective_model_label}] "
                        f"{str(response.get('content') or '').strip()}"
                    ).strip()

                if candidate_engine is not self:
                    if not stream:
                        await candidate_engine.aclose()
                    else:
                        async def _cleanup_generator(gen, engine_to_close):
                            try:
                                async for chunk in gen:
                                    yield chunk
                            finally:
                                await engine_to_close.aclose()
                        return _cleanup_generator(response, candidate_engine)

                return response
            except Exception as error:
                if candidate_engine is not self:
                    await candidate_engine.aclose()
                last_error = error
                last_provider = candidate_engine.provider
                last_model = effective_model_label
                if idx + 1 < len(provider_candidates):
                    logger.warning(
                        f"Current provider exhausted all local model fallbacks, preparing provider failover: "
                        f"provider={candidate_engine.provider} error={error}"
                    )
                    continue
                raise

        if last_error is not None:
            raise last_error
        raise RuntimeError("Provider request failed and no usable provider failover is available.")

    async def _chat_current_provider(
        self,
        messages: list,
        stream: bool = False,
        json_mode: bool = False,
        thinking_mode: Optional[bool] = None,
        model: Optional[str] = None,
        tools: Optional[list] = None,
        tool_choice: Optional[Union[str, dict]] = None,
        stop: Optional[List[str]] = None,
        prefix_completion: bool = False,
        extra_body: Optional[Dict[str, Any]] = None,
        use_beta: bool = False,
    ) -> Union[Dict[str, Any], AsyncGenerator[str, None]]:
        use_model = model or self.model
        use_thinking_mode = self.thinking_default if thinking_mode is None else bool(thinking_mode)
        normalized_tools = self._normalize_tools(tools)
        protocol = self._provider_protocol()

        async def _execute():
            if protocol == "openai-compatible":
                return await self._chat_openai_compatible(
                    messages=messages,
                    stream=stream,
                    json_mode=json_mode,
                    use_model=use_model,
                    use_thinking_mode=use_thinking_mode,
                    normalized_tools=normalized_tools,
                    tool_choice=tool_choice,
                    stop=stop,
                    prefix_completion=prefix_completion,
                    extra_body=extra_body,
                    use_beta=use_beta,
                )
            if protocol == "google-official":
                return await self._chat_gemini(
                    messages=messages,
                    stream=stream,
                    json_mode=json_mode,
                    use_model=use_model,
                    normalized_tools=normalized_tools,
                )
            if protocol == "anthropic-official":
                return await self._chat_claude(
                    messages=messages,
                    stream=stream,
                    json_mode=json_mode,
                    use_model=use_model,
                    normalized_tools=normalized_tools,
                )
            raise ValueError(f"Unsupported provider protocol: {self.provider} ({protocol})")

        if self.provider == "custom":
            limit = self._safe_int(self.ai_config.get("concurrency_limit"), 2)
            if limit <= 0:
                limit = 2
            sem = _get_semaphore("custom", limit)
            
            if stream:
                async def _stream_wrapper():
                    async with sem:
                        gen = await _execute()
                        async for chunk in gen:
                            yield chunk
                return _stream_wrapper()
            else:
                async with sem:
                    return await _execute()
        else:
            return await _execute()

    async def _chat_openai_compatible(
        self,
        messages: list,
        stream: bool,
        json_mode: bool,
        use_model: str,
        use_thinking_mode: bool,
        normalized_tools: List[Dict[str, Any]],
        tool_choice: Optional[Union[str, dict]],
        stop: Optional[List[str]],
        prefix_completion: bool,
        extra_body: Optional[Dict[str, Any]],
        use_beta: bool,
    ) -> Union[Dict[str, Any], AsyncGenerator[str, None]]:
        if not self.client:
            raise ValueError(f"{self.provider} API Key is not configured. Please set it in WebUI Settings.")

        model_candidates = self._model_candidates(use_model)
        last_error: Optional[Exception] = None
        for idx, candidate_model in enumerate(model_candidates):
            candidate_messages = self._build_prefix_messages(messages) if prefix_completion else [dict(item) for item in messages]
            if idx > 0 and last_error is not None:
                handoff = self._build_failover_handoff_message(model_candidates[idx - 1], candidate_model, last_error, candidate_messages)
                candidate_messages.append({"role": "system", "content": handoff})
                logger.warning(f"Automatic model failover: {model_candidates[idx - 1]} -> {candidate_model}")

            response_format = {"type": "json_object"} if json_mode else None
            resolved_model = self._resolve_openai_request_model(candidate_model, normalized_tools)
            candidate_messages = self._prepare_messages_for_openai_request(
                candidate_messages,
                resolved_model,
                use_thinking_mode,
                bool(normalized_tools),
            )
            kwargs = {
                "model": resolved_model,
                "messages": candidate_messages,
                "stream": stream,
            }
            provider_extra_body = dict(extra_body or {})
            max_tokens_param = self._openai_max_tokens_param()
            max_tokens_value = self._resolve_max_tokens(resolved_model, use_thinking_mode)
            client = self.beta_client if (prefix_completion or use_beta) else self.client
            create_method = client.chat.completions.create if client else None
            if create_method and self._call_supports_param(create_method, max_tokens_param):
                kwargs[max_tokens_param] = max_tokens_value
            else:
                provider_extra_body[max_tokens_param] = max_tokens_value
            if self.provider == "deepseek" and use_thinking_mode and self.reasoning_effort:
                if create_method and self._call_supports_param(create_method, "reasoning_effort"):
                    kwargs["reasoning_effort"] = self.reasoning_effort
                else:
                    provider_extra_body.setdefault("reasoning_effort", self.reasoning_effort)
            temperature = self._resolve_openai_temperature(resolved_model)
            if temperature is not None:
                kwargs["temperature"] = temperature
            if response_format:
                kwargs["response_format"] = response_format
            tools_supported = not (self.provider == "deepseek" and resolved_model == "deepseek-reasoner")
            if normalized_tools and tools_supported:
                kwargs["tools"] = normalized_tools
                if tool_choice:
                    kwargs["tool_choice"] = tool_choice
            if stop:
                kwargs["stop"] = stop
            payload = self._build_openai_extra_body(use_thinking_mode, provider_extra_body)
            if payload:
                kwargs["extra_body"] = payload
            if use_thinking_mode and resolved_model == "deepseek-chat" and self.provider == "deepseek":
                logger.info("Thinking mode enabled; using deepseek-chat with explicit thinking parameters.")

            for request_attempt in range(1, 3):
                try:
                    response = await client.chat.completions.create(**kwargs)
                    if stream:
                        return self._handle_stream(response, use_thinking_mode)
                    if not hasattr(response, "choices") and not isinstance(response, (dict, str)):
                        logger.warning(
                            f"Received a non-standard response type provider={self.provider} "
                            f"model={candidate_model} type={type(response).__name__}"
                        )
                    normalized = self._handle_response(response, use_thinking_mode)
                    normalized.setdefault("provider", self.provider)
                    normalized.setdefault("model", resolved_model)
                    if resolved_model != candidate_model:
                        normalized["model_adaptation"] = {
                            "requested_model": candidate_model,
                            "resolved_model": resolved_model,
                        }
                    if idx > 0:
                        normalized["model_failover"] = {
                            "activated": True,
                            "from_model": model_candidates[idx - 1],
                            "to_model": resolved_model,
                            "attempt_index": idx + 1,
                        }
                        normalized["content"] = (
                            f"[model failover from={model_candidates[idx - 1]} to={resolved_model}] "
                            f"{str(normalized.get('content') or '').strip()}"
                        ).strip()
                    return normalized
                except OpenAIError as e:
                    if request_attempt == 1 and self._is_transient_gateway_status(e):
                        logger.warning(
                            f"Transient gateway status detected, retrying current model provider={self.provider} model={resolved_model}"
                        )
                        continue
                    if not stream and self._is_gateway_bad_response(e):
                        logger.warning(
                            f"Gateway compression issue detected, retrying without compression provider={self.provider} "
                            f"model={resolved_model}"
                        )
                        try:
                            normalized = await self._fallback_chat_completion_no_compression(kwargs, use_thinking_mode)
                            normalized.setdefault("provider", self.provider)
                            normalized.setdefault("model", resolved_model)
                            if resolved_model != candidate_model:
                                normalized["model_adaptation"] = {
                                    "requested_model": candidate_model,
                                    "resolved_model": resolved_model,
                                }
                            if idx > 0:
                                normalized["model_failover"] = {
                                    "activated": True,
                                    "from_model": model_candidates[idx - 1],
                                    "to_model": resolved_model,
                                    "attempt_index": idx + 1,
                                }
                                normalized["content"] = (
                                    f"[model failover from={model_candidates[idx - 1]} to={resolved_model}] "
                                    f"{str(normalized.get('content') or '').strip()}"
                                ).strip()
                            return normalized
                        except Exception as fallback_error:
                            logger.error(f"No-compression fallback request failed: {fallback_error}")
                            last_error = fallback_error
                    else:
                        last_error = e
                    if idx + 1 < len(model_candidates):
                        logger.warning(f"Current model request failed, preparing failover: {e}")
                        break
                    logger.error(f"OpenAI-compatible request failed: {e}")
                    raise
                except Exception as e:
                    last_error = e
                    if not stream and self._is_empty_json_body_error(e):
                        logger.warning(
                            f"Empty JSON body detected, retrying without compression provider={self.provider} "
                            f"model={resolved_model}"
                        )
                        try:
                            normalized = await self._fallback_chat_completion_no_compression(kwargs, use_thinking_mode)
                            normalized.setdefault("provider", self.provider)
                            normalized.setdefault("model", resolved_model)
                            if resolved_model != candidate_model:
                                normalized["model_adaptation"] = {
                                    "requested_model": candidate_model,
                                    "resolved_model": resolved_model,
                                }
                            if idx > 0:
                                normalized["model_failover"] = {
                                    "activated": True,
                                    "from_model": model_candidates[idx - 1],
                                    "to_model": resolved_model,
                                    "attempt_index": idx + 1,
                                }
                                normalized["content"] = (
                                    f"[model failover from={model_candidates[idx - 1]} to={resolved_model}] "
                                    f"{str(normalized.get('content') or '').strip()}"
                                ).strip()
                            return normalized
                        except Exception as fallback_error:
                            logger.error(f"No-compression fallback after empty JSON body failed: {fallback_error}")
                            last_error = fallback_error
                    if idx + 1 < len(model_candidates):
                        logger.warning(f"Current model raised an exception, preparing failover: {e}")
                        break
                    logger.error(f"Unhandled model request error: {e}")
                    raise
            if idx + 1 < len(model_candidates):
                continue
        if last_error is not None:
            raise last_error
        raise RuntimeError("Model request failed and no usable failover model is available.")

    async def _chat_gemini(
        self,
        messages: List[Dict[str, Any]],
        stream: bool,
        json_mode: bool,
        use_model: str,
        normalized_tools: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if stream:
            raise ValueError("Gemini official protocol is not enabled for streaming in this application.")
        if provider_requires_api_key(self.provider) and not self.api_key:
            raise ValueError("gemini API Key is not configured. Please set it in WebUI Settings.")

        safe_messages = self._compact_messages_for_context(messages, False, False)
        system_text, contents = self._build_gemini_messages(safe_messages)
        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self._resolve_max_tokens(use_model, False),
            },
        }
        if system_text:
            payload["systemInstruction"] = {"parts": [{"text": system_text}]}
        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"
        gemini_tools = self._to_gemini_tools(normalized_tools)
        if gemini_tools:
            payload["tools"] = gemini_tools

        url = f"{self.base_url.rstrip('/')}/models/{use_model}:generateContent"
        last_error = None
        for attempt in range(1, 4):
            try:
                response = await self.http_client.post(url, params={"key": self.api_key}, json=payload)
                response.raise_for_status()
                data = response.json()
                parsed = self._parse_gemini_response(data)
                parsed.setdefault("provider", self.provider)
                parsed.setdefault("model", use_model)
                return parsed
            except Exception as e:
                if attempt < 3 and self._is_transient_gateway_status(e):
                    logger.warning(f"Gemini API transient gateway error, retrying ({attempt}/3): {e}")
                    await asyncio.sleep(attempt * 2)
                    continue
                last_error = e
                break
                
        raise last_error

    def _anthropic_messages_url(self) -> str:
        base = self.base_url.rstrip("/")
        if base.endswith("/messages"):
            return base
        explicit = get_provider_messages_path(self.provider, self.endpoint_key)
        if explicit:
            suffix = explicit if explicit.startswith("/") else f"/{explicit}"
            return f"{base}{suffix}"
        if base.endswith("/anthropic") or "/anthropic" in base:
            return f"{base}/v1/messages"
        return f"{base}/messages"

    async def _chat_claude(
        self,
        messages: List[Dict[str, Any]],
        stream: bool,
        json_mode: bool,
        use_model: str,
        normalized_tools: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if stream:
            raise ValueError("Claude official protocol is not enabled for streaming in this application.")
        if provider_requires_api_key(self.provider) and not self.api_key:
            raise ValueError("claude API Key is not configured. Please set it in WebUI Settings.")

        safe_messages = self._compact_messages_for_context(messages, False, False)
        system_text, anthropic_messages = self._build_claude_messages(safe_messages)
        if json_mode:
            system_text = f"{system_text}\nYou must return valid JSON.".strip()
        payload: Dict[str, Any] = {
            "model": use_model,
            "max_tokens": self._resolve_max_tokens(use_model, False),
            "temperature": self.temperature,
            "messages": anthropic_messages,
        }
        if system_text:
            payload["system"] = system_text
        claude_tools = self._to_claude_tools(normalized_tools)
        if claude_tools:
            payload["tools"] = claude_tools

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.anthropic_version,
            "content-type": "application/json",
        }
        headers.update(get_provider_auth_headers(self.provider, self.endpoint_key, self.api_key))
        if self.anthropic_beta:
            headers["anthropic-beta"] = self.anthropic_beta
        url = self._anthropic_messages_url()
        
        last_error = None
        for attempt in range(1, 4):
            try:
                response = await self.http_client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
                parsed = self._parse_claude_response(data)
                parsed.setdefault("provider", self.provider)
                parsed.setdefault("model", use_model)
                return parsed
            except Exception as e:
                if attempt < 3 and self._is_transient_gateway_status(e):
                    logger.warning(f"Claude API transient gateway error, retrying ({attempt}/3): {e}")
                    await asyncio.sleep(attempt * 2)
                    continue
                last_error = e
                break
                
        raise last_error

    async def _handle_stream(self, response, thinking_mode: bool) -> AsyncGenerator[str, None]:
        async for chunk in response:
            if isinstance(chunk, str):
                if chunk:
                    yield chunk
                continue
            if isinstance(chunk, dict):
                text = str(chunk.get("content") or "")
                if text:
                    yield text
                continue
            if not hasattr(chunk, "choices"):
                text = str(chunk or "")
                if text:
                    yield text
                continue
            delta = chunk.choices[0].delta
            reasoning_text = ""
            if thinking_mode:
                reasoning_text = str(getattr(delta, "reasoning_content", "") or "").strip()
                if not reasoning_text:
                    reasoning_text = self._extract_reasoning_text(getattr(delta, "reasoning_details", None))
            if reasoning_text:
                yield f"<thinking>{reasoning_text}</thinking>"
            if delta.content:
                yield delta.content

    @staticmethod
    def _extract_reasoning_text(value: Any) -> str:
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, list):
            chunks: List[str] = []
            for item in value:
                if isinstance(item, str) and item.strip():
                    chunks.append(item.strip())
                    continue
                if isinstance(item, dict):
                    for key in ("text", "content", "reasoning"):
                        text = str(item.get(key) or "").strip()
                        if text:
                            chunks.append(text)
                            break
            return "\n".join(chunks).strip()
        if isinstance(value, dict):
            for key in ("text", "content", "reasoning"):
                text = str(value.get(key) or "").strip()
                if text:
                    return text
        return ""

    def _handle_response(self, response, thinking_mode: bool) -> Dict[str, Any]:
        if isinstance(response, str):
            payload = response.strip()
            if not payload:
                return {"content": "", "role": "assistant", "usage": {}}
            try:
                parsed = json.loads(payload)
                return self._handle_response(parsed, thinking_mode)
            except Exception:
                return {"content": payload, "role": "assistant", "usage": {}}
        if isinstance(response, dict):
            if "content" in response and "role" in response:
                normalized = {
                    "content": str(response.get("content") or ""),
                    "role": str(response.get("role") or "assistant"),
                    "usage": response.get("usage") if isinstance(response.get("usage"), dict) else {},
                }
                tool_calls = response.get("tool_calls")
                if isinstance(tool_calls, list):
                    normalized["tool_calls"] = tool_calls
                reasoning_details = response.get("reasoning_details")
                if isinstance(reasoning_details, list) and reasoning_details:
                    normalized["reasoning_details"] = reasoning_details
                reasoning_content = self._extract_reasoning_text(
                    response.get("reasoning_content") or response.get("reasoning_details")
                )
                if reasoning_content:
                    normalized["reasoning_content"] = reasoning_content
                return normalized
            choices = response.get("choices")
            if isinstance(choices, list) and choices:
                first = choices[0] if isinstance(choices[0], dict) else {}
                message = first.get("message") if isinstance(first, dict) else {}
                content = ""
                role = "assistant"
                tool_calls: List[Dict[str, Any]] = []
                if isinstance(message, dict):
                    content = str(message.get("content") or "")
                    role = str(message.get("role") or "assistant")
                    if isinstance(message.get("tool_calls"), list):
                        tool_calls = message.get("tool_calls") or []
                result: Dict[str, Any] = {
                    "content": content,
                    "role": role,
                    "usage": response.get("usage") if isinstance(response.get("usage"), dict) else {},
                }
                if tool_calls:
                    result["tool_calls"] = tool_calls
                reasoning_details = message.get("reasoning_details") if isinstance(message, dict) else None
                if isinstance(reasoning_details, list) and reasoning_details:
                    result["reasoning_details"] = reasoning_details
                reasoning_content = self._extract_reasoning_text(
                    message.get("reasoning_content") if isinstance(message, dict) else None
                ) or self._extract_reasoning_text(
                    message.get("reasoning_details") if isinstance(message, dict) else None
                )
                if reasoning_content:
                    result["reasoning_content"] = reasoning_content
                return result
            return {"content": str(response.get("message") or ""), "role": "assistant", "usage": {}}
        if not hasattr(response, "choices"):
            return {"content": str(response or ""), "role": "assistant", "usage": {}}
        message = response.choices[0].message
        result = {
            "content": message.content,
            "role": message.role,
            "usage": response.usage.model_dump() if response.usage else {}
        }

        if message.tool_calls:
            result["tool_calls"] = [t.model_dump() for t in message.tool_calls]

        raw_reasoning_details = getattr(message, "reasoning_details", None)
        if isinstance(raw_reasoning_details, list) and raw_reasoning_details:
            result["reasoning_details"] = [
                item if isinstance(item, dict) else item.model_dump() if hasattr(item, "model_dump") else item
                for item in raw_reasoning_details
            ]

        reasoning_content = self._extract_reasoning_text(
            getattr(message, "reasoning_content", None) or getattr(message, "reasoning_details", None)
        )
        if reasoning_content:
            result["reasoning_content"] = reasoning_content

        return result


    def get_default_model(self, thinking_mode: Optional[bool] = None) -> str:
        enabled = self.thinking_default if thinking_mode is None else bool(thinking_mode)
        if enabled and self.reasoner_model:
            return self.reasoner_model
        return self.model

    def _resolve_max_tokens(self, model: str, thinking_mode: bool) -> int:
        configured = int(self.max_tokens or 0)
        if configured > 0:
            candidate = configured
        elif "reasoner" in str(model):
            candidate = int(self.max_tokens_reasoner or 32768)
        elif thinking_mode:
            candidate = int(self.max_tokens_reasoner or 32768)
        else:
            candidate = int(self.max_tokens_chat or 8192)
        max_limit = 64000 if ("reasoner" in str(model) or thinking_mode) else 8192
        if candidate <= 0:
            candidate = 4096
        return min(candidate, max_limit)

    def _build_gemini_messages(self, messages: List[Dict[str, Any]]) -> tuple[str, List[Dict[str, Any]]]:
        system_parts: List[str] = []
        contents: List[Dict[str, Any]] = []
        for message in messages:
            role = str(message.get("role") or "").strip().lower()
            if role == "system":
                text = str(message.get("content") or "").strip()
                if text:
                    system_parts.append(text)
                continue
            if role == "assistant":
                parts: List[Dict[str, Any]] = []
                text = str(message.get("content") or "").strip()
                if text:
                    parts.append({"text": text})
                for tool_call in message.get("tool_calls") or []:
                    function_data = tool_call.get("function") if isinstance(tool_call, dict) else {}
                    name = str(function_data.get("name") or "").strip()
                    raw_args = function_data.get("arguments")
                    args_payload: Dict[str, Any]
                    if isinstance(raw_args, str):
                        try:
                            args_payload = json.loads(raw_args)
                        except Exception:
                            args_payload = {}
                    elif isinstance(raw_args, dict):
                        args_payload = raw_args
                    else:
                        args_payload = {}
                    if name:
                        parts.append({"functionCall": {"name": name, "args": args_payload}})
                if parts:
                    contents.append({"role": "model", "parts": parts})
                continue
            if role == "tool":
                tool_name = str(message.get("name") or "tool_result").strip()
                tool_content = str(message.get("content") or "")
                contents.append(
                    {
                        "role": "user",
                        "parts": [
                            {
                                "functionResponse": {
                                    "name": tool_name,
                                    "response": {"content": tool_content}
                                }
                            }
                        ],
                    }
                )
                continue
            text = str(message.get("content") or "").strip()
            if text:
                contents.append({"role": "user", "parts": [{"text": text}]})
        return "\n".join(system_parts).strip(), contents or [{"role": "user", "parts": [{"text": ""}]}]

    def _to_gemini_tools(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        declarations: List[Dict[str, Any]] = []
        for item in tools:
            function_data = item.get("function") if isinstance(item, dict) else {}
            if not isinstance(function_data, dict):
                continue
            name = str(function_data.get("name") or "").strip()
            if not name:
                continue
            declarations.append(
                {
                    "name": name,
                    "description": str(function_data.get("description") or ""),
                    "parameters": function_data.get("parameters") or {"type": "object", "properties": {}},
                }
            )
        if not declarations:
            return []
        return [{"functionDeclarations": declarations}]

    @staticmethod
    def _parse_gemini_response(data: Dict[str, Any]) -> Dict[str, Any]:
        candidates = data.get("candidates") or []
        first = candidates[0] if candidates else {}
        content = first.get("content") or {}
        parts = content.get("parts") or []
        text_chunks: List[str] = []
        tool_calls: List[Dict[str, Any]] = []
        for part in parts:
            text = part.get("text")
            if text:
                text_chunks.append(str(text))
            function_call = part.get("functionCall")
            if isinstance(function_call, dict):
                name = str(function_call.get("name") or "").strip()
                args = function_call.get("args") or {}
                if name:
                    tool_calls.append(
                        {
                            "id": f"gemini_fc_{uuid.uuid4().hex[:10]}",
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(args, ensure_ascii=False),
                            },
                        }
                    )
        usage = data.get("usageMetadata") or {}
        result: Dict[str, Any] = {
            "content": "\n".join(text_chunks).strip(),
            "role": "assistant",
            "usage": usage,
        }
        if tool_calls:
            result["tool_calls"] = tool_calls
        return result

    def _build_claude_messages(self, messages: List[Dict[str, Any]]) -> tuple[str, List[Dict[str, Any]]]:
        system_parts: List[str] = []
        converted: List[Dict[str, Any]] = []
        for message in messages:
            role = str(message.get("role") or "").strip().lower()
            if role == "system":
                text = str(message.get("content") or "").strip()
                if text:
                    system_parts.append(text)
                continue
            
            blocks = []
            target_role = "user"
            
            if role == "assistant":
                target_role = "assistant"
                text = str(message.get("content") or "").strip()
                if text:
                    blocks.append({"type": "text", "text": text})
                for tool_call in message.get("tool_calls") or []:
                    function_data = tool_call.get("function") if isinstance(tool_call, dict) else {}
                    name = str(function_data.get("name") or "").strip()
                    raw_args = function_data.get("arguments")
                    args_payload: Dict[str, Any] = {}
                    if isinstance(raw_args, str):
                        try:
                            args_payload = json.loads(raw_args)
                        except Exception:
                            pass
                    elif isinstance(raw_args, dict):
                        args_payload = raw_args
                    if name:
                        blocks.append(
                            {
                                "type": "tool_use",
                                "id": str(tool_call.get("id") or f"toolu_{uuid.uuid4().hex[:10]}"),
                                "name": name,
                                "input": args_payload,
                            }
                        )
            elif role == "tool":
                target_role = "user"
                blocks.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": str(message.get("tool_call_id") or f"toolu_{uuid.uuid4().hex[:10]}"),
                        "content": str(message.get("content") or ""),
                    }
                )
            else:
                target_role = "user"
                text = str(message.get("content") or "").strip()
                if text:
                    blocks.append({"type": "text", "text": text})
            
            if not blocks:
                continue
                
            if converted and converted[-1]["role"] == target_role:
                # Merge consecutive messages with the same role
                last_content = converted[-1]["content"]
                if isinstance(last_content, str):
                    converted[-1]["content"] = [{"type": "text", "text": last_content}] + blocks
                elif isinstance(last_content, list):
                    converted[-1]["content"].extend(blocks)
            else:
                converted.append({"role": target_role, "content": blocks})
        
        if not converted:
            converted = [{"role": "user", "content": [{"type": "text", "text": "."}]}]
        elif converted[0]["role"] != "user":
            converted.insert(0, {"role": "user", "content": [{"type": "text", "text": "."}]})
            
        return "\n".join(system_parts).strip(), converted

    def _to_claude_tools(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        converted: List[Dict[str, Any]] = []
        for item in tools:
            function_data = item.get("function") if isinstance(item, dict) else {}
            if not isinstance(function_data, dict):
                continue
            name = str(function_data.get("name") or "").strip()
            if not name:
                continue
            converted.append(
                {
                    "name": name,
                    "description": str(function_data.get("description") or ""),
                    "input_schema": function_data.get("parameters") or {"type": "object", "properties": {}},
                }
            )
        return converted

    @staticmethod
    def _parse_claude_response(data: Dict[str, Any]) -> Dict[str, Any]:
        content_blocks = data.get("content") or []
        text_chunks: List[str] = []
        tool_calls: List[Dict[str, Any]] = []
        for block in content_blocks:
            block_type = str(block.get("type") or "").strip()
            if block_type == "text":
                text = block.get("text")
                if text:
                    text_chunks.append(str(text))
            elif block_type == "tool_use":
                name = str(block.get("name") or "").strip()
                if name:
                    tool_calls.append(
                        {
                            "id": str(block.get("id") or f"claude_fc_{uuid.uuid4().hex[:10]}"),
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(block.get("input") or {}, ensure_ascii=False),
                            },
                        }
                    )
        usage = data.get("usage") or {}
        result: Dict[str, Any] = {
            "content": "\n".join(text_chunks).strip(),
            "role": "assistant",
            "usage": usage,
        }
        if tool_calls:
            result["tool_calls"] = tool_calls
        return result

    @staticmethod
    def _normalize_tools(tools: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        if not tools:
            return []
        normalized: List[Dict[str, Any]] = []
        for item in tools:
            if not isinstance(item, dict):
                continue
            tool_type = str(item.get("type") or "").strip()
            if tool_type:
                normalized.append(item)
                continue
            function_data = item.get("function")
            if isinstance(function_data, dict):
                normalized.append({"type": "function", "function": function_data})
                continue
            if item.get("name") and item.get("parameters"):
                normalized.append({"type": "function", "function": item})
        return normalized

    async def web_search(self, query: str, max_results: int = 5) -> Dict[str, Any]:
        clean_query = str(query or "").strip()
        if not clean_query:
            return {"error": "query is empty"}
        if self.provider == "openai":
            return await self._web_search_openai(clean_query, max_results=max_results)
        if self.provider == "gemini":
            return await self._web_search_gemini(clean_query, max_results=max_results)
        if self.provider == "claude":
            return await self._web_search_claude(clean_query, max_results=max_results)
        return {
            "error": f"provider {self.provider} does not support built-in web search fallback in current implementation",
            "provider": self.provider,
            "query": clean_query,
        }

    async def _web_search_openai(self, query: str, max_results: int = 5) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "openai api_key missing", "provider": self.provider, "query": query}
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        url = f"{self.base_url.rstrip('/')}/responses"
        payload = {"model": self.model, "input": query, "tools": [{"type": "web_search"}]}
        response = await self.http_client.post(url, json=payload, headers=headers)
        if response.status_code >= 400:
            payload["tools"] = [{"type": "web_search_preview"}]
            response = await self.http_client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        answer = str(data.get("output_text") or "").strip()
        urls: List[str] = []
        raw = json.dumps(data, ensure_ascii=False)
        for token in raw.replace("\\/", "/").split('"'):
            if token.startswith("http://") or token.startswith("https://"):
                if token not in urls:
                    urls.append(token)
            if len(urls) >= max_results:
                break
        return {"provider": "openai", "query": query, "answer": answer, "urls": urls[:max_results], "raw": data}

    async def _web_search_gemini(self, query: str, max_results: int = 5) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "gemini api_key missing", "provider": self.provider, "query": query}
        url = f"{self.base_url.rstrip('/')}/models/{self.model}:generateContent"
        payload = {"contents": [{"role": "user", "parts": [{"text": query}]}], "tools": [{"google_search": {}}]}
        response = await self.http_client.post(url, params={"key": self.api_key}, json=payload)
        response.raise_for_status()
        data = response.json()
        candidates = data.get("candidates") or []
        answer_parts = []
        urls: List[str] = []
        if candidates:
            first = candidates[0]
            for part in (first.get("content") or {}).get("parts") or []:
                text = part.get("text")
                if text:
                    answer_parts.append(str(text))
            grounding = first.get("groundingMetadata") or {}
            for chunk in grounding.get("groundingChunks") or []:
                uri = ((chunk.get("web") or {}).get("uri") or "").strip()
                if uri and uri not in urls:
                    urls.append(uri)
                if len(urls) >= max_results:
                    break
        return {"provider": "gemini", "query": query, "answer": "\n".join(answer_parts).strip(), "urls": urls[:max_results], "raw": data}

    async def _web_search_claude(self, query: str, max_results: int = 5) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "claude api_key missing", "provider": self.provider, "query": query}
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.anthropic_version,
            "content-type": "application/json",
        }
        headers.update(get_provider_auth_headers(self.provider, self.endpoint_key, self.api_key))
        if self.anthropic_beta:
            headers["anthropic-beta"] = self.anthropic_beta
        url = self._anthropic_messages_url()
        payload = {
            "model": self.model,
            "max_tokens": min(2048, self._resolve_max_tokens(self.model, False)),
            "messages": [{"role": "user", "content": query}],
            "tools": [{"type": "web_search_20250305", "name": "web_search"}],
        }
        response = await self.http_client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        text_parts: List[str] = []
        urls: List[str] = []
        for block in data.get("content") or []:
            block_type = str(block.get("type") or "").strip()
            if block_type == "text":
                text = str(block.get("text") or "").strip()
                if text:
                    text_parts.append(text)
            if block_type in {"web_search_result", "search_result"}:
                for item in block.get("results") or []:
                    link = str(item.get("url") or item.get("uri") or "").strip()
                    if link and link not in urls:
                        urls.append(link)
                    if len(urls) >= max_results:
                        break
            if len(urls) >= max_results:
                break
        return {"provider": "claude", "query": query, "answer": "\n".join(text_parts).strip(), "urls": urls[:max_results], "raw": data}

    def append_assistant_message(self, messages: List[Dict[str, Any]], response: Dict[str, Any], include_reasoning: bool = False) -> List[Dict[str, Any]]:
        next_messages = list(messages)
        message = {"role": "assistant", "content": response.get("content") or ""}
        provider_name = str(response.get("provider") or self.provider or "").strip().lower()
        if include_reasoning and provider_name == "minimax":
            reasoning_details = response.get("reasoning_details")
            if isinstance(reasoning_details, list) and reasoning_details:
                # MiniMax 官方要求在工具调用多轮对话中保留完整 reasoning_details，
                # 否则会打断 interleaved thinking 的连续性。
                message["reasoning_details"] = reasoning_details
        if include_reasoning and provider_name in REASONING_CONTENT_PASSTHROUGH_PROVIDERS:
            reasoning_content = str(response.get("reasoning_content") or "")
            if reasoning_content:
                message["reasoning_content"] = reasoning_content
        
        tool_calls = response.get("tool_calls")
        if tool_calls:
            # Fix potentially invalid JSON arguments in tool calls before sending back to API
            fixed_tool_calls = []
            for tc in tool_calls:
                tc_copy = dict(tc)
                if "function" in tc_copy:
                    func_copy = dict(tc_copy["function"])
                    if "arguments" in func_copy:
                        args_str = func_copy["arguments"]
                        if isinstance(args_str, str):
                            try:
                                json.loads(args_str)
                            except json.JSONDecodeError:
                                # If invalid JSON, replace with empty object to prevent API 400 errors
                                func_copy["arguments"] = "{}"
                    tc_copy["function"] = func_copy
                fixed_tool_calls.append(tc_copy)
            message["tool_calls"] = fixed_tool_calls
            
        next_messages.append(message)
        return next_messages

    async def run_tool_call_loop(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        tool_executor: Callable[[Dict[str, Any]], Awaitable[str]],
        thinking_mode: Optional[bool] = None,
        model: Optional[str] = None,
        max_rounds: int = 6,
        use_beta: bool = False,
    ) -> Dict[str, Any]:
        current_messages = list(messages)
        use_thinking_mode = self.thinking_default if thinking_mode is None else bool(thinking_mode)
        use_model = model or self.get_default_model(use_thinking_mode)
        last_response: Dict[str, Any] = {}
        for _ in range(max_rounds):
            response = await self.chat(
                messages=current_messages,
                tools=tools,
                tool_choice="auto",
                thinking_mode=use_thinking_mode,
                model=use_model,
                use_beta=use_beta,
            )
            if not isinstance(response, dict):
                raise RuntimeError("run_tool_call_loop only supports non-streaming responses.")
            last_response = response
            current_messages = self.append_assistant_message(current_messages, response, include_reasoning=use_thinking_mode)
            tool_calls = response.get("tool_calls") or []
            if not tool_calls:
                return {
                    "response": response,
                    "messages": current_messages,
                    "completed": True,
                }
            for tool_call in tool_calls:
                function_data = tool_call.get("function") if isinstance(tool_call, dict) else {}
                tool_output = await tool_executor(tool_call)
                current_messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.get("id"),
                        "name": function_data.get("name") if isinstance(function_data, dict) else None,
                        "content": tool_output if isinstance(tool_output, str) else json.dumps(tool_output, ensure_ascii=False),
                    }
                )
        return {
            "response": last_response,
            "messages": current_messages,
            "completed": False,
        }

    @staticmethod
    def _build_prefix_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not messages:
            return []
        copied: List[Dict[str, Any]] = []
        for idx, message in enumerate(messages):
            item = dict(message)
            if idx == len(messages) - 1 and item.get("role") == "assistant":
                item["prefix"] = True
            copied.append(item)
        return copied
