from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Dict, List, Optional, Tuple

from core.ai.model_catalog import PROVIDER_CATALOG


PROVIDER_ALIASES = {
    "gpt": "openai",
    "openai_gpt": "openai",
    "kimi": "moonshot",
    "moonshot_ai": "moonshot",
    "xiaomi": "xiaomi",
    "mimo": "xiaomi",
}

PROTOCOL_ALIASES = {
    "openai": "openai-compatible",
    "openai-compatible": "openai-compatible",
    "anthropic": "anthropic-official",
    "anthropic-official": "anthropic-official",
    "google": "google-official",
    "gemini": "google-official",
    "google-official": "google-official",
}

CUSTOM_PROTOCOL_OPTIONS = [
    {"id": "openai-compatible", "label": "OpenAI Compatible"},
    {"id": "anthropic-official", "label": "Anthropic Messages"},
    {"id": "google-official", "label": "Google Gemini"},
]

OPENAI_COMPATIBLE_PROVIDERS = {
    provider for provider, item in PROVIDER_CATALOG.items() if item.get("protocol") == "openai-compatible"
}


def normalize_provider_name(provider: Any) -> str:
    key = str(provider or "").strip().lower()
    if not key:
        return "deepseek"
    return PROVIDER_ALIASES.get(key, key)


def list_supported_providers() -> List[str]:
    return list(PROVIDER_CATALOG.keys())


def is_supported_provider(provider: Any) -> bool:
    return normalize_provider_name(provider) in PROVIDER_CATALOG


def _parse_provider_list(raw: Any) -> List[str]:
    if isinstance(raw, list):
        return [str(item or "").strip() for item in raw if str(item or "").strip()]
    if isinstance(raw, str):
        return [segment.strip() for segment in raw.split(",") if segment and segment.strip()]
    return []


def normalize_provider_failover_order(raw: Any, default_provider: Any = None) -> List[str]:
    supported = list_supported_providers()
    default_name = normalize_provider_name(default_provider or supported[0])
    if default_name not in PROVIDER_CATALOG:
        default_name = supported[0]

    ordered: List[str] = []

    def _append(provider_name: Any) -> None:
        normalized = normalize_provider_name(provider_name)
        if normalized not in PROVIDER_CATALOG:
            return
        if normalized in ordered:
            return
        ordered.append(normalized)

    _append(default_name)
    for item in _parse_provider_list(raw):
        _append(item)
    for item in supported:
        _append(item)
    return ordered


def get_provider_definition(provider: Any) -> Dict[str, Any]:
    name = normalize_provider_name(provider)
    if name not in PROVIDER_CATALOG:
        raise KeyError(f"Unsupported provider: {provider}")
    return PROVIDER_CATALOG[name]


def get_provider_protocol(provider: Any) -> str:
    return str(get_provider_definition(provider).get("protocol") or "unknown")


def resolve_provider_protocol(provider: Any, raw_config: Optional[Dict[str, Any]] = None) -> str:
    name = normalize_provider_name(provider)
    definition = get_provider_definition(name)
    default_protocol = str(definition.get("protocol") or "unknown")
    source = dict(raw_config or {})
    if bool(definition.get("allow_custom_protocol")):
        candidate = str(source.get("protocol") or default_protocol).strip().lower()
        return PROTOCOL_ALIASES.get(candidate, default_protocol)
    endpoint_key = str(source.get("endpoint_key") or "").strip() or get_default_endpoint_key(name)
    endpoint = (definition.get("endpoints") or {}).get(endpoint_key) or {}
    endpoint_protocol = str(endpoint.get("protocol") or "").strip().lower()
    if endpoint_protocol:
        return PROTOCOL_ALIASES.get(endpoint_protocol, endpoint_protocol)
    return default_protocol


def get_provider_discovery(provider: Any) -> str:
    return str(get_provider_definition(provider).get("discovery") or "catalog_only")


def provider_requires_api_key(provider: Any) -> bool:
    return bool(get_provider_definition(provider).get("requires_api_key", True))


def provider_allows_custom_base_url(provider: Any) -> bool:
    return bool(get_provider_definition(provider).get("allow_custom_base_url"))


def provider_allows_custom_protocol(provider: Any) -> bool:
    return bool(get_provider_definition(provider).get("allow_custom_protocol"))


def provider_supports_freeform_models(provider: Any) -> bool:
    return bool(get_provider_definition(provider).get("freeform_models"))


def get_provider_protocol_options(provider: Any) -> List[Dict[str, str]]:
    definition = get_provider_definition(provider)
    options = definition.get("protocol_options") or CUSTOM_PROTOCOL_OPTIONS
    return [
        {"id": str(item.get("id") or "").strip(), "label": str(item.get("label") or item.get("id") or "").strip()}
        for item in options
        if str(item.get("id") or "").strip()
    ]


def get_default_endpoint_key(provider: Any) -> str:
    definition = get_provider_definition(provider)
    return str(definition.get("default_endpoint_key") or "")


def get_provider_endpoints(provider: Any) -> Dict[str, Dict[str, Any]]:
    return deepcopy(get_provider_definition(provider).get("endpoints") or {})


def get_provider_endpoint(provider: Any, endpoint_key: Optional[str] = None) -> Dict[str, Any]:
    definition = get_provider_definition(provider)
    endpoints = definition.get("endpoints") or {}
    selected = str(endpoint_key or "").strip() or get_default_endpoint_key(provider)
    endpoint = endpoints.get(selected)
    if endpoint:
        item = deepcopy(endpoint)
        item["key"] = selected
        return item
    fallback_key = get_default_endpoint_key(provider)
    item = deepcopy(endpoints.get(fallback_key) or {})
    item["key"] = fallback_key
    return item


def get_provider_base_url(provider: Any, endpoint_key: Optional[str] = None) -> str:
    return str(get_provider_endpoint(provider, endpoint_key).get("base_url") or "").strip()


def get_provider_beta_base_url(provider: Any, endpoint_key: Optional[str] = None) -> str:
    endpoint = get_provider_endpoint(provider, endpoint_key)
    return str(endpoint.get("beta_base_url") or get_provider_base_url(provider, endpoint_key)).strip()


def get_provider_messages_path(provider: Any, endpoint_key: Optional[str] = None) -> str:
    return str(get_provider_endpoint(provider, endpoint_key).get("messages_path") or "").strip()


def get_provider_auth_headers(provider: Any, endpoint_key: Optional[str] = None, api_key: str = "") -> Dict[str, str]:
    endpoint = get_provider_endpoint(provider, endpoint_key)
    mode = str(endpoint.get("auth_header") or "bearer").strip().lower()
    secret = str(api_key or "").strip()
    headers: Dict[str, str] = {}
    if secret and mode in {"api-key", "both"}:
        headers["api-key"] = secret
    return headers


def get_provider_models(provider: Any, endpoint_key: Optional[str] = None) -> List[str]:
    endpoint = get_provider_endpoint(provider, endpoint_key)
    return [str(item or "").strip() for item in endpoint.get("models") or [] if str(item or "").strip()]


def get_provider_default_model(provider: Any, endpoint_key: Optional[str] = None) -> str:
    endpoint = get_provider_endpoint(provider, endpoint_key)
    endpoint_default = str(endpoint.get("default_model") or "").strip()
    models = get_provider_models(provider, endpoint_key)
    model_set = set(models)
    if endpoint_default and (not model_set or endpoint_default in model_set):
        return endpoint_default
    configured = str(get_provider_definition(provider).get("default_model") or "").strip()
    if configured and configured in model_set:
        return configured
    return models[0] if models else ""


def get_provider_default_reasoner_model(provider: Any, endpoint_key: Optional[str] = None) -> str:
    configured = str(get_provider_definition(provider).get("default_reasoner_model") or "").strip()
    models = set(get_provider_models(provider, endpoint_key))
    if configured and configured in models:
        return configured
    return get_provider_default_model(provider, endpoint_key)


def get_provider_default_failover_models(provider: Any, endpoint_key: Optional[str] = None) -> List[str]:
    definition = get_provider_definition(provider)
    defaults = [str(item or "").strip() for item in definition.get("default_failover_models") or [] if str(item or "").strip()]
    available_models = get_provider_models(provider, endpoint_key)
    available = set(available_models)
    filtered = [item for item in defaults if item in available]
    if filtered:
        return filtered

    default_model = get_provider_default_model(provider, endpoint_key)
    fallbacks: List[str] = []
    for item in available_models:
        if not item or item == default_model or item in fallbacks:
            continue
        fallbacks.append(item)
    return fallbacks[:3]


def get_provider_label(provider: Any) -> str:
    return str(get_provider_definition(provider).get("label") or normalize_provider_name(provider))


def get_provider_catalog_payload() -> Dict[str, Any]:
    providers: List[Dict[str, Any]] = []
    for provider in list_supported_providers():
        definition = get_provider_definition(provider)
        endpoints = []
        for endpoint_key, endpoint in (definition.get("endpoints") or {}).items():
            endpoints.append(
                {
                    "key": endpoint_key,
                    "label": str(endpoint.get("label") or endpoint_key),
                    "base_url": str(endpoint.get("base_url") or ""),
                    "protocol": str(endpoint.get("protocol") or get_provider_protocol(provider)),
                    "billing": str(endpoint.get("billing") or "paygo"),
                    "default_model": get_provider_default_model(provider, endpoint_key),
                    "auth_header": str(endpoint.get("auth_header") or "bearer"),
                    "note": str(endpoint.get("note") or ""),
                    "models": list(get_provider_models(provider, endpoint_key)),
                }
            )
        providers.append(
            {
                "id": provider,
                "label": get_provider_label(provider),
                "protocol": get_provider_protocol(provider),
                "discovery": get_provider_discovery(provider),
                "default_endpoint_key": get_default_endpoint_key(provider),
                "default_model": get_provider_default_model(provider),
                "default_reasoner_model": get_provider_default_reasoner_model(provider),
                "default_failover_models": get_provider_default_failover_models(provider),
                "requires_api_key": provider_requires_api_key(provider),
                "allow_custom_base_url": provider_allows_custom_base_url(provider),
                "allow_custom_protocol": provider_allows_custom_protocol(provider),
                "freeform_models": provider_supports_freeform_models(provider),
                "protocol_options": get_provider_protocol_options(provider) if provider_allows_custom_protocol(provider) else [],
                "endpoints": endpoints,
            }
        )
    return {"providers": providers}


def is_provider_model_supported(provider: Any, model: Any, endpoint_key: Optional[str] = None) -> bool:
    value = str(model or "").strip()
    return bool(value) and value in set(get_provider_models(provider, endpoint_key))


def _normalize_url_candidate(raw_url: Any) -> str:
    text = str(raw_url or "").strip().strip("`").strip("'").strip('"').strip().lower().rstrip("/")
    for suffix in ("/chat/completions", "/messages"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
    if text.endswith("/responses"):
        text = text[: -len("/responses")]
    text = re.sub(r"/models/[^/]+:generatecontent$", "", text)
    if text == "https://api.minimax.chat/v1":
        return "https://api.minimaxi.com/v1"
    return text


def resolve_endpoint_key(
    provider: Any,
    endpoint_key: Optional[str] = None,
    base_url: Optional[str] = None,
) -> Tuple[str, List[str]]:
    name = normalize_provider_name(provider)
    definition = get_provider_definition(name)
    endpoints = definition.get("endpoints") or {}
    selected = str(endpoint_key or "").strip()
    warnings: List[str] = []
    if selected and selected in endpoints:
        return selected, warnings
    if provider_allows_custom_base_url(name):
        default_key = get_default_endpoint_key(name)
        if selected and selected not in endpoints:
            warnings.append(f"endpoint_key '{selected}' is invalid for provider '{name}', fallback to '{default_key}'")
        return default_key, warnings

    normalized_url = _normalize_url_candidate(base_url)
    if normalized_url:
        for candidate_key, candidate in endpoints.items():
            candidate_url = _normalize_url_candidate(candidate.get("base_url"))
            if normalized_url == candidate_url:
                if str(endpoint_key or "").strip() and str(endpoint_key).strip() != candidate_key:
                    warnings.append(f"endpoint_key migrated to official option '{candidate_key}'")
                return candidate_key, warnings
        warnings.append(f"custom endpoint removed for provider '{name}', fallback to official endpoint")

    default_key = get_default_endpoint_key(name)
    if selected and selected not in endpoints:
        warnings.append(f"endpoint_key '{selected}' is invalid for provider '{name}', fallback to '{default_key}'")
    return default_key, warnings


def _parse_string_list(raw: Any) -> List[str]:
    if isinstance(raw, list):
        return [str(item or "").strip() for item in raw if str(item or "").strip()]
    if isinstance(raw, str):
        return [segment.strip() for segment in raw.split(",") if segment and segment.strip()]
    return []


def _canonical_model(provider: str, model: Any) -> str:
    value = str(model or "").strip()
    if not value:
        return ""
    aliases = get_provider_definition(provider).get("legacy_model_aliases") or {}
    return str(aliases.get(value, value)).strip()


def get_runtime_provider_base_url(provider: Any, raw_config: Optional[Dict[str, Any]] = None) -> str:
    name = normalize_provider_name(provider)
    config = dict(raw_config or {})
    if provider_allows_custom_base_url(name):
        candidate = _normalize_url_candidate(config.get("base_url"))
        if candidate:
            return candidate
    endpoint_key = str(config.get("endpoint_key") or get_default_endpoint_key(name)).strip()
    return get_provider_base_url(name, endpoint_key)


def normalize_provider_config(provider: Any, raw_config: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], List[str]]:
    name = normalize_provider_name(provider)
    source = dict(raw_config or {})
    endpoint_key, warnings = resolve_endpoint_key(name, source.get("endpoint_key"), source.get("base_url"))
    protocol = resolve_provider_protocol(name, source)
    catalog_models = get_provider_models(name, endpoint_key)
    discovered_models = _parse_string_list(source.get("discovered_models"))
    effective_models = discovered_models or catalog_models
    supported_models = set(effective_models)
    default_model = get_provider_default_model(name, endpoint_key)
    if default_model not in supported_models and effective_models:
        default_model = effective_models[0]
    default_reasoner_model = get_provider_default_reasoner_model(name, endpoint_key)
    if default_reasoner_model not in supported_models:
        default_reasoner_model = default_model

    freeform_models = provider_supports_freeform_models(name)
    model = _canonical_model(name, source.get("model"))
    reasoner_model = _canonical_model(name, source.get("reasoner_model"))
    failover_models: List[str] = []
    if freeform_models:
        if not model:
            model = default_model or (effective_models[0] if effective_models else "")
        if not reasoner_model:
            reasoner_model = model
        for item in _parse_string_list(source.get("failover_models")):
            candidate = _canonical_model(name, item)
            if not candidate or candidate == model or candidate in failover_models:
                continue
            failover_models.append(candidate)
        if not failover_models:
            fallback_candidates = get_provider_default_failover_models(name, endpoint_key)
            if discovered_models and not fallback_candidates:
                fallback_candidates = [item for item in effective_models if item and item != model]
            for item in fallback_candidates:
                if item != model and item not in failover_models:
                    failover_models.append(item)
    else:
        if not model or model not in supported_models:
            if source.get("model"):
                warnings.append(f"model '{source.get('model')}' is not supported by provider '{name}', fallback to '{default_model}'")
            model = default_model

        if not reasoner_model or reasoner_model not in supported_models:
            fallback_reasoner = default_reasoner_model if default_reasoner_model in supported_models else model
            if source.get("reasoner_model"):
                warnings.append(
                    f"reasoner_model '{source.get('reasoner_model')}' is not supported by provider '{name}', fallback to '{fallback_reasoner}'"
                )
            reasoner_model = fallback_reasoner

        for item in _parse_string_list(source.get("failover_models")):
            candidate = _canonical_model(name, item)
            if not candidate:
                continue
            if candidate == model:
                continue
            if candidate not in supported_models:
                warnings.append(f"failover model '{item}' is not supported by provider '{name}' and has been removed")
                continue
            if candidate in failover_models:
                continue
            failover_models.append(candidate)
        if not failover_models:
            fallback_candidates = get_provider_default_failover_models(name, endpoint_key)
            if discovered_models and not fallback_candidates:
                fallback_candidates = [item for item in effective_models if item and item != model]
            for item in fallback_candidates:
                if item != model and item not in failover_models:
                    failover_models.append(item)

    normalized = {
        "api_key": str(source.get("api_key") or "").strip(),
        "endpoint_key": endpoint_key,
        "model": model,
        "reasoner_model": reasoner_model,
        "failover_models": failover_models,
        "temperature": source.get("temperature", 0.0),
        "max_tokens": source.get("max_tokens", 32768),
        "timeout": source.get("timeout", 0),
    }
    if provider_allows_custom_base_url(name):
        normalized["base_url"] = get_runtime_provider_base_url(name, source)
    if provider_allows_custom_protocol(name):
        normalized["protocol"] = protocol
    for optional_key in (
        "discovered_models",
        "max_tokens_chat",
        "max_tokens_reasoner",
        "thinking_default",
        "thinking_type",
        "reasoning_effort",
        "context_max_chars",
        "context_keep_recent_blocks",
        "context_message_max_chars",
        "anthropic_version",
        "anthropic_beta",
    ):
        if optional_key in source:
            normalized[optional_key] = source.get(optional_key)
    return normalized, warnings


def migrate_ai_config(config: Dict[str, Any]) -> Dict[str, Any]:
    payload = deepcopy(config or {})
    ai = payload.setdefault("ai", {})
    current_default = normalize_provider_name(ai.get("default_provider"))
    if current_default not in PROVIDER_CATALOG:
        current_default = "deepseek"
    ai["default_provider"] = current_default
    ai["provider_failover_order"] = normalize_provider_failover_order(ai.get("provider_failover_order"), current_default)
    providers = ai.setdefault("providers", {})
    normalized_providers: Dict[str, Dict[str, Any]] = {}
    for provider in list_supported_providers():
        normalized, _ = normalize_provider_config(provider, providers.get(provider, {}) or {})
        normalized_providers[provider] = normalized
    ai["providers"] = normalized_providers
    return payload
