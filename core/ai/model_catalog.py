"""Official AI provider catalog.

Sources checked on 2026-10-17:
- https://api-docs.deepseek.com/quick_start/pricing
- https://platform.minimax.io/docs/guides/models-intro
- https://platform.minimax.io/docs/guides/text-generation
- https://docs.bigmodel.cn/cn/guide/start/model-overview
- https://docs.bigmodel.cn/cn/coding-plan/quick-start
- https://help.aliyun.com/zh/model-studio/base-url
- https://help.aliyun.com/zh/model-studio/coding-plan
- https://mimo.mi.com/docs/en-US/quick-start/summary/first-api-call
- https://mimo.mi.com/docs/en-US/tokenplan/Token%20Plan/quick-access
- https://platform.kimi.com/docs/api/overview
- https://developers.openai.com/api/docs/models
- https://ai.google.dev/gemini-api/docs/models
- https://platform.claude.com/docs/en/models/overview

Token Plan / Coding Plan keys are not interchangeable with pay-as-you-go keys.
Some vendors also restrict plan keys to interactive coding tools.
"""

from __future__ import annotations

from typing import Any, Dict, List


def _endpoint(
    label: str,
    base_url: str,
    models: List[str],
    *,
    protocol: str = "openai-compatible",
    billing: str = "paygo",
    default_model: str = "",
    messages_path: str = "",
    auth_header: str = "bearer",
    note: str = "",
) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "label": label,
        "base_url": base_url,
        "protocol": protocol,
        "billing": billing,
        "models": list(models),
        "auth_header": auth_header,
    }
    if default_model:
        item["default_model"] = default_model
    if messages_path:
        item["messages_path"] = messages_path
    if note:
        item["note"] = note
    return item


DEEPSEEK_MODELS = ["deepseek-v4-pro", "deepseek-flash", "deepseek-v4-flash"]
MINIMAX_PAYGO_MODELS = [
    "MiniMax-M3",
    "MiniMax-M2.7",
    "MiniMax-M2.7-highspeed",
    "MiniMax-M2.5",
    "MiniMax-M2.5-highspeed",
    "MiniMax-M2.1",
    "MiniMax-M2",
]
MINIMAX_PLAN_MODELS = [
    "MiniMax-M3.1-Flash-Preview",
    "MiniMax-M3",
    "MiniMax-M2.7",
    "MiniMax-M2.7-highspeed",
]
GLM_PAYGO_MODELS = [
    "glm-5.3",
    "glm-5.3-flash",
    "glm-5.3-flashx",
    "glm-5.2",
    "glm-5.1",
    "glm-5",
    "glm-5-turbo",
    "glm-5v-turbo",
    "glm-4.7",
    "glm-4.7-flash",
    "glm-4.6",
]
GLM_PLAN_MODELS = ["glm-5.3", "glm-5.3-flash"]
QWEN_PAYGO_MODELS = [
    "qwen3.8-max",
    "qwen3.7-max",
    "qwen3.7-plus",
    "qwen3.6-plus",
    "qwen3.8-flash",
    "qwen3.6-flash",
    "qwen3.5-plus",
    "qwen3-max",
    "qwen-plus",
    "qwen-flash",
    "qwen3-coder-plus",
    "qwen3-coder-flash",
]
QWEN_TOKEN_PLAN_MODELS = [
    "qwen3.8-max",
    "qwen3.7-max",
    "qwen3.7-plus",
    "qwen3.6-plus",
    "qwen3.8-flash",
    "qwen3.6-flash",
    "qwen3.5-plus",
]
QWEN_CODING_PLAN_MODELS = [
    "qwen3.7-plus",
    "qwen3.6-plus",
    "qwen3.5-plus",
    "kimi-k2.5",
    "glm-5",
    "MiniMax-M2.5",
]
XIAOMI_MODELS = ["mimo-v2.6-pro", "mimo-v2.6-flash", "mimo-v2.6"]
KIMI_MODELS = ["kimi-k3", "kimi-k2.7-code", "kimi-k2.6", "kimi-k2.5", "kimi-k2", "moonshot-v1-128k"]
OPENAI_MODELS = [
    "gpt-6-astra",
    "gpt-6.1-sol",
    "gpt-6-luna",
    "gpt-5.5",
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-4.1",
]
GEMINI_MODELS = [
    "gemini-4-argon",
    "gemini-3.8-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-pro-preview",
    "gemini-3-flash-preview",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
]
CLAUDE_MODELS = [
    "claude-opus-5-5",
    "claude-fable-5-1",
    "claude-sonnet-5-5",
    "claude-haiku-5-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-sonnet-5",
    "claude-haiku-4-5",
]

ANTHROPIC_MESSAGES = "/v1/messages"
PLAN_NOTE = "套餐密钥与按量 API Key 不可混用。部分厂商限制套餐密钥只能用于官方允许的交互式编程工具。"


PROVIDER_CATALOG: Dict[str, Dict[str, Any]] = {
    "deepseek": {
        "label": "DeepSeek",
        "protocol": "openai-compatible",
        "discovery": "remote_models",
        "default_endpoint_key": "official",
        "default_model": "deepseek-v4-pro",
        "default_reasoner_model": "deepseek-v4-pro",
        "default_failover_models": ["deepseek-flash", "deepseek-v4-flash"],
        "endpoints": {
            "official": _endpoint(
                "按量付费 · OpenAI 兼容",
                "https://api.deepseek.com",
                DEEPSEEK_MODELS,
                default_model="deepseek-v4-pro",
                note="官方列出的 OpenAI 兼容根地址。旧名 deepseek-v4-flash 仍可调用，实际由 V4.1-Flash 承接。",
            ),
            "official_v1": _endpoint(
                "按量付费 · OpenAI 兼容 /v1",
                "https://api.deepseek.com/v1",
                DEEPSEEK_MODELS,
                default_model="deepseek-v4-pro",
            ),
            "anthropic": _endpoint(
                "按量付费 · Anthropic 兼容",
                "https://api.deepseek.com/anthropic",
                DEEPSEEK_MODELS,
                protocol="anthropic-official",
                default_model="deepseek-v4-pro",
                messages_path=ANTHROPIC_MESSAGES,
            ),
        },
        "legacy_model_aliases": {
            "deepseek-v4-preview": "deepseek-v4-pro",
            "deepseek-chat": "deepseek-flash",
            "deepseek-reasoner": "deepseek-v4-pro",
            "deepseek-v4-flash-vision-exp": "deepseek-flash",
        },
    },
    "minimax": {
        "label": "MiniMax",
        "protocol": "openai-compatible",
        "discovery": "catalog_only",
        "default_endpoint_key": "cn",
        "default_model": "MiniMax-M3",
        "default_reasoner_model": "MiniMax-M3",
        "default_failover_models": ["MiniMax-M2.7", "MiniMax-M2.7-highspeed"],
        "endpoints": {
            "cn": _endpoint(
                "中国大陆 · 按量付费 OpenAI",
                "https://api.minimaxi.com/v1",
                MINIMAX_PAYGO_MODELS,
                default_model="MiniMax-M3",
                note="使用开放平台按量 API Key。M2.5/M2.7 将于 2026-11-18 退役。",
            ),
            "cn_anthropic": _endpoint(
                "中国大陆 · 按量付费 Anthropic",
                "https://api.minimaxi.com/anthropic",
                MINIMAX_PAYGO_MODELS,
                protocol="anthropic-official",
                default_model="MiniMax-M3",
                messages_path=ANTHROPIC_MESSAGES,
            ),
            "intl": _endpoint(
                "国际 · 按量付费 OpenAI",
                "https://api.minimax.io/v1",
                MINIMAX_PAYGO_MODELS,
                default_model="MiniMax-M3",
            ),
            "intl_anthropic": _endpoint(
                "国际 · 按量付费 Anthropic",
                "https://api.minimax.io/anthropic",
                MINIMAX_PAYGO_MODELS,
                protocol="anthropic-official",
                default_model="MiniMax-M3",
                messages_path=ANTHROPIC_MESSAGES,
                note="官方推荐的 Anthropic 兼容地址。",
            ),
            "cn_token_plan": _endpoint(
                "中国大陆 · Token Plan / M Plan OpenAI",
                "https://api.minimaxi.com/v1",
                MINIMAX_PLAN_MODELS,
                billing="token_plan",
                default_model="MiniMax-M3.1-Flash-Preview",
                note="与按量接口同址，但必须使用订阅密钥。M3.1-Flash-Preview 目前仅套餐/MiniMax Code 可用。",
            ),
            "cn_token_plan_anthropic": _endpoint(
                "中国大陆 · Token Plan / M Plan Anthropic",
                "https://api.minimaxi.com/anthropic",
                MINIMAX_PLAN_MODELS,
                protocol="anthropic-official",
                billing="token_plan",
                default_model="MiniMax-M3.1-Flash-Preview",
                messages_path=ANTHROPIC_MESSAGES,
                note=PLAN_NOTE,
            ),
            "intl_token_plan": _endpoint(
                "国际 · Token Plan / M Plan OpenAI",
                "https://api.minimax.io/v1",
                MINIMAX_PLAN_MODELS,
                billing="token_plan",
                default_model="MiniMax-M3.1-Flash-Preview",
                note=PLAN_NOTE,
            ),
            "intl_token_plan_anthropic": _endpoint(
                "国际 · Token Plan / M Plan Anthropic",
                "https://api.minimax.io/anthropic",
                MINIMAX_PLAN_MODELS,
                protocol="anthropic-official",
                billing="token_plan",
                default_model="MiniMax-M3.1-Flash-Preview",
                messages_path=ANTHROPIC_MESSAGES,
                note="官方套餐示例使用该 Anthropic 地址与订阅密钥。",
            ),
        },
        "legacy_model_aliases": {
            "MiniMax-M2.7": "MiniMax-M2.7",
            "abab6.5s-chat": "MiniMax-M2",
        },
    },
    "zhipu": {
        "label": "GLM",
        "protocol": "openai-compatible",
        "discovery": "catalog_only",
        "default_endpoint_key": "official",
        "default_model": "glm-5.3",
        "default_reasoner_model": "glm-5.3",
        "default_failover_models": ["glm-5.3-flash", "glm-5.2", "glm-5.1"],
        "endpoints": {
            "official": _endpoint(
                "按量付费 · OpenAI Chat",
                "https://open.bigmodel.cn/api/paas/v4",
                GLM_PAYGO_MODELS,
                default_model="glm-5.3",
                note="标准 API Key，不可用于 Coding Plan 额度。",
            ),
            "coding_plan": _endpoint(
                "Coding Plan · OpenAI Chat",
                "https://open.bigmodel.cn/api/coding/paas/v4",
                GLM_PLAN_MODELS,
                billing="coding_plan",
                default_model="glm-5.3",
                note="必须使用 Coding Plan 专用 Key。历史模型名会由智谱自动切到 GLM-5.3 / GLM-5.3-Flash。",
            ),
            "coding_plan_anthropic": _endpoint(
                "Coding Plan · Anthropic",
                "https://open.bigmodel.cn/api/anthropic",
                GLM_PLAN_MODELS,
                protocol="anthropic-official",
                billing="coding_plan",
                default_model="glm-5.3",
                messages_path=ANTHROPIC_MESSAGES,
                note=PLAN_NOTE,
            ),
        },
        "legacy_model_aliases": {
            "glm-4-plus": "glm-5.3",
            "glm-5_1": "glm-5.1",
            "glm-5.1-turbo": "glm-5-turbo",
            "glm-4-air": "glm-4.7",
            "glm-4-flash": "glm-4.7-flash",
            "glm-5-turbo": "glm-5.3-flash",
        },
    },
    "qwen": {
        "label": "Qwen",
        "protocol": "openai-compatible",
        "discovery": "catalog_only",
        "default_endpoint_key": "cn_beijing",
        "default_model": "qwen3.8-max",
        "default_reasoner_model": "qwen3.8-max",
        "default_failover_models": ["qwen3.7-plus", "qwen3.6-plus", "qwen3.8-flash"],
        "endpoints": {
            "cn_beijing": _endpoint(
                "华北2北京 · 按量付费 OpenAI",
                "https://dashscope.aliyuncs.com/compatible-mode/v1",
                QWEN_PAYGO_MODELS,
                default_model="qwen3.8-max",
            ),
            "cn_beijing_anthropic": _endpoint(
                "华北2北京 · 按量付费 Anthropic",
                "https://dashscope.aliyuncs.com/apps/anthropic",
                QWEN_PAYGO_MODELS,
                protocol="anthropic-official",
                default_model="qwen3.8-max",
                messages_path=ANTHROPIC_MESSAGES,
            ),
            "us_virginia": _endpoint(
                "美国弗吉尼亚 · 按量付费 OpenAI",
                "https://dashscope-us.aliyuncs.com/compatible-mode/v1",
                ["qwen3.7-plus", "qwen3.6-plus", "qwen-plus", "qwen-flash"],
                default_model="qwen3.7-plus",
            ),
            "us_virginia_anthropic": _endpoint(
                "美国弗吉尼亚 · 按量付费 Anthropic",
                "https://dashscope-us.aliyuncs.com/apps/anthropic",
                ["qwen3.7-plus", "qwen3.6-plus", "qwen-plus", "qwen-flash"],
                protocol="anthropic-official",
                default_model="qwen3.7-plus",
                messages_path=ANTHROPIC_MESSAGES,
            ),
            "intl_singapore": _endpoint(
                "新加坡 · 按量付费 OpenAI",
                "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
                QWEN_PAYGO_MODELS,
                default_model="qwen3.8-max",
            ),
            "intl_singapore_anthropic": _endpoint(
                "新加坡 · 按量付费 Anthropic",
                "https://dashscope-intl.aliyuncs.com/apps/anthropic",
                QWEN_PAYGO_MODELS,
                protocol="anthropic-official",
                default_model="qwen3.8-max",
                messages_path=ANTHROPIC_MESSAGES,
            ),
            "cn_hongkong": _endpoint(
                "中国香港 · 按量付费 OpenAI",
                "https://cn-hongkong.dashscope.aliyuncs.com/compatible-mode/v1",
                QWEN_PAYGO_MODELS,
                default_model="qwen3.8-max",
            ),
            "token_plan": _endpoint(
                "Token Plan · 北京 OpenAI",
                "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
                QWEN_TOKEN_PLAN_MODELS,
                billing="token_plan",
                default_model="qwen3.8-max",
                note="使用 Token Plan 专属 Key。官方说明该地址仅限交互式 AI 工具，不能当作通用后端按量接口。",
            ),
            "token_plan_anthropic": _endpoint(
                "Token Plan · 北京 Anthropic",
                "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic",
                QWEN_TOKEN_PLAN_MODELS,
                protocol="anthropic-official",
                billing="token_plan",
                default_model="qwen3.8-max",
                messages_path=ANTHROPIC_MESSAGES,
                note=PLAN_NOTE,
            ),
            "coding_plan": _endpoint(
                "Coding Plan · OpenAI",
                "https://coding.dashscope.aliyuncs.com/v1",
                QWEN_CODING_PLAN_MODELS,
                billing="coding_plan",
                default_model="qwen3.7-plus",
                note="Key 以 sk-sp- 开头，与百炼按量 Key、Token Plan Key 均不互通。",
            ),
            "coding_plan_anthropic": _endpoint(
                "Coding Plan · Anthropic",
                "https://coding.dashscope.aliyuncs.com/apps/anthropic",
                QWEN_CODING_PLAN_MODELS,
                protocol="anthropic-official",
                billing="coding_plan",
                default_model="qwen3.7-plus",
                messages_path=ANTHROPIC_MESSAGES,
                note=PLAN_NOTE,
            ),
        },
        "legacy_model_aliases": {
            "qwen3-plus": "qwen3.7-plus",
            "qwen3.6-max": "qwen3.8-max",
            "qwen3.6-max-preview": "qwen3.8-max",
            "qwen3-max-preview": "qwen3.7-max",
            "qwen3.5-turbo": "qwen3.5-plus",
            "qwen-max": "qwen3.8-max",
            "qwen-max-latest": "qwen3.8-max",
            "qwen-plus-latest": "qwen-plus",
            "qwen-flash-latest": "qwen-flash",
        },
    },
    "xiaomi": {
        "label": "Xiaomi MiMo",
        "protocol": "openai-compatible",
        "discovery": "catalog_only",
        "default_endpoint_key": "official",
        "default_model": "mimo-v2.6-pro",
        "default_reasoner_model": "mimo-v2.6-pro",
        "default_failover_models": ["mimo-v2.6-flash", "mimo-v2.6"],
        "endpoints": {
            "official": _endpoint(
                "按量付费 · 中国 OpenAI",
                "https://api.xiaomimimo.com/v1",
                XIAOMI_MODELS,
                default_model="mimo-v2.6-pro",
                auth_header="both",
                note="按量 Key 格式 sk-。V2.5 请求自 2026-10-14 起会路由到 V2.6，旧 ID 于 2026-10-21 失效。",
            ),
            "official_anthropic": _endpoint(
                "按量付费 · 中国 Anthropic",
                "https://api.xiaomimimo.com/anthropic",
                XIAOMI_MODELS,
                protocol="anthropic-official",
                default_model="mimo-v2.6-pro",
                messages_path=ANTHROPIC_MESSAGES,
                auth_header="both",
            ),
            "token_plan_cn": _endpoint(
                "Token Plan · 中国 OpenAI",
                "https://token-plan-cn.xiaomimimo.com/v1",
                XIAOMI_MODELS,
                billing="token_plan",
                default_model="mimo-v2.6-pro",
                auth_header="both",
                note="个人套餐 Key 为 tp-，团队为 ttp-，不能使用按量 sk- Key。",
            ),
            "token_plan_cn_anthropic": _endpoint(
                "Token Plan · 中国 Anthropic",
                "https://token-plan-cn.xiaomimimo.com/anthropic",
                XIAOMI_MODELS,
                protocol="anthropic-official",
                billing="token_plan",
                default_model="mimo-v2.6-pro",
                messages_path=ANTHROPIC_MESSAGES,
                auth_header="both",
            ),
            "token_plan_sgp": _endpoint(
                "Token Plan · 新加坡 OpenAI",
                "https://token-plan-sgp.xiaomimimo.com/v1",
                XIAOMI_MODELS,
                billing="token_plan",
                default_model="mimo-v2.6-pro",
                auth_header="both",
            ),
            "token_plan_sgp_anthropic": _endpoint(
                "Token Plan · 新加坡 Anthropic",
                "https://token-plan-sgp.xiaomimimo.com/anthropic",
                XIAOMI_MODELS,
                protocol="anthropic-official",
                billing="token_plan",
                default_model="mimo-v2.6-pro",
                messages_path=ANTHROPIC_MESSAGES,
                auth_header="both",
            ),
            "token_plan_ams": _endpoint(
                "Token Plan · 欧洲 OpenAI",
                "https://token-plan-ams.xiaomimimo.com/v1",
                XIAOMI_MODELS,
                billing="token_plan",
                default_model="mimo-v2.6-pro",
                auth_header="both",
            ),
            "token_plan_ams_anthropic": _endpoint(
                "Token Plan · 欧洲 Anthropic",
                "https://token-plan-ams.xiaomimimo.com/anthropic",
                XIAOMI_MODELS,
                protocol="anthropic-official",
                billing="token_plan",
                default_model="mimo-v2.6-pro",
                messages_path=ANTHROPIC_MESSAGES,
                auth_header="both",
            ),
        },
        "legacy_model_aliases": {
            "mimo-v2.5-pro": "mimo-v2.6-pro",
            "mimo-v2.5": "mimo-v2.6-flash",
            "mimo-v2-pro": "mimo-v2.6-pro",
            "mimo-v2-flash": "mimo-v2.6-flash",
            "mimo-v2-omni": "mimo-v2.6",
        },
    },
    "moonshot": {
        "label": "Moonshot Kimi",
        "protocol": "openai-compatible",
        "discovery": "remote_models",
        "default_endpoint_key": "official",
        "default_model": "kimi-k3",
        "default_reasoner_model": "kimi-k3",
        "default_failover_models": ["kimi-k2.7-code", "kimi-k2.6", "kimi-k2.5"],
        "endpoints": {
            "official": _endpoint(
                "开放平台 · OpenAI",
                "https://api.moonshot.cn/v1",
                KIMI_MODELS,
                default_model="kimi-k3",
                note="platform.kimi.com 与 platform.kimi.ai 的 Key 不可混用。",
            ),
            "anthropic": _endpoint(
                "开放平台 · Anthropic",
                "https://api.moonshot.cn/anthropic",
                KIMI_MODELS,
                protocol="anthropic-official",
                default_model="kimi-k3",
                messages_path=ANTHROPIC_MESSAGES,
            ),
            "kimi_code": _endpoint(
                "Kimi Code / 会员密钥 · OpenAI",
                "https://api.moonshot.cn/v1",
                ["kimi-k3", "kimi-k2.7-code", "kimi-k2.6"],
                billing="token_plan",
                default_model="kimi-k3",
                note="会员/Kimi Code 密钥与开放平台按量 Key 不通用。官方当前未单列另一套根域名，调用协议仍是该 OpenAI 兼容地址。",
            ),
        },
        "legacy_model_aliases": {
            "kimi-latest": "kimi-k3",
            "kimi-k2.6": "kimi-k2.6",
            "moonshot-v1-auto": "kimi-k3",
            "moonshot-v1-8k": "kimi-k2.6",
            "moonshot-v1-32k": "kimi-k2.6",
        },
    },
    "openai": {
        "label": "ChatGPT",
        "protocol": "openai-compatible",
        "discovery": "remote_models",
        "default_endpoint_key": "official",
        "default_model": "gpt-6-astra",
        "default_reasoner_model": "gpt-6-astra",
        "default_failover_models": ["gpt-6.1-sol", "gpt-6-luna", "gpt-5.5"],
        "endpoints": {
            "official": _endpoint(
                "官方 API · Responses/Chat 兼容根地址",
                "https://api.openai.com/v1",
                OPENAI_MODELS,
                default_model="gpt-6-astra",
                note="ChatGPT Plus/Pro 订阅不是独立 API 端点。此处只接官方 API Key。",
            ),
        },
        "legacy_model_aliases": {
            "gpt-5.5": "gpt-5.5",
            "gpt-5.4-mini": "gpt-5.4-mini",
            "gpt-4o": "gpt-5.5",
            "gpt-4o-mini": "gpt-6-luna",
        },
    },
    "gemini": {
        "label": "Gemini",
        "protocol": "google-official",
        "discovery": "remote_models",
        "default_endpoint_key": "official",
        "default_model": "gemini-4-argon",
        "default_reasoner_model": "gemini-4-argon",
        "default_failover_models": ["gemini-3.8-flash", "gemini-3.6-flash", "gemini-3.1-pro-preview"],
        "endpoints": {
            "official": _endpoint(
                "Gemini API 官方",
                "https://generativelanguage.googleapis.com/v1beta",
                GEMINI_MODELS,
                protocol="google-official",
                default_model="gemini-4-argon",
                note="Google AI 订阅与 API Key 共用该官方地址，没有单独的 Token Plan 根域名。",
            ),
        },
        "legacy_model_aliases": {
            "gemini-3-pro": "gemini-3.1-pro-preview",
            "gemini-3.1-pro": "gemini-3.1-pro-preview",
            "gemini-3-pro-preview": "gemini-4-argon",
            "gemini-3-flash-preview": "gemini-3.8-flash",
            "gemini-2.5-pro": "gemini-2.5-pro",
            "gemini-2.5-flash": "gemini-3.8-flash",
        },
    },
    "claude": {
        "label": "Claude",
        "protocol": "anthropic-official",
        "discovery": "remote_models",
        "default_endpoint_key": "official",
        "default_model": "claude-opus-5-5",
        "default_reasoner_model": "claude-opus-5-5",
        "default_failover_models": ["claude-sonnet-5-5", "claude-fable-5-1", "claude-haiku-5-5"],
        "endpoints": {
            "official": _endpoint(
                "Claude API 官方",
                "https://api.anthropic.com/v1",
                CLAUDE_MODELS,
                protocol="anthropic-official",
                default_model="claude-opus-5-5",
                note="claude.ai 订阅不是独立 API 端点。此处使用 Claude API Key 与 Messages API。",
            ),
        },
        "legacy_model_aliases": {
            "claude-opus-4-7": "claude-opus-4-7",
            "claude-opus-4-6": "claude-opus-5-5",
            "claude-sonnet-4-6": "claude-sonnet-5-5",
            "claude-haiku-4-5": "claude-haiku-5-5",
            "claude-sonnet-4-20250514": "claude-sonnet-5-5",
            "claude-opus-4-20250514": "claude-opus-5-5",
        },
    },
    "ollama": {
        "label": "Ollama",
        "protocol": "openai-compatible",
        "discovery": "remote_models",
        "default_endpoint_key": "local",
        "default_model": "",
        "default_reasoner_model": "",
        "default_failover_models": [],
        "requires_api_key": False,
        "allow_custom_base_url": True,
        "freeform_models": True,
        "endpoints": {
            "local": _endpoint(
                "本地 / 远程 Ollama",
                "http://127.0.0.1:11434/v1",
                [],
                note="模型列表从本机 Ollama 发现。",
            ),
        },
        "legacy_model_aliases": {},
    },
    "custom": {
        "label": "Custom AI",
        "protocol": "openai-compatible",
        "discovery": "remote_models",
        "default_endpoint_key": "manual",
        "default_model": "",
        "default_reasoner_model": "",
        "default_failover_models": [],
        "requires_api_key": True,
        "allow_custom_base_url": True,
        "allow_custom_protocol": True,
        "freeform_models": True,
        "endpoints": {
            "manual": _endpoint("手动填写地址", "", [], billing="custom"),
        },
        "legacy_model_aliases": {},
    },
}
