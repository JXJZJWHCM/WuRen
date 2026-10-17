const { createApp, ref, computed, onMounted, onBeforeUnmount, nextTick, watch } = Vue;

        createApp({
            setup() {
                const views = [
                    { id: 'project-control', label: '项目控制台' },
                    { id: 'attack-chain', label: '攻击链' },
                    { id: 'sessions', label: '会话管理' },
                    { id: 'files', label: '文件管理' },
                    { id: 'cli', label: '终端沙盒' },
                    { id: 'report', label: '渗透报告' },
                    { id: 'lib-knowledge', label: '知识库' },
                    { id: 'lib-skills', label: '技能库' },
                    { id: 'lib-vuldb', label: '漏洞库' },
                    { id: 'lib-fingerprints', label: '指纹库' },
                    { id: 'lib-plugins', label: '插件库' },
                    { id: 'lib-poc-exp', label: 'POC/EXP库' },
                    { id: 'lib-custom-tools', label: '自定义工具库' },
                    { id: 'lib-audit-rules', label: '网页审计规则库' },
                    { id: 'learning', label: '自我学习' },
                    { id: 'web-audit', label: 'Web源码审计' },
                    { id: 'settings', label: '平台设置' }
                ];
                const getView = (id) => views.find(item => item.id === id);
                const viewGroups = [
                    { id: 'group-ops', label: '执行控制', items: [getView('project-control'), getView('attack-chain'), getView('sessions'), getView('files'), getView('cli'), getView('report')].filter(Boolean) },
                    { id: 'group-lib', label: '武器与资产库', items: [getView('lib-knowledge'), getView('lib-skills'), getView('lib-vuldb'), getView('lib-fingerprints'), getView('lib-plugins'), getView('lib-poc-exp'), getView('lib-custom-tools'), getView('lib-audit-rules')].filter(Boolean) },
                    { id: 'group-extensions', label: '扩展功能', items: [getView('learning'), getView('web-audit')].filter(Boolean) },
                    { id: 'group-platform', label: '系统管理', items: [getView('settings')].filter(Boolean) }
                ];

                const libraryViewMap = {
                    'lib-fingerprints': 'fingerprints',
                    'lib-plugins': 'plugins',
                    'lib-vuldb': 'vuldb',
                    'lib-knowledge': 'knowledge',
                    'lib-skills': 'skills',
                    'lib-poc-exp': 'poc_exp',
                    'lib-custom-tools': 'custom_tools',
                    'lib-audit-rules': 'audit_rules'
                };
                const multiLibraryViewMap = {};
                const libTypeLabelMap = {
                    knowledge: '知识库',
                    skills: '技能库',
                    vuldb: '漏洞库',
                    fingerprints: '指纹库',
                    plugins: '插件库',
                    poc_exp: 'POC/EXP 库',
                    custom_tools: '自定义工具库',
                    audit_rules: '网页审计规则库'
                };

                const activeView = ref('project-control');
                const mobileNavOpen = ref(false);
                const serverStatus = ref('checking');
                const selectedLibType = ref('');
                const loading = ref(false);
                const notice = ref({ type: 'success', message: '' });
                const projects = ref([]);
                const selectedProjectId = ref('');
                const newProject = ref({ target: '', description: '' });
                const liveLogs = ref([]);
                const logStreamRef = ref(null);
                const autoFollowLogStream = ref(true);
                const lastUiInteractionAt = ref(Date.now());
                const LOG_STREAM_IDLE_MS = 30000;
                const MAX_LIVE_LOG_ENTRIES = 600;
                let logSocket = null;
                let logIdleTimer = null;

                const attackChainData = ref({});
                const attackChainStages = computed(() => {
                    const data = attackChainData.value || {};
                    if (Array.isArray(data.stages)) return data.stages;
                    if (Array.isArray(data.chain)) return data.chain;
                    if (Array.isArray(data.items)) return data.items;
                    return [];
                });
                const attackChainMetrics = computed(() => {
                    const data = attackChainData.value || {};
                    const fallback = {
                        completed: attackChainStages.value.filter(item => String(item?.status || '') === 'completed').length,
                        running: attackChainStages.value.filter(item => String(item?.status || '') === 'running').length,
                        failed: attackChainStages.value.filter(item => ['failed', 'error'].includes(String(item?.status || ''))).length,
                        insufficient_evidence: attackChainStages.value.filter(item => String(item?.status || '') === 'insufficient_evidence').length
                    };
                    return (data.stage_counts && typeof data.stage_counts === 'object') ? { ...fallback, ...data.stage_counts } : fallback;
                });
                const attackChainUsage = computed(() => {
                    const data = attackChainData.value || {};
                    return (data.usage_summary && typeof data.usage_summary === 'object') ? data.usage_summary : {};
                });
                const attackGraph = computed(() => {
                    const graph = attackChainData.value?.attack_graph;
                    return (graph && typeof graph === 'object') ? graph : { nodes: [], edges: [] };
                });
                const attackChainViolations = computed(() => {
                    const violations = attackChainData.value?.sequence_constraints?.violations;
                    return Array.isArray(violations) ? violations : [];
                });
                const attackChainSelectedStagePhase = ref('');
                const fileOps = ref({ action: 'list', path: '.', content: '', recursive: false, max_entries: 200 });
                const fileOpsResult = ref({});
                const sessionState = ref({ items: [], selectedSessionId: '', newSessionName: '', status: {} });
                const sessionBackend = ref({ mode: 'workspace', msf_binary: 'msfconsole' });
                const shellState = ref({ items: [], selectedShellId: '', lastLoadedAt: 0 });
                const sessionDraft = ref({ name: '', cwd: '.', shellId: '' });
                const uploadState = ref({ file: null });

                const cliForm = ref({ command: '', cwd: '', timeout: 120 });
                const cliResult = ref({});

                const reportGenerateResult = ref({});
                const latestReport = ref({ content: '' });
                const latestReportMeta = ref({});
                const autoLoadedReportProject = ref('');

                const libraryState = ref({ path: '', filePath: '', content: '', recursive: false });
                const libraryItems = ref([]);
                const libraryResultMeta = ref({});

const providerCatalog = ref({ providers: [], checked_at: null });
const providerModelOptions = ref({});
const modelListKey = (provider, endpointKey) => `${String(provider || '').trim()}::${String(endpointKey || '').trim()}`;
const buildCatalogModelOptions = (catalogPayload) => {
    const options = {};
    const providers = Array.isArray(catalogPayload?.providers) ? catalogPayload.providers : [];
    providers.forEach(provider => {
        const providerId = String(provider?.id || '').trim();
        const endpoints = Array.isArray(provider?.endpoints) ? provider.endpoints : [];
        endpoints.forEach(endpoint => {
            const endpointKey = String(endpoint?.key || '').trim();
            options[modelListKey(providerId, endpointKey)] = Array.isArray(endpoint?.models)
                ? endpoint.models.map(item => String(item || '').trim()).filter(Boolean)
                : [];
        });
    });
    return options;
};
const providerCatalogMap = computed(() => {
    const map = {};
    const providers = Array.isArray(providerCatalog.value?.providers) ? providerCatalog.value.providers : [];
    providers.forEach(item => {
        const providerId = String(item?.id || '').trim();
        if (providerId) map[providerId] = item;
    });
    return map;
});
const getCatalogProvider = (provider) => providerCatalogMap.value[String(provider || '').trim()] || null;
const getCatalogEndpoint = (provider, endpointKey = null) => {
    const providerEntry = getCatalogProvider(provider);
    if (!providerEntry) return null;
    const endpoints = Array.isArray(providerEntry.endpoints) ? providerEntry.endpoints : [];
    return endpoints.find(item => item.key === String(endpointKey || '').trim())
        || endpoints.find(item => item.key === providerEntry.default_endpoint_key)
        || endpoints[0]
        || null;
};
const getAvailableModels = (provider, endpointKey = null) => {
    const cacheKey = modelListKey(provider, endpointKey);
    const cached = providerModelOptions.value[cacheKey];
    if (Array.isArray(cached) && cached.length) return cached;
    const endpoint = getCatalogEndpoint(provider, endpointKey);
    return Array.isArray(endpoint?.models) ? endpoint.models : [];
};
const settingsForm = ref({
    provider: 'deepseek',
    default_provider: 'deepseek',
    provider_failover_order: [],
    endpoint_key: 'official',
    protocol: 'openai-compatible',
    base_url: '',
    model: '',
    failover_models: [],
    failover_models_text: '',
    api_key: '',
    access_key: '',
});
const settingsResult = ref({});
const loadedModelsResult = ref({});
const providerOptions = computed(() => Array.isArray(providerCatalog.value?.providers) ? providerCatalog.value.providers : []);
const providerLabelOverrides = {
    deepseek: 'DeepSeek',
    minimax: 'MiniMax',
    zhipu: '智谱 GLM',
    qwen: '通义千问',
    xiaomi: '小米 MiMo',
    moonshot: '月之暗面 Kimi',
    openai: 'OpenAI',
    gemini: 'Google Gemini',
    claude: 'Claude',
    ollama: 'Ollama 本地模型',
    custom: '自定义兼容接口',
};
const displayProviderLabel = (providerId, fallbackLabel = '') => {
    const normalized = String(providerId || '').trim();
    if (!normalized) return String(fallbackLabel || '').trim() || '-';
    return providerLabelOverrides[normalized] || String(fallbackLabel || '').trim() || normalized;
};
const displayEndpointLabel = (label, endpointKey = '') => {
    const normalizedLabel = String(label || '').trim();
    const normalizedKey = String(endpointKey || '').trim();
    if (normalizedLabel) return normalizedLabel;
    const presetMap = {
        official: '官方接口',
        cn: '中国大陆节点',
        intl: '国际节点',
        cn_beijing: '中国大陆节点',
        local: '本地 / 远程 Ollama',
        manual: '手动填写地址',
    };
    if (presetMap[normalizedKey]) return presetMap[normalizedKey];
    const replacements = [
        ['Official', '官方接口'],
        ['China Mainland', '中国大陆节点'],
        ['International', '国际节点'],
        ['Local / Remote Ollama', '本地 / 远程 Ollama'],
        ['Manual Endpoint', '手动填写地址'],
    ];
    return replacements.reduce((text, [from, to]) => text.replace(from, to), normalizedLabel);
};
const displayProtocolLabel = (protocol) => {
    const normalized = String(protocol || '').trim();
    const protocolMap = {
        'openai-compatible': 'OpenAI 兼容协议',
        'anthropic-official': 'Anthropic 官方协议',
        'google-official': 'Google Gemini 官方协议',
    };
    return protocolMap[normalized] || normalized || '-';
};
const displayDiscoveryLabel = (discovery) => {
    const normalized = String(discovery || '').trim();
    if (normalized === 'remote_models') return '支持联网读取官方模型列表';
    if (normalized === 'catalog_only') return '使用内置模型目录';
    return normalized || '-';
};
const configuredProviderChain = computed(() => Array.isArray(settingsResult.value?.configured_provider_chain) ? settingsResult.value.configured_provider_chain : []);
const effectiveProviderFailoverOrder = computed(() => {
    const explicit = Array.isArray(settingsForm.value.provider_failover_order) ? settingsForm.value.provider_failover_order : [];
    const normalizedExplicit = explicit.map(item => String(item || '').trim()).filter(Boolean);
    if (normalizedExplicit.length) return normalizedExplicit;
    return providerOptions.value.map(item => String(item?.id || '').trim()).filter(Boolean);
});
const providerSaveFailoverOrder = computed(() => {
    // 以“默认厂商”为主排序，避免仅编辑某个厂商配置时误改全局默认链路。
    const primaryProvider = String(settingsForm.value.default_provider || settingsForm.value.provider || '').trim();
    const catalogProviders = providerOptions.value
        .map(item => String(item?.id || '').trim())
        .filter(Boolean);
    if (!primaryProvider) {
        return catalogProviders;
    }
    return [primaryProvider, ...catalogProviders.filter(item => item !== primaryProvider)];
});
const currentProviderEntry = computed(() => getCatalogProvider(settingsForm.value.provider) || providerOptions.value[0] || null);
const currentProviderEndpoints = computed(() => Array.isArray(currentProviderEntry.value?.endpoints) ? currentProviderEntry.value.endpoints : []);
const currentEndpoint = computed(() => getCatalogEndpoint(settingsForm.value.provider, settingsForm.value.endpoint_key));
const currentProviderRequiresApiKey = computed(() => Boolean(currentProviderEntry.value?.requires_api_key !== false));
const currentProviderAllowsCustomBaseUrl = computed(() => Boolean(currentProviderEntry.value?.allow_custom_base_url));
const currentProviderAllowsCustomProtocol = computed(() => Boolean(currentProviderEntry.value?.allow_custom_protocol));
const currentProviderFreeformModels = computed(() => Boolean(currentProviderEntry.value?.freeform_models));
const currentProtocolOptions = computed(() => Array.isArray(currentProviderEntry.value?.protocol_options) ? currentProviderEntry.value.protocol_options : []);
const currentProviderModels = computed(() => {
    const provider = String(settingsForm.value.provider || '').trim();
    const endpointKey = String(settingsForm.value.endpoint_key || '').trim();
    const models = getAvailableModels(provider, endpointKey);
    const current = String(settingsForm.value.model || '').trim();
    if (current && !models.includes(current)) return [current, ...models];
    return models;
});
const currentSelectableFailoverModels = computed(() => {
    const activeModel = String(settingsForm.value.model || '').trim();
    return currentProviderModels.value.filter(item => String(item || '').trim() && String(item || '').trim() !== activeModel);
});
const currentProviderBaseUrl = computed(() => {
    if (currentProviderAllowsCustomBaseUrl.value) {
        return String(settingsForm.value.base_url || currentEndpoint.value?.base_url || '');
    }
    return String(currentEndpoint.value?.base_url || '');
});
const currentProviderDisplayLabel = computed(() => displayProviderLabel(settingsForm.value.provider, currentProviderEntry.value?.label));
const currentEndpointDisplayLabel = computed(() => displayEndpointLabel(currentEndpoint.value?.label, currentEndpoint.value?.key));
const currentEndpointNote = computed(() => String(currentEndpoint.value?.note || '').trim());
const currentProtocolDisplayLabel = computed(() => displayProtocolLabel(settingsForm.value.protocol || currentProviderEntry.value?.protocol));
const currentProviderDiscoveryLabel = computed(() => displayDiscoveryLabel(currentProviderEntry.value?.discovery));
const currentModelInputPlaceholder = computed(() => (
    currentProviderFreeformModels.value
        ? '输入模型名称'
        : '选择模型'
));
const currentBaseUrlInputPlaceholder = computed(() => (
    currentProviderAllowsCustomBaseUrl.value
        ? '输入接口地址'
        : '官方接口地址'
));
const currentApiKeyInputPlaceholder = computed(() => (
    currentProviderRequiresApiKey.value
        ? '输入请求密钥'
        : '请求密钥'
));
const currentApiKeyStatusText = computed(() => {
    const masked = String(settingsResult.value?.api_key_masked || '').trim();
    if (masked) return `已保存：${masked}`;
    return '';
});
const effectiveProviderChainDisplay = computed(() => {
    const chain = (configuredProviderChain.value.length ? configuredProviderChain.value : effectiveProviderFailoverOrder.value)
        .map(item => displayProviderLabel(item))
        .filter(Boolean);
    return chain.length ? chain.join(' → ') : '仅当前厂商';
});
const providerSaveStrategyText = computed(() => {
    const chain = providerSaveFailoverOrder.value.map(item => displayProviderLabel(item)).filter(Boolean);
    return chain.length ? chain.join(' → ') : '未选择厂商';
});
const currentMigrationWarnings = computed(() => Array.isArray(settingsResult.value?.migration_warnings) ? settingsResult.value.migration_warnings : []);
const showEndpointSelector = computed(() => currentProviderEndpoints.value.length > 1);
const loadedAiModelRows = computed(() => {
    const loadedResult = loadedModelsResult.value || {};
    const rows = Array.isArray(loadedResult.loaded_models) ? loadedResult.loaded_models : [];
    return rows;
});
const failedAiModelRows = computed(() => {
    const loadedResult = loadedModelsResult.value || {};
    const rows = Array.isArray(loadedResult.failed_models) ? loadedResult.failed_models : [];
    return rows;
});
const loadedAiSummary = computed(() => {
    const payload = settingsResult.value || {};
    const loadedResult = loadedModelsResult.value || {};
    return {
        configured_count: Number(loadedResult.configured_count || 0),
        loaded_count: Number(loadedResult.loaded_count || 0),
        checked: Boolean(payload.load_test_triggered),
    };
});
const parseFailoverModelsText = (raw) => String(raw || '')
    .split(/[\n,]/g)
    .map(item => String(item || '').trim())
    .filter(Boolean);
const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj || {}, key);
const syncFailoverModelsText = (models) => {
    settingsForm.value.failover_models_text = Array.isArray(models) ? models.map(item => String(item || '').trim()).filter(Boolean).join('\n') : '';
};
const setFailoverModels = (models) => {
    const normalized = Array.isArray(models)
        ? models.map(item => String(item || '').trim()).filter(Boolean).filter((item, idx, arr) => arr.indexOf(item) === idx)
        : [];
    settingsForm.value.failover_models = normalized;
    syncFailoverModelsText(normalized);
};
const toggleFailoverModel = (model) => {
    const target = String(model || '').trim();
    if (!target) return;
    const current = Array.isArray(settingsForm.value.failover_models) ? [...settingsForm.value.failover_models] : [];
    const next = current.includes(target) ? current.filter(item => item !== target) : [...current, target];
    setFailoverModels(next);
};
                const learningForm = ref({ topic: '', content: '', urlsText: '' });
                const learningResult = ref({});
                const learningHistory = ref({ keyword: '', item_type: '', limit: 50, offset: 0 });
                const learningHistoryResult = ref({});
                const webAuditForm = ref({ target: '', auto_fix_rules: true, use_yak: true, timeout_seconds: 20 });
                const webAuditValidationResult = ref({});
                const webAuditRunResult = ref({});

                const currentViewLabel = computed(() => views.find(v => v.id === activeView.value)?.label || '');
                const currentLibCandidates = computed(() => multiLibraryViewMap[activeView.value] || []);
                const currentLibType = computed(() => {
                    if (libraryViewMap[activeView.value]) return libraryViewMap[activeView.value];
                    if (!currentLibCandidates.value.length) return '';
                    if (currentLibCandidates.value.includes(selectedLibType.value)) return selectedLibType.value;
                    return currentLibCandidates.value[0];
                });
                const currentLibTypeLabel = computed(() => libTypeLabelMap[currentLibType.value] || currentLibType.value || '');
                const isLibraryView = computed(() => !!currentLibType.value);
                const managedSessions = computed(() => (
                    Array.isArray(sessionState.value.items)
                        ? sessionState.value.items
                        : []
                ));
                const recentShellSessions = computed(() => (
                    Array.isArray(shellState.value.items) ? shellState.value.items : []
                ));
                const selectedManagedSession = computed(() => (
                    managedSessions.value.find(item => item.session_id === sessionState.value.selectedSessionId) || null
                ));
                const sessionWorkspaceRoot = computed(() => (
                    sessionState.value.status?.workspace_root
                    || selectedManagedSession.value?.workspace_root
                    || ''
                ));
                const selectedSessionHealth = computed(() => {
                    const health = sessionState.value.status?.health;
                    return (health && typeof health === 'object') ? health : {};
                });
                const selectedAttackStage = computed(() => {
                    if (!attackChainStages.value.length) return null;
                    return attackChainStages.value.find(item => item.phase === attackChainSelectedStagePhase.value)
                        || attackChainStages.value.find(item => String(item?.status || '') === 'running')
                        || attackChainStages.value.find(item => String(item?.status || '') !== 'completed')
                        || attackChainStages.value[attackChainStages.value.length - 1]
                        || null;
                });
                const attackChainOverviewCards = computed(() => {
                    const progress = Number(attackChainData.value?.progress || 0);
                    const normalizedProgress = Math.max(0, Math.min(progress > 1 ? progress : progress * 100, 100));
                    return [
                        {
                            key: 'progress',
                            label: '整体推进',
                            value: `${Math.round(normalizedProgress)}%`,
                            tone: 'primary',
                            help: `当前阶段：${attackChainData.value?.phase || 'pending'}`
                        },
                        {
                            key: 'validated',
                            label: '已验证漏洞',
                            value: String(attackChainData.value?.sequence_constraints?.validated_vulnerability_count || 0),
                            tone: 'warning',
                            help: '用于解锁利用阶段'
                        },
                        {
                            key: 'shells',
                            label: '有效 Shell',
                            value: String(attackChainData.value?.sequence_constraints?.active_shell_count || 0),
                            tone: 'success',
                            help: '用于后渗透与横向'
                        },
                        {
                            key: 'violations',
                            label: '链路阻断',
                            value: String(attackChainViolations.value.length),
                            tone: attackChainViolations.value.length ? 'danger' : 'muted',
                            help: attackChainViolations.value.length ? '存在跳步执行或证据缺口' : '未发现阻断'
                        }
                    ];
                });
                const fileResultEntries = computed(() => {
                    const items = fileOpsResult.value?.items;
                    return Array.isArray(items) ? items : [];
                });
                const sessionCommandHistory = computed(() => {
                    const history = sessionState.value.status?.command_history;
                    return Array.isArray(history) ? [...history].reverse() : [];
                });
                const sessionFileHistory = computed(() => {
                    const history = sessionState.value.status?.file_history;
                    return Array.isArray(history) ? [...history].reverse() : [];
                });
                const commandPresets = [
                    { label: '身份', command: 'whoami' },
                    { label: '当前目录', command: 'pwd' },
                    { label: '目录列表', command: 'ls -la' },
                    { label: '网络配置', command: 'ipconfig /all' },
                    { label: '进程列表', command: 'tasklist' },
                    { label: '主机信息', command: 'hostname' },
                ];

                const shortId = (id) => (id || '').toString().slice(0, 8);
                const pretty = (obj) => JSON.stringify(obj || {}, null, 2);
                const formatInt = (value) => {
                    const n = Number(value || 0);
                    if (!Number.isFinite(n)) return '0';
                    return Math.round(n).toLocaleString('zh-CN');
                };
                const escapeHtml = (unsafe) => {
                    return (unsafe || '').replace(/&/g, "&amp;")
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;")
                        .replace(/"/g, "&quot;")
                        .replace(/'/g, "&#039;");
                };
                const basename = (value) => {
                    const text = String(value || '').replaceAll('\\', '/');
                    const parts = text.split('/');
                    return parts[parts.length - 1] || text || '-';
                };
                const normalizePathText = (value) => String(value || '').replaceAll('\\', '/').trim();
                const formatDateTime = (value) => {
                    const ts = Number(value || 0);
                    if (!Number.isFinite(ts) || ts <= 0) return '-';
                    const date = new Date(ts > 1e12 ? ts : ts * 1000);
                    return date.toLocaleString('zh-CN', { hour12: false });
                };
                const formatRelativeTime = (value) => {
                    const ts = Number(value || 0);
                    if (!Number.isFinite(ts) || ts <= 0) return '-';
                    const delta = Math.max(0, Math.round(Date.now() / 1000 - (ts > 1e12 ? ts / 1000 : ts)));
                    if (delta < 60) return `${delta} 秒前`;
                    if (delta < 3600) return `${Math.floor(delta / 60)} 分钟前`;
                    if (delta < 86400) return `${Math.floor(delta / 3600)} 小时前`;
                    return `${Math.floor(delta / 86400)} 天前`;
                };
                const formatDuration = (value) => {
                    const duration = Number(value || 0);
                    if (!Number.isFinite(duration) || duration <= 0) return '-';
                    if (duration < 1) return `${Math.round(duration * 1000)} ms`;
                    if (duration < 60) return `${duration.toFixed(duration >= 10 ? 1 : 2)} s`;
                    const minutes = Math.floor(duration / 60);
                    const seconds = Math.round(duration % 60);
                    return `${minutes} 分 ${seconds} 秒`;
                };
                const formatBytes = (value) => {
                    const size = Number(value || 0);
                    if (!Number.isFinite(size) || size < 0) return '-';
                    if (size < 1024) return `${size} B`;
                    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
                    if (size < 1024 * 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`;
                    return `${(size / 1024 / 1024 / 1024).toFixed(1)} GB`;
                };
                const normalizeSessionPath = (value) => {
                    const text = normalizePathText(value || '.');
                    if (!text) return '.';
                    return text;
                };
                const toWorkspaceRelativePath = (value) => {
                    const normalizedValue = String(value || '').replaceAll('\\', '/');
                    const workspaceRoot = String(sessionWorkspaceRoot.value || '').replaceAll('\\', '/');
                    if (!normalizedValue) return '.';
                    if (!workspaceRoot) return normalizedValue;
                    if (normalizedValue === workspaceRoot) return '.';
                    if (normalizedValue.startsWith(`${workspaceRoot}/`)) {
                        return normalizedValue.slice(workspaceRoot.length + 1) || '.';
                    }
                    return normalizedValue;
                };
                const resolveFileEntryPath = (item) => {
                    const rawPath = item?.path || item?.name || '.';
                    if (String(selectedManagedSession.value?.backend_mode || '').toLowerCase() === 'msf') {
                        return normalizeSessionPath(rawPath);
                    }
                    return normalizeSessionPath(toWorkspaceRelativePath(rawPath));
                };
                const sessionHealthLabel = (status) => {
                    const text = String(status || '').trim().toLowerCase();
                    if (text === 'online') return '在线';
                    if (text === 'offline') return '离线';
                    if (text === 'unknown') return '未知';
                    return text || '未知';
                };
                const sessionHealthClass = (status) => {
                    const text = String(status || '').trim().toLowerCase();
                    if (text === 'online') return 'tone-success';
                    if (text === 'offline') return 'tone-danger';
                    return 'tone-muted';
                };
                const shellHostLabel = (item) => String(item?.target || item?.host || item?.raw?.host || '-');
                const shellUserLabel = (item) => String(item?.user || item?.raw?.user || item?.raw?.username || '未知用户');
                const shellTypeLabel = (item) => String(item?.type || item?.raw?.type || 'unknown');
                const shellStatusLabel = (status) => {
                    const text = String(status || '').trim().toLowerCase();
                    if (text === 'active' || text === 'online') return '可用';
                    if (text === 'closed' || text === 'offline') return '失效';
                    return text || '未知';
                };
                const stageTitle = (stage) => (
                    stage?.attack?.title
                    || stage?.name
                    || stage?.phase
                    || '未知阶段'
                );
                const normalizeLogLevel = (value) => {
                    const text = String(value || 'INFO');
                    const matched = text.match(/name='([^']+)'/);
                    if (matched?.[1]) return matched[1].toUpperCase();
                    return text.toUpperCase();
                };
                const formatLogTimestamp = (value) => {
                    const ts = Number(value || 0);
                    if (!Number.isFinite(ts) || ts <= 0) return new Date().toLocaleTimeString();
                    const date = new Date(ts > 1e12 ? ts : ts * 1000);
                    return date.toLocaleTimeString('zh-CN', { hour12: false });
                };
                const prettyArgs = (value) => {
                    if (!value || typeof value !== 'object') return '';
                    try {
                        return JSON.stringify(value, null, 2);
                    } catch (_) {
                        return String(value);
                    }
                };
                const logLevelClass = (level) => {
                    const normalized = normalizeLogLevel(level);
                    if (normalized === 'ERROR') return 'log-level-error';
                    if (normalized === 'WARNING' || normalized === 'WARN') return 'log-level-warn';
                    if (normalized === 'INFO') return 'log-level-info';
                    return 'log-level-default';
                };
                const providerVerifyStatusLabel = (status) => {
                    const text = String(status || '').trim().toLowerCase();
                    if (text === 'ok') return '通过';
                    if (text === 'model_mismatch') return '模型不匹配';
                    if (text === 'api_key_missing') return '密钥缺失';
                    if (text === 'auth_error') return '鉴权失败';
                    if (text === 'network_timeout') return '网络超时';
                    if (text === 'dns_error') return 'DNS异常';
                    if (text === 'network_error') return '网络异常';
                    return '未知';
                };
                const providerVerifyStatusClass = (status) => {
                    const text = String(status || '').trim().toLowerCase();
                    if (text === 'ok') return 'text-emerald-600';
                    if (text === 'model_mismatch') return 'text-amber-600';
                    if (text === 'api_key_missing') return 'text-slate-500';
                    return 'text-rose-600';
                };
                const normalizeDisplayText = (value) => String(value || '').replace(/\r\n/g, '\n').trim();
                const toChineseThinking = (value) => {
                    const text = normalizeDisplayText(value);
                    if (!text) return '';
                    return text;
                };
                const toToolResultEcho = (payload) => {
                    const text = normalizeDisplayText(payload?.tool_result_excerpt);
                    if (!text) return '';
                    const skipPatterns = [
                        /^status=\d+\s*\|\s*returncode=0$/i,
                        /^success=true$/i,
                        /^ok$/i
                    ];
                    if (skipPatterns.some(pattern => pattern.test(text))) return '';
                    return text;
                };
                const toToolCommand = (payload) => {
                    const explicit = normalizeDisplayText(payload?.tool_command || payload?.tool_help_command);
                    if (explicit) return explicit;
                    const result = payload?.tool_result_excerpt || '';
                    const matched = String(result).match(/command['"]?\s*[:=]\s*['"]([^'"]+)['"]/i);
                    return matched?.[1] ? normalizeDisplayText(matched[1]) : '';
                };
                const scrollLogStreamToLatest = () => {
                    nextTick(() => {
                        const el = logStreamRef.value;
                        if (!el) return;
                        el.scrollTop = el.scrollHeight;
                    });
                };
                const updateAutoFollowFromScroll = () => {
                    const el = logStreamRef.value;
                    if (!el) return;
                    markUiInteraction();
                    const distance = el.scrollHeight - (el.scrollTop + el.clientHeight);
                    autoFollowLogStream.value = distance <= 16;
                };
                const markUiInteraction = () => {
                    lastUiInteractionAt.value = Date.now();
                };
                const isCurrentLogPageActive = () => {
                    if (activeView.value !== 'project-control') return false;
                    if (document.visibilityState !== 'visible') return false;
                    if (typeof document.hasFocus === 'function' && !document.hasFocus()) return false;
                    return true;
                };
                const shouldAutoTrackLatestLog = () => {
                    if (!isCurrentLogPageActive()) return false;
                    return Date.now() - lastUiInteractionAt.value > LOG_STREAM_IDLE_MS;
                };
                const trimLiveLogs = () => {
                    if (liveLogs.value.length > MAX_LIVE_LOG_ENTRIES) {
                        liveLogs.value = liveLogs.value.slice(-MAX_LIVE_LOG_ENTRIES);
                    }
                };
                const buildLiveLogEntry = (raw, payload) => {
                    const level = normalizeLogLevel(payload?.level || 'INFO');
                    const phase = String(payload?.phase || 'runtime');
                    const message = normalizeDisplayText(payload?.message || raw);
                    const thinking = toChineseThinking(payload?.reasoning_content);
                    const finalAnswer = normalizeDisplayText(payload?.ai_content);
                    const toolName = normalizeDisplayText(payload?.tool_name);
                    const toolArguments = prettyArgs(payload?.tool_arguments);
                    const toolCommand = toToolCommand(payload);
                    const toolEcho = toToolResultEcho(payload);
                    const stableId = payload?.id || payload?.event_id || `${payload?.timestamp || Date.now() / 1000}-${phase}-${message.slice(0, 48)}`;
                    return {
                        id: stableId,
                        timestamp: payload?.timestamp || Date.now() / 1000,
                        level,
                        phase,
                        message,
                        thinking,
                        finalAnswer,
                        toolName,
                        toolArguments,
                        toolCommand,
                        toolEcho,
                    };
                };
                const replaceLiveLogs = (entries) => {
                    liveLogs.value = Array.isArray(entries) ? entries : [];
                    trimLiveLogs();
                    if (autoFollowLogStream.value) {
                        scrollLogStreamToLatest();
                    }
                };
                const appendLiveLogEntry = (entry) => {
                    if (!entry) return;
                    liveLogs.value.push(entry);
                    trimLiveLogs();
                    if (autoFollowLogStream.value) {
                        scrollLogStreamToLatest();
                    }
                };
                const domainRegex = /^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;
                const ipv4Regex = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
                const PROJECT_TARGET_MAX_LENGTH = 253;
                const PROJECT_DESCRIPTION_MAX_LENGTH = 160;
                const projectInjectionRules = [
                    {
                        // 明显的英文提示注入句式
                        pattern: /\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|messages?)\b/i,
                        message: '描述中疑似包含“忽略前文指令”类注入语句。'
                    },
                    {
                        // 角色标签通常不应出现在项目备注中
                        pattern: /^\s*(?:system|developer|assistant|user)\s*:/i,
                        message: '描述中疑似包含角色指令片段。'
                    },
                    {
                        pattern: /<\s*\/?\s*(?:system|developer|assistant|user)\s*>/i,
                        message: '描述中疑似包含角色标签。'
                    },
                    {
                        pattern: /\b(?:system\s+prompt|prompt\s+injection)\b/i,
                        message: '描述中疑似包含提示注入关键词。'
                    },
                    {
                        pattern: /\b(?:act|behave)\s+as\b/i,
                        message: '描述中疑似包含角色扮演指令。'
                    },
                    {
                        pattern: /\b(?:bypass|override)\b[\s\S]{0,24}\b(?:safety|guardrails?|restrictions?|policy)\b/i,
                        message: '描述中疑似包含绕过限制的指令。'
                    }
                ];
                const normalizeInlineText = (value) => String(value || '')
                    .replace(/[\u0000-\u001F\u007F]+/g, ' ')
                    .replace(/\u3000/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim();
                const inspectProjectTarget = (rawValue) => {
                    const value = normalizeInlineText(rawValue);
                    if (!value) {
                        return {
                            value: '',
                            valid: false,
                            level: 'neutral',
                            message: '仅支持域名或 IPv4，勿填写协议、端口、路径或参数。'
                        };
                    }
                    if (value.length > PROJECT_TARGET_MAX_LENGTH) {
                        return {
                            value,
                            valid: false,
                            level: 'error',
                            message: `目标长度不能超过 ${PROJECT_TARGET_MAX_LENGTH} 个字符。`
                        };
                    }
                    if (/^https?:\/\//i.test(value) || /[\/\\?#]/.test(value) || /:\d+$/.test(value)) {
                        return {
                            value,
                            valid: false,
                            level: 'error',
                            message: '目标仅填写主机名或 IPv4，请去掉协议、端口、路径与查询参数。'
                        };
                    }
                    if (domainRegex.test(value) || ipv4Regex.test(value)) {
                        return {
                            value,
                            valid: true,
                            level: 'success',
                            message: '格式正确，可直接创建项目。'
                        };
                    }
                    return {
                        value,
                        valid: false,
                        level: 'error',
                        message: '目标仅支持域名或 IPv4 地址。'
                    };
                };
                const inspectProjectDescription = (rawValue) => {
                    const value = normalizeInlineText(rawValue);
                    if (!value) {
                        return {
                            value: '',
                            valid: true,
                            level: 'neutral',
                            length: 0,
                            message: '描述为可选项，建议填写资产归属、业务用途或测试备注。'
                        };
                    }
                    if (value.length > PROJECT_DESCRIPTION_MAX_LENGTH) {
                        return {
                            value,
                            valid: false,
                            level: 'error',
                            length: value.length,
                            message: `描述长度不能超过 ${PROJECT_DESCRIPTION_MAX_LENGTH} 个字符。`
                        };
                    }
                    const hitRule = projectInjectionRules.find(rule => rule.pattern.test(value));
                    if (hitRule) {
                        return {
                            value,
                            valid: false,
                            level: 'error',
                            length: value.length,
                            message: hitRule.message
                        };
                    }
                    return {
                        value,
                        valid: true,
                        level: value.length > 120 ? 'warning' : 'success',
                        length: value.length,
                        message: value.length > 120 ? '描述较长，建议仅保留必要业务备注。' : '描述内容正常。'
                    };
                };
                const projectDraftValidation = computed(() => {
                    const target = inspectProjectTarget(newProject.value.target);
                    const description = inspectProjectDescription(newProject.value.description);
                    const submitDisabled = loading.value || !target.valid || !description.valid;
                    const primaryError = target.valid ? description.message : target.message;
                    return {
                        target,
                        description,
                        submitDisabled,
                        primaryError,
                        canSubmit: !submitDisabled
                    };
                });
                const normalizeProjectField = (field) => {
                    if (!newProject.value || !Object.prototype.hasOwnProperty.call(newProject.value, field)) return;
                    if (field === 'target') {
                        newProject.value.target = inspectProjectTarget(newProject.value.target).value;
                        return;
                    }
                    if (field === 'description') {
                        newProject.value.description = inspectProjectDescription(newProject.value.description).value;
                    }
                };
                const displayProgress = (progress) => {
                    const p = Number(progress || 0);
                    const normalized = p > 1 ? p : p * 100;
                    const clamped = Math.max(0, Math.min(normalized, 100));
                    return `${Math.round(clamped)}%`;
                };
                const progressFraction = (project) => {
                    const p = Number(project?.progress ?? project?.current_progress ?? 0);
                    const normalized = p > 1 ? p / 100 : p;
                    if (!Number.isFinite(normalized)) return 0;
                    return Math.max(0, Math.min(normalized, 1));
                };
                const projectUsage = (project) => {
                    const summary = project?.results?.usage_summary;
                    return (summary && typeof summary === 'object') ? summary : {};
                };
                const normalizeProjectStatus = (project) => {
                    return String(
                        project?.status ||
                        project?.state ||
                        project?.runtime_status ||
                        'unknown'
                    ).toLowerCase();
                };
                const displayProjectStatus = (project) => {
                    const status = normalizeProjectStatus(project);
                    if (status.includes('run')) return '运行中';
                    if (status.includes('pause')) return '已暂停';
                    if (status.includes('stop')) return '已停止';
                    if (status.includes('insufficient')) return '证据不足';
                    if (status.includes('complete')) return '已完成';
                    if (status.includes('fail') || status.includes('error')) return '异常';
                    if (status === 'unknown') return '待启动';
                    return status;
                };
                const statusDotClass = (project) => {
                    const status = normalizeProjectStatus(project);
                    if (status.includes('run')) return 'status-running';
                    if (status.includes('pause')) return 'status-paused';
                    if (status.includes('insufficient')) return 'status-insufficient';
                    if (status.includes('complete')) return 'status-completed';
                    if (status.includes('fail') || status.includes('error')) return 'status-failed';
                    return 'status-stopped';
                };
                const displayStageStatus = (status) => {
                    const text = String(status || '').toLowerCase();
                    if (text === 'completed') return '已完成';
                    if (text === 'running') return '运行中';
                    if (text === 'paused') return '已暂停';
                    if (text === 'insufficient_evidence') return '证据不足';
                    if (text === 'failed' || text === 'error') return '失败';
                    if (text === 'unknown') return '未知';
                    return '待处理';
                };
                const statusBadgeClass = (status) => {
                    const text = String(status || '').toLowerCase();
                    if (text === 'completed') return 'border-white/30 bg-emerald-50 text-emerald-700';
                    if (text === 'running') return 'border-blue-200 bg-blue-50 text-blue-700';
                    if (text === 'paused') return 'border-white/30 bg-amber-50 text-amber-700';
                    if (text === 'insufficient_evidence') return 'border-orange-200 bg-orange-50 text-orange-700';
                    if (text === 'failed' || text === 'error') return 'border-rose-200 bg-rose-50 text-rose-700';
                    return 'border-slate-200 bg-slate-50 text-slate-600';
                };

                const setNotice = (message, type = 'success') => {
                    const normalizedType = type === 'warn' ? 'warning' : type;
                    notice.value = { message, type: normalizedType };
                    setTimeout(() => {
                        if (notice.value.message === message) notice.value.message = '';
                    }, 2500);
                };
                const toggleMobileNav = () => {
                    mobileNavOpen.value = !mobileNavOpen.value;
                };

                const closeMobileNav = () => {
                    mobileNavOpen.value = false;
                };

                const ensureProjectSelected = () => {
                    if (!selectedProjectId.value) {
                        setNotice('请先选择项目。', 'error');
                        return false;
                    }
                    return true;
                };

                const ensureSessionSelected = async () => {
                    if (!ensureProjectSelected()) return false;
                    await loadSessions();
                    if (!sessionState.value.selectedSessionId) {
                        setNotice('请先创建并选择会话。', 'error');
                        return false;
                    }
                    const exists = managedSessions.value.some(item => item.session_id === sessionState.value.selectedSessionId);
                    if (!exists) {
                        sessionState.value.selectedSessionId = '';
                        sessionState.value.status = {};
                        setNotice('当前选择不是可控制会话，请先从 Shell 创建工作会话。', 'error');
                        return false;
                    }
                    return true;
                };
                const validateSessionBackendInput = () => {
                    if (sessionBackend.value.mode === 'msf' && !String(sessionBackend.value.msf_binary || '').trim()) {
                        setNotice('启用渗透会话模式时，MSF 程序路径不能为空。', 'error');
                        return false;
                    }
                    return true;
                };
                const validateSessionDraft = () => {
                    const name = String(sessionDraft.value.name || '').trim();
                    const cwd = normalizeSessionPath(sessionDraft.value.cwd || '.');
                    if (!name) {
                        setNotice('请输入会话名称。', 'error');
                        return false;
                    }
                    if (name.length > 128) {
                        setNotice('会话名称长度不能超过 128 个字符。', 'error');
                        return false;
                    }
                    if (!cwd || cwd.includes('..')) {
                        setNotice('工作目录仅支持会话工作区内的相对路径。', 'error');
                        return false;
                    }
                    sessionDraft.value.name = name;
                    sessionDraft.value.cwd = cwd;
                    sessionDraft.value.shellId = String(sessionDraft.value.shellId || '').trim();
                    return true;
                };
                const validateFileOperationInput = () => {
                    const action = String(fileOps.value.action || '').trim().toLowerCase();
                    const path = normalizeSessionPath(fileOps.value.path || '.');
                    const maxEntries = Number(fileOps.value.max_entries || 200);
                    if (!path) {
                        setNotice('请输入目标路径。', 'error');
                        return false;
                    }
                    if (!['list', 'read', 'write', 'delete'].includes(action)) {
                        setNotice('不支持的文件操作类型。', 'error');
                        return false;
                    }
                    if (!Number.isFinite(maxEntries) || maxEntries < 1 || maxEntries > 2000) {
                        setNotice('最大条目数仅支持 1 到 2000。', 'error');
                        return false;
                    }
                    if (action === 'delete' && ['.', './', '/'].includes(path)) {
                        setNotice('禁止直接删除工作区根目录。', 'error');
                        return false;
                    }
                    fileOps.value.path = path;
                    fileOps.value.max_entries = Math.min(2000, Math.max(1, Math.round(maxEntries)));
                    return true;
                };
                const validateCliInput = () => {
                    const command = String(cliForm.value.command || '').trim();
                    const timeout = Number(cliForm.value.timeout || 0);
                    if (!command) {
                        setNotice('命令不能为空。', 'error');
                        return false;
                    }
                    if (!Number.isFinite(timeout) || timeout < 0 || timeout > 3600) {
                        setNotice('命令超时时间仅支持 0 到 3600 秒。', 'error');
                        return false;
                    }
                    cliForm.value.command = command;
                    cliForm.value.timeout = Math.round(timeout);
                    return true;
                };

                const safeRequest = async (task, successMsg = '') => {
                    loading.value = true;
                    try {
                        const result = await task();
                        if (successMsg) setNotice(successMsg, 'success');
                        return result;
                    } catch (error) {
                        const msg = error?.response?.data?.detail || error.message || '请求失败';
                        if (String(msg).toLowerCase().includes('session not found')) {
                            sessionState.value.selectedSessionId = '';
                            sessionState.value.status = {};
                            try { await loadSessions(); } catch (_) {}
                        }
                        setNotice(msg, 'error');
                        throw error;
                    } finally {
                        loading.value = false;
                    }
                };

                const requestConfig = () => {
                    const accessKey = String(settingsForm.value.access_key || '').trim();
                    if (!accessKey) return {};
                    return { headers: { 'X-Admin-Key': accessKey } };
                };
                const initializeProtectedRuntime = async () => {
                    await fetchProjects();
                    try {
                        await loadSessionBackend();
                        await loadProviderCatalog(true);
                    } catch (_) {
                        serverStatus.value = 'offline';
                    }
                };
                const fetchProjects = async () => {
                    try {
                        await safeRequest(async () => {
                            const res = await axios.get('/api/projects');
                            projects.value = res.data || [];
                            serverStatus.value = 'online';
                            const projectExists = projects.value.some(item => item.id === selectedProjectId.value);
                            if (!projectExists) selectedProjectId.value = '';
                            if (!selectedProjectId.value && projects.value.length > 0) {
                                selectedProjectId.value = projects.value[0].id;
                            }
                        });
                        await loadSessions();
                        await loadShells();
                        await loadProjectEventLogs(selectedProjectId.value, true, true);
                        if (serverStatus.value === 'online' && !logSocket) {
                            initLiveLogs();
                        }
                    } catch (error) {
                        serverStatus.value = 'offline';
                    }
                };

                const silentFetchProjects = async () => {
                    try {
                        const res = await axios.get('/api/projects');
                        projects.value = res.data || [];
                        serverStatus.value = 'online';
                        await silentLoadShells();
                        await ensureCompletedProjectReportReady();
                    } catch (error) {
                        serverStatus.value = 'offline';
                    }
                };
                const updateProjectRuntimeByEvent = (payload) => {
                    if (!payload || !payload.project_id) return;
                    const idx = projects.value.findIndex(item => item.id === payload.project_id);
                    if (idx < 0) return;
                    const current = projects.value[idx] || {};
                    const nextStatus = payload.status || current.status;
                    const nextPhase = payload.phase || current.phase;
                    const hasProgress = payload.progress !== undefined && payload.progress !== null;
                    const nextProgress = hasProgress ? Number(payload.progress) : Number(current.progress || 0);
                    const normalizedProgress = Number.isFinite(nextProgress) ? Math.max(0, Math.min(1, nextProgress > 1 ? nextProgress / 100 : nextProgress)) : Number(current.progress || 0);
                    const prevProgress = progressFraction(current);
                    const mergedProgress = ['running', 'paused'].includes(String(nextStatus || '').toLowerCase())
                        ? Math.max(prevProgress, normalizedProgress)
                        : normalizedProgress;
                    projects.value[idx] = {
                        ...current,
                        status: nextStatus,
                        phase: nextPhase,
                        progress: mergedProgress
                    };
                };
                const onSelectedProjectChange = async () => {
                    await loadSessions();
                    await loadShells();
                    await silentLoadAttackChain();
                    await ensureCompletedProjectReportReady();
                    await loadProjectEventLogs(selectedProjectId.value, true, true);
                };
                const selectProject = async (projectId) => {
                    if (!projectId) return;
                    selectedProjectId.value = projectId;
                    await onSelectedProjectChange();
                };
                const runProjectAction = async (projectId, action) => {
                    await selectProject(projectId);
                    await controlProject(action);
                };
                const removeProject = async (projectId) => {
                    if (!projectId) return;
                    if (!window.confirm('确认删除该项目吗？此操作不可恢复。')) return;
                    selectedProjectId.value = projectId;
                    await deleteProject();
                };

                const loadSessions = async () => {
                    if (!selectedProjectId.value) {
                        sessionState.value.items = [];
                        sessionState.value.selectedSessionId = '';
                        sessionState.value.status = {};
                        return;
                    }
                    const res = await safeRequest(async () => {
                        return await axios.get(`/api/webui/projects/${selectedProjectId.value}/sessions`);
                    });
                    sessionState.value.items = res.data?.items || [];
                    const exists = managedSessions.value.some(item => item.session_id === sessionState.value.selectedSessionId);
                    if (!exists) sessionState.value.selectedSessionId = '';
                    if (!sessionState.value.selectedSessionId && managedSessions.value.length > 0) {
                        sessionState.value.selectedSessionId = managedSessions.value[0].session_id;
                    }
                    if (sessionState.value.selectedSessionId) {
                        await refreshSelectedSessionStatus();
                    } else {
                        sessionState.value.status = {};
                    }
                };
                const loadShells = async () => {
                    if (!selectedProjectId.value) {
                        shellState.value.items = [];
                        shellState.value.selectedShellId = '';
                        shellState.value.lastLoadedAt = 0;
                        return;
                    }
                    const res = await safeRequest(async () => {
                        return await axios.get(`/api/webui/projects/${selectedProjectId.value}/shells`);
                    });
                    shellState.value.items = res.data?.items || [];
                    shellState.value.lastLoadedAt = Date.now();
                    const exists = shellState.value.items.some(item => String(item?.id || '') === shellState.value.selectedShellId);
                    if (!exists) {
                        shellState.value.selectedShellId = shellState.value.items[0]?.id || '';
                    }
                };
                const silentLoadShells = async () => {
                    if (!selectedProjectId.value) return;
                    try {
                        const res = await axios.get(`/api/webui/projects/${selectedProjectId.value}/shells`);
                        shellState.value.items = res.data?.items || [];
                        shellState.value.lastLoadedAt = Date.now();
                    } catch (_) {
                        // ignore silent error
                    }
                };
                const selectManagedSession = async (sessionId) => {
                    if (!sessionId) return;
                    sessionState.value.selectedSessionId = sessionId;
                    await refreshSelectedSessionStatus();
                };
                const selectShell = (shellId) => {
                    shellState.value.selectedShellId = String(shellId || '').trim();
                    sessionDraft.value.shellId = shellState.value.selectedShellId;
                    if (!sessionDraft.value.name) {
                        const matched = shellState.value.items.find(item => String(item?.id || '') === shellState.value.selectedShellId);
                        if (matched) {
                            sessionDraft.value.name = `${shellUserLabel(matched)}@${shellHostLabel(matched)}`;
                        }
                    }
                };
                const bindShellToSessionDraft = (shell) => {
                    if (!shell) return;
                    selectShell(shell.id);
                    sessionDraft.value.cwd = '.';
                    switchView('sessions');
                };

                const refreshSelectedSessionStatus = async () => {
                    if (!ensureProjectSelected()) return;
                    if (!sessionState.value.selectedSessionId) return;
                    if (!managedSessions.value.some(item => item.session_id === sessionState.value.selectedSessionId)) {
                        sessionState.value.status = {};
                        return;
                    }
                    const res = await safeRequest(async () => {
                        return await axios.get(`/api/webui/projects/${selectedProjectId.value}/sessions/${sessionState.value.selectedSessionId}/status`);
                    });
                    sessionState.value.status = res.data || {};
                };

                const loadSessionBackend = async () => {
                    const res = await safeRequest(async () => {
                        return await axios.get('/api/webui/session-backend');
                    });
                    sessionBackend.value = {
                        mode: res.data?.mode || 'workspace',
                        msf_binary: res.data?.msf_binary || 'msfconsole'
                    };
                };

                const saveSessionBackend = async () => {
                    if (!validateSessionBackendInput()) return;
                    const res = await safeRequest(async () => {
                        return await axios.put('/api/webui/session-backend', {
                            mode: sessionBackend.value.mode || 'workspace',
                            msf_binary: sessionBackend.value.msf_binary || 'msfconsole'
                        }, requestConfig());
                    }, '会话后端已更新');
                    sessionBackend.value = {
                        mode: res.data?.mode || 'workspace',
                        msf_binary: res.data?.msf_binary || 'msfconsole'
                    };
                    await loadSessions();
                };

                const probeMsfSessions = async () => {
                    const res = await safeRequest(async () => {
                        return await axios.get('/api/webui/msf/sessions');
                    }, 'MSF会话探测完成');
                    fileOpsResult.value = res.data || {};
                };

                const syncMsfSessions = async () => {
                    if (!ensureProjectSelected()) return;
                    const res = await safeRequest(async () => {
                        return await axios.post(`/api/webui/projects/${selectedProjectId.value}/sessions/sync-msf`, {}, requestConfig());
                    }, 'MSF会话已同步');
                    fileOpsResult.value = res.data || {};
                    await loadSessions();
                    await loadShells();
                };

                const checkSessionHealth = async () => {
                    if (!(await ensureSessionSelected())) return;
                    const res = await safeRequest(async () => {
                        return await axios.post(`/api/webui/projects/${selectedProjectId.value}/sessions/${sessionState.value.selectedSessionId}/health-check`, {
                            timeout: 20
                        }, requestConfig());
                    }, '会话健康检查完成');
                    fileOpsResult.value = res.data || {};
                    await refreshSelectedSessionStatus();
                };

                const createProject = async () => {
                    const validation = projectDraftValidation.value;
                    if (!validation.canSubmit) {
                        setNotice(validation.primaryError, 'error');
                        return;
                    }
                    const target = validation.target.value;
                    const description = validation.description.value;
                    newProject.value.target = target;
                    newProject.value.description = description;
                    await safeRequest(async () => {
                        await axios.post('/api/projects', {
                            target,
                            description
                        });
                        newProject.value = { target: '', description: '' };
                        await fetchProjects();
                    }, '项目创建成功');
                };

                const controlProject = async (action) => {
                    if (!ensureProjectSelected()) return;
                    const actionNameMap = {
                        start: '启动',
                        continue: '继续',
                        pause: '暂停',
                        stop: '停止'
                    };
                    await safeRequest(async () => {
                        await axios.post(`/api/webui/projects/${selectedProjectId.value}/control/${action}`, {}, requestConfig());
                        await fetchProjects();
                    }, `项目已执行 ${actionNameMap[action] || action}`);
                };

                const deleteProject = async () => {
                    if (!ensureProjectSelected()) return;
                    await safeRequest(async () => {
                        await axios.delete(`/api/projects/${selectedProjectId.value}`, requestConfig());
                        selectedProjectId.value = '';
                        await fetchProjects();
                    }, '项目已删除');
                };

                const openSession = async () => {
                    if (!ensureProjectSelected()) return;
                    if (!validateSessionDraft()) return;
                    const res = await safeRequest(async () => {
                        return await axios.post(`/api/webui/projects/${selectedProjectId.value}/sessions/open`, {
                            name: sessionDraft.value.name,
                            cwd: sessionDraft.value.cwd || '.',
                            shell_id: sessionDraft.value.shellId || null
                        }, requestConfig());
                    }, '会话已创建');
                    sessionDraft.value = { name: '', cwd: '.', shellId: '' };
                    sessionState.value.selectedSessionId = res.data?.session_id || '';
                    await loadSessions();
                };

                const closeSession = async () => {
                    if (!(await ensureSessionSelected())) return;
                    await safeRequest(async () => {
                        await axios.post(`/api/webui/projects/${selectedProjectId.value}/sessions/${sessionState.value.selectedSessionId}/close`, { reason: 'ui-close' }, requestConfig());
                        sessionState.value.selectedSessionId = '';
                        await loadSessions();
                    }, '会话已关闭');
                };

                const loadAttackChain = async () => {
                    if (!ensureProjectSelected()) return;
                    const res = await safeRequest(async () => {
                        return await axios.get(`/api/webui/projects/${selectedProjectId.value}/attack-chain`);
                    }, '攻击链加载成功');
                    attackChainData.value = res.data || {};
                    attackChainSelectedStagePhase.value = selectedAttackStage.value?.phase || attackChainStages.value[0]?.phase || '';
                    await silentLoadShells();
                };

                const silentLoadAttackChain = async () => {
                    if (!selectedProjectId.value) return;
                    try {
                        const res = await axios.get(`/api/webui/projects/${selectedProjectId.value}/attack-chain`);
                        attackChainData.value = res.data || {};
                        attackChainSelectedStagePhase.value = selectedAttackStage.value?.phase || attackChainStages.value[0]?.phase || '';
                    } catch (error) {
                        // ignore silent error
                    }
                };
                const selectAttackStage = (phase) => {
                    attackChainSelectedStagePhase.value = String(phase || '').trim();
                };

                const runFileOps = async () => {
                    if (!(await ensureSessionSelected())) return;
                    if (!validateFileOperationInput()) return;
                    const payload = {
                        action: fileOps.value.action,
                        path: fileOps.value.path || '.',
                        recursive: !!fileOps.value.recursive,
                        max_entries: Number(fileOps.value.max_entries || 200),
                        project_id: selectedProjectId.value,
                        session_id: sessionState.value.selectedSessionId
                    };
                    if (fileOps.value.action === 'write') payload.content = fileOps.value.content || '';
                    const res = await safeRequest(async () => {
                        return await axios.post('/api/webui/files/ops', payload, requestConfig());
                    }, '文件操作完成');
                    fileOpsResult.value = res.data || {};
                    if (fileOps.value.action === 'read' && typeof res.data?.content === 'string') {
                        fileOps.value.content = res.data.content;
                    }
                    await refreshSelectedSessionStatus();
                };

                const executeCli = async () => {
                    if (!(await ensureSessionSelected())) return;
                    if (!validateCliInput()) return;
                    const res = await safeRequest(async () => {
                        return await axios.post('/api/webui/cli/execute', {
                            command: cliForm.value.command,
                            cwd: cliForm.value.cwd || null,
                            timeout: Number(cliForm.value.timeout || 120),
                            project_id: selectedProjectId.value,
                            session_id: sessionState.value.selectedSessionId
                        }, requestConfig());
                    }, '命令执行完成');
                    cliResult.value = res.data || {};
                    await refreshSelectedSessionStatus();
                };
                const applyCommandPreset = (command) => {
                    cliForm.value.command = String(command || '').trim();
                };
                const reuseHistoryCommand = (item) => {
                    if (!item?.command) return;
                    cliForm.value.command = item.command;
                    cliForm.value.cwd = item.cwd || '';
                    cliForm.value.timeout = Math.max(0, Number(cliResult.value?.timeout || cliForm.value.timeout || 120));
                    switchView('cli');
                };
                const pickFileEntry = (item) => {
                    const nextPath = resolveFileEntryPath(item);
                    fileOps.value.path = nextPath;
                    if (!item?.is_dir) {
                        fileOps.value.action = 'read';
                    }
                };
                const loadFileEntry = async (item) => {
                    pickFileEntry(item);
                    if (!item?.is_dir) {
                        await runFileOps();
                    }
                };

                const onUploadFileChange = (event) => {
                    uploadState.value.file = event?.target?.files?.[0] || null;
                };

                const uploadFile = async () => {
                    if (!(await ensureSessionSelected())) return;
                    if (!uploadState.value.file) {
                        setNotice('请先选择要上传的文件。', 'error');
                        return;
                    }
                    if (!validateFileOperationInput()) return;
                    const form = new FormData();
                    form.append('project_id', selectedProjectId.value);
                    form.append('session_id', sessionState.value.selectedSessionId);
                    form.append('path', fileOps.value.path || uploadState.value.file.name);
                    form.append('file', uploadState.value.file);
                    const res = await safeRequest(async () => {
                        const config = requestConfig();
                        return await axios.post('/api/webui/files/upload', form, {
                            ...config,
                            headers: {
                                ...(config.headers || {}),
                                'Content-Type': 'multipart/form-data'
                            }
                        });
                    }, '文件上传完成');
                    fileOpsResult.value = res.data || {};
                    uploadState.value.file = null;
                    await refreshSelectedSessionStatus();
                };

                const downloadFile = async () => {
                    if (!(await ensureSessionSelected())) return;
                    if (!validateFileOperationInput()) return;
                    const params = new URLSearchParams({
                        project_id: selectedProjectId.value,
                        session_id: sessionState.value.selectedSessionId,
                        path: fileOps.value.path || '.'
                    });
                    window.open(`/api/webui/files/download?${params.toString()}`, '_blank');
                };

                const uploadMTool = async () => {
                    const fileInput = document.getElementById('mtool-upload-file-lib');
                    if (!fileInput.files.length) {
                        setNotice('请选择要上传的文件', 'error');
                        return;
                    }
                    const formData = new FormData();
                    formData.append('file', fileInput.files[0]);
                    try {
                        const accessKey = localStorage.getItem('wr_admin_key') || '';
                        const config = accessKey
                            ? { headers: { 'Content-Type': 'multipart/form-data', 'X-Admin-Key': accessKey } }
                            : { headers: { 'Content-Type': 'multipart/form-data' } };
                        const res = await axios.post('/api/mtools/upload', formData, config);
                        const data = res.data || {};
                        if (data) {
                            setNotice('工具/插件上传成功: ' + (data.message || ''), 'success');
                            fileInput.value = '';
                            if (currentLibType.value === 'custom_tools') {
                                await listLibFiles();
                            }
                        } else {
                            setNotice('上传失败', 'error');
                        }
                    } catch (e) {
                        setNotice('上传出错: ' + (e?.response?.data?.detail || e.message), 'error');
                    }
                };

                const generateReport = async () => {
                    if (!ensureProjectSelected()) return;
                    const res = await safeRequest(async () => {
                        return await axios.post(`/api/webui/projects/${selectedProjectId.value}/reports/generate`);
                    }, '报告生成完成');
                    reportGenerateResult.value = res.data || {};
                };

                const loadLatestReport = async () => {
                    if (!ensureProjectSelected()) return;
                    const res = await safeRequest(async () => {
                        return await axios.get(`/api/webui/projects/${selectedProjectId.value}/reports/latest`);
                    }, '已读取最新报告');
                    latestReport.value = { content: res.data?.content || '' };
                    latestReportMeta.value = {
                        project_id: res.data?.project_id,
                        report_path: res.data?.report_path,
                        content_length: (res.data?.content || '').length,
                        evidence_gate_active: !!res.data?.evidence_gate_active,
                        evidence_gap_checklist: Array.isArray(res.data?.evidence_gap_checklist) ? res.data.evidence_gap_checklist : []
                    };
                    if (res.data?.evidence_gate_active) {
                        setNotice('当前报告为证据缺口模板：后渗透已因证据门禁被阻断。', 'warning');
                    }
                };
                const downloadReport = (fmt) => {
                    if (!ensureProjectSelected()) return;
                    if (!['md', 'json', 'html'].includes(String(fmt || '').toLowerCase())) {
                        setNotice('不支持的下载格式。', 'error');
                        return;
                    }
                    const url = `/api/webui/projects/${selectedProjectId.value}/reports/download?fmt=${encodeURIComponent(fmt)}`;
                    window.open(url, '_blank');
                };
                const ensureCompletedProjectReportReady = async () => {
                    const pid = selectedProjectId.value;
                    if (!pid) return;
                    const project = projects.value.find(item => item.id === pid);
                    if (!project) return;
                    const status = normalizeProjectStatus(project);
                    if (status !== 'completed' && status !== 'insufficient_evidence') return;
                    const hasLoadedCurrent = autoLoadedReportProject.value === pid && latestReportMeta.value?.project_id === pid && String(latestReport.value?.content || '').length > 0;
                    if (hasLoadedCurrent) return;
                    try {
                        await loadLatestReport();
                        autoLoadedReportProject.value = pid;
                        return;
                    } catch (error) {
                        const detail = String(error?.response?.data?.detail || error?.message || '').toLowerCase();
                        if (!detail.includes('report')) return;
                    }
                    try {
                        await generateReport();
                        await loadLatestReport();
                        autoLoadedReportProject.value = pid;
                    } catch (_) {}
                };

                const listLibFiles = async () => {
                    if (!currentLibType.value) return;
                    const res = await safeRequest(async () => {
                        return await axios.get('/api/webui/libs/files', {
                            params: {
                                lib_type: currentLibType.value,
                                path: libraryState.value.path || '',
                                recursive: !!libraryState.value.recursive,
                                limit: 500
                            }
                        });
                    }, `目录已加载`);
                    libraryItems.value = res.data?.items || [];
                    libraryResultMeta.value = {
                        lib_type: res.data?.lib_type,
                        path: res.data?.path,
                        count: res.data?.count
                    };
                };

                const readLibFile = async () => {
                    if (!currentLibType.value || !libraryState.value.filePath) {
                        setNotice('请先填写文件路径。', 'error');
                        return;
                    }
                    const res = await safeRequest(async () => {
                        return await axios.get('/api/webui/libs/file', {
                            params: { lib_type: currentLibType.value, path: libraryState.value.filePath }
                        });
                    }, '文件读取成功');
                    libraryState.value.content = res.data?.content || '';
                    libraryResultMeta.value = { lib_type: res.data?.lib_type, path: res.data?.path };
                };

                const saveLibFile = async () => {
                    if (!currentLibType.value || !libraryState.value.filePath) {
                        setNotice('请先填写文件路径。', 'error');
                        return;
                    }
                    const res = await safeRequest(async () => {
                        return await axios.put('/api/webui/libs/file', {
                            lib_type: currentLibType.value,
                            path: libraryState.value.filePath,
                            content: libraryState.value.content || '',
                            overwrite: true
                        });
                    }, '文件写入成功');
                    libraryResultMeta.value = res.data || {};
                    await listLibFiles();
                };

                const deleteLibFile = async () => {
                    if (!currentLibType.value || !libraryState.value.filePath) {
                        setNotice('请先填写文件路径。', 'error');
                        return;
                    }
                    const res = await safeRequest(async () => {
                        return await axios.delete('/api/webui/libs/file', {
                            params: { lib_type: currentLibType.value, path: libraryState.value.filePath }
                        });
                    }, '删除操作完成');
                    libraryResultMeta.value = res.data || {};
                    await listLibFiles();
                };

                const joinPath = (base, child) => {
                    if (!base) return child;
                    if (!child) return base;
                    return `${base.replace(/\/+$/g, '')}/${child.replace(/^\/+/g, '')}`;
                };

                const selectLibItem = (item) => {
                    if (item.is_dir) {
                        libraryState.value.path = joinPath(libraryState.value.path, item.path);
                        listLibFiles();
                    } else {
                        libraryState.value.filePath = joinPath(libraryState.value.path, item.path);
                    }
                };

const applyCatalogSelection = (provider, endpointKey, preferredModel = null, preferredFailovers = null) => {
    const providerEntry = getCatalogProvider(provider) || providerOptions.value[0] || null;
    if (!providerEntry) return;
    const providerFreeformModels = Boolean(providerEntry.freeform_models);
    const providerAllowsCustomProtocol = Boolean(providerEntry.allow_custom_protocol);
    const providerAllowsCustomBaseUrl = Boolean(providerEntry.allow_custom_base_url);
    const providerProtocolOptions = Array.isArray(providerEntry.protocol_options) ? providerEntry.protocol_options : [];
    const endpoints = Array.isArray(providerEntry.endpoints) ? providerEntry.endpoints : [];
    const selectedEndpoint = endpoints.find(item => item.key === String(endpointKey || '').trim())
        || endpoints.find(item => item.key === providerEntry.default_endpoint_key)
        || endpoints[0]
        || null;
    const safeProvider = String(providerEntry.id || provider || 'deepseek').trim();
    const safeEndpointKey = String(selectedEndpoint?.key || providerEntry.default_endpoint_key || '').trim();
    const models = getAvailableModels(safeProvider, safeEndpointKey);
    const endpointDefaultModel = String(selectedEndpoint?.default_model || '').trim();
    const providerDefaultModel = String(providerEntry.default_model || '').trim();
    const defaultModel = models.includes(endpointDefaultModel)
        ? endpointDefaultModel
        : (models.includes(providerDefaultModel) ? providerDefaultModel : (models[0] || ''));
    const requestedModel = String(preferredModel ?? settingsForm.value.model ?? '').trim();
    const safeModel = providerFreeformModels
        ? (requestedModel || defaultModel)
        : (requestedModel && models.includes(requestedModel) ? requestedModel : defaultModel);
    const requestedFailovers = Array.isArray(preferredFailovers)
        ? preferredFailovers
        : (Array.isArray(settingsForm.value.failover_models) ? settingsForm.value.failover_models : []);
    const safeFailovers = requestedFailovers
        .map(item => String(item || '').trim())
        .filter(Boolean)
        .filter(item => item !== safeModel)
        .filter(item => providerFreeformModels ? true : models.includes(item))
        .filter((item, idx, arr) => arr.indexOf(item) === idx);
    const defaultProtocol = String(selectedEndpoint?.protocol || providerEntry.protocol || 'openai-compatible').trim();
    const currentProtocol = String(settingsForm.value.protocol || '').trim();
    const safeProtocol = providerAllowsCustomProtocol
        ? (providerProtocolOptions.some(item => item.id === currentProtocol) ? currentProtocol : (providerProtocolOptions[0]?.id || defaultProtocol))
        : defaultProtocol;
    const preferredBaseUrl = String(settingsForm.value.base_url || '').trim();
    const safeBaseUrl = providerAllowsCustomBaseUrl
        ? (preferredBaseUrl || String(selectedEndpoint?.base_url || '').trim())
        : String(selectedEndpoint?.base_url || '').trim();
    settingsForm.value.provider = safeProvider;
    settingsForm.value.endpoint_key = safeEndpointKey;
    settingsForm.value.protocol = safeProtocol;
    settingsForm.value.base_url = safeBaseUrl;
    settingsForm.value.model = safeModel;
    setFailoverModels(safeFailovers);
};

const loadProviderCatalog = async (silent = true) => {
    const res = await axios.get('/api/webui/settings/providers/catalog', requestConfig());
    providerCatalog.value = res?.data || { providers: [] };
    providerModelOptions.value = buildCatalogModelOptions(providerCatalog.value);
    if (!Array.isArray(settingsForm.value.provider_failover_order) || !settingsForm.value.provider_failover_order.length) {
        settingsForm.value.provider_failover_order = providerOptions.value.map(item => String(item?.id || '').trim()).filter(Boolean);
    }
    applyCatalogSelection(settingsForm.value.provider, settingsForm.value.endpoint_key);
    if (!silent) {
        setNotice('已刷新大模型厂商目录。', 'success');
    }
    return providerCatalog.value;
};

const loadProviderModels = async (provider, endpointKeyOrSilent = null, silent = true) => {
    let endpointKey = endpointKeyOrSilent;
    if (typeof endpointKeyOrSilent === 'boolean') {
        silent = endpointKeyOrSilent;
        endpointKey = null;
    }
    const targetProvider = String(provider || settingsForm.value.provider || '').trim();
    const targetEndpointKey = String(endpointKey || settingsForm.value.endpoint_key || '').trim();
    if (!targetProvider) return [];
    try {
        const res = await axios.get('/api/webui/settings/providers/models', {
            params: {
                provider: targetProvider,
                endpoint_key: targetEndpointKey || undefined,
            },
            ...(requestConfig() || {}),
        });
        const effectiveEndpointKey = String(res?.data?.endpoint_key || targetEndpointKey || '').trim();
        const models = Array.isArray(res?.data?.models)
            ? res.data.models.map(item => String(item || '').trim()).filter(Boolean)
            : [];
        const nextOptions = { ...providerModelOptions.value };
        nextOptions[modelListKey(targetProvider, effectiveEndpointKey)] = models.length
            ? Array.from(new Set(models))
            : (getCatalogEndpoint(targetProvider, effectiveEndpointKey)?.models || []);
        providerModelOptions.value = nextOptions;
        if (targetProvider === settingsForm.value.provider) {
            applyCatalogSelection(targetProvider, effectiveEndpointKey, settingsForm.value.model, settingsForm.value.failover_models);
        }
        if (!silent && res?.data?.source === 'remote') {
            setNotice(`已从官方接口刷新 ${displayProviderLabel(targetProvider)} 的模型列表。`, 'success');
        }
        return nextOptions[modelListKey(targetProvider, effectiveEndpointKey)] || [];
    } catch (error) {
        const fallbackModels = getCatalogEndpoint(targetProvider, targetEndpointKey)?.models || [];
        providerModelOptions.value = {
            ...providerModelOptions.value,
            [modelListKey(targetProvider, targetEndpointKey)]: fallbackModels,
        };
        if (targetProvider === settingsForm.value.provider) {
            applyCatalogSelection(targetProvider, targetEndpointKey, settingsForm.value.model, settingsForm.value.failover_models);
        }
        if (!silent) {
            setNotice(error?.response?.data?.detail || '模型列表刷新失败，已回退到当前可用候选项。', 'warning');
        }
        return fallbackModels;
    }
};

const saveApiKey = async () => {
    const provider = String(settingsForm.value.provider || '').trim();
    const default_provider = String(settingsForm.value.default_provider || provider).trim();
    const provider_failover_order = providerSaveFailoverOrder.value;
    const endpoint_key = String(settingsForm.value.endpoint_key || '').trim();
    const api_key = String(settingsForm.value.api_key || '').trim();
    const protocol = currentProviderAllowsCustomProtocol.value
        ? String(settingsForm.value.protocol || '').trim()
        : String(currentProviderEntry.value?.protocol || '').trim();
    const base_url = currentProviderAllowsCustomBaseUrl.value
        ? String(settingsForm.value.base_url || '').trim()
        : String(currentProviderBaseUrl.value || '').trim();
    const model = String(settingsForm.value.model || '').trim();
    const failover_models = currentProviderFreeformModels.value
        ? parseFailoverModelsText(settingsForm.value.failover_models_text)
        : (Array.isArray(settingsForm.value.failover_models)
            ? settingsForm.value.failover_models.map(item => String(item || '').trim()).filter(Boolean)
            : []);
    if (currentProviderRequiresApiKey.value && !api_key) {
        setNotice('该厂商必须填写接口密钥。', 'error');
        return;
    }
    if (!provider || !endpoint_key || !model) {
        setNotice('请先选择服务商、接入节点和主模型。', 'error');
        return;
    }
    if (currentProviderAllowsCustomBaseUrl.value && !base_url) {
        setNotice('当前厂商必须填写接口地址。', 'error');
        return;
    }
    const res = await safeRequest(async () => {
        return await axios.put('/api/webui/settings/apikey', {
            provider,
            default_provider,
            provider_failover_order,
            endpoint_key,
            api_key,
            protocol: protocol || undefined,
            base_url: base_url || undefined,
            model,
            failover_models,
        }, requestConfig());
    }, '配置已保存，正在重载引擎。');
    settingsResult.value = res.data || {};
    loadedModelsResult.value = settingsResult.value?.loaded_models_result || {};
    applyCatalogSelection(
        res?.data?.provider || provider,
        res?.data?.endpoint_key || endpoint_key,
        hasOwn(res?.data, 'model') ? res.data.model : model,
        hasOwn(res?.data, 'failover_models') ? res.data.failover_models : failover_models,
    );
    settingsForm.value.default_provider = String(res?.data?.default_provider || default_provider || provider).trim();
    settingsForm.value.provider_failover_order = Array.isArray(res?.data?.provider_failover_order)
        ? res.data.provider_failover_order.map(item => String(item || '').trim()).filter(Boolean)
        : provider_failover_order;
    settingsForm.value.base_url = String(hasOwn(res?.data, 'base_url') ? res.data.base_url : base_url).trim();
    settingsForm.value.protocol = String(hasOwn(res?.data, 'protocol') ? res.data.protocol : (protocol || settingsForm.value.protocol || '')).trim();
    setFailoverModels(hasOwn(res?.data, 'failover_models') ? res.data.failover_models : failover_models);
    const migrationWarnings = Array.isArray(res?.data?.migration_warnings) ? res.data.migration_warnings : [];
    if (migrationWarnings.length) {
        setNotice(`已自动迁移旧配置：${migrationWarnings[0]}`, 'warning');
        return;
    }
    const loadedResult = loadedModelsResult.value || {};
    if (settingsResult.value?.load_test_triggered) {
        const configuredCount = Number(loadedResult.configured_count || 0);
        const loadedCount = Number(loadedResult.loaded_count || 0);
        if (configuredCount > 0) {
            if (loadedCount === configuredCount) {
                setNotice(`重载完成：已成功加载 ${loadedCount}/${configuredCount} 个模型。`, 'success');
            } else {
                setNotice(`重载完成：已成功加载 ${loadedCount}/${configuredCount} 个模型，其余模型加载失败。`, 'warning');
            }
        } else {
            setNotice('重载完成：当前没有可用于加载模型的有效密钥。', 'warning');
        }
    }
};

const loadApiKeyStatus = async (targetProvider = null, silentNotice = false) => {
    if (targetProvider && typeof targetProvider === 'object' && ('preventDefault' in targetProvider || targetProvider instanceof Event)) {
        targetProvider = null;
    }
    if (!providerOptions.value.length) {
        await loadProviderCatalog(true);
    }
    const res = await safeRequest(async () => {
        return await axios.get('/api/webui/settings/apikey', {
            params: {
                provider: targetProvider || settingsForm.value.provider || undefined,
            },
            ...(requestConfig() || {}),
        });
    }, silentNotice ? '' : '已读取当前接口配置状态。');
    if (!res || !res.data) {
        return;
    }
    settingsResult.value = {
        ...(settingsResult.value || {}),
        ...(res.data || {}),
        load_test_triggered: Boolean((settingsResult.value || {}).load_test_triggered),
    };
    settingsForm.value.default_provider = String(res.data.default_provider || settingsForm.value.default_provider || settingsForm.value.provider || 'deepseek').trim();
    settingsForm.value.provider_failover_order = Array.isArray(res.data.provider_failover_order)
        ? res.data.provider_failover_order.map(item => String(item || '').trim()).filter(Boolean)
        : effectiveProviderFailoverOrder.value;
    settingsForm.value.base_url = String(hasOwn(res.data, 'base_url') ? res.data.base_url : '').trim();
    settingsForm.value.protocol = String(hasOwn(res.data, 'protocol') ? res.data.protocol : (currentProviderEntry.value?.protocol || 'openai-compatible')).trim();
    applyCatalogSelection(
        res.data.provider || settingsForm.value.provider,
        res.data.endpoint_key || settingsForm.value.endpoint_key,
        hasOwn(res.data, 'model') ? res.data.model : settingsForm.value.model,
        hasOwn(res.data, 'failover_models') ? res.data.failover_models : [],
    );
    setFailoverModels(hasOwn(res.data, 'failover_models') ? res.data.failover_models : []);
    settingsForm.value.api_key = '';
    await loadProviderModels(settingsForm.value.provider, settingsForm.value.endpoint_key, true);
    const migrationWarnings = Array.isArray(res?.data?.migration_warnings) ? res.data.migration_warnings : [];
    if (silentNotice) {
        return;
    }
    if (migrationWarnings.length) {
        setNotice(`已自动迁移旧配置：${migrationWarnings[0]}`, 'warning');
    } else if (res.data && res.data.is_configured) {
        setNotice(`当前已保存接口密钥：${res.data.api_key_masked}`, 'success');
    } else {
        setNotice('当前未保存有效接口密钥，或仍为占位值。', 'warning');
    }
};
const handleSettingsProviderChange = async () => {
    await loadApiKeyStatus(settingsForm.value.provider, true);
};
                const saveAccessKey = async () => {
                    if (!settingsForm.value.access_key || settingsForm.value.access_key.length < 8) {
                        setNotice('访问密钥至少8位。', 'error');
                        return;
                    }
                    const res = await safeRequest(async () => {
                        return await axios.put('/api/webui/settings/access-key', {
                            access_key: settingsForm.value.access_key
                        }, requestConfig());
                    }, '访问密钥已保存');
                    settingsResult.value = res.data || {};
                };

                const loadAccessKeyStatus = async () => {
                    const res = await safeRequest(async () => {
                        return await axios.get('/api/webui/settings/access-key', requestConfig());
                    }, '已读取访问密钥状态');
                    settingsResult.value = res.data || {};
                };

                const clearLiveLogs = () => {
                    liveLogs.value = [];
                    autoFollowLogStream.value = true;
                };
                const loadProjectEventLogs = async (projectId, silentNotice = true, replaceExisting = true) => {
                    if (!projectId) {
                        if (replaceExisting) replaceLiveLogs([]);
                        return;
                    }
                    const res = await safeRequest(async () => {
                        return await axios.get(`/api/projects/${projectId}/events`, {
                            params: {
                                limit: MAX_LIVE_LOG_ENTRIES
                            }
                        });
                    }, silentNotice ? '' : '已恢复项目历史遥测');
                    const items = Array.isArray(res?.data) ? res.data : [];
                    const entries = items.map(item => buildLiveLogEntry(item?.message || '', item));
                    if (replaceExisting) {
                        replaceLiveLogs(entries);
                    } else {
                        entries.forEach(entry => appendLiveLogEntry(entry));
                    }
                };
                const restoreLiveLogs = async () => {
                    if (!selectedProjectId.value) {
                        setNotice('请先选择项目。', 'error');
                        return;
                    }
                    await loadProjectEventLogs(selectedProjectId.value, false, true);
                };

                const syncExploitDB = async () => {
                    setNotice('正在后台同步漏洞库，请稍候...', 'success');
                    const res = await safeRequest(async () => {
                        return await axios.post('/api/system/exploitdb/sync', {}, requestConfig());
                    }, '漏洞库全量同步完成');
                    if (res && res.data) {
                        setNotice(res.data.details || '同步成功', 'success');
                    }
                };

                const submitLearningSync = async () => {
                    const topic = String(learningForm.value.topic || '').trim();
                    if (!topic) {
                        setNotice('学习主题不能为空。', 'error');
                        return;
                    }
                    const urls = String(learningForm.value.urlsText || '')
                        .split('\n')
                        .map(item => item.trim())
                        .filter(Boolean);
                    const payload = {
                        topic,
                        urls,
                        content: String(learningForm.value.content || '').trim() || null
                    };
                    const res = await safeRequest(async () => {
                        return await axios.post('/api/webui/learning/sync', payload, requestConfig());
                    }, '学习入库完成');
                    learningResult.value = res.data || {};
                    await loadLearningHistory();
                };

                const loadLearningHistory = async () => {
                    const res = await safeRequest(async () => {
                        return await axios.get('/api/webui/learning/history', {
                            params: {
                                keyword: learningHistory.value.keyword || undefined,
                                item_type: learningHistory.value.item_type || undefined,
                                limit: learningHistory.value.limit,
                                offset: learningHistory.value.offset
                            }
                        });
                    }, '学习历史已加载');
                    learningHistoryResult.value = res.data || {};
                };

                const validateWebAuditRules = async () => {
                    const res = await safeRequest(async () => {
                        return await axios.post('/api/webui/web-audit/rules/validate', {
                            auto_fix: !!webAuditForm.value.auto_fix_rules
                        }, requestConfig());
                    }, '审计规则校验完成');
                    webAuditValidationResult.value = res.data || {};
                };

                const runWebAudit = async () => {
                    const target = String(webAuditForm.value.target || '').trim();
                    if (!target) {
                        setNotice('请先输入审计目标', 'error');
                        return;
                    }
                    const res = await safeRequest(async () => {
                        return await axios.post('/api/webui/web-audit/run', {
                            target,
                            auto_fix_rules: !!webAuditForm.value.auto_fix_rules,
                            use_yak: !!webAuditForm.value.use_yak,
                            timeout_seconds: Number(webAuditForm.value.timeout_seconds || 20)
                        }, requestConfig());
                    }, 'Web源码审计完成');
                    webAuditRunResult.value = res.data || {};
                };

                const initLiveLogs = () => {
                    try {
                        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
                        logSocket = new WebSocket(`${protocol}://${window.location.host}/api/logs`);
                        logSocket.onmessage = (event) => {
                            const raw = String(event.data || '').trim();
                            if (!raw) return;
                            let entry = buildLiveLogEntry(raw, null);
                            try {
                                const payload = JSON.parse(raw);
                                updateProjectRuntimeByEvent(payload);
                                if (selectedProjectId.value && payload.project_id && payload.project_id !== selectedProjectId.value) {
                                    return;
                                }
                                entry = buildLiveLogEntry(raw, payload);
                                if (
                                    payload.project_id &&
                                    selectedProjectId.value === payload.project_id &&
                                    activeView.value === 'attack-chain' &&
                                    ['phase', 'status', 'log'].includes(String(payload.type || ''))
                                ) {
                                    silentLoadAttackChain();
                                }
                                const isCompleted = ['completed', 'insufficient_evidence'].includes(String(payload.status || '').toLowerCase());
                                if (isCompleted && payload.project_id && selectedProjectId.value === payload.project_id && autoLoadedReportProject.value !== payload.project_id) {
                                    autoLoadedReportProject.value = payload.project_id;
                                    generateReport().then(() => loadLatestReport()).catch(() => {});
                                }
                            } catch (_) {}
                            appendLiveLogEntry(entry);
                        };
                        logSocket.onerror = () => setNotice('日志连接异常。', 'error');
                    } catch (error) {
                        setNotice(error.message || '日志连接失败', 'error');
                    }
                };

                const switchView = async (viewId) => {
                    activeView.value = viewId;
                    closeMobileNav();
                    const nextCandidates = multiLibraryViewMap[viewId] || [];
                    if (nextCandidates.length > 0) {
                        selectedLibType.value = nextCandidates[0];
                    } else {
                        selectedLibType.value = '';
                    }
                    if (libraryViewMap[viewId] || nextCandidates.length > 0) {
                        libraryState.value.path = '';
                        libraryState.value.filePath = '';
                        libraryState.value.content = '';
                        await listLibFiles();
                    }
                    if (viewId === 'learning') {
                        await loadLearningHistory();
                    }
                    if (viewId === 'attack-chain' && selectedProjectId.value) {
                        await loadAttackChain();
                    }
                    if (['sessions', 'files', 'cli'].includes(viewId) && selectedProjectId.value) {
                        await loadSessions();
                    }
                    if (['attack-chain', 'sessions'].includes(viewId) && selectedProjectId.value) {
                        await loadShells();
                    }
                    if (viewId === 'settings') {
                        await loadApiKeyStatus();
                    }
                };

                let pollingInterval = null;

                onMounted(async () => {
                    try {
                        await initializeProtectedRuntime();
                    } catch (_) {
                        serverStatus.value = 'offline';
                    }
                    
                    pollingInterval = setInterval(async () => {
                        await silentFetchProjects();
                        if (activeView.value === 'attack-chain' && selectedProjectId.value) {
                            await silentLoadAttackChain();
                        }
                        if (['sessions', 'files', 'cli'].includes(activeView.value) && selectedProjectId.value) {
                            await loadSessions();
                        }
                    }, 5000);
                    document.addEventListener('click', markUiInteraction, true);
                    document.addEventListener('keydown', markUiInteraction, true);
                    document.addEventListener('input', markUiInteraction, true);
                    document.addEventListener('change', markUiInteraction, true);
                    document.addEventListener('wheel', markUiInteraction, true);
                    document.addEventListener('touchstart', markUiInteraction, true);
                    document.addEventListener('scroll', markUiInteraction, true);
                    if (logStreamRef.value) {
                        logStreamRef.value.addEventListener('scroll', updateAutoFollowFromScroll, { passive: true });
                    }
                    logIdleTimer = setInterval(() => {
                        if (shouldAutoTrackLatestLog()) {
                            autoFollowLogStream.value = true;
                            scrollLogStreamToLatest();
                        }
                    }, 1000);
                });
                watch(
                    () => sessionState.value.selectedSessionId,
                    async (sessionId, previousId) => {
                        if (!sessionId || sessionId === previousId) return;
                        if (!managedSessions.value.some(item => item.session_id === sessionId)) return;
                        await refreshSelectedSessionStatus();
                    }
                );
                watch(
                    () => [settingsForm.value.provider, settingsForm.value.endpoint_key],
                    async ([provider, endpointKey]) => {
                        const normalizedProvider = String(provider || '').trim();
                        if (!normalizedProvider) return;
                        applyCatalogSelection(normalizedProvider, endpointKey);
                        await loadProviderModels(normalizedProvider, endpointKey, true);
                    }
                );
                onBeforeUnmount(() => {
                    if (pollingInterval) {
                        clearInterval(pollingInterval);
                        pollingInterval = null;
                    }
                    if (logSocket) {
                        try { logSocket.close(); } catch (_) {}
                        logSocket = null;
                    }
                    document.removeEventListener('click', markUiInteraction, true);
                    document.removeEventListener('keydown', markUiInteraction, true);
                    document.removeEventListener('input', markUiInteraction, true);
                    document.removeEventListener('change', markUiInteraction, true);
                    document.removeEventListener('wheel', markUiInteraction, true);
                    document.removeEventListener('touchstart', markUiInteraction, true);
                    document.removeEventListener('scroll', markUiInteraction, true);
                    if (logStreamRef.value) {
                        logStreamRef.value.removeEventListener('scroll', updateAutoFollowFromScroll);
                    }
                    if (logIdleTimer) {
                        clearInterval(logIdleTimer);
                        logIdleTimer = null;
                    }
                });

                return {
                    views,
                    viewGroups,
                    activeView,
                    mobileNavOpen,
                    serverStatus,
                    loading,
                    notice,
                    projects,
                    selectedProjectId,
                    newProject,
                    PROJECT_TARGET_MAX_LENGTH,
                    PROJECT_DESCRIPTION_MAX_LENGTH,
                    projectDraftValidation,
                    liveLogs,
                    attackChainData,
                    attackChainStages,
                    attackChainMetrics,
                    attackChainUsage,
                    attackGraph,
                    attackChainViolations,
                    attackChainSelectedStagePhase,
                    selectedAttackStage,
                    attackChainOverviewCards,
                    fileOps,
                    fileOpsResult,
                    fileResultEntries,
                    sessionState,
                    sessionBackend,
                    shellState,
                    sessionDraft,
                    managedSessions,
                    recentShellSessions,
                    selectedManagedSession,
                    selectedSessionHealth,
                    sessionCommandHistory,
                    sessionFileHistory,
                    cliForm,
                    cliResult,
                    commandPresets,
                    reportGenerateResult,
                    latestReport,
                    latestReportMeta,
                    libraryState,
                    libraryItems,
                    libraryResultMeta,
                    providerOptions,
                    displayProviderLabel,
                    displayEndpointLabel,
                    displayProtocolLabel,
                    displayDiscoveryLabel,
                    configuredProviderChain,
                    effectiveProviderFailoverOrder,
                    providerSaveFailoverOrder,
                    settingsForm,
                    settingsResult,
                    currentProviderEndpoints,
                    currentProviderModels,
                    currentSelectableFailoverModels,
                    currentProviderRequiresApiKey,
                    currentProviderAllowsCustomBaseUrl,
                    currentProviderAllowsCustomProtocol,
                    currentProviderFreeformModels,
                    currentProtocolOptions,
                    currentProviderBaseUrl,
                    currentProviderDisplayLabel,
                    currentEndpointDisplayLabel,
                    currentEndpointNote,
                    currentProtocolDisplayLabel,
                    currentProviderDiscoveryLabel,
                    currentModelInputPlaceholder,
                    currentBaseUrlInputPlaceholder,
                    currentApiKeyInputPlaceholder,
                    currentApiKeyStatusText,
                    effectiveProviderChainDisplay,
                    providerSaveStrategyText,
                    currentMigrationWarnings,
                    showEndpointSelector,
                    loadedAiModelRows,
                    failedAiModelRows,
                    loadedAiSummary,
                    learningForm,
                    learningResult,
                    learningHistory,
                    learningHistoryResult,
                    webAuditForm,
                    webAuditValidationResult,
                    webAuditRunResult,
                    currentViewLabel,
                    currentLibCandidates,
                    currentLibType,
                    currentLibTypeLabel,
                    isLibraryView,
                    selectedLibType,
                    libTypeLabelMap,
                    toggleMobileNav,
                    closeMobileNav,
                    switchView,
                    shortId,
                    pretty,
                    basename,
                    formatInt,
                    formatBytes,
                    formatDateTime,
                    formatRelativeTime,
                    formatDuration,
                    escapeHtml,
                    formatLogTimestamp,
                    logLevelClass,
                    providerVerifyStatusLabel,
                    providerVerifyStatusClass,
                    displayProgress,
                    normalizeProjectStatus,
                    displayProjectStatus,
                    statusDotClass,
                    displayStageStatus,
                    statusBadgeClass,
                    projectUsage,
                    sessionHealthLabel,
                    sessionHealthClass,
                    shellHostLabel,
                    shellUserLabel,
                    shellTypeLabel,
                    shellStatusLabel,
                    stageTitle,
                    fetchProjects,
                    loadSessions,
                    loadShells,
                    onSelectedProjectChange,
                    loadSessionBackend,
                    saveSessionBackend,
                    probeMsfSessions,
                    syncMsfSessions,
                    refreshSelectedSessionStatus,
                    checkSessionHealth,
                    selectProject,
                    selectManagedSession,
                    selectShell,
                    bindShellToSessionDraft,
                    runProjectAction,
                    removeProject,
                    createProject,
                    normalizeProjectField,
                    controlProject,
                    deleteProject,
                    openSession,
                    closeSession,
                    loadAttackChain,
                    selectAttackStage,
                    runFileOps,
                    pickFileEntry,
                    loadFileEntry,
                    onUploadFileChange,
                    uploadFile,
                    uploadMTool,
                    downloadFile,
                    executeCli,
                    applyCommandPreset,
                    reuseHistoryCommand,
                    generateReport,
                    loadLatestReport,
                    downloadReport,
                    listLibFiles,
                    readLibFile,
                    saveLibFile,
                    deleteLibFile,
                    selectLibItem,
                    saveApiKey,
                    loadApiKeyStatus,
                    handleSettingsProviderChange,
                    loadProviderCatalog,
                    loadProviderModels,
                    toggleFailoverModel,
                    restoreLiveLogs,
                    clearLiveLogs,
                    logStreamRef,
                    autoFollowLogStream,
                    syncExploitDB,
                    submitLearningSync,
                    loadLearningHistory,
                    validateWebAuditRules,
                    runWebAudit,
                    saveAccessKey,
                    loadAccessKeyStatus
                };
            }
        }).mount('#app');





