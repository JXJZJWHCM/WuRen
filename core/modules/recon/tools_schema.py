from typing import List, Dict, Any

def get_active_recon_tools_schema() -> List[Dict[str, Any]]:
    """
    Returns JSON schemas for active reconnaissance tools.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": "active_recon_port_scan",
                "description": "Perform an active port scan on a target using Nmap to identify open ports.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "The target IP address or hostname to scan."
                        }
                    },
                    "required": ["target"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "active_recon_service_scan",
                "description": "Perform a service version detection scan on a target using Nmap.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "The target IP address or hostname."
                        },
                        "ports": {
                            "type": "array",
                            "items": {
                                "type": "integer"
                            },
                            "description": "Optional list of specific ports to scan. If omitted, scans common ports."
                        }
                    },
                    "required": ["target"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "active_recon_web_fingerprint",
                "description": "Perform web fingerprinting on a target using Nuclei to identify technologies and potential vulnerabilities.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "The target URL or IP address."
                        }
                    },
                    "required": ["target"]
                }
            }
        }
    ]

def get_passive_recon_tools_schema() -> List[Dict[str, Any]]:
    """
    Returns JSON schemas for passive reconnaissance tools.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": "passive_recon_dns_lookup",
                "description": "Perform passive DNS lookup to retrieve A, AAAA, MX, NS, and TXT records.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "The domain name to lookup."
                        }
                    },
                    "required": ["target"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "passive_recon_whois_lookup",
                "description": "Perform a WHOIS lookup to retrieve domain registration information.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "The domain name or IP address."
                        }
                    },
                    "required": ["target"]
                }
            }
        }
    ]

WEB_SOURCE_AUDIT_SCHEMA = {
    "name": "run_web_source_audit",
    "description": "Run web source code audit against a target URL using repo audit rules with optional yak execution.",
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL or host (host will be normalized to http://host)."
            },
            "auto_fix_rules": {
                "type": "boolean",
                "description": "Automatically validate and overwrite-fix invalid rule files before audit."
            },
            "use_yak": {
                "type": "boolean",
                "description": "Whether to invoke yak analyzer as part of audit."
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "HTTP fetch timeout in seconds.",
                "minimum": 3,
                "maximum": 120
            }
        },
        "required": ["target"]
    }
}

QUERY_KNOWLEDGE_BASE_SCHEMA = {
    "name": "query_knowledge_base",
    "description": "Query the built-in RAG (Retrieval-Augmented Generation) knowledge base for penetration testing techniques, vulnerabilities, or framework-specific attack methods.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The search query (e.g., 'How to exploit Weblogic CVE-2020-14882', 'Nmap scanning techniques for SMB')."
            },
            "top_k": {
                "type": "integer",
                "description": "Number of results to retrieve (default is 3).",
                "minimum": 1,
                "maximum": 10
            }
        },
        "required": ["query"]
    }
}

def get_all_recon_tools_schema() -> List[Dict[str, Any]]:
    """
    Returns all reconnaissance tool schemas.
    """
    from core.modules.exploit.tools_schema import (
        AI_TOOL_GENERATOR_SCHEMA,
        LOCAL_FINGERPRINT_SCHEMA,
        QUERY_KNOWLEDGE_BASE_SCHEMA,
        QUERY_SKILLS_BASE_SCHEMA,
        RUN_LOCAL_PLUGIN_SCHEMA,
        RUN_MTOOL_SCHEMA,
        RUN_TOOL_SCHEMA,
        SEARCH_LOCAL_PLUGINS_SCHEMA,
        SEARCH_MTOOLS_SCHEMA,
        SELF_LEARNING_SEARCH_SCHEMA,
    )
    from core.modules.advanced_tools_schema import DETECT_WAF_SCHEMA, BROWSER_ACTION_SCHEMA
    
    return get_active_recon_tools_schema() + get_passive_recon_tools_schema() + [
        {
            "type": "function",
            "function": WEB_SOURCE_AUDIT_SCHEMA
        },
        {
            "type": "function",
            "function": LOCAL_FINGERPRINT_SCHEMA
        },
        {
            "type": "function",
            "function": SEARCH_LOCAL_PLUGINS_SCHEMA
        },
        {
            "type": "function",
            "function": RUN_LOCAL_PLUGIN_SCHEMA
        },
        {
            "type": "function",
            "function": SEARCH_MTOOLS_SCHEMA
        },
        {
            "type": "function",
            "function": RUN_MTOOL_SCHEMA
        },
        {
            "type": "function",
            "function": AI_TOOL_GENERATOR_SCHEMA
        },
        {
            "type": "function",
            "function": QUERY_KNOWLEDGE_BASE_SCHEMA
        },
        {
            "type": "function",
            "function": QUERY_SKILLS_BASE_SCHEMA
        },
        {
            "type": "function",
            "function": SELF_LEARNING_SEARCH_SCHEMA
        },
        {
            "type": "function",
            "function": RUN_TOOL_SCHEMA
        },
        {
            "type": "function",
            "function": DETECT_WAF_SCHEMA
        },
        {
            "type": "function",
            "function": BROWSER_ACTION_SCHEMA
        }
    ]
