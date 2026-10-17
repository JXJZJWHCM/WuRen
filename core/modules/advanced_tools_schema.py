# JSON Schemas for Advanced Web Attack and Defense Evasion Tools

BROWSER_ACTION_SCHEMA = {
    "name": "browser_action",
    "description": "Perform an autonomous browser action (navigate, click, type, screenshot, etc.) for dynamic web testing.",
    "parameters": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The URL to perform the action on (e.g., 'http://target.com/login')."
            },
            "action": {
                "type": "string",
                "enum": ["screenshot", "get_content", "click", "type", "intercept_requests"],
                "description": "The type of browser action to perform."
            },
            "params": {
                "type": "object",
                "description": "Optional parameters for the action (e.g., {'selector': '#login-btn'} for click).",
                "properties": {
                    "selector": {"type": "string"},
                    "text": {"type": "string"},
                    "path": {"type": "string"}
                }
            }
        },
        "required": ["url", "action"]
    }
}

REPLAY_REQUEST_SCHEMA = {
    "name": "replay_request",
    "description": "Manually replay/modify and send an HTTP request to test for logic vulnerabilities or bypass WAF.",
    "parameters": {
        "type": "object",
        "properties": {
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                "description": "The HTTP method to use."
            },
            "url": {
                "type": "string",
                "description": "The full target URL."
            },
            "headers": {
                "type": "object",
                "description": "The HTTP headers to send.",
                "additionalProperties": {"type": "string"}
            },
            "body": {
                "type": "string",
                "description": "The raw HTTP request body (for POST/PUT requests)."
            }
        },
        "required": ["method", "url", "headers"]
    }
}

DETECT_WAF_SCHEMA = {
    "name": "detect_waf",
    "description": "Identify the target's WAF (Web Application Firewall) to plan for bypasses.",
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "The target URL or domain to test."
            }
        },
        "required": ["target"]
    }
}

FIND_BYPASS_STRATEGIES_SCHEMA = {
    "name": "find_bypass_strategies",
    "description": "Search for known bypass strategies for a given WAF and attack type.",
    "parameters": {
        "type": "object",
        "properties": {
            "waf_name": {
                "type": "string",
                "description": "The name of the detected WAF (e.g., 'Cloudflare', 'ModSecurity')."
            },
            "attack_type": {
                "type": "string",
                "enum": ["SQLI", "XSS", "RCE", "LFI", "SSTI"],
                "description": "The type of attack you are trying to perform."
            }
        },
        "required": ["waf_name", "attack_type"]
    }
}

TEST_BYPASS_FEASIBILITY_SCHEMA = {
    "name": "test_bypass_feasibility",
    "description": "Tests if a specific bypass payload is feasible against the target's defense.",
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "The target URL or domain to test against."
            },
            "payload": {
                "type": "string",
                "description": "The specific bypass payload to test."
            },
            "attack_type": {
                "type": "string",
                "description": "The type of attack being tested (e.g., 'SQLI', 'XSS')."
            }
        },
        "required": ["target", "payload", "attack_type"]
    }
}

ALL_ADVANCED_TOOLS = [
    {"type": "function", "function": BROWSER_ACTION_SCHEMA},
    {"type": "function", "function": REPLAY_REQUEST_SCHEMA},
    {"type": "function", "function": DETECT_WAF_SCHEMA},
    {"type": "function", "function": FIND_BYPASS_STRATEGIES_SCHEMA},
    {"type": "function", "function": TEST_BYPASS_FEASIBILITY_SCHEMA}
]
