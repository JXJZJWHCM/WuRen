REPORT_TOOLS_SCHEMA = [
    {
        "name": "generate_report",
        "description": "Generate a penetration testing report based on provided data.",
        "parameters": {
            "type": "object",
            "properties": {
                "project_id": {
                    "type": "string",
                    "description": "Unique identifier for the project."
                },
                "data": {
                    "type": "object",
                    "description": "Report data including recon results, vulnerabilities, shells, etc.",
                    "properties": {
                        "executive_summary": {
                            "type": "string",
                            "description": "High-level summary of findings."
                        },
                        "methodology": {
                            "type": "string",
                            "description": "Testing methodology used."
                        },
                        "findings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "title": {"type": "string"},
                                    "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
                                    "description": {"type": "string"},
                                    "remediation": {"type": "string"}
                                }
                            }
                        },
                        "recommendations": {
                            "type": "string",
                            "description": "General recommendations."
                        }
                    },
                    "required": ["findings"]
                }
            },
            "required": ["project_id", "data"]
        }
    },
    {
        "name": "verify_artifact",
        "description": "Verify an artifact (PoC or Report) using AI.",
        "parameters": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "The content to verify."
                },
                "type": {
                    "type": "string",
                    "enum": ["poc", "report"],
                    "description": "Type of artifact to verify."
                }
            },
            "required": ["content", "type"]
        }
    }
]
