"""NIST CSF 2.0 Function Metadata Configuration.

This module contains the central configuration dictionary mapping each
NIST CSF 2.0 function to its abbreviation and description.
"""

FUNCTION_META = {
    "GOVERN": {
        "abbr": "GV",
        "description": "Establish cybersecurity risk management strategy, expectations, and policy"
    },
    "IDENTIFY": {
        "abbr": "ID",
        "description": "Understand assets, risks, and vulnerabilities across the environment"
    },
    "PROTECT": {
        "abbr": "PR",
        "description": "Safeguards to manage cybersecurity risk and limit impact"
    },
    "DETECT": {
        "abbr": "DE",
        "description": "Find and analyze cybersecurity events and anomalies"
    },
    "RESPOND": {
        "abbr": "RS",
        "description": "Take action on detected cybersecurity incidents"
    },
    "RECOVER": {
        "abbr": "RC",
        "description": "Restore capabilities impaired by cybersecurity incidents"
    },
}
