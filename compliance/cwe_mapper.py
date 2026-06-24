"""CWE (Common Weakness Enumeration) mapper."""
from __future__ import annotations

CWE_MAP = {
    "SSRF": {"id": "CWE-918", "name": "Server-Side Request Forgery"},
    "SQLI": {"id": "CWE-89", "name": "SQL Injection"},
    "XSS": {"id": "CWE-79", "name": "Cross-site Scripting"},
    "IDOR": {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key"},
    "SSTI": {"id": "CWE-94", "name": "Code Injection"},
    "XXE": {"id": "CWE-611", "name": "XML External Entity Reference"},
    "PATH_TRAVERSAL": {"id": "CWE-22", "name": "Path Traversal"},
    "DESERIALIZATION": {"id": "CWE-502", "name": "Deserialization of Untrusted Data"},
}


class CWEMapper:
    """Maps vulnerability types to CWE identifiers."""

    def map(self, vuln_type: str) -> dict:
        """Return CWE info with URL."""
        entry = CWE_MAP.get(vuln_type.upper(), {})
        if not entry:
            return {"id": "N/A", "name": "Unknown", "url": ""}
        cwe_num = entry["id"].replace("CWE-", "")
        return {
            "id": entry["id"],
            "name": entry["name"],
            "url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
        }

    def get_cwe_id(self, vuln_type: str) -> str:
        """Return CWE ID string like 'CWE-918'."""
        return CWE_MAP.get(vuln_type.upper(), {}).get("id", "N/A")
