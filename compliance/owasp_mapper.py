"""OWASP Top 10 2021 mapper."""
from __future__ import annotations

OWASP_TOP10_2021 = {
    "A01": {
        "name": "Broken Access Control",
        "vuln_types": ["IDOR", "PATH_TRAVERSAL"],
        "description": "访问控制失效，允许用户访问未授权资源",
    },
    "A02": {
        "name": "Cryptographic Failures",
        "vuln_types": [],
        "description": "密码学相关失败",
    },
    "A03": {
        "name": "Injection",
        "vuln_types": ["SQLI", "SSTI", "XXE", "XSS"],
        "description": "注入攻击，包括SQL、NoSQL、命令注入等",
    },
    "A05": {
        "name": "Security Misconfiguration",
        "vuln_types": [],
        "description": "安全配置错误",
    },
    "A06": {
        "name": "Vulnerable Components",
        "vuln_types": ["DESERIALIZATION"],
        "description": "使用含已知漏洞的组件",
    },
    "A07": {
        "name": "Auth & Session Failures",
        "vuln_types": [],
        "description": "身份认证和会话管理失败",
    },
    "A08": {
        "name": "Software & Data Integrity Failures",
        "vuln_types": ["DESERIALIZATION"],
        "description": "软件和数据完整性失败",
    },
    "A10": {
        "name": "SSRF",
        "vuln_types": ["SSRF"],
        "description": "服务端请求伪造",
    },
}

# Risk ratings per OWASP category
_RISK_RATINGS = {
    "A01": "Critical",
    "A03": "Critical",
    "A10": "High",
    "A06": "High",
    "A08": "High",
    "A05": "Medium",
    "A07": "High",
    "A02": "Medium",
}


class OWASPMapper:
    """Maps vulnerability types to OWASP Top 10 2021 categories."""

    def map(self, vuln_type: str) -> list[dict]:
        """Return all matching OWASP entries for a vulnerability type."""
        vt = vuln_type.upper()
        results = []
        for owasp_id, entry in OWASP_TOP10_2021.items():
            if vt in entry["vuln_types"]:
                results.append({
                    "owasp_id": owasp_id,
                    "name": entry["name"],
                    "description": entry["description"],
                })
        return results

    def get_owasp_id(self, vuln_type: str) -> str:
        """Return the primary OWASP ID for a vulnerability type."""
        matches = self.map(vuln_type)
        if matches:
            return matches[0]["owasp_id"]
        return "N/A"

    def get_risk_rating(self, vuln_type: str) -> str:
        """Return risk rating based on OWASP classification."""
        matches = self.map(vuln_type)
        if matches:
            return _RISK_RATINGS.get(matches[0]["owasp_id"], "Medium")
        return "Low"
