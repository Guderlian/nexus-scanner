"""Vulnerability pattern library - 8 vulnerability types."""
from __future__ import annotations

VULN_PATTERNS: dict[str, dict] = {
    "SSRF": {
        "dangerous_functions": [
            "requests.get", "requests.post", "requests.put", "requests.request",
            "urllib.request.urlopen", "httpx.get", "httpx.post",
            "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
        ],
        "external_sources": ["request.args", "request.form", "request.json", "os.environ", "sys.argv"],
        "safe_patterns": ["urlparse", "ALLOWED_HOSTS", "whitelist", "allowlist"],
        "attack_vectors": [
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.x.x/",
            "file:///etc/passwd",
            "http://localhost/admin",
        ],
        "semgrep_rule_id": "ssrf-detection",
    },
    "SQLI": {
        "dangerous_functions": [
            "execute", "executemany", "raw", "RawSQL",
            "cursor.execute", "db.execute",
        ],
        "dangerous_patterns": [
            'f"SELECT', "f'SELECT", "% (", ".format(",
            "string_agg", "GROUP_CONCAT",
        ],
        "external_sources": ["request.args", "request.form", "request.GET", "request.POST"],
        "safe_patterns": ["parameterized", "prepared", "?", "%s", "ORM", "filter("],
        "attack_vectors": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
        ],
        "semgrep_rule_id": "sqli-detection",
    },
    "IDOR": {
        "dangerous_patterns": [
            "request.args.get('id')", "request.args.get('user_id')",
            "request.args.get('file')", "request.args.get('path')",
            "request.form.get('id')",
        ],
        "missing_checks": ["current_user", "owner_id", "permission", "authorize", "is_owner"],
        "dangerous_operations": [".get(id=", ".filter(id=", "open(", "os.path.join("],
        "attack_vectors": [
            "修改 id 参数访问他人资源",
            "遍历数字 id 枚举所有对象",
            "路径遍历：../../etc/passwd",
        ],
        "semgrep_rule_id": "idor-detection",
    },
    "XSS": {
        "dangerous_functions": [
            "render_template_string", "Markup(", "mark_safe(",
            "innerHTML", "document.write(", "eval(",
        ],
        "dangerous_patterns": [
            'f"<', "f'<", "request.args", "request.form",
            "| safe", "escape=False",
        ],
        "safe_patterns": ["escape(", "bleach.clean(", "html.escape(", "markupsafe"],
        "attack_vectors": [
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ],
        "semgrep_rule_id": "xss-detection",
    },
    "SSTI": {
        "dangerous_functions": [
            "render_template_string", "Template(", "from_string(",
            "Environment().from_string", "jinja2.Template(",
        ],
        "dangerous_patterns": [
            "render_template_string(request", "Template(user_input",
            "from_string(request",
        ],
        "safe_patterns": ["render_template(", "template_name"],
        "attack_vectors": [
            "{{7*7}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "${7*7}",
        ],
        "semgrep_rule_id": "ssti-detection",
    },
    "XXE": {
        "dangerous_functions": [
            "etree.parse(", "xml.dom.minidom.parse(",
            "lxml.etree.fromstring(", "xmltodict.parse(",
            "parseString(",
        ],
        "dangerous_patterns": [
            "resolve_entities=True", "no_network=False",
            "FEATURE_EXTERNAL_GENERAL_ENTITIES",
        ],
        "safe_patterns": [
            "defusedxml", "resolve_entities=False",
            "no_network=True", "XMLParser(resolve_entities=False)",
        ],
        "attack_vectors": [
            "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
            "<!ENTITY xxe SYSTEM 'http://attacker.com/'>",
        ],
        "semgrep_rule_id": "xxe-detection",
    },
    "PATH_TRAVERSAL": {
        "dangerous_functions": [
            "open(", "os.path.join(", "pathlib.Path(",
            "send_file(", "send_from_directory(",
        ],
        "dangerous_patterns": [
            "open(request.args", "open(user_input",
            "os.path.join(base, user", "Path(request",
            "send_file(request",
        ],
        "safe_patterns": [
            "os.path.abspath", "Path.resolve()",
            "safe_join(", "werkzeug.security.safe_join",
        ],
        "attack_vectors": [
            "../../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f",
        ],
        "semgrep_rule_id": "path-traversal-detection",
    },
    "DESERIALIZATION": {
        "dangerous_functions": [
            "pickle.loads(", "pickle.load(",
            "yaml.load(", "marshal.loads(",
            "jsonpickle.decode(", "shelve.open(",
        ],
        "dangerous_patterns": [
            "pickle.loads(request", "pickle.loads(user",
            "yaml.load(request", "yaml.load(user",
        ],
        "safe_patterns": [
            "yaml.safe_load(", "pickle.loads.*trusted",
            "Loader=yaml.SafeLoader",
        ],
        "attack_vectors": [
            "cos\\nsystem\\n(S'id'\\ntR.",
            "!!python/object/apply:os.system ['id']",
        ],
        "semgrep_rule_id": "deserialization-detection",
    },
}


def get_pattern(vuln_type: str) -> dict:
    """Get the pattern dict for a vulnerability type."""
    return VULN_PATTERNS.get(vuln_type.upper(), {})


def list_vuln_types() -> list[str]:
    """List all available vulnerability types."""
    return list(VULN_PATTERNS.keys())
