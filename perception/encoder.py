"""PerceptionEncoder - AST-based SSRF detection in Python/Java files."""
from __future__ import annotations

import ast
import os
import re
from typing import List, Optional

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fact_card import FactCard


class PerceptionEncoder:
    """Scans source files for dangerous URL-fetching calls using AST analysis."""

    # Dangerous sinks: (module_pattern, function_name)
    PYTHON_SINKS = {
        "requests": ["get", "post", "put", "delete", "patch", "head", "options"],
        "httpx": ["get", "post", "put", "delete", "patch", "head", "options"],
        "urllib.request": ["urlopen", "urlretrieve"],
        "aiohttp": ["get", "post", "put", "delete", "patch", "request"],
    }

    # Patterns indicating external controllability
    EXTERNAL_PATTERNS = [
        r'request\.(args|form|json|data|values|get)',
        r'request\.\w+',
        r'os\.environ',
        r'sys\.argv',
        r'input\s*\(',
        r'request\.args\.get',
        r'request\.form\.get',
    ]

    # Patterns for string concatenation with URL-like variables
    CONCAT_PATTERNS = [
        r'\+\s*\w+',
        r'f["\'].*{.*}',
        r'%s.*%',
        r'\.format\(',
    ]

    def __init__(self, context_lines: int = 3, min_confidence: float = 0.3):
        self.context_lines = context_lines
        self.min_confidence = min_confidence

    def encode_file(self, path: str) -> List[FactCard]:
        """Scan a single file and return FactCards for suspicious fragments."""
        if not os.path.isfile(path):
            return []
        ext = os.path.splitext(path)[1].lower()
        cards: List[FactCard] = []
        if ext == ".py":
            cards.extend(self._scan_python(path))
            cards.extend(self._scan_python_sqli(path))
            cards.extend(self._scan_python_idor(path))
            cards.extend(self._scan_python_xss(path))
            cards.extend(self._scan_python_ssti(path))
            cards.extend(self._scan_python_xxe(path))
            cards.extend(self._scan_python_path_traversal(path))
            cards.extend(self._scan_python_deserialization(path))
        elif ext in (".js", ".ts", ".jsx", ".tsx"):
            from languages.javascript_encoder import JavaScriptEncoder
            cards.extend(JavaScriptEncoder().encode_file(path))
        elif ext == ".go":
            from languages.go_encoder import GoEncoder
            cards.extend(GoEncoder().encode_file(path))
        elif ext == ".java":
            cards.extend(self._scan_java(path))
        return cards

    def encode_directory(self, path: str) -> List[FactCard]:
        """Recursively scan a directory for suspicious code."""
        cards: List[FactCard] = []
        for root, _, files in os.walk(path):
            for fname in files:
                if fname.endswith((".py", ".java", ".js", ".ts", ".jsx", ".tsx", ".go")):
                    cards.extend(self.encode_file(os.path.join(root, fname)))
        return cards

    def _read_context(self, path: str, line_start: int, line_end: int) -> tuple[list[str], str]:
        """Read context lines before the suspicious code, bounded by function scope."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except (IOError, OSError):
            return [], ""

        snippet_start = max(0, line_start - 1)
        snippet_end = min(len(all_lines), line_end)
        snippet = "".join(all_lines[snippet_start:snippet_end]).strip()

        # Fix 3: Bound context to the enclosing function
        func_start, func_end = self._get_function_bounds(all_lines, line_start - 1)
        ctx_start = max(func_start, line_start - 1 - self.context_lines)
        context_lines = [l.rstrip() for l in all_lines[ctx_start:snippet_start]]
        return context_lines, snippet

    def _get_function_bounds(self, lines: list[str], trigger_line: int) -> tuple[int, int]:
        """Return (start, end) line indices of the enclosing function."""
        # Find function start: go upward looking for def
        func_start = 0
        for i in range(trigger_line, -1, -1):
            stripped = lines[i].lstrip()
            if stripped.startswith("def ") or stripped.startswith("async def "):
                func_start = i
                break

        # Find function end: go downward looking for next def at same or lower indent
        func_indent = len(lines[func_start]) - len(lines[func_start].lstrip())
        func_end = len(lines) - 1
        for i in range(trigger_line + 1, len(lines)):
            stripped = lines[i].lstrip()
            if stripped and (stripped.startswith("def ") or stripped.startswith("async def ")):
                current_indent = len(lines[i]) - len(stripped)
                if current_indent <= func_indent:
                    func_end = i - 1
                    break

        return func_start, func_end

    def _scan_python(self, path: str) -> List[FactCard]:
        """Use Python AST to find dangerous calls."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except (IOError, OSError):
            return []

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        cards: List[FactCard] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Determine if this is a dangerous sink
            sink_info = self._identify_python_sink(node)
            if not sink_info:
                continue

            module, func = sink_info
            line_start = node.lineno
            line_end = getattr(node, "end_lineno", node.lineno)

            context_lines, snippet = self._read_context(path, line_start, line_end)
            context_text = "\n".join(context_lines)

            # Calculate confidence
            confidence = 0.3
            heuristics = []
            data_flow = []

            # Check if URL arg is a variable (not hardcoded)
            url_arg_external = self._is_url_external(node, context_text)
            if url_arg_external:
                confidence += 0.2
                heuristics.append("外部可控URL")
                data_flow.append(f"{url_arg_external}->{module}.{func}")

            # Check for string concatenation in context
            if self._has_concat_pattern(snippet + "\n" + context_text):
                confidence += 0.2
                heuristics.append("字符串拼接")

            # Check for validation (reduces confidence) — check snippet + context + enclosing function
            all_text = snippet + "\n" + context_text
            # Also grab enclosing function body for better validation detection
            func_body = self._get_enclosing_function_text(source, line_start)
            if func_body:
                all_text += "\n" + func_body
            if self._has_validation(all_text):
                confidence -= 0.2
                heuristics.append("有URL校验")
            else:
                confidence += 0.2
                heuristics.append("无URL校验")

            # Check for TODO/FIXME
            if re.search(r'TODO|FIXME|HACK|XXX', snippet + context_text, re.IGNORECASE):
                confidence += 0.1
                heuristics.append("含TODO/FIXME")

            if confidence < self.min_confidence:
                continue

            # Find enclosing function name
            func_name = self._find_enclosing_function(tree, line_start)

            cards.append(FactCard(
                file_path=path,
                line_start=line_start,
                line_end=line_end,
                code_snippet=snippet,
                language="python",
                data_flow=data_flow,
                heuristics=heuristics,
                confidence=min(confidence, 1.0),
                function_name=func_name,
                sink=f"{module}.{func}",
            ))

        return cards

    def _identify_python_sink(self, node: ast.Call) -> Optional[tuple[str, str]]:
        """Check if a Call node matches a known dangerous sink."""
        func = node.func

        # requests.get(...) / httpx.get(...)
        if isinstance(func, ast.Attribute):
            method = func.attr
            if isinstance(func.value, ast.Attribute):
                # e.g. aiohttp.ClientSession().get — parent is an attribute
                parent = func.value.attr
                for mod, methods in self.PYTHON_SINKS.items():
                    mod_short = mod.split(".")[-1]
                    if method in methods and parent in (mod, mod_short, "session", "client", "aiohttp"):
                        return (mod, method)
            elif isinstance(func.value, ast.Name):
                obj_name = func.value.id
                # Direct: requests.get / httpx.get
                for mod, methods in self.PYTHON_SINKS.items():
                    mod_short = mod.split(".")[-1]
                    if obj_name in (mod, mod_short, "session", "client", "aiohttp") and method in methods:
                        return (mod, method)

        # from urllib.request import urlopen; urlopen(...)
        if isinstance(func, ast.Name):
            name = func.id
            if name == "urlopen":
                return ("urllib.request", "urlopen")
            if name == "urlretrieve":
                return ("urllib.request", "urlretrieve")

        return None

    def _is_url_external(self, node: ast.Call, context: str) -> Optional[str]:
        """Check if the URL argument is externally controlled. Returns variable name if so."""
        if not node.args:
            return None

        url_arg = node.args[0]

        # Hardcoded string literal — NOT external
        if isinstance(url_arg, ast.Constant) and isinstance(url_arg.value, str):
            return None

        # Direct variable reference
        if isinstance(url_arg, ast.Name):
            var_name = url_arg.id
            # Check if variable is from external source
            for pat in self.EXTERNAL_PATTERNS:
                if re.search(pat, context):
                    return var_name
            # If it's a function parameter, it's likely external
            if re.search(rf'def\s+\w+\s*\([^)]*\b{var_name}\b', context):
                return var_name
            return var_name  # Variables are assumed potentially external

        # f-string or format
        if isinstance(url_arg, ast.JoinedStr):
            return "f_string"
        if isinstance(url_arg, ast.Call) and isinstance(url_arg.func, ast.Attribute):
            if url_arg.func.attr == "format":
                return "format_string"

        return None

    def _has_concat_pattern(self, text: str) -> bool:
        """Check for URL string concatenation patterns."""
        for pat in self.CONCAT_PATTERNS:
            if re.search(pat, text):
                return True
        return False

    def _has_validation(self, context: str) -> bool:
        """Check if there's URL validation in the context."""
        validation_patterns = [
            r'urlparse',
            r'url\s*==',
            r'\.startswith\s*\(',
            r'whitelist',
            r'allowlist',
            r'regex.*url',
            r'validate.*url',
            r'is_valid',
            r'check_url',
        ]
        for pat in validation_patterns:
            if re.search(pat, context, re.IGNORECASE):
                return True
        return False

    def _find_enclosing_function(self, tree: ast.AST, line: int) -> Optional[str]:
        """Find the function name that contains the given line."""
        best = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.lineno <= line:
                    end = getattr(node, "end_lineno", node.lineno + 1000)
                    if line <= end:
                        if best is None or node.lineno >= best[1]:
                            best = (node.name, node.lineno)
        return best[0] if best else None

    def _get_enclosing_function_text(self, source: str, line: int) -> str:
        """Get the text of the enclosing function for better context analysis."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return ""
        lines = source.split("\n")
        best = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.lineno <= line:
                    end = getattr(node, "end_lineno", node.lineno + 1000)
                    if line <= end:
                        if best is None or node.lineno >= best[0]:
                            best = (node.lineno, end)
        if best:
            start_idx = best[0] - 1
            end_idx = min(best[1], len(lines))
            return "\n".join(lines[start_idx:end_idx])
        return ""

    def _scan_java(self, path: str) -> List[FactCard]:
        """Regex-based scanning for Java files."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except (IOError, OSError):
            return []

        cards: List[FactCard] = []
        java_sinks = [
            (r'new\s+URL\s*\(', "java.net.URL", "constructor"),
            (r'HttpURLConnection', "java.net.HttpURLConnection", "openConnection"),
            (r'HttpClient\.create', "org.apache.http", "create"),
            (r'RestTemplate\.\w+', "org.springframework.web", "restTemplate"),
            (r'WebClient\.\w+', "org.springframework.web", "webClient"),
        ]

        for i, line in enumerate(lines):
            for pattern, module, method in java_sinks:
                if re.search(pattern, line):
                    line_start = i + 1
                    line_end = line_start
                    ctx_start = max(0, i - self.context_lines)
                    context_lines = [l.rstrip() for l in lines[ctx_start:i]]
                    snippet = line.strip()
                    context_text = "\n".join(context_lines)

                    confidence = 0.3
                    heuristics = []
                    if not self._has_validation(context_text):
                        confidence += 0.2
                        heuristics.append("无URL校验")
                    if self._has_concat_pattern(snippet + context_text):
                        confidence += 0.2
                        heuristics.append("字符串拼接")

                    if confidence >= self.min_confidence:
                        cards.append(FactCard(
                            file_path=path,
                            line_start=line_start,
                            line_end=line_end,
                            code_snippet=snippet,
                            language="java",
                            heuristics=heuristics,
                            confidence=min(confidence, 1.0),
                            sink=f"{module}.{method}",
                        ))
        return cards

    # ===== SQLi Detection =====

    SQLI_SINKS = {"execute", "executemany", "raw", "RawSQL"}
    SQLI_DANGEROUS_PATTERNS = [
        r'f["\'].*SELECT', r"f'.*SELECT", r'f".*SELECT',
        r'SELECT.*%s', r'SELECT.*\{',
        r'\.format\(', r'% \(',
        r'INSERT.*f["\']', r'UPDATE.*f["\']', r'DELETE.*f["\']',
    ]
    SQLI_SAFE_PATTERNS = [
        r'\?',
        r'%s',
        r'execute\([^,]+,\s*\(',
        r'\.filter\(',
        r'objects\.filter',
    ]

    def _scan_python_sqli(self, path: str) -> List[FactCard]:
        """Scan for SQL injection patterns."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except (IOError, OSError):
            return []

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        cards: List[FactCard] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            sink_info = self._identify_sqli_sink(node)
            if not sink_info:
                continue

            module, func = sink_info
            line_start = node.lineno
            line_end = getattr(node, "end_lineno", node.lineno)
            context_lines, snippet = self._read_context(path, line_start, line_end)
            context_text = "\n".join(context_lines)
            all_text = snippet + "\n" + context_text
            func_body = self._get_enclosing_function_text(source, line_start)
            if func_body:
                all_text += "\n" + func_body

            confidence = 0.3
            heuristics = []
            data_flow = []

            has_dangerous_concat = False
            for pat in self.SQLI_DANGEROUS_PATTERNS:
                if re.search(pat, all_text, re.IGNORECASE):
                    has_dangerous_concat = True
                    break
            if has_dangerous_concat:
                confidence += 0.3
                heuristics.append("SQL字符串拼接")

            for src_pattern in [r'request\.(args|form|GET|POST)', r'request\.args\.get']:
                if re.search(src_pattern, all_text):
                    confidence += 0.2
                    heuristics.append("外部可控参数")
                    data_flow.append(f"request->{module}.{func}")
                    break

            has_safe = False
            for sp in self.SQLI_SAFE_PATTERNS:
                if re.search(sp, all_text):
                    has_safe = True
                    break
            if has_safe:
                confidence -= 0.2
                heuristics.append("参数化查询")
            else:
                confidence += 0.2
                heuristics.append("无参数化")

            if confidence < self.min_confidence:
                continue

            func_name = self._find_enclosing_function(tree, line_start)
            cards.append(FactCard(
                file_path=path,
                line_start=line_start,
                line_end=line_end,
                code_snippet=snippet,
                language="python",
                data_flow=data_flow,
                heuristics=heuristics,
                confidence=min(confidence, 1.0),
                function_name=func_name,
                sink=f"{module}.{func}",
            ))

        return cards

    def _identify_sqli_sink(self, node: ast.Call) -> Optional[tuple[str, str]]:
        """Check if a Call node matches a known SQLi sink."""
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in self.SQLI_SINKS:
            obj = func.value
            if isinstance(obj, ast.Name):
                return (obj.id, func.attr)
            if isinstance(obj, ast.Attribute):
                return (obj.attr, func.attr)
        if isinstance(func, ast.Name) and func.id in self.SQLI_SINKS:
            return ("builtin", func.id)
        return None

    # ===== IDOR Detection =====

    IDOR_ID_PARAMS = [
        "id", "user_id", "user", "file", "filename", "path", "doc_id",
        "order_id", "item_id", "account_id", "profile_id",
    ]
    IDOR_DANGEROUS_OPS = [
        r'\.get\(id\s*=', r'\.filter\(id\s*=',
        r'\.get\(pk\s*=', r'\.filter\(pk\s*=',
        r'open\(', r'os\.path\.join\(',
    ]
    IDOR_AUTH_CHECKS = [
        r'current_user', r'owner_id', r'permission', r'authorize',
        r'is_owner', r'login_required', r'@login_required',
        r'permission_required', r'current_user\.id',
    ]

    IDOR_ROUTE_PARAMS = [
        "id", "user_id", "doc_id", "order_id", "item_id",
        "account_id", "profile_id", "file_id",
    ]
    IDOR_DB_OPS = [
        r'\.get\(', r'\.filter\(', r'execute\(', r'find_by_id',
        r'WHERE\s+id', r'WHERE\s+user_id',
    ]
    IDOR_ROUTE_MISSING_AUTH = [
        "current_user", "owner_id", "permission", "authorize",
        "is_owner", "has_permission", "login_required", "requires_auth",
    ]
    PARAMETERIZED_PATTERNS = [
        r"execute\([^f]*\?\s*,", r"\?\s*,\s*\(", r"\?\s*,\s*\[",
        r"%s\s*,\s*\(", r"%s\s*,\s*\[", r":param",
        r"\.filter\(", r"\.get\(",
    ]

    def _scan_python_idor(self, path: str) -> List[FactCard]:
        """Scan for IDOR patterns - both request.args and Flask route params."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except (IOError, OSError):
            return []

        cards: List[FactCard] = []
        lines = source.split("\n")

        # --- Pattern A: request.args.get('id') ---
        for i, line in enumerate(lines):
            for param in self.IDOR_ID_PARAMS:
                patterns = [
                    rf"request\.args\.get\(['\"]?{param}['\"]?\)",
                    rf"request\.form\.get\(['\"]?{param}['\"]?\)",
                    rf"request\.GET\.get\(['\"]?{param}['\"]?\)",
                    rf"request\.POST\.get\(['\"]?{param}['\"]?\)",
                    rf"request\.args\[['\"]?{param}['\"]?\]",
                ]
                matched = False
                for pat in patterns:
                    if re.search(pat, line):
                        matched = True
                        break
                if not matched:
                    continue

                line_start = i + 1
                lookahead = "\n".join(lines[i:min(i+15, len(lines))])
                ctx_start = max(0, i - self.context_lines)
                context_text = "\n".join(lines[ctx_start:i])

                confidence = 0.3
                heuristics = [f"ID参数:{param}"]
                data_flow = [f"request.args->{param}"]

                has_dangerous_op = False
                for dop in self.IDOR_DANGEROUS_OPS:
                    if re.search(dop, lookahead):
                        has_dangerous_op = True
                        break
                if has_dangerous_op:
                    confidence += 0.3
                    heuristics.append("直接用于查询/文件操作")

                has_auth = False
                full_text = lookahead + "\n" + context_text
                func_body = self._get_enclosing_function_text(source, line_start)
                if func_body:
                    full_text += "\n" + func_body
                for ac in self.IDOR_AUTH_CHECKS:
                    if re.search(ac, full_text):
                        has_auth = True
                        break
                if not has_auth:
                    confidence += 0.3
                    heuristics.append("无权限检查")
                else:
                    confidence -= 0.2
                    heuristics.append("有权限检查")

                # Fix 2: Cross-reference parameterized queries
                if func_body and self._has_parameterized_query(func_body):
                    confidence -= 0.3
                    heuristics.append("使用参数化查询（降低风险）")

                if confidence >= self.min_confidence:
                    func_name = self._find_enclosing_function_from_source(source, line_start)
                    cards.append(FactCard(
                        file_path=path,
                        line_start=line_start,
                        line_end=line_start,
                        code_snippet=line.strip(),
                        language="python",
                        data_flow=data_flow,
                        heuristics=heuristics,
                        confidence=min(confidence, 1.0),
                        function_name=func_name,
                        sink=f"request.args.get('{param}')",
                    ))
                break

        # --- Pattern B: Flask route parameters ---
        cards.extend(self._scan_idor_route_params(path, source, lines))

        return cards

    def _has_parameterized_query(self, func_body: str) -> bool:
        """Check if function body uses parameterized queries."""
        for pat in self.PARAMETERIZED_PATTERNS:
            if re.search(pat, func_body):
                return True
        return False

    def _scan_idor_route_params(self, path: str, source: str, lines: list[str]) -> List[FactCard]:
        """Detect IDOR via Flask/FastAPI route parameters used in DB queries."""
        cards: List[FactCard] = []

        # Find @app.route decorators with <type:param> patterns
        route_param_re = re.compile(r"<(?:int|float|string|path)?:?(\w+)>")

        for i, line in enumerate(lines):
            # Look for route decorators
            if "@app.route" not in line and "@router" not in line:
                continue

            route_match = route_param_re.findall(line)
            if not route_match:
                continue

            # Find the next def (the handler function)
            func_start = None
            for j in range(i + 1, min(i + 5, len(lines))):
                if lines[j].lstrip().startswith("def "):
                    func_start = j
                    break
            if func_start is None:
                continue

            # Get function name
            func_name_match = re.match(r'\s*def\s+(\w+)', lines[func_start])
            func_name = func_name_match.group(1) if func_name_match else None

            # Get function body
            func_body = self._get_enclosing_function_text(source, func_start + 1)
            if not func_body:
                continue

            # Extract function parameters from def line
            def_match = re.search(r'def\s+\w+\s*\(([^)]*)\)', lines[func_start])
            if not def_match:
                continue
            func_params = [p.strip().split(':')[0].strip()
                          for p in def_match.group(1).split(',')
                          if p.strip() and p.strip() not in ('self', 'cls', 'request')]

            # Check which route params are used in the function
            for param in route_match:
                if param not in func_params:
                    continue

                # Check for DB operations using this param
                has_db_op = False
                for dop in self.IDOR_DB_OPS:
                    if re.search(dop, func_body):
                        has_db_op = True
                        break

                if not has_db_op:
                    continue

                # Check for auth
                has_auth = False
                for ac in self.IDOR_ROUTE_MISSING_AUTH:
                    if re.search(ac, func_body):
                        has_auth = True
                        break

                confidence = 0.4
                heuristics = [f"路由参数:{param}", "IDOR风险"]

                if has_db_op:
                    confidence += 0.3
                    heuristics.append("直接用于数据库查询")

                if not has_auth:
                    confidence += 0.2
                    heuristics.append("无权限检查")
                else:
                    confidence -= 0.3
                    heuristics.append("有权限检查")

                # Cross-reference parameterized queries
                if self._has_parameterized_query(func_body):
                    confidence -= 0.15
                    heuristics.append("使用参数化查询（降低风险）")

                if confidence >= self.min_confidence:
                    cards.append(FactCard(
                        file_path=path,
                        line_start=func_start + 1,
                        line_end=func_start + 1,
                        code_snippet=lines[func_start].strip(),
                        language="python",
                        data_flow=[f"route_param->{param}->db_query"],
                        heuristics=heuristics,
                        confidence=min(confidence, 1.0),
                        function_name=func_name,
                        sink=f"route_param({param})",
                    ))

        return cards

    def _find_enclosing_function_from_source(self, source: str, line: int) -> Optional[str]:
        """Find enclosing function name from raw source."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None
        return self._find_enclosing_function(tree, line)

    # ===== XSS Detection =====

    XSS_SINKS = {
        "render_template_string", "Markup", "mark_safe",
    }
    XSS_DANGEROUS_PATTERNS = [
        r'f["\'].*<', r"f'.*<", r'f".*<',
        r'request\.args', r'request\.form',
        r'\|\s*safe', r'escape\s*=\s*False',
        r'innerHTML\s*=',
        r'document\.write\(',
    ]
    XSS_SAFE_PATTERNS = [
        r'escape\(', r'bleach\.clean\(', r'html\.escape\(', r'markupsafe',
    ]

    def _scan_python_xss(self, path: str) -> List[FactCard]:
        """Scan for XSS patterns."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except (IOError, OSError):
            return []
        lines = source.split("\n")
        cards: List[FactCard] = []
        for i, line in enumerate(lines):
            for sink in self.XSS_SINKS:
                if sink in line:
                    line_start = i + 1
                    ctx_start = max(0, i - self.context_lines)
                    context_text = "\n".join(lines[ctx_start:i])
                    all_text = line + "\n" + context_text
                    func_body = self._get_enclosing_function_text(source, line_start)
                    if func_body:
                        all_text += "\n" + func_body

                    confidence = 0.3
                    heuristics = [f"XSS sink:{sink}"]
                    has_danger = False
                    for pat in self.XSS_DANGEROUS_PATTERNS:
                        if re.search(pat, all_text):
                            has_danger = True
                            break
                    if has_danger:
                        confidence += 0.3
                        heuristics.append("外部可控输入")
                    has_safe = False
                    for sp in self.XSS_SAFE_PATTERNS:
                        if re.search(sp, all_text):
                            has_safe = True
                            break
                    if has_safe:
                        confidence -= 0.2
                        heuristics.append("有转义")
                    else:
                        confidence += 0.2
                        heuristics.append("无转义")
                    if confidence >= self.min_confidence:
                        func_name = self._find_enclosing_function_from_source(source, line_start)
                        cards.append(FactCard(
                            file_path=path, line_start=line_start, line_end=line_start,
                            code_snippet=line.strip(), language="python",
                            heuristics=heuristics,
                            confidence=min(confidence, 1.0),
                            function_name=func_name, sink=sink,
                        ))
                    break
        # Also check innerHTML/document.write via regex
        for i, line in enumerate(lines):
            if re.search(r'innerHTML\s*=', line) or re.search(r'document\.write\(', line):
                line_start = i + 1
                confidence = 0.5
                heuristics = ["XSS:DOM manipulation"]
                func_name = self._find_enclosing_function_from_source(source, line_start)
                cards.append(FactCard(
                    file_path=path, line_start=line_start, line_end=line_start,
                    code_snippet=line.strip(), language="python",
                    heuristics=heuristics, confidence=confidence,
                    function_name=func_name, sink="innerHTML/document.write",
                ))
        return cards

    # ===== SSTI Detection =====

    SSTI_SINKS = {"render_template_string", "from_string", "Template("}
    SSTI_DANGEROUS_PATTERNS = [
        r'render_template_string\s*\(\s*request', r'Template\s*\(\s*(request|user)',
        r'from_string\s*\(\s*request', r'jinja2\.Template\s*\(\s*(request|user)',
    ]
    SSTI_SAFE_PATTERNS = [r'render_template\(', r'template_name']

    def _scan_python_ssti(self, path: str) -> List[FactCard]:
        """Scan for SSTI patterns."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except (IOError, OSError):
            return []
        lines = source.split("\n")
        cards: List[FactCard] = []
        for i, line in enumerate(lines):
            for sink in self.SSTI_SINKS:
                if sink in line:
                    line_start = i + 1
                    all_text = line
                    func_body = self._get_enclosing_function_text(source, line_start)
                    if func_body:
                        all_text += "\n" + func_body
                    confidence = 0.4
                    heuristics = [f"SSTI sink:{sink}"]
                    has_danger = False
                    for pat in self.SSTI_DANGEROUS_PATTERNS:
                        if re.search(pat, all_text, re.IGNORECASE):
                            has_danger = True
                            break
                    if has_danger:
                        confidence += 0.4
                        heuristics.append("用户输入直接传入模板")
                    has_safe = False
                    for sp in self.SSTI_SAFE_PATTERNS:
                        if re.search(sp, all_text):
                            has_safe = True
                            break
                    if has_safe:
                        confidence -= 0.3
                        heuristics.append("使用安全模板")
                    if confidence >= self.min_confidence:
                        func_name = self._find_enclosing_function_from_source(source, line_start)
                        cards.append(FactCard(
                            file_path=path, line_start=line_start, line_end=line_start,
                            code_snippet=line.strip(), language="python",
                            heuristics=heuristics,
                            confidence=min(confidence, 1.0),
                            function_name=func_name, sink=sink,
                        ))
                    break
        return cards

    # ===== XXE Detection =====

    XXE_SINKS = {"etree.parse", "minidom.parse", "fromstring", "xmltodict.parse", "parseString"}
    XXE_SAFE_PATTERNS = [r'defusedxml', r'resolve_entities\s*=\s*False', r'no_network\s*=\s*True']

    def _scan_python_xxe(self, path: str) -> List[FactCard]:
        """Scan for XXE patterns."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except (IOError, OSError):
            return []
        lines = source.split("\n")
        cards: List[FactCard] = []
        for i, line in enumerate(lines):
            for sink in self.XXE_SINKS:
                if sink in line:
                    line_start = i + 1
                    all_text = line
                    func_body = self._get_enclosing_function_text(source, line_start)
                    if func_body:
                        all_text += "\n" + func_body
                    confidence = 0.4
                    heuristics = [f"XXE sink:{sink}"]
                    has_safe = False
                    for sp in self.XXE_SAFE_PATTERNS:
                        if re.search(sp, all_text):
                            has_safe = True
                            break
                    if has_safe:
                        confidence -= 0.2
                        heuristics.append("有XXE防护")
                    else:
                        confidence += 0.3
                        heuristics.append("无XXE防护")
                    if confidence >= self.min_confidence:
                        func_name = self._find_enclosing_function_from_source(source, line_start)
                        cards.append(FactCard(
                            file_path=path, line_start=line_start, line_end=line_start,
                            code_snippet=line.strip(), language="python",
                            heuristics=heuristics,
                            confidence=min(confidence, 1.0),
                            function_name=func_name, sink=sink,
                        ))
                    break
        return cards

    # ===== Path Traversal Detection =====

    PT_SINKS = {"open(", "os.path.join(", "send_file(", "send_from_directory("}
    PT_DANGEROUS_PATTERNS = [
        r'open\s*\(\s*request', r'open\s*\(\s*user',
        r'os\.path\.join\s*\([^)]*,\s*(request|user|path)',
        r'send_file\s*\(\s*request',
    ]
    PT_SAFE_PATTERNS = [
        r'os\.path\.abspath', r'Path\.resolve\(\)', r'safe_join\(',
        r'werkzeug\.security\.safe_join',
    ]

    def _scan_python_path_traversal(self, path: str) -> List[FactCard]:
        """Scan for path traversal patterns."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except (IOError, OSError):
            return []
        lines = source.split("\n")
        cards: List[FactCard] = []
        for i, line in enumerate(lines):
            matched_sink = None
            for sink in self.PT_SINKS:
                if sink in line:
                    matched_sink = sink
                    break
            if not matched_sink:
                continue
            line_start = i + 1
            all_text = line
            func_body = self._get_enclosing_function_text(source, line_start)
            if func_body:
                all_text += "\n" + func_body
            confidence = 0.3
            heuristics = [f"PathTraversal sink:{matched_sink}"]
            has_danger = False
            for pat in self.PT_DANGEROUS_PATTERNS:
                if re.search(pat, all_text):
                    has_danger = True
                    break
            if has_danger:
                confidence += 0.3
                heuristics.append("外部输入用于文件操作")
            has_safe = False
            for sp in self.PT_SAFE_PATTERNS:
                if re.search(sp, all_text):
                    has_safe = True
                    break
            if has_safe:
                confidence -= 0.2
                heuristics.append("有路径校验")
            else:
                confidence += 0.2
                heuristics.append("无路径校验")
            if confidence >= self.min_confidence:
                func_name = self._find_enclosing_function_from_source(source, line_start)
                cards.append(FactCard(
                    file_path=path, line_start=line_start, line_end=line_start,
                    code_snippet=line.strip(), language="python",
                    heuristics=heuristics,
                    confidence=min(confidence, 1.0),
                    function_name=func_name, sink=matched_sink,
                ))
        return cards

    # ===== Deserialization Detection =====

    DESER_SINKS = {"pickle.loads", "pickle.load", "yaml.load", "marshal.loads", "jsonpickle.decode", "shelve.open"}
    DESER_DANGEROUS_PATTERNS = [
        r'pickle\.loads?\s*\(\s*(request|user|data)',
        r'yaml\.load\s*\(\s*(request|user|data)',
    ]
    DESER_SAFE_PATTERNS = [
        r'yaml\.safe_load\(', r'Loader\s*=\s*yaml\.SafeLoader',
        r'pickle\.loads?\s*\(\s*trusted',
    ]

    def _scan_python_deserialization(self, path: str) -> List[FactCard]:
        """Scan for insecure deserialization patterns."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except (IOError, OSError):
            return []
        lines = source.split("\n")
        cards: List[FactCard] = []
        for i, line in enumerate(lines):
            matched_sink = None
            for sink in self.DESER_SINKS:
                if sink in line:
                    matched_sink = sink
                    break
            if not matched_sink:
                continue
            line_start = i + 1
            all_text = line
            func_body = self._get_enclosing_function_text(source, line_start)
            if func_body:
                all_text += "\n" + func_body
            confidence = 0.4
            heuristics = [f"Deserialization sink:{matched_sink}"]
            has_danger = False
            for pat in self.DESER_DANGEROUS_PATTERNS:
                if re.search(pat, all_text):
                    has_danger = True
                    break
            if has_danger:
                confidence += 0.3
                heuristics.append("反序列化外部输入")
            has_safe = False
            for sp in self.DESER_SAFE_PATTERNS:
                if re.search(sp, all_text):
                    has_safe = True
                    break
            if has_safe:
                confidence -= 0.2
                heuristics.append("使用安全加载器")
            else:
                confidence += 0.2
                heuristics.append("无安全加载器")
            if confidence >= self.min_confidence:
                func_name = self._find_enclosing_function_from_source(source, line_start)
                cards.append(FactCard(
                    file_path=path, line_start=line_start, line_end=line_start,
                    code_snippet=line.strip(), language="python",
                    heuristics=heuristics,
                    confidence=min(confidence, 1.0),
                    function_name=func_name, sink=matched_sink,
                ))
        return cards
