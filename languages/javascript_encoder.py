"""JavaScript/TypeScript vulnerability encoder."""
from __future__ import annotations

import os
import re
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fact_card import FactCard


class JavaScriptEncoder:
    """Detects security vulnerabilities in JS/TypeScript code."""

    def encode_file(self, file_path: str) -> list[FactCard]:
        """Scan a JS/TS file for vulnerabilities."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (IOError, OSError):
            return []

        lines = content.split("\n")
        cards: list[FactCard] = []
        cards.extend(self._detect_ssrf(content, lines, file_path))
        cards.extend(self._detect_sqli(content, lines, file_path))
        cards.extend(self._detect_xss(content, lines, file_path))
        cards.extend(self._detect_path_traversal(content, lines, file_path))
        return cards

    def _detect_ssrf(self, content: str, lines: list[str], fpath: str) -> list[FactCard]:
        """Detect SSRF patterns in JS."""
        cards = []
        # Dangerous: fetch/axios/http.get with user-controlled URL
        patterns = [
            (r'fetch\s*\(\s*(?:req\.\w+|userInput|url|target)', 'fetch(user_input)'),
            (r'axios\.\w+\s*\(\s*(?:req\.\w+|userInput|url)', 'axios(user_input)'),
            (r'(?:http|https)\.get\s*\(\s*(?:req\.\w+|userInput|url)', 'http.get(user_input)'),
            (r'request\s*\(\s*\{.*(?:url|uri)\s*:\s*(?:req\.\w+|userInput|url)', 'request({url})'),
        ]
        for i, line in enumerate(lines):
            for pat, sink_name in patterns:
                if re.search(pat, line, re.IGNORECASE):
                    cards.append(FactCard(
                        file_path=fpath, line_start=i+1, line_end=i+1,
                        code_snippet=line.strip(), language="javascript",
                        heuristics=["SSRF sink", "外部可控URL"],
                        confidence=0.7, sink=sink_name,
                    ))
        return cards

    def _detect_sqli(self, content: str, lines: list[str], fpath: str) -> list[FactCard]:
        """Detect SQL injection in JS."""
        cards = []
        patterns = [
            (r'`SELECT\s.*\$\{', 'template_literal_sql'),
            (r'["\']SELECT\s.*["\']?\s*\+', 'string_concat_sql'),
            (r'\.query\s*\(\s*`', 'db.query_template'),
            (r'\.query\s*\(\s*["\']SELECT.*\+', 'db.query_concat'),
        ]
        for i, line in enumerate(lines):
            for pat, sink_name in patterns:
                if re.search(pat, line, re.IGNORECASE):
                    # Check for safe patterns
                    safe = re.search(r'\?\s*[,\]]', line) or 'prepare' in line.lower()
                    conf = 0.4 if safe else 0.8
                    heur = ["SQL注入sink", "参数化查询"] if safe else ["SQL注入sink", "字符串拼接"]
                    cards.append(FactCard(
                        file_path=fpath, line_start=i+1, line_end=i+1,
                        code_snippet=line.strip(), language="javascript",
                        heuristics=heur, confidence=conf, sink=sink_name,
                    ))
        return cards

    def _detect_xss(self, content: str, lines: list[str], fpath: str) -> list[FactCard]:
        """Detect XSS in JS."""
        cards = []
        patterns = [
            (r'res\.send\s*\(\s*`.*\$\{', 'res.send(template)'),
            (r'innerHTML\s*=', 'innerHTML'),
            (r'document\.write\s*\(', 'document.write'),
            (r'\.html\s*\(\s*(?:req\.|user)', '.html(user_input)'),
        ]
        safe_patterns = [r'escapeHtml', r'\.textContent\s*=', r'sanitize']
        for i, line in enumerate(lines):
            for pat, sink_name in patterns:
                if re.search(pat, line, re.IGNORECASE):
                    has_safe = any(re.search(sp, line) for sp in safe_patterns)
                    conf = 0.4 if has_safe else 0.8
                    cards.append(FactCard(
                        file_path=fpath, line_start=i+1, line_end=i+1,
                        code_snippet=line.strip(), language="javascript",
                        heuristics=["XSS sink", "无转义" if not has_safe else "有转义"],
                        confidence=conf, sink=sink_name,
                    ))
        return cards

    def _detect_path_traversal(self, content: str, lines: list[str], fpath: str) -> list[FactCard]:
        """Detect path traversal in JS."""
        cards = []
        patterns = [
            (r'fs\.readFile\s*\(\s*(?:req\.|path\.join.*req)', 'fs.readFile(req)'),
            (r'res\.sendFile\s*\(\s*(?:req\.|path\.join.*req)', 'res.sendFile(req)'),
            (r'fs\.readFileSync\s*\(\s*(?:req\.)', 'fs.readFileSync(req)'),
        ]
        safe_patterns = [r'path\.resolve', r'safePath', r'startsWith.*base']
        for i, line in enumerate(lines):
            for pat, sink_name in patterns:
                if re.search(pat, line, re.IGNORECASE):
                    has_safe = any(re.search(sp, line) for sp in safe_patterns)
                    conf = 0.4 if has_safe else 0.8
                    cards.append(FactCard(
                        file_path=fpath, line_start=i+1, line_end=i+1,
                        code_snippet=line.strip(), language="javascript",
                        heuristics=["路径遍历sink", "无路径校验" if not has_safe else "有路径校验"],
                        confidence=conf, sink=sink_name,
                    ))
        return cards
