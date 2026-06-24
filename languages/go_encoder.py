"""Go vulnerability encoder."""
from __future__ import annotations

import os
import re
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fact_card import FactCard


class GoEncoder:
    """Detects security vulnerabilities in Go code."""

    def encode_file(self, file_path: str) -> list[FactCard]:
        """Scan a Go file for vulnerabilities."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (IOError, OSError):
            return []

        lines = content.split("\n")
        cards: list[FactCard] = []
        cards.extend(self._detect_ssrf(content, lines, file_path))
        cards.extend(self._detect_sqli(content, lines, file_path))
        cards.extend(self._detect_path_traversal(content, lines, file_path))
        return cards

    def _detect_ssrf(self, content: str, lines: list[str], fpath: str) -> list[FactCard]:
        """Detect SSRF patterns in Go."""
        cards = []
        # Dangerous: http.Get with user-controlled URL
        patterns = [
            (r'http\.Get\s*\(\s*(?:r\.|userInput|url|target)', 'http.Get(user_input)'),
            (r'http\.Post\s*\(\s*(?:r\.|userInput|url)', 'http.Post(user_input)'),
            (r'http\.NewRequest\s*\([^,]+,\s*(?:r\.|userInput|url)', 'http.NewRequest(user_input)'),
        ]
        for i, line in enumerate(lines):
            for pat, sink_name in patterns:
                if re.search(pat, line):
                    cards.append(FactCard(
                        file_path=fpath, line_start=i+1, line_end=i+1,
                        code_snippet=line.strip(), language="go",
                        heuristics=["SSRF sink", "外部可控URL"],
                        confidence=0.7, sink=sink_name,
                    ))
        return cards

    def _detect_sqli(self, content: str, lines: list[str], fpath: str) -> list[FactCard]:
        """Detect SQL injection in Go."""
        cards = []
        patterns = [
            (r'fmt\.Sprintf\s*\(\s*"SELECT', 'fmt.Sprintf(SELECT...)'),
            (r'fmt\.Sprintf\s*\(\s*"INSERT', 'fmt.Sprintf(INSERT...)'),
            (r'fmt\.Sprintf\s*\(\s*"UPDATE', 'fmt.Sprintf(UPDATE...)'),
            (r'fmt\.Sprintf\s*\(\s*"DELETE', 'fmt.Sprintf(DELETE...)'),
            (r'\.Query\s*\(\s*fmt\.', 'db.Query(fmt.Sprintf)'),
            (r'\.Exec\s*\(\s*fmt\.', 'db.Exec(fmt.Sprintf)'),
        ]
        for i, line in enumerate(lines):
            for pat, sink_name in patterns:
                if re.search(pat, line, re.IGNORECASE):
                    cards.append(FactCard(
                        file_path=fpath, line_start=i+1, line_end=i+1,
                        code_snippet=line.strip(), language="go",
                        heuristics=["SQL注入sink", "字符串拼接"],
                        confidence=0.8, sink=sink_name,
                    ))
        return cards

    def _detect_path_traversal(self, content: str, lines: list[str], fpath: str) -> list[FactCard]:
        """Detect path traversal in Go."""
        cards = []
        patterns = [
            (r'os\.Open\s*\(\s*(?:r\.|userInput|filepath)', 'os.Open(user_input)'),
            (r'ioutil\.ReadFile\s*\(\s*(?:r\.|userInput)', 'ioutil.ReadFile(user_input)'),
            (r'http\.ServeFile\s*\(\s*[^,]+,\s*(?:r\.)', 'http.ServeFile(req)'),
        ]
        for i, line in enumerate(lines):
            for pat, sink_name in patterns:
                if re.search(pat, line):
                    cards.append(FactCard(
                        file_path=fpath, line_start=i+1, line_end=i+1,
                        code_snippet=line.strip(), language="go",
                        heuristics=["路径遍历sink", "无路径校验"],
                        confidence=0.7, sink=sink_name,
                    ))
        return cards
