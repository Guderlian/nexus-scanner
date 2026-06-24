"""Multi-language encoder tests."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from perception.encoder import PerceptionEncoder
from languages.javascript_encoder import JavaScriptEncoder
from languages.go_encoder import GoEncoder


def _write(code: str, ext: str) -> str:
    fd, path = tempfile.mkstemp(suffix=ext)
    with os.fdopen(fd, "w") as f:
        f.write(code)
    return path


class TestJavaScriptEncoder:
    def test_fetch_ssrf(self):
        code = 'app.get("/fetch", async (req, res) => { const response = await fetch(req.query.url); });'
        path = _write(code, ".js")
        try:
            cards = JavaScriptEncoder().encode_file(path)
            assert len(cards) >= 1
        finally:
            os.unlink(path)

    def test_sqli_template_literal(self):
        code = 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);'
        path = _write(code, ".js")
        try:
            cards = JavaScriptEncoder().encode_file(path)
            assert len(cards) >= 1
        finally:
            os.unlink(path)

    def test_xss_res_send(self):
        code = "res.send(`<h1>${req.query.name}</h1>`);"
        path = _write(code, ".js")
        try:
            cards = JavaScriptEncoder().encode_file(path)
            assert len(cards) >= 1
        finally:
            os.unlink(path)

    def test_path_traversal(self):
        code = "fs.readFile(path.join(__dirname, req.query.file), callback);"
        path = _write(code, ".js")
        try:
            cards = JavaScriptEncoder().encode_file(path)
            assert len(cards) >= 1
        finally:
            os.unlink(path)

    def test_safe_fetch_no_detection(self):
        code = "fetch('https://api.example.com/data');"
        path = _write(code, ".js")
        try:
            cards = JavaScriptEncoder().encode_file(path)
            assert len(cards) == 0
        finally:
            os.unlink(path)


class TestGoEncoder:
    def test_http_get_ssrf(self):
        code = 'func handler(w http.ResponseWriter, r *http.Request) {\n    url := r.URL.Query().Get("url")\n    resp, err := http.Get(url)\n}'
        path = _write(code, ".go")
        try:
            cards = GoEncoder().encode_file(path)
            assert len(cards) >= 1
        finally:
            os.unlink(path)

    def test_sqli_fmt_sprintf(self):
        code = 'query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)\ndb.Query(query)'
        path = _write(code, ".go")
        try:
            cards = GoEncoder().encode_file(path)
            assert len(cards) >= 1
        finally:
            os.unlink(path)

    def test_safe_http_get_no_detection(self):
        code = 'resp, err := http.Get("https://api.example.com")'
        path = _write(code, ".go")
        try:
            cards = GoEncoder().encode_file(path)
            assert len(cards) == 0
        finally:
            os.unlink(path)


class TestEncoderRouting:
    def test_py_goes_to_python(self):
        code = "import requests\ndef f(url): return requests.get(url)"
        path = _write(code, ".py")
        try:
            cards = PerceptionEncoder().encode_file(path)
            ssrf = [c for c in cards if c.sink and 'requests' in c.sink]
            assert len(ssrf) >= 1
        finally:
            os.unlink(path)

    def test_js_goes_to_javascript(self):
        code = 'fetch(req.query.url);'
        path = _write(code, ".js")
        try:
            cards = PerceptionEncoder().encode_file(path)
            assert len(cards) >= 1
        finally:
            os.unlink(path)

    def test_go_goes_to_go(self):
        code = 'http.Get(r.URL.Query().Get("url"))'
        path = _write(code, ".go")
        try:
            cards = PerceptionEncoder().encode_file(path)
            assert len(cards) >= 1
        finally:
            os.unlink(path)
