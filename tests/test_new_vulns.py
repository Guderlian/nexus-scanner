"""Tests for 5 new vulnerability types (XSS, SSTI, XXE, Path Traversal, Deserialization)."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from perception.encoder import PerceptionEncoder


def _detect(code: str) -> list:
    enc = PerceptionEncoder()
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(code)
    try:
        return enc.encode_file(path)
    finally:
        os.unlink(path)


# === XSS (3 tests) ===

class TestXSS:
    def test_render_template_string_detected(self):
        code = 'from flask import request, render_template_string\ndef v():\n    return render_template_string(f"<h1>{request.args.get(\"name\")}</h1>")'
        cards = _detect(code)
        assert len(cards) >= 1

    def test_innerhtml_detected(self):
        code = 'def update():\n    element.innerHTML = user_input'
        cards = _detect(code)
        assert len(cards) >= 1

    def test_html_escape_safe(self):
        code = 'from markupsafe import escape\ndef safe():\n    return escape(user_input)'
        cards = _detect(code)
        high = [c for c in cards if c.confidence > 0.5 and any("XSS" in h for h in c.heuristics)]
        assert len(high) == 0


# === SSTI (2 tests) ===

class TestSSTI:
    def test_jinja2_template_detected(self):
        code = 'import jinja2\ndef v():\n    t = jinja2.Template(user_input)\n    return t.render()'
        cards = _detect(code)
        ssti = [c for c in cards if any("SSTI" in h for h in c.heuristics)]
        assert len(ssti) >= 1

    def test_render_template_safe(self):
        code = 'from flask import render_template\ndef safe():\n    return render_template("index.html", name="world")'
        cards = _detect(code)
        ssti = [c for c in cards if any("SSTI" in h for h in c.heuristics)]
        assert len(ssti) == 0


# === XXE (2 tests) ===

class TestXXE:
    def test_etree_parse_detected(self):
        code = 'from lxml import etree\ndef parse_xml(f):\n    return etree.parse(f)'
        cards = _detect(code)
        xxe = [c for c in cards if any("XXE" in h for h in c.heuristics)]
        assert len(xxe) >= 1

    def test_defusedxml_safe(self):
        code = 'def safe_parse(f):\n    from defusedxml import etree\n    return etree.parse(f)'
        cards = _detect(code)
        xxe = [c for c in cards if any("XXE" in h for h in c.heuristics) and c.confidence > 0.5]
        assert len(xxe) == 0


# === Path Traversal (3 tests) ===

class TestPathTraversal:
    def test_open_request_detected(self):
        code = 'from flask import request\ndef read():\n    f = request.args.get("file")\n    return open(f).read()'
        cards = _detect(code)
        pt = [c for c in cards if any("PathTraversal" in h for h in c.heuristics)]
        assert len(pt) >= 1

    def test_os_path_join_detected(self):
        code = 'import os\ndef read(base, user_path):\n    full = os.path.join(base, user_path)\n    return open(full).read()'
        cards = _detect(code)
        pt = [c for c in cards if any("PathTraversal" in h for h in c.heuristics)]
        assert len(pt) >= 1

    def test_safe_join_no_detection(self):
        code = 'from werkzeug.security import safe_join\ndef serve(base, path):\n    return safe_join(base, path)'
        cards = _detect(code)
        pt = [c for c in cards if any("PathTraversal" in h for h in c.heuristics) and c.confidence > 0.5]
        assert len(pt) == 0


# === Deserialization (2 tests) ===

class TestDeserialization:
    def test_pickle_loads_detected(self):
        code = 'import pickle\nfrom flask import request\ndef load():\n    return pickle.loads(request.get_data())'
        cards = _detect(code)
        deser = [c for c in cards if any("Deserialization" in h for h in c.heuristics)]
        assert len(deser) >= 1

    def test_yaml_safe_load_no_detection(self):
        code = 'import yaml\ndef safe():\n    return yaml.safe_load(data)'
        cards = _detect(code)
        deser = [c for c in cards if any("Deserialization" in h for h in c.heuristics) and c.confidence > 0.5]
        assert len(deser) == 0
