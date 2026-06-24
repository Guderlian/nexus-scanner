"""SQLi benchmark test suite for Nexus P1."""
from __future__ import annotations

import os
import sys
import tempfile
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from perception.encoder import PerceptionEncoder
from agents.semantic_analyst import SemanticAnalystAgent
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard

# =====================================================================
# Vulnerable SQLi Samples
# =====================================================================

SQLI_VULN_1_FSTRING = """\
from flask import request

def get_user(user_id):
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
    return cursor.fetchone()
"""

SQLI_VULN_2_CONCAT = """\
def get_orders(username):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM orders WHERE user='" + username + "'")
    return cursor.fetchall()
"""

SQLI_VULN_3_DJANGO_RAW = """\
from django.http import HttpResponse

def view_user(request, id):
    users = User.objects.raw(f"SELECT * FROM auth_user WHERE id={id}")
    return HttpResponse(str(users))
"""

SQLI_VULN_4_LIKE = """\
def search_items(search):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM items WHERE name LIKE '%" + search + "%'")
    return cursor.fetchall()
"""

SQLI_VULN_5_ALCHEMY = """\
from sqlalchemy import text

def get_products(cat):
    result = db.execute(text(f"SELECT * FROM products WHERE category='{cat}'"))
    return result.fetchall()
"""

# =====================================================================
# Safe SQLi Samples
# =====================================================================

SQLI_SAFE_1_PARAMETERIZED = """\
def get_user(user_id):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return cursor.fetchone()
"""

SQLI_SAFE_2_ORM = """\
def get_user(user_id):
    return User.objects.filter(id=user_id)
"""

# =====================================================================
# LLM Mock Responses
# =====================================================================

LLM_SQLI_VULN = """\
{
    "is_vulnerable": true,
    "confidence": 0.9,
    "attack_path": "SQL injection via f-string interpolation",
    "preconditions": ["User-controlled input in SQL query", "No parameterization"],
    "reasoning": "Direct string interpolation in SQL query without parameterization",
    "false_positive_risk": "low"
}"""

LLM_SQLI_SAFE = """\
{
    "is_vulnerable": false,
    "confidence": 0.2,
    "attack_path": "",
    "preconditions": [],
    "reasoning": "Parameterized query prevents injection",
    "false_positive_risk": "high"
}"""


def _write_temp(code: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(code)
    return path


class TestSQLiPerception:
    """Test SQLi detection in the perception encoder."""

    def setup_method(self):
        self.encoder = PerceptionEncoder()

    def _detect(self, code: str) -> list[FactCard]:
        path = _write_temp(code)
        try:
            return self.encoder.encode_file(path)
        finally:
            os.unlink(path)

    def test_sqli_vuln1_fstring(self):
        cards = self._detect(SQLI_VULN_1_FSTRING)
        assert len(cards) >= 1, f"Expected >=1, got {len(cards)}"

    def test_sqli_vuln2_concat(self):
        cards = self._detect(SQLI_VULN_2_CONCAT)
        assert len(cards) >= 1

    def test_sqli_vuln3_django_raw(self):
        cards = self._detect(SQLI_VULN_3_DJANGO_RAW)
        assert len(cards) >= 1

    def test_sqli_vuln4_like(self):
        cards = self._detect(SQLI_VULN_4_LIKE)
        assert len(cards) >= 1

    def test_sqli_vuln5_alchemy(self):
        cards = self._detect(SQLI_VULN_5_ALCHEMY)
        assert len(cards) >= 1

    def test_sqli_safe1_parameterized(self):
        cards = self._detect(SQLI_SAFE_1_PARAMETERIZED)
        high_conf = [c for c in cards if c.confidence > 0.5]
        assert len(high_conf) == 0, f"FP: {high_conf}"

    def test_sqli_safe2_orm(self):
        cards = self._detect(SQLI_SAFE_2_ORM)
        high_conf = [c for c in cards if c.confidence > 0.5]
        assert len(high_conf) == 0, f"FP: {high_conf}"


class TestSQLiBenchmark:
    """SQLi benchmark: recall and false positive rates."""

    def setup_method(self):
        self.encoder = PerceptionEncoder()

    def _detect(self, code: str) -> list[FactCard]:
        path = _write_temp(code)
        try:
            return self.encoder.encode_file(path)
        finally:
            os.unlink(path)

    def test_recall_and_fp(self):
        vulnerable = [
            ("SQLi-1 fstring", SQLI_VULN_1_FSTRING),
            ("SQLi-2 concat", SQLI_VULN_2_CONCAT),
            ("SQLi-3 django_raw", SQLI_VULN_3_DJANGO_RAW),
            ("SQLi-4 like", SQLI_VULN_4_LIKE),
            ("SQLi-5 alchemy", SQLI_VULN_5_ALCHEMY),
        ]
        safe = [
            ("Safe-1 parameterized", SQLI_SAFE_1_PARAMETERIZED),
            ("Safe-2 ORM", SQLI_SAFE_2_ORM),
        ]

        tp = 0
        details = []
        for name, code in vulnerable:
            cards = self._detect(code)
            detected = len(cards) >= 1
            if detected:
                tp += 1
            details.append((name, len(cards), detected))

        recall = tp / len(vulnerable)

        fp = 0
        fp_details = []
        for name, code in safe:
            cards = self._detect(code)
            high = [c for c in cards if c.confidence > 0.5]
            is_fp = len(high) >= 1
            if is_fp:
                fp += 1
            fp_details.append((name, len(cards), len(high), is_fp))

        fp_rate = fp / len(safe) if safe else 0

        print(f"\n{'='*60}")
        print(f"{'SQLi BENCHMARK RESULTS':^60}")
        print(f"{'='*60}")
        for name, count, det in details:
            print(f"  {name:<25} cards={count}  {'✅' if det else '❌'}")
        for name, total, high, is_fp in fp_details:
            print(f"  {name:<25} cards={total}  high={high}  {'⚠️FP' if is_fp else '✅'}")
        print(f"\n  Recall: {recall:.0%} ({tp}/{len(vulnerable)})")
        print(f"  FP Rate: {fp_rate:.0%} ({fp}/{len(safe)})")
        print(f"{'='*60}")

        assert recall >= 0.8, f"Recall {recall:.0%} < 80%"
        assert fp_rate <= 0.3, f"FP rate {fp_rate:.0%} > 30%"
