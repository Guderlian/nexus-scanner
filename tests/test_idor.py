"""IDOR benchmark test suite for Nexus P1."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from perception.encoder import PerceptionEncoder
from core.fact_card import FactCard

# =====================================================================
# Vulnerable IDOR Samples
# =====================================================================

IDOR_VULN_1_FLASK = """\
from flask import request, jsonify

@app.route('/api/user')
def get_user():
    user_id = request.args.get('id')
    user = User.query.get(id=user_id)
    return jsonify(user.to_dict())
"""

IDOR_VULN_2_FILE_DOWNLOAD = """\
from flask import request, send_file

@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(os.path.join('/data', filename))
"""

IDOR_VULN_3_MODIFY = """\
from flask import request

@app.route('/api/profile', methods=['PUT'])
def update_profile():
    user_id = request.args.get('user_id')
    data = request.json
    User.query.filter(id=user_id).update(data)
    return {'status': 'ok'}
"""

IDOR_VULN_4_LIST_ALL = """\
from flask import request, jsonify

@app.route('/api/documents')
def list_docs():
    doc_id = request.args.get('doc_id')
    if doc_id:
        doc = Document.query.get(id=doc_id)
        return jsonify(doc.to_dict())
    return jsonify([d.to_dict() for d in Document.query.all()])
"""

# =====================================================================
# Safe IDOR Samples
# =====================================================================

IDOR_SAFE_1_OWNER_CHECK = """\
from flask import request, jsonify

@app.route('/api/user')
def get_user():
    user_id = request.args.get('id')
    if current_user.id != user_id:
        return jsonify({'error': 'forbidden'}), 403
    user = User.query.get(id=user_id)
    return jsonify(user.to_dict())
"""

IDOR_SAFE_2_LOGIN_REQUIRED = """\
from flask import request, jsonify
from flask_login import login_required, current_user

@app.route('/api/profile')
@login_required
def get_profile():
    user_id = request.args.get('user_id')
    if current_user.id != user_id:
        return jsonify({'error': 'not owner'}), 403
    user = User.query.get(id=user_id)
    return jsonify(user.to_dict())
"""


def _write_temp(code: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(code)
    return path


class TestIDORPerception:
    """Test IDOR detection in the perception encoder."""

    def setup_method(self):
        self.encoder = PerceptionEncoder()

    def _detect(self, code: str) -> list[FactCard]:
        path = _write_temp(code)
        try:
            return self.encoder.encode_file(path)
        finally:
            os.unlink(path)

    def test_idor_vuln1_flask(self):
        cards = self._detect(IDOR_VULN_1_FLASK)
        assert len(cards) >= 1, f"Expected >=1, got {len(cards)}"

    def test_idor_vuln2_file_download(self):
        cards = self._detect(IDOR_VULN_2_FILE_DOWNLOAD)
        assert len(cards) >= 1

    def test_idor_vuln3_modify(self):
        cards = self._detect(IDOR_VULN_3_MODIFY)
        assert len(cards) >= 1

    def test_idor_vuln4_list_all(self):
        cards = self._detect(IDOR_VULN_4_LIST_ALL)
        assert len(cards) >= 1

    def test_idor_safe1_owner_check(self):
        cards = self._detect(IDOR_SAFE_1_OWNER_CHECK)
        high_conf = [c for c in cards if c.confidence > 0.5]
        assert len(high_conf) == 0, f"FP: {high_conf}"

    def test_idor_safe2_login_required(self):
        cards = self._detect(IDOR_SAFE_2_LOGIN_REQUIRED)
        high_conf = [c for c in cards if c.confidence > 0.5]
        assert len(high_conf) == 0, f"FP: {high_conf}"


class TestIDORBenchmark:
    """IDOR benchmark: recall and false positive rates."""

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
            ("IDOR-1 flask", IDOR_VULN_1_FLASK),
            ("IDOR-2 file_download", IDOR_VULN_2_FILE_DOWNLOAD),
            ("IDOR-3 modify", IDOR_VULN_3_MODIFY),
            ("IDOR-4 list_all", IDOR_VULN_4_LIST_ALL),
        ]
        safe = [
            ("Safe-1 owner_check", IDOR_SAFE_1_OWNER_CHECK),
            ("Safe-2 login_required", IDOR_SAFE_2_LOGIN_REQUIRED),
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
        print(f"{'IDOR BENCHMARK RESULTS':^60}")
        print(f"{'='*60}")
        for name, count, det in details:
            print(f"  {name:<25} cards={count}  {'✅' if det else '❌'}")
        for name, total, high, is_fp in fp_details:
            print(f"  {name:<25} cards={total}  high={high}  {'⚠️FP' if is_fp else '✅'}")
        print(f"\n  Recall: {recall:.0%} ({tp}/{len(vulnerable)})")
        print(f"  FP Rate: {fp_rate:.0%} ({fp}/{len(safe)})")
        print(f"{'='*60}")

        assert recall >= 0.75, f"Recall {recall:.0%} < 75%"
        assert fp_rate <= 0.3, f"FP rate {fp_rate:.0%} > 30%"
