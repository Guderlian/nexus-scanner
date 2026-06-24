"""WorkspaceStore tests - SQLite persistence."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.workspace_store import WorkspaceStore
from orchestrator.workspace import GlobalWorkspace
from core.fact_card import FactCard
from core.hypothesis_card import HypothesisCard
from core.evidence_chain import EvidenceChain, EvidenceItem


def _store() -> WorkspaceStore:
    return WorkspaceStore(db_path=tempfile.mktemp(suffix=".db"))


def _populated_workspace() -> GlobalWorkspace:
    ws = GlobalWorkspace()
    ws.add_fact(FactCard(
        file_path="a.py", line_start=1, line_end=5,
        code_snippet="requests.get(url)", language="python",
        confidence=0.8,
    ))
    ws.add_hypothesis(HypothesisCard(
        source_fact_id="a.py:1", is_vulnerable=True,
        confidence=0.85, file_path="a.py", line_start=1, line_end=5,
    ))
    ws.add_evidence(EvidenceChain(
        hypothesis_id="a.py:1", verdict="confirmed",
        final_confidence=0.85, file_path="a.py", line_start=1, line_end=5,
        evidence=[EvidenceItem(tool="semgrep", result="SSRF found")],
    ))
    ws.add_note("test", "analysis complete")
    return ws


class TestSaveAndLoad:
    def test_save_then_load(self):
        """保存 workspace 后能正确加载."""
        store = _store()
        ws = _populated_workspace()
        sid = store.save_session(ws, target_path="/code")
        loaded = store.load_session(sid)
        assert loaded is not None
        assert loaded["session_id"] == sid
        assert loaded["target_path"] == "/code"
        assert loaded["fact_count"] == 1
        assert loaded["evidence_count"] == 1


class TestListSessions:
    def test_multiple_saves_listed(self):
        """多次保存后列表数量正确."""
        store = _store()
        ws = GlobalWorkspace()
        store.save_session(ws, "/a")
        store.save_session(ws, "/b")
        store.save_session(ws, "/c")
        sessions = store.list_sessions()
        assert len(sessions) == 3


class TestDeleteSession:
    def test_deleted_session_unloadable(self):
        """删除后无法再加载."""
        store = _store()
        ws = GlobalWorkspace()
        sid = store.save_session(ws)
        store.delete_session(sid)
        assert store.load_session(sid) is None


class TestStats:
    def test_stats_correct(self):
        """统计数据正确."""
        store = _store()
        ws = _populated_workspace()
        store.save_session(ws, "/a")
        store.complete_session(store.list_sessions()[0]["session_id"])
        store.save_session(ws, "/b")
        stats = store.get_stats()
        assert stats["total_sessions"] == 2
        assert stats["total_facts"] == 2
        assert stats["total_evidences"] == 2
        assert stats["completed_sessions"] == 1


class TestSessionPersistence:
    def test_cross_instance_load(self):
        """跨实例加载（新建 WorkspaceStore 对象仍能读取）."""
        db_path = tempfile.mktemp(suffix=".db")
        store1 = WorkspaceStore(db_path=db_path)
        ws = _populated_workspace()
        sid = store1.save_session(ws, "/persist")

        store2 = WorkspaceStore(db_path=db_path)
        loaded = store2.load_session(sid)
        assert loaded is not None
        assert loaded["target_path"] == "/persist"


class TestEmptyWorkspace:
    def test_empty_save_load(self):
        """空 workspace 保存加载不报错."""
        store = _store()
        ws = GlobalWorkspace()
        sid = store.save_session(ws)
        loaded = store.load_session(sid)
        assert loaded is not None
        assert loaded["fact_count"] == 0
        assert loaded["evidence_count"] == 0
