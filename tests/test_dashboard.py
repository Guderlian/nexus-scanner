"""Dashboard tests - Flask test_client, no real server."""
from __future__ import annotations

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.server import create_app, set_store, set_cache
from storage.workspace_store import WorkspaceStore
from cache.frugal_engine import FrugalEngine
from orchestrator.workspace import GlobalWorkspace


def _make_app():
    """Create a test app with isolated store and cache."""
    db_path = tempfile.mktemp(suffix=".db")
    cache_path = tempfile.mktemp(suffix=".json")
    store = WorkspaceStore(db_path=db_path)
    cache = FrugalEngine(cache_path=cache_path)
    set_store(store)
    set_cache(cache)
    app = create_app(store=store, cache=cache)
    app.config["TESTING"] = True
    return app, store, cache


class TestStatsEndpoint:
    def test_stats_returns_200_with_fields(self):
        """GET /api/stats 返回 200 且包含正确字段."""
        app, store, cache = _make_app()
        with app.test_client() as client:
            resp = client.get("/api/stats")
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert "store" in data
            assert "cache" in data
            assert "total_sessions" in data["store"]
            assert "total_entries" in data["cache"]


class TestSessionsEndpoint:
    def test_sessions_returns_list(self):
        """GET /api/sessions 返回列表."""
        app, store, cache = _make_app()
        with app.test_client() as client:
            resp = client.get("/api/sessions")
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert "sessions" in data
            assert isinstance(data["sessions"], list)


class TestSessionDetail:
    def test_saved_session_retrievable(self):
        """存入一个 session 后能正确取回."""
        app, store, cache = _make_app()
        ws = GlobalWorkspace()
        ws.add_note("test", "hello")
        sid = store.save_session(ws, target_path="/code")

        with app.test_client() as client:
            resp = client.get(f"/api/session/{sid}")
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data["session_id"] == sid
            assert data["target_path"] == "/code"


class TestIndexPage:
    def test_index_returns_html(self):
        """GET / 返回 200 且包含 HTML."""
        app, _, _ = _make_app()
        with app.test_client() as client:
            resp = client.get("/")
            assert resp.status_code == 200
            assert b"Nexus" in resp.data
            assert b"<html" in resp.data


class TestSSEEndpoint:
    def test_live_endpoint_connects(self):
        """GET /api/live 连接不报错."""
        app, _, _ = _make_app()
        with app.test_client() as client:
            resp = client.get("/api/live")
            assert resp.status_code == 200
            assert resp.mimetype == "text/event-stream"
