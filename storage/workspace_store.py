"""WorkspaceStore - SQLite-backed persistent workspace."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Optional

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestrator.workspace import GlobalWorkspace


class WorkspaceStore:
    """Persists GlobalWorkspace sessions to SQLite for resume/stats."""

    def __init__(self, db_path: str = ".nexus_cache/workspace.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    task_id TEXT,
                    target_path TEXT,
                    created_at TEXT,
                    completed_at TEXT,
                    fact_count INTEGER DEFAULT 0,
                    hypothesis_count INTEGER DEFAULT 0,
                    evidence_count INTEGER DEFAULT 0,
                    snapshot TEXT
                )
            """)
            conn.commit()

    def save_session(self, workspace: GlobalWorkspace, target_path: str = "") -> str:
        """Save a workspace snapshot. Returns session_id."""
        session_id = uuid.uuid4().hex[:12]
        snap = workspace.snapshot()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, task_id, target_path, created_at, "
                "fact_count, hypothesis_count, evidence_count, snapshot) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    snap["task_id"],
                    target_path,
                    snap["created_at"],
                    snap["fact_cards_count"],
                    snap["hypotheses_count"],
                    snap["evidences_count"],
                    json.dumps(snap),
                ),
            )
            conn.commit()
        return session_id

    def complete_session(self, session_id: str) -> None:
        """Mark a session as completed."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE sessions SET completed_at = ? WHERE session_id = ?",
                (datetime.utcnow().isoformat(), session_id),
            )
            conn.commit()

    def load_session(self, session_id: str) -> Optional[dict]:
        """Load a session snapshot (returns raw dict, not GlobalWorkspace)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    def list_sessions(self) -> list[dict]:
        """List all sessions with summary info."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT session_id, task_id, target_path, created_at, completed_at, "
                "fact_count, hypothesis_count, evidence_count "
                "FROM sessions ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_session(self, session_id: str) -> None:
        """Delete a session."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            conn.commit()

    def get_stats(self) -> dict:
        """Global statistics across all sessions."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) as total, "
                "SUM(fact_count) as total_facts, "
                "SUM(hypothesis_count) as total_hypotheses, "
                "SUM(evidence_count) as total_evidences, "
                "SUM(CASE WHEN completed_at IS NOT NULL THEN 1 ELSE 0 END) as completed "
                "FROM sessions"
            ).fetchone()
        return {
            "total_sessions": row[0] or 0,
            "total_facts": row[1] or 0,
            "total_hypotheses": row[2] or 0,
            "total_evidences": row[3] or 0,
            "completed_sessions": row[4] or 0,
        }
