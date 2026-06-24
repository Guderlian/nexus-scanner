"""Git diff tests."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vcs.git_differ import GitDiffer, DiffResult


class TestGitDiffer:
    def test_non_git_repo_no_crash(self):
        """Non-git directory should return is_git_repo=False."""
        gd = GitDiffer(tempfile.mkdtemp())
        result = gd.get_diff()
        assert result.is_git_repo is False

    def test_extension_filter(self):
        """filter_by_extension keeps only matching files."""
        diff = DiffResult(
            changed_files=["a.py", "b.js", "c.java", "d.txt"],
            added_lines={"a.py": [1, 2], "b.js": [5], "c.java": [10]},
            is_git_repo=True,
        )
        filtered = GitDiffer(".").filter_by_extension(diff, [".py", ".java"])
        assert "a.py" in filtered.changed_files
        assert "c.java" in filtered.changed_files
        assert "b.js" not in filtered.changed_files
        assert "d.txt" not in filtered.changed_files

    def test_diff_result_structure(self):
        """DiffResult has all required fields."""
        dr = DiffResult()
        assert hasattr(dr, "changed_files")
        assert hasattr(dr, "added_lines")
        assert hasattr(dr, "removed_lines")
        assert hasattr(dr, "is_git_repo")

    def test_is_git_repo_returns_bool(self):
        """is_git_repo returns a boolean."""
        gd = GitDiffer(".")
        result = gd.is_git_repo()
        assert isinstance(result, bool)

    def test_empty_diff_returns_empty(self):
        """Non-git repo returns empty changed_files."""
        gd = GitDiffer(tempfile.mkdtemp())
        diff = gd.get_staged_diff()
        assert diff.changed_files == []
