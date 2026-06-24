"""GitDiffer - Git diff driven incremental scanning."""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DiffResult:
    """Result of a git diff operation."""
    changed_files: list[str] = field(default_factory=list)
    added_lines: dict[str, list[int]] = field(default_factory=dict)
    removed_lines: dict[str, list[int]] = field(default_factory=dict)
    is_git_repo: bool = False
    base_commit: str = ""
    head_commit: str = ""


class GitDiffer:
    """Detects changed files and lines via git diff."""

    def __init__(self, repo_path: str = "."):
        self.repo_path = repo_path

    def is_git_repo(self) -> bool:
        """Check if the current path is inside a git repository."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                capture_output=True, text=True, cwd=self.repo_path, timeout=10,
            )
            return result.returncode == 0 and result.stdout.strip() == "true"
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def get_diff(self, base: str = "HEAD~1", head: str = "HEAD") -> DiffResult:
        """Get diff between two commits."""
        if not self.is_git_repo():
            return DiffResult(is_git_repo=False)

        result = DiffResult(is_git_repo=True, base_commit=base, head_commit=head)

        # Get changed file list
        try:
            proc = subprocess.run(
                ["git", "diff", "--name-only", base, head],
                capture_output=True, text=True, cwd=self.repo_path, timeout=30,
            )
            if proc.returncode != 0:
                return result
            result.changed_files = [
                os.path.join(self.repo_path, f.strip())
                for f in proc.stdout.strip().split("\n")
                if f.strip()
            ]
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return result

        # Get added lines per file
        for filepath in result.changed_files:
            rel_path = os.path.relpath(filepath, self.repo_path)
            try:
                proc = subprocess.run(
                    ["git", "diff", "-U0", base, head, "--", rel_path],
                    capture_output=True, text=True, cwd=self.repo_path, timeout=30,
                )
                added, removed = self._parse_diff_output(proc.stdout)
                if added:
                    result.added_lines[filepath] = added
                if removed:
                    result.removed_lines[filepath] = removed
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass

        return result

    def get_staged_diff(self) -> DiffResult:
        """Get diff of staged (cached) changes."""
        if not self.is_git_repo():
            return DiffResult(is_git_repo=False)
        return self._get_diff_from_args(["--cached"])

    def get_uncommitted_diff(self) -> DiffResult:
        """Get diff of uncommitted (working tree) changes."""
        if not self.is_git_repo():
            return DiffResult(is_git_repo=False)
        return self._get_diff_from_args([])

    def filter_by_extension(self, diff: DiffResult,
                             extensions: list[str]) -> DiffResult:
        """Keep only files matching the given extensions."""
        ext_set = set(extensions)
        filtered = DiffResult(
            is_git_repo=diff.is_git_repo,
            base_commit=diff.base_commit,
            head_commit=diff.head_commit,
        )
        for f in diff.changed_files:
            if os.path.splitext(f)[1].lower() in ext_set:
                filtered.changed_files.append(f)
                if f in diff.added_lines:
                    filtered.added_lines[f] = diff.added_lines[f]
                if f in diff.removed_lines:
                    filtered.removed_lines[f] = diff.removed_lines[f]
        return filtered

    def _get_diff_from_args(self, extra_args: list[str]) -> DiffResult:
        """Internal: get diff with extra git arguments."""
        result = DiffResult(is_git_repo=True)
        try:
            proc = subprocess.run(
                ["git", "diff", "--name-only"] + extra_args,
                capture_output=True, text=True, cwd=self.repo_path, timeout=30,
            )
            if proc.returncode != 0:
                return result
            result.changed_files = [
                os.path.join(self.repo_path, f.strip())
                for f in proc.stdout.strip().split("\n")
                if f.strip()
            ]
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return result

        for filepath in result.changed_files:
            rel_path = os.path.relpath(filepath, self.repo_path)
            try:
                proc = subprocess.run(
                    ["git", "diff", "-U0"] + extra_args + ["--", rel_path],
                    capture_output=True, text=True, cwd=self.repo_path, timeout=30,
                )
                added, removed = self._parse_diff_output(proc.stdout)
                if added:
                    result.added_lines[filepath] = added
                if removed:
                    result.removed_lines[filepath] = removed
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass

        return result

    def _parse_diff_output(self, raw: str) -> tuple[list[int], list[int]]:
        """Parse unified diff output to extract added/removed line numbers."""
        added = []
        removed = []
        for line in raw.split("\n"):
            # Match hunk header: @@ -old,count +new,count @@
            m = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) else 1
                # These are the added line numbers
                for i in range(start, start + count):
                    added.append(i)
        return added, removed
