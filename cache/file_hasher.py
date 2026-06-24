"""FileHasher - SHA256-based incremental file change detection."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional


# Default exclusion patterns
EXCLUDE_DIRS = {"node_modules", ".git", "__pycache__", ".nexus_cache", ".venv", "venv"}
EXCLUDE_EXTENSIONS = {".pyc", ".pyo", ".so", ".o", ".class"}


class FileHasher:
    """Tracks file SHA256 hashes for incremental scanning."""

    def __init__(self, cache_path: str = ".nexus_cache/file_hashes.json"):
        self.cache_path = cache_path
        self._hashes: dict[str, str] = {}  # file_path -> sha256
        self._dirty = False

    def get_hash(self, file_path: str) -> str:
        """Compute SHA256 of a file."""
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except (IOError, OSError):
            return ""
        return h.hexdigest()

    def has_changed(self, file_path: str) -> bool:
        """Check if a file has changed since last scan. First scan = always changed."""
        current_hash = self.get_hash(file_path)
        if not current_hash:
            return False
        cached_hash = self._hashes.get(os.path.abspath(file_path))
        if cached_hash is None:
            return True  # First time seen = changed
        return current_hash != cached_hash

    def update(self, file_path: str) -> None:
        """Update the cached hash for a file."""
        current_hash = self.get_hash(file_path)
        if current_hash:
            self._hashes[os.path.abspath(file_path)] = current_hash
            self._dirty = True

    def get_changed_files(self, dir_path: str, extensions: list[str] = None) -> list[str]:
        """Walk directory and return only files that have changed."""
        if extensions is None:
            extensions = [".py", ".java"]
        ext_set = set(extensions)
        changed = []
        for root, dirs, files in os.walk(dir_path):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()
                if ext in ext_set and ext not in EXCLUDE_EXTENSIONS:
                    if self.has_changed(fpath):
                        changed.append(fpath)
        return changed

    def save(self) -> None:
        """Persist hashes to JSON file."""
        os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(self._hashes, f, indent=2)
        self._dirty = False

    def load(self) -> None:
        """Load hashes from JSON file."""
        if not os.path.exists(self.cache_path):
            self._hashes = {}
            return
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                self._hashes = json.load(f)
        except (json.JSONDecodeError, IOError):
            self._hashes = {}
