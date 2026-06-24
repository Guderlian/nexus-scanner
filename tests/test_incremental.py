"""Incremental scanning tests."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cache.file_hasher import FileHasher


def _tmp_cache():
    return tempfile.mktemp(suffix=".json")


def _write_temp(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


class TestIncrementalScanning:
    def test_first_scan_sees_all_files(self):
        """首次扫描应将所有文件视为已变更."""
        cache_path = _tmp_cache()
        fh = FileHasher(cache_path=cache_path)
        f1 = _write_temp("a = 1")
        f2 = _write_temp("b = 2")
        try:
            assert fh.has_changed(f1) is True
            assert fh.has_changed(f2) is True
        finally:
            os.unlink(f1)
            os.unlink(f2)

    def test_second_scan_skips_unchanged(self):
        """第二次扫描应跳过未变更文件."""
        cache_path = _tmp_cache()
        fh = FileHasher(cache_path=cache_path)
        f1 = _write_temp("unchanged")
        f2 = _write_temp("also unchanged")
        try:
            fh.update(f1)
            fh.update(f2)
            fh.save()

            fh2 = FileHasher(cache_path=cache_path)
            fh2.load()
            assert fh2.has_changed(f1) is False
            assert fh2.has_changed(f2) is False
        finally:
            os.unlink(f1)
            os.unlink(f2)

    def test_modified_file_detected_after_save(self):
        """修改文件后重新扫描应检测到变更."""
        cache_path = _tmp_cache()
        fh = FileHasher(cache_path=cache_path)
        fname = _write_temp("original")
        try:
            fh.update(fname)
            fh.save()

            # Modify
            with open(fname, "w") as f:
                f.write("modified content")

            fh2 = FileHasher(cache_path=cache_path)
            fh2.load()
            assert fh2.has_changed(fname) is True
        finally:
            os.unlink(fname)

    def test_persistence_across_instances(self):
        """缓存应跨实例持久化."""
        cache_path = _tmp_cache()
        fname = _write_temp("persistent")
        try:
            # Instance 1
            fh1 = FileHasher(cache_path=cache_path)
            fh1.update(fname)
            fh1.save()

            # Instance 2
            fh2 = FileHasher(cache_path=cache_path)
            fh2.load()
            assert fh2.has_changed(fname) is False
        finally:
            os.unlink(fname)
