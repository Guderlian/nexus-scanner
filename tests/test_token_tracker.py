"""Token tracker tests."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cost.token_tracker import TokenTracker


class TestTokenTracker:
    def test_single_record(self):
        tracker = TokenTracker("mimo-v2.5-pro-max")
        usage = tracker.record("SemanticAnalyst", 500, 200)
        assert usage.total_tokens == 700
        assert usage.cost_usd > 0

    def test_multiple_accumulation(self):
        tracker = TokenTracker("mimo-v2.5-pro-max")
        tracker.record("SemanticAnalyst", 500, 200)
        tracker.record("AdversarialVerifier", 300, 150)
        tracker.record("SemanticAnalyst", 450, 180)
        assert tracker.total_tokens() == 500 + 200 + 300 + 150 + 450 + 180

    def test_by_agent(self):
        tracker = TokenTracker("mimo-v2.5-pro-max")
        tracker.record("SemanticAnalyst", 500, 200)
        tracker.record("AdversarialVerifier", 300, 150)
        tracker.record("SemanticAnalyst", 450, 180)
        by_agent = tracker.by_agent()
        assert "SemanticAnalyst" in by_agent
        assert by_agent["SemanticAnalyst"]["calls"] == 2
        assert by_agent["AdversarialVerifier"]["calls"] == 1

    def test_cost_calculation(self):
        tracker = TokenTracker("mimo-v2.5-pro-max")
        tracker.record("test", 1000, 0)
        # Pricing: $0.14 per 1M input, $0.28 per 1M output
        expected = 1000 * 0.14 / 1_000_000
        assert abs(tracker.total_cost() - expected) < 0.0001

    def test_save_load(self):
        path = tempfile.mktemp(suffix=".json")
        try:
            tracker1 = TokenTracker("mimo-v2.5-pro-max")
            tracker1.record("test", 500, 200)
            tracker1.save(path)

            tracker2 = TokenTracker("mimo-v2.5-pro-max")
            tracker2.load(path)
            assert tracker2.total_tokens() == 700
        finally:
            if os.path.exists(path):
                os.unlink(path)
