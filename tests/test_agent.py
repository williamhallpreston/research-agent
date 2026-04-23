"""
tests/test_agent.py
===================
Unit tests for research_agent.py.

Run with:  pytest tests/ -v --cov=src
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Ensure env vars are set before importing the module ──────────────────────
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")
os.environ.setdefault("BRAVE_API_KEY",     "test-brave-key")
os.environ.setdefault("FLASK_SECRET_KEY",  "test-flask-secret-aaabbbcccdddeeefff")

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from research_agent import (
    CitationTracker,
    cache_get,
    cache_set,
    safe_report_path,
    score_url,
    session_create,
    session_get,
    session_update,
    sessions_list,
    validate_formats,
    validate_question,
    REPORTS_DIR,
    CACHE_DIR,
)

# ═════════════════════════════════════════════════════════════════════════════
# Input validation
# ═════════════════════════════════════════════════════════════════════════════

class TestValidateQuestion:
    def test_valid_question(self):
        assert validate_question("What is the speed of light?") == "What is the speed of light?"

    def test_strips_leading_trailing_whitespace(self):
        assert validate_question("  hello  ") == "hello"

    def test_strips_null_bytes(self):
        assert validate_question("hello\x00world") == "helloworld"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_question("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_question("   ")

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="character limit"):
            validate_question("x" * 600)

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="string"):
            validate_question(42)  # type: ignore


class TestValidateFormats:
    def test_valid_single(self):
        assert validate_formats(["md"]) == ["md"]

    def test_valid_multiple(self):
        result = validate_formats(["md", "pdf", "docx"])
        assert set(result) == {"md", "pdf", "docx"}

    def test_case_insensitive(self):
        assert validate_formats(["MD", "PDF"]) == ["md", "pdf"]

    def test_filters_invalid(self):
        assert validate_formats(["md", "exe", "sh"]) == ["md"]

    def test_all_invalid_raises(self):
        with pytest.raises(ValueError, match="no valid formats"):
            validate_formats(["exe", "bat"])

    def test_not_list_raises(self):
        with pytest.raises(ValueError, match="list"):
            validate_formats("md")  # type: ignore


# ═════════════════════════════════════════════════════════════════════════════
# Path traversal prevention
# ═════════════════════════════════════════════════════════════════════════════

class TestSafeReportPath:
    def test_valid_path(self):
        valid = str(REPORTS_DIR / "report_test_20250101.md")
        result = safe_report_path(valid)
        assert result.parent.resolve() == REPORTS_DIR.resolve()

    def test_traversal_raises(self):
        with pytest.raises(PermissionError):
            safe_report_path(str(REPORTS_DIR / ".." / "sessions.db"))

    def test_absolute_outside_raises(self):
        with pytest.raises(PermissionError):
            safe_report_path("/etc/passwd")

    def test_double_dot_raises(self):
        with pytest.raises(PermissionError):
            safe_report_path("../../etc/shadow")


# ═════════════════════════════════════════════════════════════════════════════
# Credibility scoring
# ═════════════════════════════════════════════════════════════════════════════

class TestScoreUrl:
    @pytest.mark.parametrize("url,expected_score", [
        ("https://arxiv.org/abs/2401.00001",           5),
        ("https://www.ncbi.nlm.nih.gov/pmc/articles/", 5),
        ("https://www.nature.com/articles/test",        5),
        ("https://www.cdc.gov/flu",                     4),
        ("https://mit.edu/research",                    4),
        ("https://reuters.com/world/",                  3),
        ("https://bbc.com/news",                        3),
        ("https://medium.com/@user/post",               1),
        ("https://example-random-blog.com/",            2),
    ])
    def test_score(self, url: str, expected_score: int):
        score, label = score_url(url)
        assert score == expected_score
        assert isinstance(label, str) and len(label) > 0


# ═════════════════════════════════════════════════════════════════════════════
# CitationTracker
# ═════════════════════════════════════════════════════════════════════════════

class TestCitationTracker:
    def test_register_returns_id(self):
        ct = CitationTracker()
        cid = ct.register("https://example.com", "Example", "A site")
        assert cid == "[^1]"

    def test_deduplication(self):
        ct = CitationTracker()
        cid1 = ct.register("https://example.com")
        cid2 = ct.register("https://example.com")
        assert cid1 == cid2
        assert len(ct.to_dict()) == 1

    def test_multiple_sources_incrementing(self):
        ct = CitationTracker()
        ids = [ct.register(f"https://example{i}.com") for i in range(3)]
        assert ids == ["[^1]", "[^2]", "[^3]"]

    def test_credibility_scored(self):
        ct = CitationTracker()
        ct.register("https://arxiv.org/abs/test")
        data = ct.to_dict()
        cid = list(data.keys())[0]
        assert data[cid]["credibility_score"] == 5

    def test_markdown_refs_empty(self):
        ct = CitationTracker()
        assert "No sources" in ct.markdown_refs()

    def test_markdown_refs_populated(self):
        ct = CitationTracker()
        ct.register("https://example.com", "Example Site", "snippet")
        refs = ct.markdown_refs()
        assert "Example Site" in refs
        assert "https://example.com" in refs

    def test_thread_safety(self):
        """Register URLs from multiple threads; expect no duplicates or ID collisions."""
        ct = CitationTracker()
        urls = [f"https://site{i}.com" for i in range(50)]
        results = []

        def reg(url):
            results.append(ct.register(url))

        threads = [threading.Thread(target=reg, args=(u,)) for u in urls]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(set(results)) == 50  # all unique IDs
        assert len(ct.to_dict()) == 50

    def test_snippet_truncated(self):
        ct = CitationTracker()
        ct.register("https://example.com", snippet="x" * 300)
        data = ct.to_dict()
        cid = list(data.keys())[0]
        assert len(data[cid]["snippet"]) <= 200


# ═════════════════════════════════════════════════════════════════════════════
# Disk cache
# ═════════════════════════════════════════════════════════════════════════════

class TestCache:
    def test_roundtrip(self):
        cache_set("test", "mykey", {"hello": "world"})
        result = cache_get("test", "mykey")
        assert result == {"hello": "world"}

    def test_miss_returns_none(self):
        assert cache_get("test", "nonexistent_key_xyz_123") is None

    def test_ttl_expiry(self, monkeypatch):
        """Simulate a cache entry that is older than the TTL."""
        import research_agent as ra

        original_ttl = ra.CACHE_TTL_SECONDS
        # Write an entry
        cache_set("ttl_test", "key1", "data")
        # Make TTL effectively 0
        monkeypatch.setattr(ra, "CACHE_TTL_SECONDS", -1)
        result = cache_get("ttl_test", "key1")
        assert result is None
        # Restore
        monkeypatch.setattr(ra, "CACHE_TTL_SECONDS", original_ttl)

    def test_cache_key_no_path_separators(self):
        """Cache filenames must not contain user-controlled path components."""
        import research_agent as ra
        p = ra._cache_path("prefix", "../../etc/passwd")
        assert "/" not in p.name
        assert "\\" not in p.name
        assert p.parent == CACHE_DIR


# ═════════════════════════════════════════════════════════════════════════════
# Session store
# ═════════════════════════════════════════════════════════════════════════════

class TestSessionStore:
    def test_create_and_get(self):
        session_create("sess_test_001", "test question")
        s = session_get("sess_test_001")
        assert s is not None
        assert s["question"] == "test question"
        assert s["status"] == "running"

    def test_update_status(self):
        session_create("sess_test_002", "another question")
        session_update("sess_test_002", status="done")
        s = session_get("sess_test_002")
        assert s["status"] == "done"

    def test_update_invalid_column_raises(self):
        session_create("sess_test_003", "q")
        with pytest.raises(ValueError, match="invalid session columns"):
            session_update("sess_test_003", malicious_col="DROP TABLE sessions")

    def test_nonexistent_session_returns_none(self):
        assert session_get("does_not_exist_xyz") is None

    def test_list_returns_list(self):
        result = sessions_list()
        assert isinstance(result, list)

    def test_idempotent_create(self):
        """Second create with same ID should not raise (INSERT OR IGNORE)."""
        session_create("sess_test_004", "q1")
        session_create("sess_test_004", "q2")  # must not raise
        s = session_get("sess_test_004")
        assert s["question"] == "q1"  # original preserved


# ═════════════════════════════════════════════════════════════════════════════
# Flask web UI
# ═════════════════════════════════════════════════════════════════════════════

class TestFlaskApp:
    @pytest.fixture
    def client(self):
        from research_agent import create_app
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c

    def test_index_returns_200(self, client):
        resp = client.get("/", headers={"Host": "localhost"})
        assert resp.status_code == 200

    def test_security_headers_present(self, client):
        resp = client.get("/", headers={"Host": "localhost"})
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert "Content-Security-Policy" in resp.headers

    def test_invalid_host_rejected(self, client):
        resp = client.get("/", headers={"Host": "evil.attacker.com"})
        assert resp.status_code == 400

    def test_start_empty_question(self, client):
        resp = client.post(
            "/start",
            json={"question": "", "formats": ["md"]},
            headers={"Host": "localhost"},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_start_invalid_format(self, client):
        resp = client.post(
            "/start",
            json={"question": "test question", "formats": ["exe"]},
            headers={"Host": "localhost"},
        )
        assert resp.status_code == 400

    def test_download_traversal_blocked(self, client):
        resp = client.get(
            "/download?path=../../etc/passwd",
            headers={"Host": "localhost"},
        )
        assert resp.status_code == 404

    def test_stream_invalid_sid_rejected(self, client):
        resp = client.get(
            "/stream/../../../../etc/passwd",
            headers={"Host": "localhost"},
        )
        assert resp.status_code == 400

    def test_sessions_endpoint(self, client):
        resp = client.get("/sessions", headers={"Host": "localhost"})
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)
