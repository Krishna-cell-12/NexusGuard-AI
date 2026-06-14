#!/usr/bin/env python3
# ============================================================
#  NexusGuard AI — Unit Tests for Layer 3 & Layer 4
#  tests/test_layers.py
# ============================================================

"""
Tests for:
  - Layer 3: PoC generation, report formatting, BetterBugs export
  - Layer 4: Patch generation, PR formatting, JSON output schema
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.ai_exploit_reproduction import (
    generate_report,
    export_betterbugs,
    run_poc_sandboxed,
)
from scripts.ai_patch_generator import (
    format_pr,
    generate_full_output,
)


# ── Fixtures ─────────────────────────────────────────────────
SAMPLE_VULN = {
    "tool_name": "Semgrep",
    "file_path": "services/user_service.py",
    "line_number": 14,
    "vulnerability_type": "SQL Injection",
    "description": "User-supplied input 'user_id' is directly concatenated into a SQL string.",
    "vulnerable_code_snippet": (
        "def get_user_profile(db_connection, user_id: str):\n"
        "    cursor = db_connection.cursor()\n"
        '    query = "SELECT id, username, email, role FROM users WHERE id = \'" + user_id + "\'"\n'
        "    cursor.execute(query)\n"
        "    return cursor.fetchone()"
    ),
}

SAMPLE_POC = 'print("PoC: SQL injection demonstration")'

SAMPLE_EXEC = {
    "stdout": "PoC: SQL injection demonstration\n",
    "stderr": "",
    "returncode": 0,
    "status": "success",
}

SAMPLE_EXPLANATION = "The original code concatenates user input into SQL. Use parameterized queries."


# ─────────────────────────────────────────────────────────────
#  LAYER 3 TESTS
# ─────────────────────────────────────────────────────────────
class TestLayer3:
    """Tests for AI Exploit Reproduction (Layer 3)."""

    def test_generate_report_returns_markdown(self):
        """Report should be valid markdown with all sections."""
        report = generate_report(SAMPLE_VULN, SAMPLE_POC, SAMPLE_EXEC, SAMPLE_EXPLANATION)
        assert "# 🛡️ NexusGuard AI" in report
        assert "SQL Injection" in report
        assert "Proof-of-Concept" in report
        assert "Execution Results" in report
        assert SAMPLE_POC in report

    def test_generate_report_with_screenshots(self):
        """Report should embed screenshot paths."""
        report = generate_report(
            SAMPLE_VULN, SAMPLE_POC, SAMPLE_EXEC, SAMPLE_EXPLANATION,
            screenshots=["screenshot_1.png", "screenshot_2.png"],
        )
        assert "screenshot_1.png" in report
        assert "screenshot_2.png" in report

    def test_export_betterbugs_creates_valid_json(self, tmp_path):
        """BetterBugs export should create a valid JSON file with correct schema."""
        out = tmp_path / "bb_export.json"
        result = export_betterbugs(SAMPLE_VULN, SAMPLE_POC, SAMPLE_EXEC, SAMPLE_EXPLANATION, out)

        assert result.exists()
        data = json.loads(result.read_text())
        assert data["schema_version"] == "1.0"
        assert data["vulnerability"]["type"] == "SQL Injection"
        assert data["proof_of_concept"]["code"] == SAMPLE_POC
        assert "generated_at" in data

    def test_run_poc_sandboxed_captures_output(self):
        """PoC runner should capture stdout from a simple script."""
        result = run_poc_sandboxed('print("hello from PoC")')
        assert result["status"] == "success"
        assert "hello from PoC" in result["stdout"]

    def test_run_poc_sandboxed_timeout(self):
        """PoC runner should handle timeouts gracefully."""
        result = run_poc_sandboxed("import time; time.sleep(60)", timeout=2)
        assert result["status"] == "timeout"
        assert result["returncode"] == -1


# ─────────────────────────────────────────────────────────────
#  LAYER 4 TESTS
# ─────────────────────────────────────────────────────────────
class TestLayer4:
    """Tests for AI Patch Generator (Layer 4)."""

    def test_format_pr_title(self):
        """PR title should contain the vulnerability type."""
        patch_result = {
            "patched_code": "secure code here",
            "explanation": "Fixed the issue.",
        }
        pr = format_pr(SAMPLE_VULN, patch_result, SAMPLE_EXPLANATION)
        assert "SQL Injection" in pr["pr_title"]
        assert pr["pr_title"].startswith("Fix:")

    def test_format_pr_body_contains_sections(self):
        """PR body should contain all required sections."""
        patch_result = {
            "patched_code": "secure code here",
            "explanation": "Fixed the issue.",
        }
        pr = format_pr(SAMPLE_VULN, patch_result, SAMPLE_EXPLANATION)
        body = pr["pr_body"]
        assert "Security Patch" in body
        assert "Vulnerable Code" in body
        assert "Patched Code" in body
        assert "Why This Fix Works" in body
        assert "NexusGuard AI" in body

    @patch("scripts.ai_patch_generator.LLMProvider")
    def test_generate_full_output_schema(self, mock_provider_cls):
        """Full output should match the required JSON schema."""
        mock_instance = MagicMock()
        # First call: generate_patch, second call: generate_explanation
        mock_instance.invoke.side_effect = [
            json.dumps({
                "patched_code": "def get_user_profile(db, uid):\n    cursor = db.cursor()\n    cursor.execute('SELECT id FROM users WHERE id = %s', (uid,))\n    return cursor.fetchone()",
                "explanation": "Replaced string concatenation with parameterized query.",
            }),
            "The fix uses parameterized queries to prevent injection.",
        ]
        mock_provider_cls.return_value = mock_instance

        result = generate_full_output(SAMPLE_VULN, provider="gemini")

        assert "patched_code" in result
        assert "explanation" in result
        assert "pr_title" in result
        assert "pr_body" in result
        assert len(result["patched_code"]) > 0
        assert result["pr_title"].startswith("Fix:")


# ─────────────────────────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
