"""
Shared pytest fixtures for the sfhound integration test suite.

Prerequisites
-------------
1. Copy tests/test_config.yaml.example → tests/test_config.yaml and fill in
   your Salesforce dev-org credentials and BloodHound connection details.
2. Start BloodHound CE locally (default: http://127.0.0.1:8080).

The entire session is skipped automatically when test_config.yaml is absent,
so a plain `pytest` invocation in a CI environment without credentials is safe.
"""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parent.parent
TEST_CONFIG_PATH = Path(__file__).parent / "test_config.yaml"


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def cfg():
    """Load tests/test_config.yaml.  Skip the entire session if it is missing."""
    if not TEST_CONFIG_PATH.exists():
        pytest.skip(
            f"Test config not found: {TEST_CONFIG_PATH}\n"
            "Copy tests/test_config.yaml.example → tests/test_config.yaml "
            "and fill in your credentials."
        )
    with TEST_CONFIG_PATH.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="session")
def bh_api(cfg):
    """
    Return an authenticated BloodHoundAPI session.

    Skips all tests that depend on this fixture when BloodHound is unreachable.
    The JWT is cached on the instance so subsequent calls within the session
    reuse the same token.
    """
    from sfhound.bloodhound_api import BloodHoundAPI

    api = BloodHoundAPI(cfg)
    token = api.login()
    if not token:
        pytest.skip(
            "Could not authenticate with BloodHound — "
            "check that it is running and that the credentials in "
            "tests/test_config.yaml are correct."
        )
    return api


@pytest.fixture(scope="session")
def uploaded_graph(cfg, bh_api, tmp_path_factory):
    """
    Session-scoped fixture used by the cypher query tests.

    Runs a full (no-scope) sfhound extraction once per test session, uploads
    the resulting OpenGraph JSON to BloodHound, and returns the Path of the
    uploaded file.  All cypher query tests declare this fixture as a dependency
    so that BloodHound is guaranteed to contain graph data before any Cypher is
    executed.

    Note: a full extraction can take several minutes on a large org.
    """
    out_dir = tmp_path_factory.mktemp("full_extract")

    stdout_file = out_dir / "stdout.txt"
    stderr_file = out_dir / "stderr.txt"
    with stdout_file.open("w") as fout, stderr_file.open("w") as ferr:
        result = subprocess.run(
            [
                sys.executable, "-m", "sfhound",
                "--config", str(TEST_CONFIG_PATH),
                "--output-path", str(out_dir),
            ],
            stdout=fout,
            stderr=ferr,
            cwd=str(PROJECT_ROOT),
        )
    assert result.returncode == 0, (
        f"Full (no-scope) extraction failed (rc={result.returncode}).\n"
        f"STDOUT:\n{stdout_file.read_text(errors='replace')}\n"
        f"STDERR:\n{stderr_file.read_text(errors='replace')}"
    )

    json_files = list(out_dir.glob("*.json"))
    assert json_files, "Full extraction produced no JSON output files."
    graph_path = json_files[0]

    # Temporarily enable auto_ingest on the shared session api so that
    # upload_graph() actually transmits the file.
    original_auto_ingest = bh_api.auto_ingest
    bh_api.auto_ingest = True
    try:
        bh_api.upload_graph(str(graph_path))
    finally:
        bh_api.auto_ingest = original_auto_ingest

    return graph_path


@pytest.fixture(scope="session")
def scope_extracted_files(cfg, tmp_path_factory):
    """
    Session-scoped fixture: runs sfhound once per scope (all 9 individually)
    and returns a dict mapping scope name -> Path of the output JSON file.

    No BloodHound interaction takes place here — this fixture exists solely so
    that scope-collection validation tests can assert on the local JSON output
    *before* any ingestion happens.
    """
    from sfhound.sfhound import VALID_SCOPES

    out_root = tmp_path_factory.mktemp("scope_assembly")
    scope_files: dict = {}

    for scope in sorted(VALID_SCOPES):
        scope_dir = out_root / scope
        scope_dir.mkdir()
        stdout_file = scope_dir / "stdout.txt"
        stderr_file = scope_dir / "stderr.txt"
        with stdout_file.open("w") as fout, stderr_file.open("w") as ferr:
            result = subprocess.run(
                [
                    sys.executable, "-m", "sfhound",
                    "--config", str(TEST_CONFIG_PATH),
                    "--output-path", str(scope_dir),
                    "--scope", scope,
                ],
                stdout=fout,
                stderr=ferr,
                cwd=str(PROJECT_ROOT),
            )
        assert result.returncode == 0, (
            f"Scope '{scope}' extraction failed (rc={result.returncode}).\n"
            f"STDOUT:\n{stdout_file.read_text(errors='replace')}\n"
            f"STDERR:\n{stderr_file.read_text(errors='replace')}"
        )
        json_files = [f for f in scope_dir.glob("*.json") if f.name != "stdout.txt"]
        assert json_files, f"Scope '{scope}' produced no JSON output file."
        scope_files[scope] = json_files[0]

    return scope_files


@pytest.fixture(scope="session")
def scope_assembled_graph(bh_api, scope_extracted_files):
    """
    Session-scoped fixture: clears BloodHound and ingests every file produced
    by ``scope_extracted_files``, then returns the same scope -> Path dict.

    Depends on ``scope_extracted_files`` (extraction only) so that the
    collection-validation tests run first — after each scope is extracted but
    before any data reaches BloodHound.

    Local bhopengraph schema validation is bypassed because scoped files
    contain cross-scope edge references that the validator rejects, even though
    BloodHound itself ingests them without error.
    """
    bh_api.clear_database()

    original_auto_ingest = bh_api.auto_ingest
    bh_api.auto_ingest = True
    try:
        # Bypass local schema validation: scoped files have cross-scope edge
        # references that trip bhopengraph's validator.  BloodHound itself
        # ingests partial/scoped graphs without error.
        with patch.object(bh_api, "validate_opengraph_json", return_value=True):
            for scope, path in scope_extracted_files.items():
                bh_api.upload_graph(str(path))
    finally:
        bh_api.auto_ingest = original_auto_ingest

    return scope_extracted_files


# ---------------------------------------------------------------------------
# Function-scoped fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def run_sfhound(cfg):
    """
    Return a callable that invokes ``python -m sfhound`` with a standard
    ``--config tests/test_config.yaml`` prefix plus any extra args provided.

    The callable returns a ``subprocess.CompletedProcess``; it does NOT raise
    on a non-zero exit code — tests are responsible for asserting ``returncode``.

    Depends on ``cfg`` so that the entire test is skipped when the config file
    is absent (skip propagates from the session-scoped ``cfg`` fixture).
    """
    def _run(*extra_args):
        cmd = (
            [sys.executable, "-m", "sfhound", "--config", str(TEST_CONFIG_PATH)]
            + list(extra_args)
        )
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )

    return _run


@pytest.fixture
def tmp_output(tmp_path):
    """Return a fresh temporary directory for sfhound JSON output per test."""
    out = tmp_path / "output"
    out.mkdir()
    return out
