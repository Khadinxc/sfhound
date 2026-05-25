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

    result = subprocess.run(
        [
            sys.executable, "-m", "sfhound",
            "--config", str(TEST_CONFIG_PATH),
            "--output-path", str(out_dir),
        ],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert result.returncode == 0, (
        f"Full (no-scope) extraction failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
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
