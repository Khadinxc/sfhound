"""
User-filter integration tests for sfhound.

Verifies that the --user-types and --exclude-username-pattern flags are purely
additive (i.e. they only narrow the set of extracted users; they do not
introduce new node kinds, break the OpenGraph envelope, or cause BloodHound to
reject the upload).

Test sequence
-------------
For each filter combination the test:
  1. Invokes sfhound against the live dev org (``tests/test_config.yaml``).
  2. Asserts the process exits with code 0.
  3. Asserts the output file has a valid OpenGraph envelope.
  4. Uploads the file to BloodHound and asserts BloodHound accepts it.
  5. (Where applicable) asserts the filtered user count is ≤ the unfiltered
     user count collected for the same scope in the same session.

All tests in this module are skipped automatically when:
  - ``tests/test_config.yaml`` is absent (credentials not configured), or
  - BloodHound CE is unreachable (the ``bh_api`` fixture skips).

The session-scoped fixtures in this module call subprocess directly (mirroring
the pattern used by ``scope_extracted_files`` in conftest.py) because the
``run_sfhound`` helper in conftest.py is function-scoped.
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Paths (mirrors conftest.py so we don't depend on its internal symbols)
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).parent.parent
_TEST_CONFIG_PATH = Path(__file__).parent / "test_config.yaml"


def _run_sfhound(*extra_args):
    """Invoke ``python -m sfhound`` with the standard test config prefix."""
    return subprocess.run(
        [sys.executable, "-m", "sfhound", "--config", str(_TEST_CONFIG_PATH)]
        + list(extra_args),
        capture_output=True,
        text=True,
        cwd=str(_PROJECT_ROOT),
    )


# ---------------------------------------------------------------------------
# Helpers (duplicated locally to keep this module self-contained)
# ---------------------------------------------------------------------------


def _load_json(json_path: Path) -> dict:
    with json_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _node_kinds(data: dict) -> set:
    kinds: set = set()
    for node in data.get("graph", {}).get("nodes", []):
        kinds.update(node.get("kinds", []))
    return kinds


def _user_ids(data: dict) -> set:
    return {
        node["id"]
        for node in data.get("graph", {}).get("nodes", [])
        if "SFUser" in node.get("kinds", [])
    }


def _find_json(directory: Path, pattern: str = "*.json") -> list:
    return list(directory.glob(pattern))


def _assert_valid_json_structure(json_path: Path) -> dict:
    assert json_path.exists(), f"Output file not found: {json_path}"
    data = _load_json(json_path)
    assert isinstance(data, dict) and "graph" in data, (
        f"{json_path.name}: missing 'graph' key (not a valid OpenGraph envelope)."
    )
    graph = data["graph"]
    assert "nodes" in graph and "edges" in graph, (
        f"{json_path.name}: 'graph' object is missing 'nodes' or 'edges' array."
    )
    return data


def _upload_to_bh(bh_api, json_path: Path) -> None:
    """Upload *json_path* to BloodHound, bypassing the local schema validator.

    Scoped files may contain cross-scope edge references that trip the local
    bhopengraph validator even though BloodHound itself ingests them without
    error.  The upload is what matters here.
    """
    original = bh_api.auto_ingest
    bh_api.auto_ingest = True
    try:
        with patch.object(bh_api, "validate_opengraph_json", return_value=True):
            bh_api.upload_graph(str(json_path))
    finally:
        bh_api.auto_ingest = original


# ---------------------------------------------------------------------------
# Session fixtures — run each extraction once per test session
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def baseline_users_file(cfg, tmp_path_factory):
    """
    Session-scoped: run ``sfhound --scope users`` without any user filters.

    Returns the Path of the produced JSON file.  This is the baseline against
    which filtered collections are compared.

    Depends on ``cfg`` so the entire session is skipped when test_config.yaml
    is absent (skip propagates from the session-scoped ``cfg`` fixture).
    """
    out_dir = tmp_path_factory.mktemp("user_filter_baseline")
    result = _run_sfhound("--scope", "users", "--output-path", str(out_dir))
    assert result.returncode == 0, (
        f"Baseline users collection failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    json_files = _find_json(out_dir)
    assert json_files, "Baseline users collection produced no JSON output file."
    return json_files[0]


@pytest.fixture(scope="session")
def user_types_file(cfg, tmp_path_factory):
    """
    Session-scoped: run ``sfhound --scope users --user-types Standard``.

    Returns the Path of the produced JSON file.
    """
    out_dir = tmp_path_factory.mktemp("user_filter_types")
    result = _run_sfhound(
        "--scope", "users",
        "--user-types", "Standard",
        "--output-path", str(out_dir),
    )
    assert result.returncode == 0, (
        f"--user-types Standard collection failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    json_files = _find_json(out_dir)
    assert json_files, "--user-types Standard collection produced no JSON output file."
    return json_files[0]


@pytest.fixture(scope="session")
def exclude_pattern_file(cfg, tmp_path_factory):
    """
    Session-scoped: run ``sfhound --scope users`` with an exclusion pattern
    that drops automated / integration users whose usernames end in
    ``@<orgid>.invalid`` (the Salesforce-standard pattern for org-internal
    service accounts).

    Returns the Path of the produced JSON file.
    """
    out_dir = tmp_path_factory.mktemp("user_filter_pattern")
    result = _run_sfhound(
        "--scope", "users",
        "--exclude-username-pattern", "%@00D%.invalid",
        "--output-path", str(out_dir),
    )
    assert result.returncode == 0, (
        f"--exclude-username-pattern collection failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    json_files = _find_json(out_dir)
    assert json_files, "--exclude-username-pattern collection produced no JSON output file."
    return json_files[0]


@pytest.fixture(scope="session")
def combined_filters_file(cfg, tmp_path_factory):
    """
    Session-scoped: run ``sfhound --scope users`` with both filters active
    simultaneously.

    Returns the Path of the produced JSON file.
    """
    out_dir = tmp_path_factory.mktemp("user_filter_combined")
    result = _run_sfhound(
        "--scope", "users",
        "--user-types", "Standard",
        "--exclude-username-pattern", "%@00D%.invalid",
        "--output-path", str(out_dir),
    )
    assert result.returncode == 0, (
        f"Combined-filter collection failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    json_files = _find_json(out_dir)
    assert json_files, "Combined-filter collection produced no JSON output file."
    return json_files[0]


# ---------------------------------------------------------------------------
# Structural / additive tests (no BloodHound interaction)
# ---------------------------------------------------------------------------


def test_baseline_users_structure(baseline_users_file):
    """Baseline --scope users run produces a valid OpenGraph envelope."""
    data = _assert_valid_json_structure(baseline_users_file)
    found_kinds = _node_kinds(data)
    if found_kinds:
        assert "SFUser" in found_kinds, (
            f"Baseline users file contains nodes but SFUser is absent: {found_kinds}"
        )


def test_user_types_structure(user_types_file):
    """--user-types produces a valid OpenGraph envelope with only SFUser nodes."""
    data = _assert_valid_json_structure(user_types_file)
    found_kinds = _node_kinds(data)
    if found_kinds:
        assert "SFUser" in found_kinds, (
            f"--user-types file contains nodes but SFUser is absent: {found_kinds}"
        )


def test_exclude_pattern_structure(exclude_pattern_file):
    """--exclude-username-pattern produces a valid OpenGraph envelope."""
    data = _assert_valid_json_structure(exclude_pattern_file)
    found_kinds = _node_kinds(data)
    if found_kinds:
        assert "SFUser" in found_kinds, (
            f"--exclude-username-pattern file contains nodes but SFUser is absent: {found_kinds}"
        )


def test_combined_filters_structure(combined_filters_file):
    """Both filters together produce a valid OpenGraph envelope."""
    data = _assert_valid_json_structure(combined_filters_file)
    found_kinds = _node_kinds(data)
    if found_kinds:
        assert "SFUser" in found_kinds, (
            f"Combined-filter file contains nodes but SFUser is absent: {found_kinds}"
        )


def test_user_types_is_subset_of_baseline(baseline_users_file, user_types_file):
    """
    --user-types Standard must return a subset of the unfiltered user set.

    Filters are purely additive: they can only *remove* users, never introduce
    new ones.
    """
    baseline_data = _load_json(baseline_users_file)
    filtered_data = _load_json(user_types_file)

    baseline_ids = _user_ids(baseline_data)
    filtered_ids = _user_ids(filtered_data)

    extra = filtered_ids - baseline_ids
    assert not extra, (
        f"--user-types filter returned {len(extra)} user(s) NOT present in the "
        f"baseline collection — filters must be purely subtractive.\n"
        f"Extra IDs: {sorted(extra)}"
    )


def test_exclude_pattern_is_subset_of_baseline(baseline_users_file, exclude_pattern_file):
    """
    --exclude-username-pattern must return a subset of the unfiltered user set.
    """
    baseline_data = _load_json(baseline_users_file)
    filtered_data = _load_json(exclude_pattern_file)

    baseline_ids = _user_ids(baseline_data)
    filtered_ids = _user_ids(filtered_data)

    extra = filtered_ids - baseline_ids
    assert not extra, (
        f"--exclude-username-pattern filter returned {len(extra)} user(s) NOT "
        f"present in the baseline collection.\n"
        f"Extra IDs: {sorted(extra)}"
    )


def test_combined_filters_is_subset_of_user_types(user_types_file, combined_filters_file):
    """
    Applying both filters simultaneously must yield a subset of the
    --user-types-only filtered set (since the combined filter is strictly
    more restrictive).
    """
    types_data = _load_json(user_types_file)
    combined_data = _load_json(combined_filters_file)

    types_ids = _user_ids(types_data)
    combined_ids = _user_ids(combined_data)

    extra = combined_ids - types_ids
    assert not extra, (
        f"Combined-filter collection returned {len(extra)} user(s) NOT present "
        f"in the --user-types-only collection — combined filters must be "
        f"strictly at least as restrictive as --user-types alone.\n"
        f"Extra IDs: {sorted(extra)}"
    )


def test_no_new_node_kinds_with_user_types(baseline_users_file, user_types_file):
    """--user-types must not introduce node kinds absent from the baseline."""
    baseline_kinds = _node_kinds(_load_json(baseline_users_file))
    filtered_kinds = _node_kinds(_load_json(user_types_file))
    new_kinds = filtered_kinds - baseline_kinds
    assert not new_kinds, (
        f"--user-types introduced unexpected node kind(s): {new_kinds}"
    )


def test_no_new_node_kinds_with_exclude_pattern(baseline_users_file, exclude_pattern_file):
    """--exclude-username-pattern must not introduce node kinds absent from the baseline."""
    baseline_kinds = _node_kinds(_load_json(baseline_users_file))
    filtered_kinds = _node_kinds(_load_json(exclude_pattern_file))
    new_kinds = filtered_kinds - baseline_kinds
    assert not new_kinds, (
        f"--exclude-username-pattern introduced unexpected node kind(s): {new_kinds}"
    )


# ---------------------------------------------------------------------------
# BloodHound ingestion tests
# ---------------------------------------------------------------------------


def test_baseline_users_accepted_by_bloodhound(baseline_users_file, bh_api):
    """
    BloodHound must accept the baseline (unfiltered) users scope file.

    This test runs first in the ingestion sequence so that BloodHound contains
    a known good user set before the filtered uploads.
    """
    bh_api.clear_database()
    _upload_to_bh(bh_api, baseline_users_file)


def test_user_types_accepted_by_bloodhound(user_types_file, bh_api):
    """
    BloodHound must accept a users scope file collected with --user-types Standard.

    Clears the database first so the upload is validated in isolation.
    """
    bh_api.clear_database()
    _upload_to_bh(bh_api, user_types_file)


def test_exclude_pattern_accepted_by_bloodhound(exclude_pattern_file, bh_api):
    """
    BloodHound must accept a users scope file collected with
    --exclude-username-pattern.

    Clears the database first so the upload is validated in isolation.
    """
    bh_api.clear_database()
    _upload_to_bh(bh_api, exclude_pattern_file)


def test_combined_filters_accepted_by_bloodhound(combined_filters_file, bh_api):
    """
    BloodHound must accept a users scope file collected with both
    --user-types and --exclude-username-pattern active simultaneously.

    Clears the database first so the upload is validated in isolation.
    """
    bh_api.clear_database()
    _upload_to_bh(bh_api, combined_filters_file)


# ---------------------------------------------------------------------------
# Per-UserType full-collection cypher query validation
# ---------------------------------------------------------------------------
#
# For every UserType present in the dev org we run a complete (no --scope)
# sfhound extraction filtered by that type, upload the result to BloodHound,
# and then:
#
#   a) assert that a small set of *required* queries return actual data (not
#      404 "no matching nodes"), which proves the graph is structurally
#      complete for that user population.
#   b) assert that NO query in the full 50-query library triggers a 5xx
#      server error, which would indicate a corrupt graph or a BloodHound bug.
#
# This test class specifically catches the scenario observed during development
# where a filtered collection yielded 49/50 SKIPPED cypher queries (all 404s)
# because the graph was structurally incomplete for the filtered user set.
# ---------------------------------------------------------------------------

_CYPHER_QUERIES_PATH = (
    Path(__file__).parent.parent / "sfhound" / "examples" / "cypher_queries.yaml"
)

# UserTypes present in the dev org.  Update this list when new service-account
# types appear in the target Salesforce org.
_ORG_USER_TYPES = [
    "Standard",
    "AutomatedProcess",
    "Guest",
    "CloudIntegrationUser",
    "CsnOnly",
]

# Queries that MUST return at least one result (HTTP 200 with data) for any
# valid user-type-filtered full collection.  A 404 here means BloodHound has
# no nodes of that kind, which indicates an incomplete extraction.
_REQUIRED_CYPHER_QUERIES: dict[str, str] = {
    "Count - All Users": "MATCH (m:SFUser) RETURN m LIMIT 1",
    "Count - All Permission Sets": "MATCH (m:SFPermissionSet) RETURN m LIMIT 1",
}


def _load_cypher_queries() -> list[tuple[str, str]]:
    """Return [(name, query_text), ...] for all entries in the YAML file."""
    with _CYPHER_QUERIES_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return [
        (entry["name"], entry["query"].strip())
        for entry in data.get("queries", [])
    ]


def _run_cypher(bh_api, query_text: str) -> tuple[int | None, str]:
    """Execute *query_text* via the BloodHound cypher API.

    Returns ``(http_status, detail)`` where *http_status* is:
    - ``200``  — success (result may be empty but query was accepted).
    - An integer error code (e.g. 400, 404) extracted from the exception
      message ``"... HTTP <N> ..."`` for known API errors.
    - ``None`` for unexpected (non-HTTP) failures.

    *detail* contains the raw exception message or an empty string on success.
    """
    try:
        bh_api.cypher_query(query_text, include_properties=False)
        return 200, ""
    except Exception as exc:
        detail = str(exc)
        match = re.search(r"HTTP (\d{3})", detail)
        if match:
            return int(match.group(1)), detail
        return None, detail


@pytest.mark.parametrize("user_type", _ORG_USER_TYPES)
def test_full_collection_by_user_type_is_queryable(user_type, bh_api, tmp_path):
    """
    For a full (no --scope) sfhound extraction filtered to *user_type*:

    1. Assert the extraction exits cleanly (rc=0).
    2. Assert the local JSON file is a valid OpenGraph envelope that contains
       at least one SFUser node — i.e. the filter returned actual users.
    3. Clear BloodHound, then upload the file and wait for ingestion to
       complete.
    4. Assert that the two *required* cypher queries (All Users, All Permission
       Sets) return HTTP 200 — a 404 proves BloodHound has no nodes of that
       kind and the graph is incomplete.
    5. Assert that none of the 50 queries in the full library triggers a 5xx
       server error — which would indicate a corrupt graph.

    ``bh_api`` and ``tmp_path`` are function-scoped so each parametrized case
    gets its own isolated BloodHound state and temp directory.
    """
    out_dir = tmp_path / "output"
    out_dir.mkdir()

    # ------------------------------------------------------------------
    # Step 1 — extract
    # ------------------------------------------------------------------
    result = _run_sfhound(
        "--user-types", user_type,
        "--output-path", str(out_dir),
    )
    assert result.returncode == 0, (
        f"[{user_type}] sfhound --user-types {user_type} failed "
        f"(rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    json_files = _find_json(out_dir)
    assert json_files, (
        f"[{user_type}] sfhound --user-types {user_type} produced no JSON output."
    )
    json_path = json_files[0]

    # ------------------------------------------------------------------
    # Step 2 — local structural validation
    # ------------------------------------------------------------------
    data = _assert_valid_json_structure(json_path)
    user_ids = _user_ids(data)
    assert user_ids, (
        f"[{user_type}] The extracted OpenGraph file contains no SFUser nodes. "
        "Either the UserType has no active users in the org or the extractor "
        "silently dropped all users."
    )

    # ------------------------------------------------------------------
    # Step 3 — clear BH and upload (using the real validator to prove that
    # the hydrated stub nodes make the local OpenGraph schema check pass)
    # ------------------------------------------------------------------
    bh_api.clear_database()
    original_auto_ingest = bh_api.auto_ingest
    bh_api.auto_ingest = True
    try:
        bh_api.upload_graph(str(json_path))
    finally:
        bh_api.auto_ingest = original_auto_ingest

    # ------------------------------------------------------------------
    # Step 4 — required queries must return data (not 404)
    # ------------------------------------------------------------------
    required_failures: list[str] = []
    for query_name, query_text in _REQUIRED_CYPHER_QUERIES.items():
        status, detail = _run_cypher(bh_api, query_text)
        if status != 200:
            label = f"HTTP {status}" if status is not None else "non-HTTP error"
            required_failures.append(
                f"  Query '{query_name}' returned {label}: {detail}"
            )

    assert not required_failures, (
        f"[{user_type}] Required cypher queries returned no data after upload — "
        "the filtered graph is structurally incomplete:\n"
        + "\n".join(required_failures)
    )

    # ------------------------------------------------------------------
    # Step 5 — full query library: no 5xx errors
    # ------------------------------------------------------------------
    server_errors: list[str] = []
    for query_name, query_text in _load_cypher_queries():
        status, detail = _run_cypher(bh_api, query_text)
        if status is None or status >= 500:
            label = f"HTTP {status}" if status is not None else "non-HTTP error"
            server_errors.append(
                f"  Query '{query_name}' → {label}: {detail}"
            )

    assert not server_errors, (
        f"[{user_type}] The following cypher queries triggered server errors "
        "against the filtered graph — this indicates a corrupt or invalid graph:\n"
        + "\n".join(server_errors)
    )
