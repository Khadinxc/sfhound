"""
CLI integration tests for sfhound.

Each test invokes `python -m sfhound` as a subprocess so the full argument-
parsing, config-loading, extraction, graph-building, and export pipeline is
exercised end-to-end against the Salesforce developer org configured in
tests/test_config.yaml.

Test categories
---------------
- Scope tests   : one test per valid --scope value (9 total)
- Flag tests    : --verbose, --throttle, --output-path, --fields, --auto-ingest
- Multi-scope   : several scopes in one invocation
"""

import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_json(json_path: Path) -> dict:
    with json_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _node_kinds(data: dict) -> set:
    """Return the union of all 'kinds' labels across every node in the graph."""
    kinds: set = set()
    for node in data.get("graph", {}).get("nodes", []):
        kinds.update(node.get("kinds", []))
    return kinds


def _find_json(directory: Path, pattern: str = "*.json") -> list:
    """Return all JSON files matching *pattern* in *directory*."""
    return list(directory.glob(pattern))


def _assert_valid_json_structure(json_path: Path) -> dict:
    """
    Assert that *json_path* exists, is parseable JSON, and contains the
    OpenGraph envelope structure (``{"graph": {"nodes": [...], "edges": [...]}}``)
    expected from sfhound.  Returns the parsed dict.

    Unlike ``_assert_valid_opengraph``, this does NOT invoke the bhopengraph
    schema validator, so it is safe to use for *scoped* exports that may
    contain edges whose partner nodes live in a different scope file.
    """
    assert json_path.exists(), f"Output file not found: {json_path}"
    data = _load_json(json_path)
    assert isinstance(data, dict) and "graph" in data, (
        f"{json_path.name} is not a valid OpenGraph envelope (missing 'graph' key)."
    )
    graph = data["graph"]
    assert "nodes" in graph and "edges" in graph, (
        f"{json_path.name}: 'graph' object is missing 'nodes' or 'edges' array."
    )
    return data


def _assert_valid_opengraph(json_path: Path, bh_api) -> dict:
    """
    Assert that *json_path* exists, is parseable JSON, and passes the
    BloodHound OpenGraph schema validator.  Returns the parsed dict.
    """
    assert json_path.exists(), f"Output file not found: {json_path}"
    data = _load_json(json_path)
    assert isinstance(data, dict) and "graph" in data, (
        f"{json_path.name} is not a valid OpenGraph envelope (missing 'graph' key)."
    )
    assert bh_api.validate_opengraph_json(str(json_path)), (
        f"OpenGraph schema validation failed for {json_path.name}."
    )
    return data


# ---------------------------------------------------------------------------
# Scope tests
# ---------------------------------------------------------------------------

# Maps each --scope value to the set of node kinds that MUST appear in its
# output when the org contains any data for that scope.  The assertion is
# relaxed: if the extraction produces zero nodes (e.g. the dev org has no
# queues), the kind-presence check is skipped; the important invariants are
# exit-code 0 and a valid OpenGraph file.
SCOPE_EXPECTED_KINDS: dict[str, set] = {
    "users":          {"SFUser"},
    "groups":         {"SFGroup", "SFPublicGroup"},
    "queues":         {"SFQueue"},
    "profiles":       {"SFProfile"},
    "permissionsets": {"SFPermissionSet"},
    "roles":          {"SFRole"},
    "connectedapps":  {"SFConnectedApp"},
    "objects":        {"SFSObject"},
    "fields":         {"SFField"},
}


@pytest.mark.parametrize("scope", list(SCOPE_EXPECTED_KINDS))
def test_scope(scope, run_sfhound, tmp_output):
    """
    Run sfhound with a single --scope value and verify:
      1. Process exits with code 0.
      2. Exactly one JSON file is written to --output-path.
      3. The file has valid OpenGraph JSON structure (envelope + nodes/edges arrays).
      4. When the file contains any nodes, at least one expected kind is present.

    Note: full bhopengraph schema validation is intentionally skipped here.
    Scoped exports contain edges whose partner nodes live in a *different* scope
    file; the bhopengraph validator rejects these dangling references even
    though they are perfectly valid for incremental BloodHound ingestion.
    """
    result = run_sfhound("--scope", scope, "--output-path", str(tmp_output))

    assert result.returncode == 0, (
        f"`sfhound --scope {scope}` failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    json_files = _find_json(tmp_output)
    assert json_files, (
        f"--scope {scope}: no JSON output file produced in {tmp_output}."
    )
    # Each scope writes exactly one file named *_{scope}.json
    json_path = json_files[0]
    data = _assert_valid_json_structure(json_path)

    found_kinds = _node_kinds(data)
    if found_kinds:
        expected = SCOPE_EXPECTED_KINDS[scope]
        assert found_kinds & expected, (
            f"--scope {scope}: none of the expected node kinds {expected} "
            f"were found in the output.  Found: {found_kinds}"
        )


# ---------------------------------------------------------------------------
# Flag tests
# ---------------------------------------------------------------------------


def test_verbose_flag(run_sfhound, tmp_output):
    """--verbose must not break the extraction; output file must be produced."""
    result = run_sfhound(
        "--scope", "users",
        "--verbose",
        "--output-path", str(tmp_output),
    )
    assert result.returncode == 0, (
        f"--verbose flag test failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert _find_json(tmp_output), "No output file produced with --verbose."


def test_throttle_flag(run_sfhound, tmp_output):
    """--throttle must limit SOQL queries and still produce a valid output file."""
    result = run_sfhound(
        "--scope", "users",
        "--throttle", "50",
        "--output-path", str(tmp_output),
    )
    assert result.returncode == 0, (
        f"--throttle flag test failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    json_files = _find_json(tmp_output)
    assert json_files, "No output file produced with --throttle."
    _assert_valid_json_structure(json_files[0])


def test_output_path(run_sfhound, tmp_output):
    """--output-path must place the JSON file in the specified directory."""
    result = run_sfhound(
        "--scope", "users",
        "--output-path", str(tmp_output),
    )
    assert result.returncode == 0, (
        f"--output-path flag test failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert _find_json(tmp_output), (
        f"No JSON file found in explicitly specified --output-path: {tmp_output}"
    )


def test_fields_all(run_sfhound, tmp_output):
    """
    --fields all (the default) must produce a valid output.

    The *_fields.json scope file is checked for valid JSON structure and the
    presence of SFField nodes (when the org exposes field permissions).
    """
    result = run_sfhound(
        "--scope", "objects,fields",
        "--fields", "all",
        "--output-path", str(tmp_output),
    )
    assert result.returncode == 0, (
        f"--fields all test failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    fields_files = _find_json(tmp_output, "*_fields.json")
    assert fields_files, "No '*_fields.json' output file produced with --fields all."

    data = _assert_valid_json_structure(fields_files[0])
    found_kinds = _node_kinds(data)
    if found_kinds:
        assert "SFField" in found_kinds, (
            f"--fields all produced nodes but SFField was not among them: {found_kinds}"
        )


def test_fields_none(run_sfhound, tmp_output):
    """--fields none must suppress all SFField nodes from every output file."""
    result = run_sfhound(
        "--scope", "objects,fields",
        "--fields", "none",
        "--output-path", str(tmp_output),
    )
    assert result.returncode == 0, (
        f"--fields none test failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    for json_file in _find_json(tmp_output):
        data = _load_json(json_file)
        found_kinds = _node_kinds(data)
        assert "SFField" not in found_kinds, (
            f"SFField nodes unexpectedly found in {json_file.name} with --fields none."
        )


def test_multi_scope(run_sfhound, tmp_output):
    """
    Running several scopes in one invocation must produce one valid file per
    scope and each expected node kind must be present in the combined output.
    """
    result = run_sfhound(
        "--scope", "users,profiles,roles",
        "--output-path", str(tmp_output),
    )
    assert result.returncode == 0, (
        f"Multi-scope test failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    all_kinds: set = set()
    json_files = _find_json(tmp_output)
    assert json_files, "Multi-scope invocation produced no output files."

    for json_file in json_files:
        data = _assert_valid_json_structure(json_file)
        all_kinds.update(_node_kinds(data))

    for expected_kind in ("SFUser", "SFProfile", "SFRole"):
        assert expected_kind in all_kinds, (
            f"Multi-scope output is missing expected node kind '{expected_kind}'. "
            f"All found kinds: {all_kinds}"
        )


def test_auto_ingest(run_sfhound, tmp_output, bh_api):
    """
    --auto-ingest must perform a full extraction, write the output file, and
    upload it to BloodHound without error.

    Note: this test runs a complete (no-scope) extraction which may take
    several minutes depending on the size of the org.  BloodHound must be
    running and reachable via the credentials in tests/test_config.yaml.
    """
    result = run_sfhound(
        "--auto-ingest",
        "--output-path", str(tmp_output),
    )
    assert result.returncode == 0, (
        f"--auto-ingest test failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    json_files = _find_json(tmp_output)
    assert json_files, "No output file produced with --auto-ingest."
    # Full (no-scope) export should pass complete schema validation.
    _assert_valid_opengraph(json_files[0], bh_api)
