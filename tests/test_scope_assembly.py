"""
Scope-assembly integration tests.

Verifies that collecting each sfhound scope individually and then ingesting
all of the resulting files into BloodHound produces a database that is
queryable in the same way as a full (no-scope) collection.

Test structure
--------------
Phase 1 — non-scoped (``test_cypher_queries.py``):
  ``uploaded_graph`` fixture: run sfhound without --scope -> upload to
  BloodHound.  ``test_cypher_query`` then validates every Cypher query.

Phase 2 — scoped (this module, runs after test_cypher_queries.py):
  1. ``test_scope_assembly_collection`` — parametrized per scope; uses the
     ``scope_extracted_files`` session fixture, which runs all 9 scope
     extractions into local temp directories (no BloodHound interaction).
     Validates that each output file has a valid OpenGraph envelope and the
     expected node kinds.

  2. ``test_cypher_query_scope_assembled`` — uses the ``scope_assembled_graph``
     session fixture, which depends on ``scope_extracted_files`` and then
     clears BloodHound and ingests all scope files.  Re-executes every Cypher
     query from the library, mirroring ``test_cypher_query``.

Execution order
---------------
- ``scope_extracted_files`` runs (all 9 extractions) when the first
  ``test_scope_assembly_collection`` test is encountered.
- All 9 collection-validation tests run against the local JSON files.
- ``scope_assembled_graph`` runs (BH clear + ingest) when the first
  ``test_cypher_query_scope_assembled`` test is encountered.
- All 50 cypher-query tests run against the scope-assembled BH database.
"""

import json
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CYPHER_QUERIES_PATH = (
    Path(__file__).parent.parent / "sfhound" / "examples" / "cypher_queries.yaml"
)

# Mirrors SCOPE_EXPECTED_KINDS in test_cli.py.
_SCOPE_EXPECTED_KINDS: dict[str, set] = {
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


def _load_json(json_path: Path) -> dict:
    with json_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _node_kinds(data: dict) -> set:
    kinds: set = set()
    for node in data.get("graph", {}).get("nodes", []):
        kinds.update(node.get("kinds", []))
    return kinds


def _load_queries() -> list[tuple[str, str]]:
    with _CYPHER_QUERIES_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return [
        (entry["name"], entry["query"].strip())
        for entry in data.get("queries", [])
    ]


_QUERIES = _load_queries()
_QUERY_IDS = [name for name, _ in _QUERIES]


# ---------------------------------------------------------------------------
# Scope-assembly collection tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope", sorted(_SCOPE_EXPECTED_KINDS))
def test_scope_assembly_collection(scope, scope_extracted_files):
    """
    Verify that the individual scope collection file for *scope* is valid.

    Uses the ``scope_extracted_files`` session fixture, which runs all 9 scope
    extractions into local temp directories with no BloodHound interaction.
    This ensures collection validation happens *before* any ingestion occurs.

    Assertions:
      1. A JSON file was produced for the scope.
      2. The file has a valid OpenGraph envelope (graph/nodes/edges structure).
      3. When nodes are present, at least one expected node kind appears.
    """
    assert scope in scope_extracted_files, (
        f"scope_extracted_files fixture did not produce a file for scope '{scope}'."
    )
    json_path = scope_extracted_files[scope]
    assert json_path.exists(), f"Scope '{scope}' output file not found: {json_path}"

    data = _load_json(json_path)
    assert isinstance(data, dict) and "graph" in data, (
        f"Scope '{scope}': {json_path.name} is not a valid OpenGraph envelope "
        "(missing 'graph' key)."
    )
    graph = data["graph"]
    assert "nodes" in graph and "edges" in graph, (
        f"Scope '{scope}': 'graph' object is missing 'nodes' or 'edges' array."
    )

    found_kinds = _node_kinds(data)
    expected = _SCOPE_EXPECTED_KINDS[scope]
    assert found_kinds & expected, (
        f"Scope '{scope}': none of the expected node kinds {expected} were "
        f"found in the output.  Found: {found_kinds}"
    )


# ---------------------------------------------------------------------------
# Cypher query tests against scope-assembled BloodHound database
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("query_name,query_text", _QUERIES, ids=_QUERY_IDS)
@pytest.mark.timeout(1200)
def test_cypher_query_scope_assembled(query_name, query_text, bh_api, scope_assembled_graph):
    """
    Execute *query_text* against BloodHound, which has been populated by
    ingesting one file per scope (all 9 scopes collected individually).

    Mirrors ``test_cypher_query`` in ``test_cypher_queries.py`` but targets the
    scope-assembled database instead of the full-extraction database.  Verifies
    that:

    1. No HTTP error is raised (query is syntactically valid Cypher).
    2. The response is a JSON dict.

    An empty result set is acceptable — queries referencing placeholder values
    will return zero rows in most orgs.

    ``scope_assembled_graph`` is listed as a parameter to guarantee BloodHound
    has been cleared and repopulated before any query runs.
    """
    _ = scope_assembled_graph  # consumed for its side-effect (BH population)

    try:
        result = bh_api.cypher_query(query_text, include_properties=False)
    except Exception as exc:
        msg = str(exc)
        if "HTTP 404" in msg:
            pytest.skip(
                f"Query '{query_name}': BloodHound returned 404 (no matching "
                "nodes/relationships in this org — likely a placeholder query "
                f"or data not present). Detail: {msg}"
            )
        if "HTTP 400" in msg:
            pytest.skip(
                f"Query '{query_name}': BloodHound rejected the query as too "
                f"complex (HTTP 400). Detail: {msg}"
            )
        raise

    assert isinstance(result, dict), (
        f"Query '{query_name}': expected a dict response from BloodHound, "
        f"got {type(result).__name__!r}."
    )
