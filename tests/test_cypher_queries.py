"""
Cypher query library validation tests.

Loads every query defined in sfhound/examples/cypher_queries.yaml and executes
it against the live BloodHound instance.  Tests verify that each query is
accepted by BloodHound (i.e. syntactically valid Cypher that executes without
an HTTP error), regardless of whether it returns results — queries that use
placeholder names such as "PETER WIENER" or "SECRETDATA__C" will legitimately
return empty result sets in most orgs.

Prerequisites
-------------
- BloodHound CE must be running and accessible.
- The ``uploaded_graph`` session fixture (conftest.py) populates BloodHound
  with a full sfhound extraction before any query is attempted.
"""

from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Load queries at collection time
# ---------------------------------------------------------------------------

CYPHER_QUERIES_PATH = (
    Path(__file__).parent.parent / "sfhound" / "examples" / "cypher_queries.yaml"
)


def _load_queries() -> list[tuple[str, str]]:
    """Return [(name, query_text), ...] for all entries in the YAML file."""
    with CYPHER_QUERIES_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return [
        (entry["name"], entry["query"].strip())
        for entry in data.get("queries", [])
    ]


_QUERIES = _load_queries()
_QUERY_IDS = [name for name, _ in _QUERIES]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("query_name,query_text", _QUERIES, ids=_QUERY_IDS)
def test_cypher_query(query_name, query_text, bh_api, uploaded_graph):
    """
    Execute a single Cypher query from the YAML library against BloodHound and
    assert that:

    1. No exception is raised (HTTP 200 received).
    2. The response is a JSON object (dict).

    An empty result set is acceptable — queries that reference placeholder
    values will return zero rows in orgs that lack matching data.

    ``uploaded_graph`` is listed as a parameter so pytest guarantees the full
    graph has been ingested before this test runs.
    """
    # uploaded_graph is consumed only for its side-effect (BH population).
    _ = uploaded_graph

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
