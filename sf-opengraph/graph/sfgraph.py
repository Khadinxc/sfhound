"""
graph/sfgraph.py — sfhound-specific OpenGraph subclass.

Extends bhopengraph.OpenGraph with:
  - add_or_merge_node()   upsert semantics: merges kinds + properties when a
                           node ID is already present (needed because the same
                           Salesforce record can be emitted by multiple builders,
                           e.g. Group + PublicGroup or Group + Queue).
  - print_summary()       per-kind node-count output.
  - check_dangling()      warns about edges whose endpoints are absent from the
                           graph, using bhopengraph's get_isolated_edges().
"""
from __future__ import annotations

from typing import Dict

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.OpenGraph import OpenGraph


# Ordered mapping from internal SF kind labels to human-readable names used in
# the summary output.  Unknown kinds are printed at the end in sorted order.
_KIND_LABELS: Dict[str, str] = {
    "SFOrganization":       "organizations",
    "SFUser":               "users",
    "SFProfile":            "profiles",
    "SFPermissionSet":      "permission sets",
    "SFPermissionSetGroup": "permission set groups",
    "SFRole":               "roles",
    "SFGroup":              "groups",
    "SFPublicGroup":        "public groups",
    "SFQueue":              "queues",
    "SFConnectedApp":       "connected apps",
    "SFSObject":            "objects",
    "SFField":              "fields",
}


class SFGraph(OpenGraph):
    """
    OpenGraph subclass for the sfhound collector.

    Usage::

        graph = SFGraph()
        for node in node_builder.build_users(users):
            graph.add_or_merge_node(node)
        for edge in edge_builder.build_profile_assignments(users):
            graph.add_edge_without_validation(edge)
        graph.print_summary()
        graph.check_dangling()
        graph.export_to_file(output_path, include_metadata=False, indent=2)
    """

    # ------------------------------------------------------------------
    # Node management
    # ------------------------------------------------------------------

    def add_or_merge_node(self, node: Node) -> None:
        """
        Add *node* to the graph, or merge it into the existing node when the
        same ID is already present.

        Merge semantics (deduplication logic):
          - kinds:       union of existing and incoming lists (sorted for
                         determinism so graph output is stable across runs)
          - properties:  incoming values overwrite existing ones (last-write wins)

        This is needed because multiple NodeBuilder methods can emit the same
        Salesforce ID — for example, build_groups() and build_queues() both
        process records from the same SOQL result keyed on group ID.
        """
        existing = self.get_node_by_id(node.id)
        if existing is None:
            # First time we see this ID — add directly without the source_kind
            # injection that add_node() would apply (sfhound manages its own kinds).
            self.add_node_without_validation(node)
            return

        # Merge kinds (union, sorted for deterministic serialization order)
        for kind in node.kinds:
            if not existing.has_kind(kind):
                existing.add_kind(kind)
        existing.kinds.sort()

        # Merge properties — incoming values overwrite existing ones
        for key, value in node.properties.get_all_properties().items():
            existing.properties.set_property(key, value)

    # ------------------------------------------------------------------
    # Summary output
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        """
        Print a per-kind node-count summary to stdout, matching the output
        format of the old Exporter.
        """
        kind_counts: Dict[str, int] = {}
        for node in self.nodes.values():
            # Use the first SF-prefixed kind, falling back to the first kind
            primary = next(
                (k for k in node.kinds if k.startswith("SF")),
                node.kinds[0] if node.kinds else "Unknown",
            )
            kind_counts[primary] = kind_counts.get(primary, 0) + 1

        printed: set = set()
        for kind, label in _KIND_LABELS.items():
            if kind in kind_counts:
                print(f"[+] Found {kind_counts[kind]} {label}")
                printed.add(kind)
        for kind, count in sorted(kind_counts.items()):
            if kind not in printed:
                print(f"[+] Found {count} {kind}")

    # ------------------------------------------------------------------
    # Dangling-edge check
    # ------------------------------------------------------------------

    def check_dangling(self) -> None:
        """
        Warn about edges whose start or end node is absent from the graph.

        Uses bhopengraph's get_isolated_edges() which returns every edge where
        either endpoint ID is not present in self.nodes.
        """
        isolated = self.get_isolated_edges()
        if not isolated:
            return

        print(
            f"[!] Warning: {len(isolated)} dangling edges "
            f"(start/end node missing). First 20:"
        )
        for edge in isolated[:20]:
            print(f"    {edge.kind}: {edge.start_node} -> {edge.end_node}")
