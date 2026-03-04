"""
graph/export.py — retained for backward compatibility.

The Exporter class has been superseded by graph.sfgraph.SFGraph which uses
bhopengraph.OpenGraph as its foundation.  New code should use SFGraph directly:

    from graph.sfgraph import SFGraph

    graph = SFGraph()
    graph.add_or_merge_node(node)
    graph.add_edge_without_validation(edge)
    graph.print_summary()
    graph.check_dangling()
    graph.export_to_file(output_path, include_metadata=False, indent=2)
"""