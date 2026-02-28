import json
from typing import Any, Dict, List, Tuple


class Exporter:
    def export(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], output_path: str) -> None:
        # ----
        # 1) Deduplicate nodes by id (last write wins, but merge properties)
        # ----
        node_map: Dict[str, Dict[str, Any]] = {}

        for n in nodes:
            nid = n.get("id")
            if not nid:
                continue

            kinds = n.get("kinds") or []
            props = n.get("properties") or {}

            if nid not in node_map:
                node_map[nid] = {"id": nid, "kinds": list(kinds), "properties": dict(props)}
            else:
                # Merge kinds
                existing_kinds = set(node_map[nid].get("kinds") or [])
                existing_kinds.update(kinds)
                node_map[nid]["kinds"] = sorted(existing_kinds)

                # Merge properties (new overwrites old)
                existing_props = node_map[nid].get("properties") or {}
                existing_props.update(props)
                node_map[nid]["properties"] = existing_props

        norm_nodes: List[Dict[str, Any]] = []
        for nid, n in node_map.items():
            out = {"id": n["id"], "kinds": n.get("kinds") or []}
            if n.get("properties"):
                out["properties"] = n["properties"]
            norm_nodes.append(out)

        # ----
        # 2) Normalize edges (omit null properties)
        #    Also dedupe identical edges
        # ----
        def edge_key(e: Dict[str, Any]) -> Tuple[str, str, str]:
            return (
                e.get("kind") or "",
                (e.get("start") or {}).get("value") or "",
                (e.get("end") or {}).get("value") or "",
            )

        seen_edges = set()
        norm_edges: List[Dict[str, Any]] = []

        for e in edges:
            k = e.get("kind")
            s = e.get("start")
            t = e.get("end")
            if not (k and s and t):
                continue

            key = edge_key(e)
            if key in seen_edges:
                continue
            seen_edges.add(key)

            out = {"kind": k, "start": s, "end": t}
            if e.get("properties"):
                out["properties"] = e["properties"]
            norm_edges.append(out)

        # ----
        # 3) Sanity check: dangling edges
        # ----
        node_ids = set(node_map.keys())
        dangling = []
        for e in norm_edges:
            s_id = e["start"]["value"]
            t_id = e["end"]["value"]
            if s_id not in node_ids or t_id not in node_ids:
                dangling.append((e["kind"], s_id, t_id))

        if dangling:
            print(f"[!] Warning: {len(dangling)} dangling edges (start/end node missing). First 20:")
            for kind, s_id, t_id in dangling[:20]:
                print(f"    {kind}: {s_id} -> {t_id}")

        # ----
        # 4) Print per-kind node counts (BloodHound-style summary)
        # ----
        KIND_LABELS = {
            "SFOrganization":      "organizations",
            "SFUser":              "users",
            "SFProfile":          "profiles",
            "SFPermissionSet":    "permission sets",
            "SFPermissionSetGroup": "permission set groups",
            "SFRole":             "roles",
            "SFGroup":            "groups",
            "SFPublicGroup":      "public groups",
            "SFQueue":            "queues",
            "SFConnectedApp":     "connected apps",
            "SFSObject":          "objects",
            "SFField":            "fields",
        }

        kind_counts: Dict[str, int] = {}
        for n in norm_nodes:
            kinds = n.get("kinds") or []
            # Use first SF* kind found, falling back to the first kind
            primary = next((k for k in kinds if k.startswith("SF")), kinds[0] if kinds else "Unknown")
            kind_counts[primary] = kind_counts.get(primary, 0) + 1

        # Print in a consistent order: known kinds first (in definition order), then any extras
        printed = set()
        for kind in KIND_LABELS:
            if kind in kind_counts:
                label = KIND_LABELS[kind]
                print(f"[+] Found {kind_counts[kind]} {label}")
                printed.add(kind)
        for kind, count in sorted(kind_counts.items()):
            if kind not in printed:
                print(f"[+] Found {count} {kind}")

        # ----
        # 5) Emit OpenGraph payload
        # ----
        opengraph = {"graph": {"nodes": norm_nodes, "edges": norm_edges}}

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(opengraph, f, indent=2, ensure_ascii=False)