#!/usr/bin/env python3
"""
dump_sobject.py

Dump:
  1) SObject describe metadata (fields + capabilities)
  2) A sample query result for that SObject, selecting as many fields as feasible

Key points:
- Uses Salesforce REST Describe: /services/data/vXX.X/sobjects/<SObject>/describe
- Builds a SELECT list from describe["fields"][].name (NOT a non-existent "queryable" flag)
- Avoids emitting `SELECT  FROM ...` via guards
- Chunks large field lists to avoid URL/SOQL length limits
- Writes a single JSON output file containing describe + sample records + field selection info

Usage:
  python3 -m examples.dump_sobject --config config.yaml --sobject PermissionSet \
    --where "Id = '0PS...'" --limit 1 --out permset.dump.json

Optional flags:
  --max-fields 150        # max fields per query chunk
  --max-soql-len 9000     # safety limit for query string length
  --include-deprecated    # include deprecatedAndHidden fields
  --include-base64        # include base64 fields
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from extractor.sf_client import SalesforceClient


def describe_object(sf: SalesforceClient, sobject: str) -> Dict[str, Any]:
    # IMPORTANT: SalesforceClient.get(...) in your project likely expects a FULL REST path
    # without base URL, e.g. "/services/data/v56.0/..."
    api_ver = sf.api_version  # e.g. "v56.0"
    path = f"/sobjects/{sobject}/describe"
    return sf.get(path)


def pick_selectable_fields(
    desc: Dict[str, Any],
    include_deprecated: bool = False,
    include_base64: bool = False,
) -> List[str]:
    fields: List[str] = []
    for f in desc.get("fields", []):
        name = f.get("name")
        if not name:
            continue

        # Skip deprecated/hidden unless asked
        if not include_deprecated and f.get("deprecatedAndHidden"):
            continue

        ftype = f.get("type")
        # base64 tends to be big + sometimes annoying
        if not include_base64 and ftype in ("base64",):
            continue

        # In practice, most fields are selectable. However, "compound" fields can
        # be tricky (Address/Location). Salesforce often supports selecting the compound
        # name, but if your org rejects it, you'll see INVALID_FIELD and you can
        # exclude those by type here.
        #
        # If you want to be extra conservative, uncomment this:
        # if ftype in ("address", "location"):
        #     continue

        fields.append(name)

    return fields


def build_soql(
    sobject: str,
    fields: List[str],
    where: Optional[str],
    limit: int,
) -> str:
    if not fields:
        raise RuntimeError(f"No fields available to select for SObject: {sobject}")

    select_clause = ", ".join(fields)
    soql = f"SELECT {select_clause} FROM {sobject}"
    if where:
        soql += f" WHERE {where}"
    soql += f" LIMIT {limit}"
    return soql


def chunk_fields_for_limits(
    sobject: str,
    fields: List[str],
    where: Optional[str],
    limit: int,
    max_fields: int,
    max_soql_len: int,
) -> List[List[str]]:
    """
    Chunk fields into groups that stay under max_fields and max_soql_len.
    """
    chunks: List[List[str]] = []
    cur: List[str] = []

    def soql_len_for(candidate_fields: List[str]) -> int:
        return len(build_soql(sobject, candidate_fields, where, limit))

    for f in fields:
        candidate = cur + [f]

        # if candidate breaks either limit, finalize current chunk
        if cur and (len(candidate) > max_fields or soql_len_for(candidate) > max_soql_len):
            chunks.append(cur)
            cur = [f]
        else:
            cur = candidate

    if cur:
        chunks.append(cur)

    return chunks


def merge_records_by_id(
    record_sets: List[Dict[str, Any]],
    id_field: str = "Id",
) -> Dict[str, Dict[str, Any]]:
    """
    Merge multiple query results (each with records[]) into a dict keyed by Id.
    """
    merged: Dict[str, Dict[str, Any]] = {}
    for rs in record_sets:
        for r in rs.get("records", []) or []:
            rid = r.get(id_field)
            if not rid:
                # fallback: merge into a synthetic bucket
                rid = "__no_id__"
            if rid not in merged:
                merged[rid] = {}
            # merge fields (later chunks overwrite earlier if duplicates)
            merged[rid].update(r)
    return merged


def safe_query(sf: SalesforceClient, soql: str) -> Dict[str, Any]:
    """
    Wrap sf.query so we can surface errors with the SOQL that caused it.
    """
    try:
        return sf.query(soql)
    except Exception as e:
        raise RuntimeError(f"SOQL failed:\n{soql}\n\nError:\n{e}") from e


def main() -> None:
    ap = argparse.ArgumentParser(description="Dump Salesforce SObject describe + sample record(s) to JSON.")
    ap.add_argument("--config", required=True, help="Path to config.yaml (Salesforce auth).")
    ap.add_argument("--sobject", required=True, help="SObject API name (e.g., User, PermissionSet).")
    ap.add_argument("--where", default=None, help="Optional WHERE clause (without the 'WHERE').")
    ap.add_argument("--limit", type=int, default=1, help="Number of records to sample per query chunk.")
    ap.add_argument("--out", required=True, help="Output JSON file.")
    ap.add_argument("--max-fields", type=int, default=150, help="Max fields per query chunk.")
    ap.add_argument("--max-soql-len", type=int, default=9000, help="Max SOQL string length per query chunk.")
    ap.add_argument("--include-deprecated", action="store_true", help="Include deprecatedAndHidden fields.")
    ap.add_argument("--include-base64", action="store_true", help="Include base64 fields.")
    ap.add_argument("--debug", action="store_true", help="Print chunk SOQL to stderr.")
    args = ap.parse_args()

    sf = SalesforceClient(args.config)
    sf.authenticate()

    # 1) Describe
    desc = describe_object(sf, args.sobject)

    # 2) Select fields from describe
    fields = pick_selectable_fields(
        desc,
        include_deprecated=args.include_deprecated,
        include_base64=args.include_base64,
    )

    if not fields:
        raise SystemExit(
            f"[!] Describe returned {len(desc.get('fields', []))} fields, "
            f"but none were selectable after filtering. "
            f"Try --include-deprecated/--include-base64 or adjust filters."
        )

    # 3) Chunk fields to avoid SOQL/URL limits
    chunks = chunk_fields_for_limits(
        args.sobject,
        fields,
        args.where,
        args.limit,
        max_fields=args.max_fields,
        max_soql_len=args.max_soql_len,
    )

    # 4) Query sample in chunks
    results: List[Dict[str, Any]] = []
    chunk_info: List[Dict[str, Any]] = []

    for i, chunk_fields in enumerate(chunks, start=1):
        soql = build_soql(args.sobject, chunk_fields, args.where, args.limit)
        if args.debug:
            print(f"[debug] Chunk {i}/{len(chunks)} fields={len(chunk_fields)} soql_len={len(soql)}", file=sys.stderr)
            print(soql, file=sys.stderr)
            print("-" * 80, file=sys.stderr)

        data = safe_query(sf, soql)
        results.append(data)
        chunk_info.append(
            {
                "chunk_index": i,
                "fields": chunk_fields,
                "soql_length": len(soql),
                "records_returned": len(data.get("records", []) or []),
            }
        )

    merged = merge_records_by_id(results, id_field="Id")

    # Preserve ordering of records as they appeared in the first chunk
    ordered_ids: List[str] = []
    first_records = results[0].get("records", []) or []
    for r in first_records:
        rid = r.get("Id")
        if rid and rid in merged and rid not in ordered_ids:
            ordered_ids.append(rid)
    # include any others that showed up only later
    for rid in merged.keys():
        if rid not in ordered_ids:
            ordered_ids.append(rid)

    sample_records = [merged[rid] for rid in ordered_ids]

    out_obj = {
        "sobject": args.sobject,
        "where": args.where,
        "limit": args.limit,
        "describe": desc,
        "field_selection": {
            "total_fields_in_describe": len(desc.get("fields", []) or []),
            "selected_fields": fields,
            "selected_field_count": len(fields),
            "chunk_count": len(chunks),
            "chunks": chunk_info,
            "filters": {
                "include_deprecated": args.include_deprecated,
                "include_base64": args.include_base64,
                "max_fields": args.max_fields,
                "max_soql_len": args.max_soql_len,
            },
        },
        "sample": {
            "total_distinct_records": len(sample_records),
            "records": sample_records,
        },
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"[+] Wrote describe + sample to {args.out}")


if __name__ == "__main__":
    main()