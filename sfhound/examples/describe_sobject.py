import argparse
import json
from extractor.sf_client import SalesforceClient

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--sobject", required=True)
    ap.add_argument("--tooling", action="store_true", help="Use Tooling API describe endpoint")
    args = ap.parse_args()

    sf = SalesforceClient(args.config)
    sf.authenticate()

    # IMPORTANT: SalesforceClient.get() in your repo expects "short" paths like:
    #   /sobjects/<SObject>/describe
    # and prefixes /services/data/<api_version> internally.
    if args.tooling:
        path = f"/tooling/sobjects/{args.sobject}/describe"
    else:
        path = f"/sobjects/{args.sobject}/describe"

    desc = sf.get(path)

    fields = desc.get("fields", [])
    out = {
        "name": desc.get("name"),
        "label": desc.get("label"),
        "queryable": desc.get("queryable"),
        "field_count": len(fields),
        "fields": [
            {
                "name": f.get("name"),
                "type": f.get("type"),
                "relationshipName": f.get("relationshipName"),
                "referenceTo": f.get("referenceTo"),
                "queryable": f.get("queryable"),
                "filterable": f.get("filterable"),
                "createable": f.get("createable"),
                "updateable": f.get("updateable"),
            }
            for f in fields
        ],
    }

    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()