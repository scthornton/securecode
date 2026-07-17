#!/usr/bin/env python3
"""
Web re-extraction keyed by ROW INDEX, not id. The web dataset has NON-UNIQUE ids (1,249 rows,
513 unique id strings; same-id rows are genuinely different examples). Keying by id collapsed the
corpus and double-counted in scoring. Here every row gets a unique key `<id>__r<rowidx>` so all
1,249 distinct examples are captured. Outputs webpkt/ packets (python candidates) + triage_webfix.json.
"""
import pandas as pd, json, os
from collections import Counter
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
_s = importlib.util.spec_from_file_location("extract_web", os.path.join(HERE, "extract_web.py"))
ew = importlib.util.module_from_spec(_s); _s.loader.exec_module(ew)
extract = ew.extract

WEB_TRAIN = os.environ.get("SECURECODE_WEB_TRAIN", "data/web/train-00000-of-00001.parquet")


def main():
    df = pd.read_parquet(WEB_TRAIN)
    os.makedirs(os.path.join(HERE, "webpkt"), exist_ok=True)
    buckets = Counter(); reasons = Counter(); rows = []
    py_ids = []
    for rowidx, (_, r) in enumerate(df.iterrows()):
        try:
            ex = ew._row_to_example(r)
            ex["id"] = f"{r['id']}__r{rowidx}"          # UNIQUE key
            p = extract.extract_packet(ex)
        except Exception:
            buckets["parse_error"] += 1
            continue
        bucket, reason = extract.stage1_triage(ex, p)
        buckets[bucket] += 1
        if bucket == "non_exec":
            reasons[reason.split("(")[0].strip()] += 1
        rows.append({"id": ex["id"], "bucket": bucket, "lang": p["lang"],
                     "owasp_web": ex["metadata"].get("owasp_2021")})
        if bucket == "py_candidate":
            packet = {"id": ex["id"], "owasp_web": ex["metadata"].get("owasp_2021"),
                      "cwe": p["cwe"], "vuln_prompt": p["vuln_prompt"],
                      "secure_heavy_imports": p["secure_heavy_imports"],
                      "secure_code": p["secure_code"], "vulnerable_code": p["vulnerable_code"]}
            json.dump(packet, open(os.path.join(HERE, "webpkt", f"{ex['id']}.json"), "w"), indent=2)
            py_ids.append(ex["id"])
    json.dump({"buckets": dict(buckets), "non_exec_reasons": dict(reasons), "rows": rows},
              open(os.path.join(HERE, "triage_webfix.json"), "w"), indent=2)
    json.dump({"ids": py_ids}, open(os.path.join(HERE, "webfix_py_ids.json"), "w"))
    n = len(df)
    print(f"WEB (row-keyed) over {n} DISTINCT examples")
    print(json.dumps(dict(buckets), indent=2))
    print("non_exec reasons:", json.dumps(dict(reasons)))
    print(f"\npython positive-control CANDIDATES: {len(py_ids)} = {len(py_ids)*100//n}% of web")


if __name__ == "__main__":
    main()
