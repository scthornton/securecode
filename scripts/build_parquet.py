#!/usr/bin/env python3
"""
Rebuild the parquet files that back the HF dataset viewer / load_dataset for
scthornton/securecode (unified). Run after editing any data/*/train.jsonl.

    python scripts/build_parquet.py

Why parquet: the JSONL sources contain heterogeneous field types across rows
(e.g. security_assertions is [] in some rows and a struct in others), which
crashes Arrow's JSON type inference (and the HF datasets-server, so the viewer
goes dark). Parquet carries an explicit schema, so the viewer loads reliably.
The web and aiml configs are written under ONE shared schema so the `default`
config (their concatenation) also loads.

Type normalization is defined in scripts/normalize_types.py and only touches
field TYPES, never example content, counts, or wording.
"""
import json
import os
import sys

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize_types import normalize_example  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return [normalize_example(json.loads(line)) for line in f if line.strip()]


def main():
    web = load("data/web/train.jsonl")
    aiml = load("data/aiml/train.jsonl")

    # One shared schema across both configs so `default` (web + aiml) loads too.
    shared = pa.Table.from_pylist(web + aiml).schema
    pq.write_table(pa.Table.from_pylist(web, schema=shared),
                   os.path.join(ROOT, "data/web/train.parquet"))
    pq.write_table(pa.Table.from_pylist(aiml, schema=shared),
                   os.path.join(ROOT, "data/aiml/train.parquet"))
    print(f"wrote data/web/train.parquet   ({len(web)} rows)")
    print(f"wrote data/aiml/train.parquet  ({len(aiml)} rows)")

    # Fail loudly if the result would not load (self-check).
    from datasets import load_dataset
    for cfg, files, n in [
        ("web", "data/web/train.parquet", len(web)),
        ("aiml", "data/aiml/train.parquet", len(aiml)),
        ("default", ["data/web/train.parquet", "data/aiml/train.parquet"], len(web) + len(aiml)),
    ]:
        paths = [os.path.join(ROOT, f) for f in ([files] if isinstance(files, str) else files)]
        ds = load_dataset("parquet", data_files=paths, split="train", download_mode="force_redownload")
        assert ds.num_rows == n, f"{cfg}: expected {n}, got {ds.num_rows}"
    print("self-check: all configs load (web, aiml, default)")


if __name__ == "__main__":
    main()
