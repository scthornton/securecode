#!/usr/bin/env python3
"""
Web-config extractor. The web dataset uses the v2.x schema (parquet; conversations stored as a
STRINGIFIED python list of {from, turn, value}), unlike aiml's {role, content} JSONL. This adapts
web rows into the SAME packet format the aiml pipeline consumes, so assemble/generator/runner/score
are unchanged. Only the PYTHON subset is positive-control-runnable in the sandbox; everything else
(js, java, go, ts, php, csharp, ruby, rust, ...) is reported as non-runnable-language, which is the
dominant term in web's non-executable denominator.
"""
import pandas as pd, json, ast, sys, os, re
from collections import Counter

WEB_DIR = os.environ.get("SECURECODE_WEB_DIR", "data/web")  # dataset web parquet dir
HERE = os.path.dirname(os.path.abspath(__file__))
import importlib.util
_spec = importlib.util.spec_from_file_location("extract", os.path.join(HERE, "extract.py"))
extract = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(extract)


def _load_train():
    return pd.read_parquet(os.path.join(WEB_DIR, "train-00000-of-00001.parquet"))


def _row_to_example(r):
    """Convert a web parquet row into an aiml-style example dict {id, metadata, conversations}."""
    md = r["metadata"]
    md = json.loads(md) if isinstance(md, str) else dict(md)
    conv = r["conversations"]
    if isinstance(conv, str):
        conv = ast.literal_eval(conv)
    norm = []
    for t in conv:
        frm = t.get("from", "")
        role = "human" if frm in ("human", "user") else "assistant"
        norm.append({"role": role, "content": t.get("value", "")})
    return {
        "id": r["id"],
        "metadata": {"lang": md.get("language") or md.get("lang"),
                     "category": md.get("category"),
                     "owasp_2021": md.get("owasp_2021") or md.get("category"),
                     "cwe": md.get("cwe")},
        "conversations": norm,
    }


def extract_packet_web(r):
    ex = _row_to_example(r)
    p = extract.extract_packet(ex)
    p["owasp_llm_2025"] = None
    p["owasp_web"] = ex["metadata"].get("owasp_2021")
    return p, ex


def main():
    df = _load_train()
    buckets = Counter(); reasons = Counter(); rows = []
    py_written = 0
    os.makedirs(os.path.join(HERE, "web_packets"), exist_ok=True)
    for _, r in df.iterrows():
        try:
            p, ex = extract_packet_web(r)
        except Exception as e:
            buckets["parse_error"] += 1
            continue
        bucket, reason = extract.stage1_triage(ex, p)
        buckets[bucket] += 1
        if bucket == "non_exec":
            reasons[reason.split("(")[0].strip()] += 1
        rows.append({"id": p["id"], "bucket": bucket, "lang": p["lang"],
                     "owasp_web": p["owasp_web"], "heavy": p["secure_heavy_imports"]})
        if bucket == "py_candidate":
            packet = {"id": p["id"], "owasp_web": p["owasp_web"], "cwe": p["cwe"],
                      "category": p["category"], "vuln_prompt": p["vuln_prompt"],
                      "secure_heavy_imports": p["secure_heavy_imports"],
                      "secure_code": p["secure_code"], "vulnerable_code": p["vulnerable_code"]}
            json.dump(packet, open(os.path.join(HERE, "web_packets", f"{p['id']}.json"), "w"), indent=2)
            py_written += 1
    json.dump({"buckets": dict(buckets), "non_exec_reasons": dict(reasons), "rows": rows},
              open(os.path.join(HERE, "triage_web.json"), "w"), indent=2)
    print("WEB TRIAGE over", len(df), "train examples")
    print(json.dumps(dict(buckets), indent=2))
    print("\nnon_exec reasons:", json.dumps(dict(reasons), indent=2))
    print(f"\npy_candidates written to web_packets/: {py_written}")
    # of ALL web, what fraction is even positive-control-runnable (python candidate)?
    print(f"POSITIVE-CONTROL-RUNNABLE FRACTION (py_candidate / all): {py_written}/{len(df)} = {py_written*100//len(df)}%")


if __name__ == "__main__":
    main()
