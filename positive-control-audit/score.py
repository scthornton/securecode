#!/usr/bin/env python3
"""
Aggregate positive-control runs into the three honest headline numbers + denominator.

  1. FIRE RATE (recall proxy) = FIRES_SOUND / (FIRES_SOUND + NO_FIRE_SOUND + NO_FIRE_CAP_UNVERIFIED)
     over the SOUND executable subset. FIRES_UNSOUND is excluded (harness problem, not a fix result).
  2. NEGATIVE-CONTROL PASS RATE over all harnesses that ran.
  3. HARNESS FALSE-NEGATIVE RATE = FIRES_UNSOUND / (FIRES_SOUND + FIRES_UNSOUND): fraction of "fires"
     whose kill mutation did not flip them off (the oracle's own mutation score).

Honest denominator: executable subset (a sound harness ran) vs non-executable remainder
(generator marked it non_executable, or the harness errored / failed to import), counted separately.

Usage: python3 score.py --ids pilot_sample.json --tails tails --runs pilot_runs
"""
import json, os, glob, argparse, math


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (p, max(0.0, centre - half), min(1.0, centre + half))


def load_ids(path):
    if path and os.path.exists(path):
        d = json.load(open(path))
        return d.get("sample") or d.get("ids") or d.get("validation")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", default=None, help="json with sample/ids/validation list; default=all tails")
    ap.add_argument("--tails", default="tails")
    ap.add_argument("--runs", default="pilot_runs")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    ids = load_ids(args.ids)
    # collect meta decisions. Prefer id-iteration (robust to flaky directory enumeration on
    # eventually-consistent filesystems); fall back to globbing when no id list is given.
    metas = {}
    if ids is not None:
        for i in ids:
            mp = os.path.join(args.tails, f"{i}.meta.json")
            if os.path.exists(mp):
                try:
                    metas[i] = json.load(open(mp))
                except Exception:
                    pass
    else:
        for f in glob.glob(os.path.join(args.tails, "*.meta.json")):
            m = json.load(open(f))
            metas[m["id"]] = m
        ids = sorted(metas.keys())

    # collect run verdicts (keyed by id inside the record)
    runs = {}
    run_files = []
    if ids is not None:
        run_files = [os.path.join(args.runs, f"harness_{i}.json") for i in ids
                     if os.path.exists(os.path.join(args.runs, f"harness_{i}.json"))]
    else:
        run_files = [f for f in glob.glob(os.path.join(args.runs, "*.json"))
                     if os.path.basename(f) != "_summary.json"]
    for f in run_files:
        base = os.path.basename(f)
        r = json.load(open(f))
        rid = r.get("id") or r.get("obs", {}).get("id")
        # import-failure records have id=None (contract never read); recover id from filename
        # harness_<id>.json so runtime NON_EXECUTABLE verdicts are not mis-counted as "not run".
        if not rid and base.startswith("harness_") and base.endswith(".json"):
            rid = base[len("harness_"):-len(".json")]
        if rid:
            runs[rid] = r

    rows = []
    for id_ in ids:
        meta = metas.get(id_)
        raw_decision = (meta or {}).get("decision", "MISSING_META")
        # Derive decision from whether a tail actually exists / ran, not the meta string
        # (one generator wrote its fire_signal into the decision field). A tail that assembled
        # and ran produces a run verdict; treat any id with a run verdict or a tail file as a
        # harness. Only ids with no tail AND meta=non_executable count as generator non_executable.
        tail_exists = os.path.exists(os.path.join(args.tails, f"{id_}.tail.py"))
        if id_ in runs or tail_exists:
            decision = "harness"
        elif raw_decision == "non_executable":
            decision = "non_executable"
        else:
            decision = "MISSING_META"
        verdict = None
        neg_ok = None
        if decision == "harness":
            r = runs.get(id_)
            if r is None:
                verdict = "NOT_RUN"
            else:
                verdict = r["verdict"]
                neg_ok = r.get("negative_control_ok")
        rows.append({"id": id_, "decision": decision, "verdict": verdict,
                     "neg_ok": neg_ok, "fire_signal": (meta or {}).get("fire_signal")})

    # accounting
    def count(pred):
        return sum(1 for r in rows if pred(r))

    fires_sound = count(lambda r: r["verdict"] == "FIRES_SOUND")
    no_fire_sound = count(lambda r: r["verdict"] == "NO_FIRE_SOUND")
    no_fire_cap = count(lambda r: r["verdict"] == "NO_FIRE_CAP_UNVERIFIED")
    fires_unsound = count(lambda r: r["verdict"] == "FIRES_UNSOUND")
    harness_error = count(lambda r: r["verdict"] in ("HARNESS_ERROR", "NOT_RUN"))
    runtime_nonexec = count(lambda r: r["verdict"] == "NON_EXECUTABLE")
    gen_nonexec = count(lambda r: r["decision"] == "non_executable")
    missing_meta = count(lambda r: r["decision"] == "MISSING_META")

    recall_denom = fires_sound + no_fire_sound + no_fire_cap
    executable_subset = recall_denom + fires_unsound
    non_exec_remainder = gen_nonexec + harness_error + runtime_nonexec + missing_meta

    fire_rate, flo, fhi = wilson(fires_sound, recall_denom)
    # negative-control pass rate over harnesses that produced a neg_ok reading
    neg_rows = [r for r in rows if r["neg_ok"] is not None]
    neg_pass = sum(1 for r in neg_rows if r["neg_ok"] is True)
    neg_rate = (neg_pass / len(neg_rows)) if neg_rows else None
    hfn_denom = fires_sound + fires_unsound
    harness_fn = (fires_unsound / hfn_denom) if hfn_denom else None

    summary = {
        "universe": len(rows),
        "denominator": {
            "executable_subset (sound harness ran)": executable_subset,
            "non_executable_remainder": non_exec_remainder,
            "breakdown": {
                "FIRES_SOUND": fires_sound, "NO_FIRE_SOUND": no_fire_sound,
                "NO_FIRE_CAP_UNVERIFIED": no_fire_cap, "FIRES_UNSOUND": fires_unsound,
                "HARNESS_ERROR_or_NOT_RUN": harness_error,
                "runtime_NON_EXECUTABLE": runtime_nonexec,
                "generator_non_executable": gen_nonexec, "missing_meta": missing_meta,
            },
        },
        "headline_numbers": {
            "fire_rate_recall": round(fire_rate, 4),
            "fire_rate_95ci": [round(flo, 4), round(fhi, 4)],
            "fire_rate_fraction": f"{fires_sound}/{recall_denom}",
            "negative_control_pass_rate": round(neg_rate, 4) if neg_rate is not None else None,
            "negative_control_fraction": f"{neg_pass}/{len(neg_rows)}" if neg_rows else None,
            "harness_false_negative_rate": round(harness_fn, 4) if harness_fn is not None else None,
            "harness_fn_fraction": f"{fires_unsound}/{hfn_denom}" if hfn_denom else None,
        },
        "defect_candidates": [r["id"] for r in rows if r["verdict"] in ("NO_FIRE_SOUND", "NO_FIRE_CAP_UNVERIFIED")],
    }
    out = args.out or os.path.join(os.path.dirname(os.path.abspath(args.runs.rstrip("/"))), "pilot_score.json")
    json.dump({"summary": summary, "rows": rows}, open(out, "w"), indent=2)
    print(json.dumps(summary, indent=2))
    print("\nwrote", out)


if __name__ == "__main__":
    main()
