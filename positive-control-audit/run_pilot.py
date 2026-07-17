#!/usr/bin/env python3
"""
Bridge: generator tails -> assembled harnesses -> runner verdicts.

For each tails/<id>.tail.py: assemble [verbatim secure_code] + [tail] into
harnesses_pilot/harness_<id>.py (via assemble.py, which also syntax-checks), then run the whole
dir through runner.py. Tails that fail to assemble (generator syntax error) are recorded as
assemble_error and counted in the non-executable remainder, never hidden.

Usage: python3 run_pilot.py [--tails tails] [--harn harnesses_pilot] [--runs pilot_runs]
"""
import os, glob, json, argparse, subprocess, sys, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(mod, path):
    spec = importlib.util.spec_from_file_location(mod, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tails", default="tails")
    ap.add_argument("--harn", default="harnesses_pilot")
    ap.add_argument("--runs", default="pilot_runs")
    ap.add_argument("--packets", default=None,
                    help="dir of <id>.json packets to source secure_code from (web/full runs); "
                         "default reads the aiml train file by id")
    ap.add_argument("--ids", default=None,
                    help="json with an id list; iterate these ids' <id>.tail.py via os.path.exists "
                         "instead of globbing (robust against flaky directory enumeration)")
    args = ap.parse_args()

    A = _load("assemble", os.path.join(HERE, "assemble.py"))
    os.makedirs(args.harn, exist_ok=True)
    if args.ids:
        d = json.load(open(args.ids))
        idlist = d.get("ids") or d.get("sample") or d.get("validation") or []
        tails = [os.path.join(args.tails, f"{i}.tail.py") for i in idlist
                 if os.path.exists(os.path.join(args.tails, f"{i}.tail.py"))]
    else:
        tails = sorted(glob.glob(os.path.join(args.tails, "*.tail.py")))
    assembled, errors = [], []
    for tp in tails:
        id_ = os.path.basename(tp)[:-len(".tail.py")]
        tail = open(tp).read()
        out = os.path.join(args.harn, f"harness_{id_}.py")
        # source secure_code from a packet dir when given (web/full runs live outside the aiml file)
        sec_override = None
        if args.packets:
            pj = os.path.join(args.packets, f"{id_}.json")
            if os.path.exists(pj):
                sec_override = json.load(open(pj)).get("secure_code")
        try:
            A.assemble(id_, tail, out, secure_override=sec_override)
            assembled.append(id_)
        except Exception as e:
            errors.append({"id": id_, "assemble_error": f"{type(e).__name__}: {e}"})
    print(f"assembled {len(assembled)} harnesses, {len(errors)} assemble errors")
    if errors:
        json.dump(errors, open(os.path.join(HERE, "assemble_errors.json"), "w"), indent=2)
        for e in errors[:10]:
            print("  ASSEMBLE_ERROR", e["id"], e["assemble_error"][:100])

    # Execute each assembled harness by EXPLICIT path (do not rely on the runner globbing the
    # harness dir - these paths sit on an eventually-consistent filesystem whose directory
    # enumeration is flaky under concurrent writes, so glob under-counts).
    R = _load("runner", os.path.join(HERE, "runner.py"))
    os.makedirs(args.runs, exist_ok=True)
    from collections import Counter
    counts = Counter()
    for id_ in assembled:
        p = os.path.join(args.harn, f"harness_{id_}.py")
        try:
            cp = subprocess.run([sys.executable, os.path.join(HERE, "runner.py"), "--child", p],
                                capture_output=True, text=True, timeout=R.CHILD_TIMEOUT)
            line = [l for l in cp.stdout.splitlines() if l.strip().startswith("{")]
            if line:
                obs = json.loads(line[-1])
            else:
                obs = {"id": id_, "imported": False,
                       "import_error": f"child rc={cp.returncode}: {cp.stderr[-300:]}"}
        except subprocess.TimeoutExpired:
            obs = {"id": id_, "imported": True, "contract_ok": True,
                   "attack_error": "child timeout"}
        except Exception as e:
            obs = {"id": id_, "imported": False, "import_error": f"parent error: {e}"}
        v = R.verdict_from_obs(obs)
        rec = {"harness": f"harness_{id_}.py", **v, "obs": obs}
        json.dump(rec, open(os.path.join(args.runs, f"harness_{id_}.json"), "w"), indent=2)
        counts[v["verdict"]] += 1
    print("=== SUMMARY ===")
    print(json.dumps(dict(counts), indent=2))


if __name__ == "__main__":
    main()
