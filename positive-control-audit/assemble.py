#!/usr/bin/env python3
"""
Assemble a harness file = [verbatim secure block] + [generated tail].

Keeping the guard verbatim (heavy imports intact, neutralized by the runner's import stubber)
is what makes the harness FAITHFUL to the shipped code. The generator (hand or delegated)
produces only the TAIL: META, call_guard, fired, ATTACK, BENIGN (+ optional benign_marker,
dangerous_token). This module just concatenates and does a syntax check.
"""
import json, re, sys, ast, os

AIML = os.environ.get("SECURECODE_AIML", "data/aiml/train.jsonl")  # dataset aiml split


def load_example(id_):
    with open(AIML) as f:
        for line in f:
            if not line.strip():
                continue
            ex = json.loads(line)
            if ex["id"] == id_:
                return ex
    raise KeyError(id_)


def secure_block(ex):
    import importlib.util, os
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("extract", os.path.join(here, "extract.py"))
    extract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(extract)
    return extract.extract_packet(ex)["secure_code"]


def definitions_only(code):
    """Return the secure block truncated at the end of its LAST top-level class/function.

    46% of secure blocks append module-level demo/usage code (not under `if __name__`) that
    executes on import - e.g. `results = processor.wait_and_retrieve(id)` calling time.sleep(10),
    which hangs the harness. Definitions and preceding config (logger, constants, app=Flask()) come
    before the last def; trailing demo code comes after it. Keeping original source lines (not
    ast.unparse) preserves the guard verbatim. Raises SyntaxError if the block does not parse
    (counted honestly as non-executable-unparseable, not silently dropped)."""
    tree = ast.parse(code)                      # raises SyntaxError on genuinely broken blocks
    lines = code.split("\n")
    last_end = 0
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            last_end = max(last_end, getattr(node, "end_lineno", node.lineno) or node.lineno)
    if last_end == 0:
        return code                              # no defs (triage should have excluded this)
    return "\n".join(lines[:last_end])


def assemble(id_, tail, out_path, secure_override=None):
    if secure_override is not None:
        sec = secure_override
    else:
        sec = secure_block(load_example(id_))
    sec = definitions_only(sec)                  # strip trailing demo/exec code
    body = ("# ===== secure block from dataset, truncated to definitions (heavy imports "
            "neutralized by runner import-stubber) =====\n"
            + sec.rstrip() + "\n\n"
            "# ===== harness tail (guard invocation + fire predicate + paired inputs) =====\n"
            + tail.strip() + "\n")
    # syntax check before writing
    ast.parse(body)
    with open(out_path, "w") as f:
        f.write(body)
    return out_path


if __name__ == "__main__":
    # smoke: python3 assemble.py <id>  -> print secure block length
    ex = load_example(sys.argv[1])
    print(sys.argv[1], "secure block loc:", len(secure_block(ex).splitlines()))
