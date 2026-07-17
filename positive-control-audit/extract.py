#!/usr/bin/env python3
"""
Extraction helper for the positive-control harness.

Turns a SecureCode aiml example into a clean "extraction packet": the vulnerable code, the
secure code, the vuln description, and structural signals (language, callable present, heavy
imports). Both the hand-built calibration harnesses and the delegated generator consume the
same packets, so inputs are standardized.

Also does STAGE-1 TRIAGE across all examples: does an example even have an isolable secure
guard (a secure code block in a runnable language that defines a callable)? Stage-1 produces
the executable-CANDIDATE pool; final executability is decided at generation time (a guard may
still be entangled with a live service). Both stages feed the honest denominator.
"""
import json, re, sys, os
from collections import Counter

AIML = os.environ.get("SECURECODE_AIML", "data/aiml/train.jsonl")  # dataset aiml split

SECURE_HEADERS = re.compile(r"(?i)\b(secure|fixed|hardened|remediat|mitigat|safe|patched|"
                            r"corrected|defended?)\b")
VULN_HEADERS = re.compile(r"(?i)\b(vulnerable|insecure|unsafe|bad|flawed|exploit|attack)\b")
TEST_HEADERS = re.compile(r"(?i)\b(test|monitor|detect|verif|validat|audit|logging)\b")

HEAVY = re.compile(r"^\s*(?:import|from)\s+(torch|tensorflow|transformers|langchain|"
                   r"llama_index|llamaindex|boto3|openai|anthropic|sklearn|numpy|pandas|faiss|"
                   r"chromadb|redis|sqlalchemy|flask|fastapi|django|neo4j|pymongo|google\.|"
                   r"googleapiclient|azure|cohere|litellm|httpx|requests|aiohttp)", re.M)

RUNNABLE_LANGS = {"python", "py"}
JS_LANGS = {"javascript", "js", "typescript", "ts", "tsx", "jsx"}


def _load_all():
    out = {}
    with open(AIML) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ex = json.loads(line)
            out[ex["id"]] = ex
    return out


def _code_blocks(text):
    """Return list of (lang, code, label) for each fenced block, label = nearest preceding
    bold/heading line within ~240 chars."""
    blocks = []
    for m in re.finditer(r"```([\w+-]*)\n(.*?)```", text, re.DOTALL):
        lang = (m.group(1) or "").lower()
        code = m.group(2)
        pre = text[max(0, m.start() - 240):m.start()]
        # nearest bold header **...** or markdown heading
        labels = re.findall(r"\*\*(.+?)\*\*\s*:?\s*$|^#{1,4}\s*(.+?)$", pre, re.M)
        label = ""
        for a, b in reversed(labels):
            label = (a or b or "").strip()
            if label:
                break
        blocks.append({"lang": lang, "code": code, "label": label})
    return blocks


def _classify_block(b):
    lab = b["label"]
    # order matters: a "Secure" label wins over generic
    if VULN_HEADERS.search(lab) and not SECURE_HEADERS.search(lab):
        return "vulnerable"
    if SECURE_HEADERS.search(lab):
        return "secure"
    if TEST_HEADERS.search(lab):
        return "test"
    return "other"


def extract_packet(ex):
    """Build an extraction packet for one example dict."""
    md = ex.get("metadata", {})
    assistant_turns = [t["content"] for t in ex["conversations"] if t["role"] == "assistant"]
    human_turns = [t["content"] for t in ex["conversations"] if t["role"] == "human"]
    all_assist = "\n\n".join(assistant_turns)
    blocks = _code_blocks(all_assist)
    for b in blocks:
        b["kind"] = _classify_block(b)

    secure = [b for b in blocks if b["kind"] == "secure"]
    vuln = [b for b in blocks if b["kind"] == "vulnerable"]
    # Heuristic fallback: if no labeled secure block, the LARGEST code block in a runnable
    # language is often the secure implementation (secure blocks are the detailed ones).
    fallback_used = False
    if not secure:
        runnable = [b for b in blocks if b["lang"] in RUNNABLE_LANGS | JS_LANGS]
        if runnable:
            biggest = max(runnable, key=lambda b: len(b["code"]))
            secure = [biggest]
            fallback_used = True

    sec = secure[0] if secure else None
    packet = {
        "id": ex["id"],
        "lang": md.get("lang"),
        "category": md.get("category"),
        "owasp_llm_2025": md.get("owasp_llm_2025"),
        "cwe": md.get("cwe"),
        "technique": md.get("technique"),
        "severity": md.get("severity"),
        "vuln_prompt": human_turns[0][:1200] if human_turns else "",
        "n_blocks": len(blocks),
        "secure_label": sec["label"] if sec else None,
        "secure_lang": sec["lang"] if sec else None,
        "secure_fallback_used": fallback_used,
        "secure_code": sec["code"] if sec else None,
        "vulnerable_code": vuln[0]["code"] if vuln else None,
        "secure_defines_callable": bool(sec and re.search(r"^\s*(def|class|function|const\s+\w+\s*=\s*\()", sec["code"], re.M)),
        "secure_heavy_imports": sorted(set(HEAVY.findall(sec["code"]))) if sec else [],
    }
    return packet


def stage1_triage(ex, packet):
    """Return (bucket, reason). Buckets: py_candidate, js_candidate, non_exec."""
    lang = (packet["lang"] or "").lower()
    sec = packet["secure_code"]
    if not sec:
        return "non_exec", "no secure code block found"
    if not packet["secure_defines_callable"]:
        return "non_exec", "secure block defines no isolable callable (config/prose/pseudocode)"
    slang = (packet["secure_lang"] or "").lower()
    if slang in RUNNABLE_LANGS or lang == "python":
        return "py_candidate", f"python secure guard, heavy_imports={packet['secure_heavy_imports']}"
    if slang in JS_LANGS or lang in ("javascript", "typescript"):
        return "js_candidate", "js/ts secure guard (deferred slice)"
    return "non_exec", f"non-runnable language ({slang or lang})"


def main():
    exs = _load_all()
    if len(sys.argv) > 1 and sys.argv[1] == "--packet":
        ex = exs[sys.argv[2]]
        print(json.dumps(extract_packet(ex), indent=2)[:4000])
        return
    # full triage
    buckets = Counter()
    reasons = Counter()
    rows = []
    for id_, ex in exs.items():
        p = extract_packet(ex)
        bucket, reason = stage1_triage(ex, p)
        buckets[bucket] += 1
        if bucket == "non_exec":
            reasons[reason.split("(")[0].strip()] += 1
        rows.append({"id": id_, "bucket": bucket, "reason": reason,
                     "owasp": p["owasp_llm_2025"], "secure_lang": p["secure_lang"],
                     "heavy": p["secure_heavy_imports"], "fallback": p["secure_fallback_used"]})
    out_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(out_dir, "triage_stage1.json"), "w") as f:
        json.dump({"buckets": dict(buckets), "non_exec_reasons": dict(reasons), "rows": rows}, f, indent=2)
    print("STAGE-1 TRIAGE over", len(exs), "aiml examples")
    print(json.dumps(dict(buckets), indent=2))
    print("\nnon_exec reasons:")
    print(json.dumps(dict(reasons), indent=2))
    # how many py_candidates are heavy-import-free at module top (easiest to isolate)?
    py = [r for r in rows if r["bucket"] == "py_candidate"]
    heavy_free = [r for r in py if not r["heavy"]]
    print(f"\npy_candidates: {len(py)} | of those with NO heavy module-top imports: {len(heavy_free)}")
    by_owasp = Counter(r["owasp"] for r in py)
    print("py_candidates by OWASP:", json.dumps(dict(sorted(by_owasp.items())), indent=0))


if __name__ == "__main__":
    main()
