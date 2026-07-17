#!/usr/bin/env python3
"""
Positive-Control Recall Runner for SecureCode fix-correctness.

This is the Claude-owned soundness oracle. It does NOT generate harnesses and it
does NOT trust them. Given a directory of harness modules, it executes each one in
an isolated subprocess sandbox and applies soundness gates the harness cannot fake.

WHY THIS EXISTS
  Adversarial review reports precision (what it flagged that held up); it cannot
  estimate its own recall. For every "secure" example that claims a specific vuln
  is gone, we push the paired attack input through the isolated guard and require it
  to FIRE. Fire rate across kept examples is the recall figure we lacked.

  A bare fire rate is itself a precision trap if the harness is broken (the
  torch.allclose-waves-through-buggy-kernels failure). So every fire is gated by:
    (1) NEGATIVE CONTROL   - a benign input must NOT fire (guard is not degenerate).
    (2) KILL MUTATION      - replace the guard with a permissive identity stub and
                             confirm the fire DISAPPEARS. This proves the fire is
                             caused by the guard, and mechanically enforces that the
                             harness routes its decision through call_guard (a harness
                             that hardcodes the guard fails this gate). Generator-
                             independent: the runner supplies the stub, not the harness.
  Every no-fire (a candidate defect) is gated by:
    (3) FORCE MUTATION     - replace the guard with an always-fire stub and confirm the
                             harness CAN report a fire. Proves the no-fire is a real
                             property of the fix, not a harness that never fires.

  The harness FALSE-NEGATIVE RATE = fraction of firing harnesses whose kill mutation
  did NOT flip the fire off. That is the mutation score the HF commenter asked for,
  reported as a first-class number.

HARNESS CONTRACT (a harness is a self-contained python module defining):
  META            dict: {id, fire_signal, guard_symbol, vuln, dangerous_token?, lang, notes?}
                  fire_signal in {raises, returns_false, redacts, sanitizes, filters, blocks}
  call_guard(payload) -> result   invoke the isolated secure guard; may raise. The runner
                  monkeypatches THIS module-global for mutation, so fired() MUST call the
                  module-global call_guard, never a captured local reference.
  fired(payload) -> bool          True iff the guard FIRED on payload. MUST obtain its
                  answer by calling call_guard(payload). Convention: returns True only on an
                  ACTIVE fire indicator (guard raised / returned falsy / removed the dangerous
                  token / changed the dangerous substring / dropped the forbidden item /
                  returned a blocked marker); False otherwise.
  ATTACK          the payload the stated vuln says MUST fire the guard.
  BENIGN          a payload that MUST NOT fire the guard.
  permissive_guard(payload)  (optional) generator-provided neutered guard for a secondary
                  kill-mutation cross-check.
  strict_guard(payload)      (optional) generator-provided always-fire guard for a secondary
                  force-mutation cross-check (useful when the signal-typed stub is ambiguous,
                  e.g. 'blocks' with a custom sentinel).

Usage:
  python3 runner.py --child <harness.py>      # execute one harness, print observations JSON
  python3 runner.py --batch <dir> [--out runs/]   # run every harness_*.py, write verdicts
"""
import sys, os, json, argparse, subprocess, glob, traceback, textwrap
# Imported at module top so they load BEFORE any sandbox hardening touches socket/ssl.
import importlib.abc, importlib.machinery, importlib.util
from unittest.mock import MagicMock

VALID_SIGNALS = {"raises", "returns_false", "redacts", "sanitizes", "filters", "blocks"}
CHILD_TIMEOUT = 25          # wall-clock seconds per harness (parent-enforced)

# ---------------------------------------------------------------------------
# CHILD SIDE: execute one harness under sandbox, emit raw observations as JSON.
# The child never decides pass/fail; it only reports what happened.
# ---------------------------------------------------------------------------
# Service / framework / heavy-ML libraries: always stubbed with a recursive Mock so a verbatim
# guard IMPORTS cleanly with no network, no credentials, no GPU. A guard whose FIRE decision
# routes through one of these gets a Mock result and will fail the soundness gates (correctly
# marking it non-isolable / service-dependent). Computational libraries (numpy, sklearn,
# cryptography, jsonschema, bleach, jwt, bcrypt, defusedxml, lxml, ...) are NOT listed here and
# import for real, so guards that actually compute on them run faithfully.
_STUB_TOP = {
    "boto3", "botocore", "openai", "anthropic", "requests", "httpx", "urllib3", "aiohttp",
    "google", "googleapiclient", "google_auth", "neo4j", "flask", "fastapi", "starlette",
    "uvicorn", "django", "litellm", "cohere", "redis", "pymongo", "sqlalchemy", "psycopg2",
    "kafka", "confluent_kafka", "celery", "langchain", "langchain_core", "langchain_community",
    "llama_index", "llamaindex", "transformers", "torch", "tensorflow", "faiss", "chromadb",
    "pinecone", "weaviate", "qdrant_client", "elasticsearch", "pika", "paho", "azure",
    "google.cloud", "google.oauth2", "slack_sdk", "twilio", "stripe", "sendgrid",
    # ML/NLP libs that are heavy, absent, or installed-but-broken in this env (their import
    # can raise TypeError/metaclass errors, not just ModuleNotFoundError). Guards that need them
    # computationally become non-isolable and fail the soundness gates; guards that only touch
    # them at the periphery (the common case) run their pure-Python fire path fine once stubbed.
    "sentence_transformers", "spacy", "gensim", "nltk", "tokenizers", "huggingface_hub",
    "datasets", "accelerate", "keras", "onnx", "onnxruntime", "presidio_analyzer",
    "presidio_anonymizer", "detoxify", "guardrails", "nemoguardrails", "mistralai", "cohere",
    "groq", "together", "replicate", "ollama", "vertexai", "langchain_openai", "langchain_anthropic",
}


def _install_import_stubs():
    """Insert a meta-path finder that returns recursive Mock modules for service/framework libs
    and for anything that would otherwise raise ImportError. Faithful: guard code is unchanged;
    only its external dependencies are neutralized."""

    class _StubLoader(importlib.abc.Loader):
        def create_module(self, spec):
            m = MagicMock(name=spec.name)
            m.__name__ = spec.name
            m.__spec__ = spec
            m.__path__ = []          # mark as package so submodule imports resolve here too
            m.__all__ = []
            return m
        def exec_module(self, module):
            pass

    class _StubFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            top = name.split(".")[0]
            if top in _STUB_TOP or name in _STUB_TOP:
                return importlib.machinery.ModuleSpec(name, _StubLoader())
            return None

    # Fallback: catch ImportError for absent libs by wrapping __import__.
    import builtins
    _real_import = builtins.__import__
    stub_finder = _StubFinder()

    def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
        try:
            return _real_import(name, globals, locals, fromlist, level)
        except ModuleNotFoundError:
            # synthesize a stub module tree for the missing name
            spec = importlib.machinery.ModuleSpec(name, _StubLoader())
            mod = importlib.util.module_from_spec(spec)
            sys.modules.setdefault(name, mod)
            return mod

    sys.meta_path.insert(0, stub_finder)
    builtins.__import__ = _safe_import


def _harden_sandbox():
    """Best-effort process hardening. Guards are string processors after import
    stripping, so this is defense in depth, not the primary safety boundary."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (12, 12))          # CPU seconds
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024,) * 2)  # 16MB file writes
        except Exception:
            pass
    except Exception:
        pass
    # Block network egress at the connection entry points. Patch only module-level functions
    # (safe to replace); do NOT replace the socket.socket CLASS, which ssl/asyncio subclass.
    # Primary network safety comes from stubbing every service lib to a Mock anyway.
    try:
        import socket
        def _blocked(*a, **k):
            raise OSError("network disabled in positive-control sandbox")
        socket.create_connection = _blocked
        socket.getaddrinfo = _blocked
    except Exception:
        pass
    # Neutralize time.sleep so any demo call that survives definition-truncation cannot stall
    # the harness (a guard's real logic never depends on wall-clock sleeping).
    try:
        import time as _t
        _t.sleep = lambda *a, **k: None
    except Exception:
        pass
    # Wall-clock backstop inside the child (parent also enforces a timeout).
    try:
        import signal as _sig
        def _timeout(signum, frame):
            raise TimeoutError("harness wall-clock exceeded")
        _sig.signal(_sig.SIGALRM, _timeout)
        _sig.alarm(CHILD_TIMEOUT - 3)
    except Exception:
        pass


def _identity_stub(payload):
    """Permissive kill mutation: the null-security action for every signal type.
    Under this stub a sound harness must report NO fire on the attack."""
    return payload


def _force_stub(signal):
    """Always-fire mutation: the maximal-security action, used to prove a harness
    CAN observe a fire. Returns None when the signal type makes a generic stub
    ambiguous (then the parent falls back to generator strict_guard / manual review)."""
    if signal == "raises":
        def s(*a, **k):
            raise RuntimeError("forced-fire")
        return s
    if signal in ("returns_false",):
        return lambda *a, **k: False            # falsy => denied
    if signal in ("redacts", "sanitizes"):
        return lambda *a, **k: ""               # empty output: token/ substring gone
    if signal in ("filters",):
        return lambda *a, **k: []               # empty collection: forbidden item gone
    return None                                  # 'blocks' custom sentinels: ambiguous


def _call_fired(mod, payload):
    """Call mod.fired(payload) and coerce to bool, capturing any exception."""
    try:
        return bool(mod.fired(payload)), None
    except Exception:
        return None, traceback.format_exc(limit=4)


TRANSFORM_SIGNALS = {"redacts", "sanitizes", "filters"}


def _as_text(x):
    """Coerce any guard output to a searchable text form (handles dict/list/tuple outputs from
    parse-then-sanitize guards, not just str->str redactors)."""
    if isinstance(x, str):
        return x
    try:
        return json.dumps(x, default=str, ensure_ascii=False)
    except Exception:
        return str(x)


def _benign_blocks(mod, signal):
    """Signal-aware negative control: does the guard over-fire on a benign input?
    For transformation guards (redacts/sanitizes/filters), fired(BENIGN) is vacuously False
    (benign lacks the dangerous token). The right test is that the guard PRESERVES benign
    content: META['benign_marker'] (a substring of BENIGN a correct guard must keep) must
    survive in the output. This is type-agnostic, so it works for guards that parse str->dict.
    Fallback when no benign_marker is declared: over-fire = guard altered clean input.
    For raise/return_false/block guards, fired(BENIGN) is the right observable (benign blocked)."""
    try:
        if signal in TRANSFORM_SIGNALS:
            out = mod.call_guard(mod.BENIGN)
            marker = getattr(mod, "META", {}).get("benign_marker")
            if marker is not None:
                # over-fire iff the guard REMOVED the benign marker it should have preserved
                return (str(marker) not in _as_text(out)), None
            try:
                return bool(out != mod.BENIGN), None
            except Exception:
                return bool(repr(out) != repr(mod.BENIGN)), None
        return _call_fired(mod, mod.BENIGN)
    except Exception:
        return None, traceback.format_exc(limit=4)


def _soften_runtime():
    """Neutralize benign module-level side effects in secure blocks so a guard whose FILE can be
    imported is not lost to incidental setup code (env-var reads, file handlers, mkdir). This
    RECOVERS executable examples that would otherwise crash at import - it does not touch guard
    logic. A guard that still needs a real service stays non-executable via the import stubber."""
    import os as _os, logging as _log
    # Missing env vars return a stub instead of raising KeyError (e.g. stripe.api_key =
    # os.environ['STRIPE_SECRET_KEY'] at module top, with stripe already stubbed to a Mock).
    class _Env(dict):
        def __missing__(self, k):
            return "sandbox-stub-value"
    try:
        _os.environ = _Env(dict(_os.environ))
    except Exception:
        pass
    # File-based logging handlers become no-op NullHandlers (avoid FileHandler('/var/log/...')).
    try:
        _log.FileHandler = lambda *a, **k: _log.NullHandler()
        import logging.handlers as _lh
        for _h in ("RotatingFileHandler", "TimedRotatingFileHandler", "WatchedFileHandler"):
            try:
                setattr(_lh, _h, lambda *a, **k: _log.NullHandler())
            except Exception:
                pass
    except Exception:
        pass
    # Directory creation swallows failures (mkdir('/data/...') on a read-only sandbox FS).
    _omk, _omd = _os.mkdir, _os.makedirs
    def _safe_mkdir(*a, **k):
        try:
            return _omk(*a, **k)
        except Exception:
            return None
    def _safe_makedirs(*a, **k):
        try:
            return _omd(*a, **k)
        except Exception:
            return None
    _os.mkdir, _os.makedirs = _safe_mkdir, _safe_makedirs


def run_child(path):
    _harden_sandbox()
    _install_import_stubs()
    _soften_runtime()
    obs = {
        "harness_path": path, "id": None, "imported": False, "import_error": None,
        "contract_ok": False, "contract_error": None, "fire_signal": None,
        "fires_on_attack": None, "attack_error": None,
        "fires_on_benign": None, "benign_error": None,
        "benign_blocks": None, "benign_blocks_error": None,
        "kill_mut_fires_on_attack": None, "kill_mut_error": None,
        "force_mut_applicable": False, "force_mut_source": None,
        "force_mut_fires_on_attack": None, "force_mut_error": None,
        "sec_kill_fires_on_attack": None, "sec_force_fires_on_attack": None,
    }
    # ---- import ----
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("pch_harness", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        obs["imported"] = True
    except Exception:
        obs["import_error"] = traceback.format_exc(limit=6)
        return obs
    # ---- contract check ----
    try:
        meta = getattr(mod, "META")
        obs["id"] = meta.get("id")
        sig = meta.get("fire_signal")
        obs["fire_signal"] = sig
        assert sig in VALID_SIGNALS, f"bad fire_signal {sig!r}"
        for attr in ("call_guard", "fired", "ATTACK", "BENIGN"):
            assert hasattr(mod, attr), f"missing {attr}"
        assert callable(mod.call_guard) and callable(mod.fired)
        obs["contract_ok"] = True
    except Exception:
        obs["contract_error"] = traceback.format_exc(limit=4)
        return obs

    orig_guard = mod.call_guard
    # ---- baseline: attack + benign ----
    obs["fires_on_attack"], obs["attack_error"] = _call_fired(mod, mod.ATTACK)
    obs["fires_on_benign"], obs["benign_error"] = _call_fired(mod, mod.BENIGN)
    # ---- signal-aware negative control (non-vacuous for transformation guards) ----
    obs["benign_blocks"], obs["benign_blocks_error"] = _benign_blocks(mod, obs["fire_signal"])

    # ---- KILL mutation (universal identity): fire must disappear ----
    try:
        mod.call_guard = _identity_stub
        obs["kill_mut_fires_on_attack"], obs["kill_mut_error"] = _call_fired(mod, mod.ATTACK)
    finally:
        mod.call_guard = orig_guard
    # secondary kill via generator permissive_guard, if provided
    if hasattr(mod, "permissive_guard") and callable(mod.permissive_guard):
        try:
            mod.call_guard = mod.permissive_guard
            r, _ = _call_fired(mod, mod.ATTACK)
            obs["sec_kill_fires_on_attack"] = r
        finally:
            mod.call_guard = orig_guard

    # ---- FORCE mutation (always-fire): harness must be able to report a fire ----
    fstub = _force_stub(obs["fire_signal"])
    if fstub is not None:
        obs["force_mut_applicable"] = True
        obs["force_mut_source"] = "signal_stub"
        try:
            mod.call_guard = fstub
            obs["force_mut_fires_on_attack"], obs["force_mut_error"] = _call_fired(mod, mod.ATTACK)
        finally:
            mod.call_guard = orig_guard
    if hasattr(mod, "strict_guard") and callable(mod.strict_guard):
        try:
            mod.call_guard = mod.strict_guard
            r, _ = _call_fired(mod, mod.ATTACK)
            obs["sec_force_fires_on_attack"] = r
            if not obs["force_mut_applicable"]:
                obs["force_mut_applicable"] = True
                obs["force_mut_source"] = "generator_strict"
                obs["force_mut_fires_on_attack"] = r
        finally:
            mod.call_guard = orig_guard
    return obs


# ---------------------------------------------------------------------------
# PARENT SIDE: spawn a child per harness, collect observations, apply verdict.
# ---------------------------------------------------------------------------
def verdict_from_obs(o):
    """Map raw observations to a verdict + soundness flags. Pure function of o."""
    v = {"id": o.get("id"), "fire_signal": o.get("fire_signal"), "verdict": None,
         "negative_control_ok": None, "kill_mutation_ok": None,
         "force_mutation_ok": None, "reason": None}

    if not o.get("imported"):
        v["verdict"] = "NON_EXECUTABLE"
        v["reason"] = "import_failed (missing dep / not isolable)"
        return v
    if not o.get("contract_ok"):
        v["verdict"] = "HARNESS_ERROR"
        v["reason"] = "contract_violation: " + (o.get("contract_error") or "")[:200]
        return v
    if o.get("attack_error"):
        v["verdict"] = "HARNESS_ERROR"
        v["reason"] = "fired(ATTACK) raised: " + (o.get("attack_error") or "")[:200]
        return v

    fa = o.get("fires_on_attack")
    # Signal-aware negative control: benign must not trigger the guard's blocking action.
    # (Raw fires_on_benign is retained in obs for transparency but is vacuous for
    # transformation guards, so the verdict keys off benign_blocks.)
    neg_ok = (o.get("benign_blocks") is False)
    v["negative_control_ok"] = neg_ok

    if fa is True:
        # Fire observed. It only counts if it is caused by the guard and the guard
        # discriminates. kill mutation must flip it off; benign must not fire.
        kill_ok = (o.get("kill_mut_fires_on_attack") is False)
        v["kill_mutation_ok"] = kill_ok
        if kill_ok and neg_ok:
            v["verdict"] = "FIRES_SOUND"
            v["reason"] = "attack fires; benign does not; kill mutation removes the fire"
        else:
            v["verdict"] = "FIRES_UNSOUND"
            bad = []
            if not kill_ok: bad.append("kill mutation did not remove fire (fire not gated on guard)")
            if not neg_ok: bad.append("benign also fires (degenerate/over-firing guard)")
            v["reason"] = "; ".join(bad)
        return v

    if fa is False:
        # No fire = candidate defect. Prove the harness CAN report a fire.
        force_applicable = o.get("force_mut_applicable")
        force_fire = o.get("force_mut_fires_on_attack")
        sec_force = o.get("sec_force_fires_on_attack")
        force_ok = (force_fire is True) or (sec_force is True)
        v["force_mutation_ok"] = force_ok if force_applicable or sec_force is not None else None
        if force_ok and neg_ok:
            v["verdict"] = "NO_FIRE_SOUND"
            v["reason"] = "attack does NOT fire; harness proven fire-capable; benign clean -> DEFECT CANDIDATE"
        elif not neg_ok:
            v["verdict"] = "HARNESS_ERROR"
            v["reason"] = "benign fires but attack does not: inverted/degenerate harness"
        else:
            v["verdict"] = "NO_FIRE_CAP_UNVERIFIED"
            v["reason"] = "attack does not fire; could not auto-prove fire-capability -> manual adjudication"
        return v

    # fa is None -> fired(ATTACK) returned non-bool or unknown
    v["verdict"] = "HARNESS_ERROR"
    v["reason"] = "fired(ATTACK) did not return a bool"
    return v


def run_batch(harness_dir, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    paths = sorted(glob.glob(os.path.join(harness_dir, "harness_*.py")))
    results = []
    self_path = os.path.abspath(__file__)
    for p in paths:
        try:
            cp = subprocess.run(
                [sys.executable, self_path, "--child", p],
                capture_output=True, text=True, timeout=CHILD_TIMEOUT,
            )
            if cp.returncode != 0 and not cp.stdout.strip():
                obs = {"id": os.path.basename(p), "imported": False,
                       "import_error": f"child crashed rc={cp.returncode}: {cp.stderr[-400:]}"}
            else:
                # last line of stdout is the JSON blob
                line = [l for l in cp.stdout.splitlines() if l.strip().startswith("{")][-1]
                obs = json.loads(line)
        except subprocess.TimeoutExpired:
            obs = {"id": os.path.basename(p), "imported": True, "contract_ok": True,
                   "attack_error": "child timeout (possible infinite loop / heavy dep)"}
        except Exception as e:
            obs = {"id": os.path.basename(p), "imported": False,
                   "import_error": f"parent error: {e}"}
        v = verdict_from_obs(obs)
        rec = {"harness": os.path.basename(p), **v, "obs": obs}
        results.append(rec)
        with open(os.path.join(out_dir, os.path.basename(p).replace(".py", ".json")), "w") as f:
            json.dump(rec, f, indent=2)
        print(f"{v['verdict']:22} {v.get('id') or os.path.basename(p)}")
    # summary
    from collections import Counter
    counts = Counter(r["verdict"] for r in results)
    summary = {"total": len(results), "by_verdict": dict(counts)}
    with open(os.path.join(out_dir, "_summary.json"), "w") as f:
        json.dump({"summary": summary, "results": results}, f, indent=2)
    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--child", help="execute one harness and print observations JSON")
    ap.add_argument("--batch", help="directory of harness_*.py to run")
    ap.add_argument("--out", default=None, help="output dir for --batch verdicts")
    args = ap.parse_args()
    if args.child:
        obs = run_child(args.child)
        print(json.dumps(obs))
    elif args.batch:
        out = args.out or os.path.join(os.path.dirname(os.path.abspath(args.batch.rstrip("/"))), "runs")
        run_batch(args.batch, out)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
