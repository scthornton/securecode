"""
Type-normalization for the SecureCode family so Arrow/parquet (and the HF viewer)
can load the data. This resolves heterogeneous field TYPES only. It does NOT change
example content, counts, wording, or metadata semantics.

Conflicts resolved (all verified by scanning every JSON path):
  1. context.real_world_example : struct vs str  -> always struct (wrap str as {"incident": str})
  2. context.affected_versions  : str vs list     -> always list[str] (wrap str as [str])
  3. context.cvss               : float vs str     -> always str (stringify)
  4. context.references[]        : struct vs bare str -> always struct (wrap str as {"type":"url","url":str})
  5. context.references[].cvss_score : float vs str -> always str
  6. security_assertions         : [] vs struct vs list[struct] -> always a struct with an
                                   `assertions` key = list[{assertion, evidence, severity}]
  7. security_assertions.tooling_signals[].expected : bool vs str
                                   -> the one offending row (spring_boot-rce-000001) gets
                                      expected=true + expected_version=<range>
  8. validation.syntax_check     : bool vs str      -> always str (True->"passed", False->"failed")
"""
import copy

CANONICAL_SA_KEYS = [
    "exploit_scenario", "secure_properties", "negative_properties",
    "tooling_signals", "common_mistakes", "compliance_mappings", "assertions",
]


def _norm_reference(ref):
    if isinstance(ref, str):
        return {"type": "url", "url": ref}
    if isinstance(ref, dict):
        r = dict(ref)
        if "cvss_score" in r and r["cvss_score"] is not None:
            r["cvss_score"] = str(r["cvss_score"])
        return r
    return {"type": "url", "url": str(ref)}


def _norm_security_assertions(sa):
    """Return a struct with the canonical key set. `assertions` holds any list-of-assertion
    objects (from the 3 web list-of-struct rows or from aiml's list[str])."""
    out = {k: None for k in CANONICAL_SA_KEYS}
    if sa is None:
        return out
    if isinstance(sa, dict):
        for k, v in sa.items():
            out[k] = v
        return out
    if isinstance(sa, list):
        assertions = []
        for e in sa:
            if isinstance(e, dict):
                assertions.append({
                    "assertion": e.get("assertion"),
                    "evidence": e.get("evidence"),
                    "severity": e.get("severity"),
                })
            elif isinstance(e, str):
                assertions.append({"assertion": e, "evidence": None, "severity": None})
        out["assertions"] = assertions if assertions else None
        return out
    return out


def normalize_example(o):
    o = copy.deepcopy(o)

    # 8. validation.syntax_check -> str
    val = o.get("validation")
    if isinstance(val, dict) and "syntax_check" in val:
        sc = val["syntax_check"]
        if isinstance(sc, bool):
            val["syntax_check"] = "passed" if sc else "failed"

    ctx = o.get("context")
    if isinstance(ctx, dict):
        # 1. real_world_example -> struct
        rwe = ctx.get("real_world_example")
        if isinstance(rwe, str):
            ctx["real_world_example"] = {"incident": rwe}

        # 2. affected_versions -> list[str]
        av = ctx.get("affected_versions")
        if isinstance(av, str):
            ctx["affected_versions"] = [av]

        # 3. cvss -> str
        cv = ctx.get("cvss")
        if isinstance(cv, (int, float)) and not isinstance(cv, bool):
            ctx["cvss"] = str(cv)

        # 4 + 5. references -> list of normalized structs
        refs = ctx.get("references")
        if isinstance(refs, list):
            ctx["references"] = [_norm_reference(r) for r in refs]

    # 7. tooling_signals expected string (one known row) - do before 6 canonicalization keeps struct
    sa = o.get("security_assertions")
    if isinstance(sa, dict):
        for ts in (sa.get("tooling_signals") or []):
            if isinstance(ts, dict) and isinstance(ts.get("expected"), str):
                ts["expected_version"] = ts["expected"]
                ts["expected"] = True

    # 6. security_assertions -> canonical struct
    if "security_assertions" in o:
        o["security_assertions"] = _norm_security_assertions(o.get("security_assertions"))

    return o
