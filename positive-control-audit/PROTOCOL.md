# Positive-Control Recall Harness - Protocol of Record

Status: PILOT (aiml Python executable subset). Author owns protocol, soundness, adjudication.
No em/en dashes anywhere (house style). All execution sandboxed.

## 1. Why (precision vs recall)

The fix-correctness audit reported "1,412 reviewed, 0 disputed, 28 removed." That is a
PRECISION statement: of what adversarial review flagged, this fraction held up. Adversarial
review cannot estimate its own RECALL (its false-negative rate). The failure mode that
matters most - a "secure" example whose code does not actually eliminate the vulnerability it
teaches - had no recall estimate.

The mechanizable slice of that failure mode: for every secure example that claims a specific
vulnerability is gone, push the paired attack input through the isolated secure guard and
require it to FIRE. The fraction that fires, across the examples we kept, is a recall figure
we can measure and publish.

## 2. The trap (a bare fire rate is precision again)

A fire rate is only as trustworthy as the harness that produces it. A harness that fires on
everything, or one whose "fire" is not actually caused by the guard, manufactures a good
number the same way adversarial review manufactures a good precision number. This is the
"torch.allclose waves through buggy kernels" failure the HF commenter named. So every fire is
gated by soundness checks the harness cannot fake, and the harness's own false-negative rate
is measured and reported as a first-class number.

## 3. Harness contract

A harness is a self-contained Python module:

- `META`: {id, fire_signal, guard_symbol, vuln, dangerous_token?, lang, notes?, provenance}
  - fire_signal in {raises, returns_false, redacts, sanitizes, filters, blocks}
- `call_guard(payload) -> result`: invoke the ISOLATED secure guard. Heavy imports and
  framework glue (LLM/cloud SDKs, web servers, DB drivers) are stripped or stubbed; the guard
  logic is copied verbatim. The runner monkeypatches this module-global for mutation, so
  `fired` MUST call the module-global `call_guard`, never a captured local reference.
- `fired(payload) -> bool`: True iff the guard took its blocking/neutralizing ACTION on
  payload. MUST obtain its answer by calling `call_guard(payload)`.
- `ATTACK`: the payload the stated vuln says MUST fire the guard.
- `BENIGN`: a payload that MUST NOT fire the guard.
- optional `permissive_guard`, `strict_guard`: generator-provided broken/always-fire fixtures
  for secondary mutation cross-checks. The runner never trusts them in place of its own
  generator-independent stubs.

## 4. Soundness gates (runner-owned, generator cannot fake)

- NEGATIVE CONTROL (signal-aware). Benign input must not trigger the blocking action.
  - raises/returns_false/blocks: `fired(BENIGN)` must be False.
  - redacts/sanitizes/filters: `fired(BENIGN)` is vacuously False (benign lacks the dangerous
    token), so over-fire is detected as "guard ALTERED clean input": `call_guard(BENIGN) !=
    BENIGN`. (This vacuity was a real bug in an earlier runner; the 4-corner self-test caught
    it. See selftest corner 3.)
- KILL MUTATION (for fires). Replace `call_guard` with a permissive identity stub and require
  the fire to DISAPPEAR. This proves the fire is caused by the guard AND mechanically enforces
  that `fired` routes through `call_guard` (a harness that hardcodes the guard fails this gate;
  see selftest corner 4).
- FORCE MUTATION (for no-fires). Replace `call_guard` with an always-fire stub and require the
  harness to report a fire. This proves the harness CAN observe a fire, so a no-fire is a real
  property of the fix, not a dead harness.

## 5. Verdict taxonomy

- FIRES_SOUND: attack fires; benign does not; kill mutation removes the fire. => RECALL PASS.
- FIRES_UNSOUND: attack fires but benign also fires, or kill mutation did not remove it.
  => excluded from recall; counts toward the harness false-negative diagnostics.
- NO_FIRE_SOUND: attack does not fire; benign clean; force mutation proves fire-capability.
  => DEFECT CANDIDATE -> manual adjudication.
- NO_FIRE_CAP_UNVERIFIED: attack does not fire; capability not auto-proven. => manual adjudication.
- HARNESS_ERROR: exception in fired(ATTACK), contract violation, or inverted harness.
- NON_EXECUTABLE: guard cannot be isolated/imported (missing service, not reducible to a
  single-input guard). => reported as a SEPARATE denominator, never hidden inside a pass.

## 6. The three headline numbers (all three, or it is not honest)

1. FIRE RATE (recall proxy) = FIRES_SOUND / (FIRES_SOUND + NO_FIRE_SOUND + NO_FIRE_CAP_UNVERIFIED),
   over the executable subset only.
2. NEGATIVE-CONTROL PASS RATE = fraction of harnesses whose benign input did not over-fire.
3. HARNESS FALSE-NEGATIVE RATE = FIRES_UNSOUND / (FIRES_SOUND + FIRES_UNSOUND) = fraction of
   "fires" whose kill mutation did NOT flip them off (the mutation score of the oracle itself).

Plus the HONEST DENOMINATOR: executable subset size vs non-executable remainder, counted
separately, with the non-executable reasons enumerated.

## 7. What positive controls measure - and what they miss (two-class defect taxonomy)

Grounded in the three aiml defects we removed by hand (all three re-examined here as
known-positives):

- CLASS A - broken guard logic. The guard, invoked on the attack, fails to fire.
  - llm02 (entropy SecretScanner): `calculate_entropy` uses `p_x.log()` on a float, which has
    no `.log()`, so `hasattr(...)` is always False and entropy is always 0.0; `scan_code` then
    skips every regex secret match as "low entropy," so redaction is a no-op.
  - Positive control CATCHES this: verdict NO_FIRE_SOUND. This is the method's sweet spot.
- CLASS B - guard correct but bypassed or incomplete on the live path.
  - llm06 (llamaindex dead-code ACL): `validate_cypher_query`, `filter_result_properties`,
    `execute_controlled_query` are correct but NEVER CALLED; the live `query()` enforces access
    control with a natural-language prompt instruction to the LLM plus a non-blocking
    `logger.warning`.
  - llm07 (bedrock prompt logging): the leak is an information-flow property (whether the
    decrypted prompt can reach a log/telemetry sink); `_scrub_logs` works on known phrases but
    the happy path never routes the prompt through it.
  - Positive control on the extracted guard FALSE-PASSES (llm06 demonstrated: FIRES_SOUND),
    because the guard works in isolation; the defect is reachability/coverage, which testing a
    guard in isolation cannot see.

CONSEQUENCE (the honest headline): of our 3 known aiml defects, a positive control would
independently catch 1 (llm02) and miss 2 (llm06, llm07). Positive-control recall measures
Class-A robustness. It is COMPLEMENTARY to the adversarial reading that caught Class B, not a
replacement for it. Neither method alone is complete.

## 8. Delegation (generator is not the judge)

Bulk extraction and harness generation may be delegated (established budget pattern). The
generator produces harness ARTIFACTS only. Execution, the soundness gates, and adjudication are
owned by the author and by the deterministic runner. The generator never adjudicates its own
harness. The runner's soundness gates are generator-independent, so a lazy or adversarial
generator is caught, not rewarded. A hand-built calibration set validates that the generator
extracts the RIGHT guard and RIGHT attack (soundness gates cannot catch a harness that soundly
tests the wrong thing).

## 9. Runner self-test (mutation-score of the oracle)

`runner.py` is validated by a 4-corner self-test (calibration/runner_selftest):
- working redactor -> FIRES_SOUND
- broken redactor (no-op) -> NO_FIRE_SOUND
- degenerate redactor (blanks all input) -> FIRES_UNSOUND (negative control)
- harness whose fired() bypasses call_guard -> FIRES_UNSOUND (kill mutation)
All four must hold before any real number is trusted.
