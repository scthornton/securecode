# Positive-Control Recall Audit

This directory holds the code and results for a positive-control recall measurement of the SecureCode
dataset's fix-correctness. It answers a question the earlier fix-correctness sweep could not: not
"what did adversarial review flag" (precision), but "of the secure examples we kept, how many actually
fire when the paired attack is pushed through them" (recall).

## Why

The fix-correctness sweep reported "1,412 reviewed, 0 disputed, 28 removed." That is a PRECISION
statement. Adversarial review cannot estimate its own false-negative rate, and the failure mode that
matters most, a "secure" example whose code does not actually eliminate the vulnerability it teaches,
had no recall estimate. This audit builds that estimate mechanically.

## Method

For each secure example that claims a specific vulnerability is gone, isolate the secure guard, push
the paired attack input through it, and require it to FIRE. Every fire is gated so the rate cannot be
precision in disguise:

- NEGATIVE CONTROL: a benign input must not trigger the guard.
- KILL MUTATION: replacing the guard with a permissive stub must make the fire vanish, which also
  proves the harness routes its decision through the guard rather than hardcoding a verdict.
- FORCE MUTATION: for a no-fire, an always-fire stub must make the harness report a fire, proving the
  no-fire is a real property of the fix and not a dead harness.

The runner (the oracle) is itself mutation-scored by a 4-corner self-test, and the harness
false-negative rate (fires whose kill mutation did not remove them) is reported as a first-class
number. The generator that writes harnesses never judges them; a deterministic runner does.

## Results (complete census)

|                         | AI/ML | Web |
|-------------------------|-------|-----|
| Fire rate (recall)      | 442/442 = 100% (95% CI 99.1-100%) | 77/77 = 100% (95% CI 95.3-100%) |
| Negative-control pass   | 444/446 = 99.6% | 77/79 = 97.5% |
| Harness false-neg rate  | 4/446 = 0.9% | 2/79 = 2.5% |
| Confirmed new defects   | 0 | 0 |
| Executable subset       | 442 of 661 py-candidates | 79 of 203 distinct examples |

519 executable secure guards across both configs, all 519 fired on their paired attack, zero defects.

## The honest limits (read these with the number)

- POSITIVE CONTROLS MEASURE ONE CLASS OF DEFECT. Re-running the three defects removed by the earlier
  sweep as known-positives, positive controls caught one (a guard with broken internal logic: an
  entropy function that always returned 0.0, so redaction never ran) and missed two (correct guards
  that were dead code on the live path, or never saw the data they were meant to scrub). Testing a
  guard in isolation cannot see whether it is reachable or complete. The fire rate is broken-guard-
  logic recall, complementary to adversarial review, not a replacement.
- THE DENOMINATOR IS NOT THE WHOLE CORPUS. Only guard-shaped examples can be positive-controlled.
  AI/ML is about 67% runnable; web is about 6% (most web fixes are configuration: a framework
  annotation, security-header middleware, a TLS setting, a dependency pin, secrets moved to env
  variables, with no input to feed). The non-executable remainder is reported separately and keeps
  its human-reviewed status; it does not inherit the executable fire rate.

See RESULTS-BOTH-CONFIGS.md for the full breakdown and PROTOCOL.md for the exact contract.

## Files

- `runner.py` - the deterministic soundness oracle (negative-control + kill/force mutation, sandbox).
- `extract.py`, `extract_web.py` - turn dataset examples into extraction packets (aiml JSONL; web
  parquet, which has non-unique ids, so web is re-keyed by row).
- `assemble.py` - splice a verbatim secure block with a generated harness tail.
- `run_pilot.py` - assemble + execute a batch through the runner.
- `score.py` - the three headline numbers + honest denominator (Wilson CI).
- `webfix.py` - web re-extraction keyed by row index (fixes the id collision).
- `PROTOCOL.md` - the protocol of record.
- `GENERATOR_SPEC.md` - the harness-generation contract (generator is not the judge).
- `METHODS-WRITEUP.md` - narrative methods writeup.
- `census_score.json`, `webfix_score.json` - raw census results.

## Reproduce

Harness tails are generated per the GENERATOR_SPEC and are not checked in (they are reproducible
artifacts). To regenerate and re-score, follow GENERATOR_SPEC.md to produce `tails/<id>.tail.py` +
`tails/<id>.meta.json`, then run `run_pilot.py` and `score.py` over the dataset's Python examples.
