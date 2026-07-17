# Measuring Recall, Not Just Precision: Positive-Control Testing of Fix-Correctness

_Draft methods section to append to the SecureCode audit article. Pilot results are filled in
after the aiml Python run. No em/en dashes (house style)._

## The gap a commenter named

Our fix-correctness sweep reported "1,412 reviewed, 0 disputed, 28 removed." A reader
(dipankarsarkar) correctly pointed out that this is a PRECISION figure, not RECALL. Adversarial
review reports what it flagged that survived scrutiny; it cannot estimate the defects it never
flagged. The failure mode that matters most, a "secure" example whose code does not actually
eliminate the vulnerability it teaches, had no false-negative estimate on it.

He proposed the right instrument: for every secure example that claims a specific vulnerability
is gone, build a POSITIVE CONTROL. Push the paired attack input through the isolated secure
guard and require it to FIRE. The fraction that fires, across the examples we kept, is a recall
figure we can measure. He also named the trap: a bare fire rate is precision again if the
harness is unsound (his analogy: mutation-scoring an LLM-GPU-kernel oracle showed torch.allclose
waving buggy kernels through). So the harness's own false-negative rate has to be measured too.

## What we built

A harness per example isolates the secure guard (its verbatim code, with service/framework
imports neutralized to Mocks so the string-processing logic runs for real) and exposes a single
predicate: does the guard FIRE on a given input? Every harness is run by a deterministic runner
that applies three soundness gates the harness cannot fake:

- NEGATIVE CONTROL (signal-aware): a benign input must not trigger the guard. For guards that
  transform text (redact/sanitize/filter) we require that a declared benign marker SURVIVES the
  guard, which is a non-vacuous test even when the benign input lacks the attack token. (An
  earlier runner used `output != input` here; a 4-corner self-test caught that it passed a
  degenerate "redact everything" guard, and we fixed it. The oracle needs its own oracle.)
- KILL MUTATION: replace the guard with a permissive identity stub and require the fire to
  DISAPPEAR. This proves the fire is caused by the guard, and it mechanically enforces that the
  harness routes its decision through the guard rather than hardcoding a verdict.
- FORCE MUTATION: for a no-fire, replace the guard with an always-fire stub and require the
  harness to report a fire, proving the no-fire is a property of the fix and not a dead harness.

The runner itself is validated by a 4-corner self-test (working guard fires-sound; broken guard
no-fire-sound; degenerate guard caught by the negative control; a harness that bypasses its own
guard caught by the kill mutation). All four must hold before any number is trusted.

We report three numbers together, because any one alone is misleading:
1. FIRE RATE (recall proxy) over the sound executable subset.
2. NEGATIVE-CONTROL PASS RATE (guards are discriminating, not degenerate).
3. HARNESS FALSE-NEGATIVE RATE = fraction of "fires" whose kill mutation did not remove them
   (the mutation score of the oracle itself).

And an honest denominator: the executable subset (where a sound harness ran) versus the
non-executable remainder (guards that could not be isolated, e.g. enforcement that lives in an
external service, test-suite-only blocks, or multi-turn/architectural defenses), counted
separately and never folded into a pass.

Generation of harnesses was delegated; judging was not. A separate deterministic runner and
manual adjudication own every pass/fail decision, and the runner's gates are generator-
independent, so a weak generator is caught rather than rewarded.

## What positive controls measure, and what they miss

Re-examining the three aiml defects we removed by hand shows two distinct classes of fake fix:

- CLASS A, broken guard logic. The guard, when invoked on the attack, fails to fire.
  Example: the entropy-based SecretScanner computed Shannon entropy with `p_x.log()` on a float
  (floats have no `.log()`), so entropy was always 0.0 and every regex secret match was skipped
  as "low entropy," making redaction a no-op. A positive control CATCHES this: no fire on the
  attack, harness sound. This is the method's sweet spot.
- CLASS B, guard correct but bypassed or incomplete on the live path. The guard fires fine in
  isolation; the defect is that it is never actually invoked, or does not cover the real sink.
  Examples: an access-control validator that is dead code because the live query path enforces
  policy with a natural-language prompt to the LLM plus a non-blocking log line; a prompt-logging
  "fix" whose scrubber never sees the prompt on the happy path. A positive control on the
  extracted guard FALSE-PASSES here, because testing a guard in isolation cannot see whether it
  is reachable or complete.

Of our three known aiml defects, a positive control independently catches one (Class A) and
misses two (Class B). That is the honest headline: positive-control recall measures Class-A
robustness. It is COMPLEMENTARY to the adversarial reading that caught the Class-B defects, not
a replacement for it. Publishing the fire rate without this caveat would repeat the original
error in the opposite direction.

## Pilot results (aiml Python executable subset)

Sample: 150 examples, stratified 15 per OWASP LLM category, from the 661 aiml Python
executable-candidate subset (of 747 aiml total). Harness generation delegated to 11 subagents;
all judging owned by the deterministic runner plus manual adjudication.

- Executable subset: 105 of 150 (a runnable isolated guard existed). Non-executable remainder: 45,
  itemized and counted separately: 28 guards not isolable (external-service enforcement, test-suite-
  only blocks, multi-turn/architectural defenses), 12 import-crash from module-level side effects,
  3 unparseable secure blocks (shipped code with a syntax error), 1 stubbed-dependency, 1 timeout.
- FIRE RATE (Class-A recall proxy): 103 / 103 = 100% (95% Wilson CI 96.4% to 100%). Every guard
  soundly testable in isolation fired on its paired attack.
- NEGATIVE-CONTROL PASS RATE: 104 / 105 = 99.0%. The one failure was an over-restrictive XPath guard
  that blocks the descendant axis and so rejects benign queries too; the negative control caught it,
  which is exactly its job (it is not vacuous).
- HARNESS FALSE-NEGATIVE RATE: 2 / 105 = 1.9%. 98.1% of fires are provably guard-caused (the kill
  mutation removes them). The 2 excluded were harness/mutation artifacts, adjudicated as non-defects.
- CONFIRMED NEW DEFECTS: 0. Every non-clean result (2 unsound, 1 harness error, 3 unparseable,
  1 timeout) was traced to a harness/stubbing/dataset-syntax artifact, not a broken fix.

Interpretation. The 100% fire rate is evidence that the KEPT dataset's Class-A fix logic is robust,
consistent with the earlier sweep having removed the broken ones. It is bounded: it speaks only to
the 105/150 executable subset, and by construction it cannot see Class-B (reachability/coverage)
defects, of which our own known-positive test showed the method misses two of three. We publish the
number and the limit together.

Byproduct finding: 3 of 150 sampled secure blocks (and 50 of 661, 7.6%, in triage) do not parse as
Python. That is a code-quality signal worth addressing on its own, separate from fix-correctness.

Decision point: extend to the web config (more framework-coupled, smaller runnable subset) and/or
run the full 661 aiml py-candidates via the staged Codex path to tighten the bound.
