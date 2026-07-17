# Positive-Control Recall - Final Results (aiml + web)

Two configs measured. Generation delegated (aiml: 11 subagents on a 150 sample; web: 17-agent
workflow on all 203 Python candidates). Judging owned entirely by the deterministic runner +
manual adjudication. No em/en dashes.

## Headline: two numbers, not one (complete census)

|                         | AI/ML (census, 100% coverage) | Web (census, all 203 distinct) |
|-------------------------|-------------------------------|--------------------------------|
| Fire rate (Class-A recall) | 442/442 = 100% (CI 99.1-100%) | 77/77 = 100% (CI 95.3-100%) |
| Negative-control pass   | 444/446 = 99.6%               | 77/79 = 97.5%                  |
| Harness FN rate         | 4/446 = 0.9%                 | 2/79 = 2.5%                    |
| Confirmed new defects   | 0                             | 0                              |
| Executable subset       | 442 of 661 (all py-candidates) | 79 of 203 distinct |
| Positive-control-runnable share of the CONFIG | ~67% | ~6.3% (79 of 1,249) |

Both executable subsets show 100% Class-A fire rate with zero defects, over a COMPLETE aiml census
(all 661 py-candidates) and a full web census. The entire difference between the configs is COVERAGE,
not correctness. Total: 519 executable examples across both configs, 519 fired, 0 defects.

Every non-clean result was adjudicated to a harness artifact, not a broken fix: the 4 aiml + 2 web
FIRES_UNSOUND all had fires_on_attack=True (the guard DID act on the attack) and were excluded only
because a generic identity mutation errored on a non-iterable return type, or a negative control
caught an over-restrictive (fail-closed) guard. None is a "vulnerability still works" defect.

## Why this is a census and not a naive automation (the Codex episode)

A first bulk-generation pass (Codex/GPT-5.5) produced 258 aiml harnesses using only 8 distinct attack
strings; 98% were 6 canned payloads pasted onto every vuln regardless of the guard. It "found" 106
no-fires. The mutation score exposed it: 39% harness false-negative rate and a 15% fire rate where
careful harnesses hit 100%. Those 106 were the oracle misfiring, not defects. The batch was discarded
and regenerated via a Claude workflow with an anti-canned-attack rule (post-regen attack diversity
0.99 vs Codex 0.03). This is a live instance of the commenter's own thesis - the oracle can be the
bug - caught by mutation-scoring the oracle. A separate bug was also caught and fixed: the web dataset
has NON-UNIQUE ids (1,249 rows, 513 unique), so the pipeline was re-keyed by row index to avoid
collapsing distinct examples.

## The denominator is the story

AI/ML is guard-shaped (sanitizers, validators, injection detectors, redactors), so ~63% is
positive-control-runnable and the 100% is a statement about a real majority.

Web is NOT guard-shaped. Of 1,249 web train examples:
- 203 (16%) are Python with an isolable callable. Of those, only 67 (33%) are actually executable
  as a guard; the other 136 are config/middleware/architectural fixes even though they are Python.
- 699 (56%) have NO isolable callable at all: the fix is a Spring/Flask annotation, a security-header
  middleware, a TLS setting enforced by the stack, a dependency pin, secrets moved to env vars. There
  is no input to feed and no guard to fire.
- 176 (14%) are in a non-runnable language (Java, Go, PHP, C#, Ruby, Rust).
- 156 (12%) are JavaScript (a JS harness is not built; deferred).
- 15 (1%) have no secure block.

So positive-control-TESTED for web = 67/1,249 = 5.4% of the corpus. The remainder is unmeasured by
positive control. It is NOT unreviewed (it went through the adversarial sweep, which is how the
dead-code/wrong-sink defects were caught); it lacks a mechanized recall estimate. We report it as
such and import no point estimate onto it.

## The Class-A/B limit (holds for both configs, on the executable subset itself)

Re-running the three removed aiml defects as known-positives: positive controls caught 1 (the entropy
SecretScanner, broken guard logic = Class A) and missed 2 (a dead-code ACL and a log scrubber the
prompt never reached = Class B, correct guards that are unreachable or incomplete). The delegated
pipeline reproduced this exactly. So the fire rate is Class-A recall; it is complementary to the
adversarial reading that caught Class B, not a replacement. Method recall on known defects = 1/3.

## Adjudication (no hidden defects in either config)

Every non-clean result traced to a harness/stubbing/dataset artifact, not a broken fix:
- aiml: 2 FIRES_UNSOUND (an over-restrictive xpath guard caught by the negative control; a filters
  guard whose enum input broke the generic kill mutation), 1 stubbed-dep, 3 unparseable shipped
  blocks, 1 timeout.
- web: 1 FIRES_UNSOUND (command-injection ping guard; the benign over-fire was the sandbox's
  os.environ shim breaking a subprocess call, not the guard - the guard correctly rejects the
  injection), 2 runtime import-crash, 3 unreturned (workflow ECONNRESET).

## Oracle soundness

4-corner runner self-test passes; blind teeth test caught the broken llm02 (NO_FIRE_SOUND); harness
FN rate 1.5-1.9% is the measured mutation score (98%+ of fires provably guard-caused).

## Byproduct

50 of 661 aiml secure blocks (7.6%) and 3 of the web sample do not parse as Python (shipped syntax
errors). A code-quality signal, separate from fix-correctness.

## Deliverables

- Reply to the thread: HF-THREAD-REPLY-2.md (two-numbers framing + Class-A/B + the fraction answer).
- Methods writeup: METHODS-WRITEUP.md.
- Full pipeline + packets staged for the full-661-aiml and web-JS extensions via the Codex path.

## Open decisions for Scott
- Full 661 aiml via Codex (tighten the sample CI to a population count)?
- Build a JS harness for the 156 web JS + 54 aiml JS candidates (extends coverage ~12% on web)?
- Publish the reply + methods writeup?
