# Detection Quality

AgentCSP treats detection quality and enforcement eligibility as separate claims. A rule can be useful for investigation without being safe to use as an automatic merge gate.

## v0.2 Release Position

- The `recommended` pack contains a bounded set of structured, high-signal advisory detections.
- The `extended` pack exposes broader research coverage and is intended for hunting, evaluation, and rule development.
- No v0.2 rule is independently calibrated for automatic blocking.
- `ci_strict` protects scanner inputs and scan completeness. It does not silently turn advisory detections into enforcement decisions.
- Teams can opt into a severity gate with `--fail-on`; that is an operator policy decision, not a claim that AgentCSP has proven a finding at runtime.

## Evidence Tiers

| Tier | Meaning | Maximum confidence |
| --- | --- | --- |
| `typed_path` | A typed adapter resolved a concrete object and authority path. | `very_high` |
| `structured` | A supported parser resolved correlated configuration fields. | `high` |
| `heuristic` | Redacted text or path signals indicate a condition worth review. | `medium` |

Confidence describes the strength of static evidence for the matched condition. It does not prove that a configuration is deployed, active, reachable, or exploitable.

## Conformance Tests

`pnpm benchmark:rules` runs a deterministic synthetic conformance matrix through the real parser, classifier, and rule engine. It covers supported serialization formats, positive conjunctions, one-sided controls, unrelated configuration, and risky substring near misses.

The output is explicitly marked `synthetic_conformance` and `enforcement_eligible: false`. Its precision and recall values describe that generated matrix only. They are not estimates of production precision.

## Blocking Promotion Gate

A future blocking rule must satisfy all of the following before its disposition can change:

1. A written semantic specification defines the risk condition independently of detector literals.
2. A versioned repository-level corpus is frozen before review and contains representative supported adapters, nesting, profiles, aliases, malformed inputs, and near misses.
3. Two independent reviewers label the corpus, with disagreements adjudicated and retained.
4. Duplicate cases are removed before statistics are calculated.
5. At least 50 distinct positive predictions and 100 distinct negative opportunities remain after deduplication.
6. Precision is at least 98%, recall is at least 85%, and the 95% Wilson lower bound for precision is at least 90%.
7. Evidence identifies the parser, semantic field paths, profile resolution, and normalized classifications without exposing values.
8. Repository-controlled policy cannot suppress the strict gate.
9. Scanner, rule, and corpus digests are bound in a reviewed calibration record. Any mismatch automatically demotes the rule to advisory.

## Independent Review Record

On 2026-07-15, an independent read-only review rejected promotion of `AGENTCSP-RUNTIME-001`. The existing generated matrix passed 150 of 150 cases, but it was detector-derived, heavily templated, and not an independently labeled holdout. The reviewer also identified broad substring matching, unresolved profile conflicts, insufficient field-level provenance, and project suppressibility as blockers.

The rule remains advisory. Exact enum matching, active-profile selection, ambiguity diagnostics, and structured evidence provenance were added in response. The independent-corpus and calibration-registry requirements remain open and are release blockers only for automatic blocking, not for advisory scanning.

## Static Limits

AgentCSP scans repository state. It cannot prove the effective runtime after command-line overrides, environment variables, user-global configuration, deployment overlays, or operating-system controls. It also cannot prove reachability or exploitation without runtime telemetry and enforcement adapters. Reports use "recommended control" language for this reason.
