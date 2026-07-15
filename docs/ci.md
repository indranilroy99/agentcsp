# CI Integration

AgentCSP supports progressive rollout. A completed advisory scan exits successfully even when findings exist; finding gates are explicit.

## GitHub Actions Examples

- [`github-code-scanning-advisory.yml`](../examples/ci/github-code-scanning-advisory.yml) scans and uploads SARIF without a finding gate.
- [`github-code-scanning-gated.yml`](../examples/ci/github-code-scanning-gated.yml) uses `ci-strict`, uploads SARIF even when a gate fails, then preserves the scanner exit decision.

The examples pin:

```yaml
env:
  AGENTCSP_VERSION: 0.2.0
```

Review and update this value deliberately. Do not use `latest` in a protected workflow.

## Rollout

Start with advisory evidence:

```bash
agentcsp scan . \
  --ruleset recommended \
  --out .agentcsp \
  --format json,md,sarif \
  --quiet
```

Then protect scanner completeness and inputs:

```bash
agentcsp scan . \
  --profile ci-strict \
  --ruleset recommended \
  --out .agentcsp \
  --format json,md,sarif \
  --quiet
```

Finally, opt into the finding policy your team has reviewed:

```bash
agentcsp scan . \
  --profile ci-strict \
  --ruleset recommended \
  --fail-on high \
  --fail-on-confidence high \
  --out .agentcsp \
  --format json,md,sarif \
  --quiet
```

No v0.2 rule is independently calibrated for automatic blocking. `--fail-on` is an operator-selected severity and confidence policy. See [Detection Quality](detection-quality.md).

## Strict Input Trust

The scanned pull request is an untrusted boundary. `ci-strict` ignores:

- repository `agentcsp.yaml`
- repository `rules/`
- repository `.agentcspignore`

Use policy stored outside the checkout and pin its content digest:

```bash
agentcsp scan . \
  --profile ci-strict \
  --config /opt/security/agentcsp.yaml \
  --config-sha256 "$AGENTCSP_POLICY_SHA256" \
  --out .agentcsp \
  --format json,md,sarif \
  --quiet
```

The scanner resolves symlinks, requires a regular file outside the scan root, enforces size limits, and parses the exact bytes read and SHA-256 verified through the opened file handle.

Apply the same model to a protected baseline:

```bash
agentcsp scan . \
  --profile ci-strict \
  --baseline /opt/security/agentcsp-baseline.json \
  --baseline-sha256 "$AGENTCSP_BASELINE_SHA256" \
  --fail-on-new \
  --fail-on high \
  --fail-on-confidence high \
  --quiet
```

## Baseline Adoption

Create a baseline only from reviewed findings:

```bash
agentcsp baseline create .agentcsp/findings.json --out agentcsp-baseline.json
```

Store the baseline where pull-request code cannot modify it. `--fail-on-new` requires both `--baseline` and `--fail-on`.

## SARIF

SARIF is written to `.agentcsp/agentcsp.sarif` when requested. Stage it with `if: always()` so findings remain available when a later gate fails.

The examples keep the scan job read-only, stage SARIF as a workflow artifact, and grant `security-events: write` only to a separate publication job. For pull requests from forks, that publication job is skipped while the scan still runs without write authority.

## Gate State

`ci_gate_summary` is emitted in the manifest, Markdown report, and SARIF run properties. It records:

- configured severity, confidence, baseline, diagnostic, suppression, and scan-health gates
- failed gate names
- bounded blocker and diagnostic IDs with truncation flags
- active and expired suppression posture
- actual scan health and stable reasons

Automation should consume this object instead of recreating AgentCSP's gate logic.

## Exit Codes

| Code | CI meaning |
| ---: | --- |
| `0` | Scan completed and configured gates passed |
| `1` | Configured finding gate failed |
| `2` | Invalid configuration or input |
| `3` | Scanner integrity, coverage, diagnostic, suppression, or packaged-artifact gate failed |
| `4` | Unexpected internal failure |

Treat `2`, `3`, and `4` as tool failures, not security findings.
