# CI Integration

AgentCSP is designed to be introduced without breaking existing pipelines, then tightened as teams establish ownership for findings and suppressions.

## GitHub Code Scanning

Use the advisory workflow when introducing AgentCSP to an existing repository:

```text
examples/ci/github-code-scanning-advisory.yml
```

It emits JSON, Markdown, and SARIF, then uploads SARIF to GitHub code scanning. It does not enable fail gates, so a completed scan exits successfully even when findings exist.

Use the gated workflow when the repository is ready to enforce policy:

```text
examples/ci/github-code-scanning-gated.yml
```

It uploads SARIF even when AgentCSP finds gate-blocking risk, then fails the job after upload. This keeps GitHub code scanning populated while preserving a hard CI gate.

## Recommended Gate Progression

Start with:

```bash
agentcsp scan . --out .agentcsp --format json,md,sarif --quiet
```

Then add scan-health controls:

```bash
agentcsp scan . \
  --out .agentcsp \
  --format json,md,sarif \
  --fail-on-diagnostics \
  --fail-on-expired-suppressions \
  --fail-on-scan-health degraded \
  --quiet
```

For mature repositories, add severity and confidence gates:

```bash
agentcsp scan . \
  --out .agentcsp \
  --format json,md,sarif \
  --fail-on high \
  --fail-on-confidence high \
  --fail-on-diagnostics \
  --fail-on-expired-suppressions \
  --fail-on-scan-health degraded \
  --quiet
```

When an existing baseline is already accepted, add `--baseline` and `--fail-on-new` so CI blocks newly introduced high-confidence risk without forcing a full backlog burn-down in the first rollout.

## Version Pinning

The example workflows use:

```yaml
env:
  AGENTCSP_VERSION: 0.1.0
```

Keep this pinned to a reviewed AgentCSP release. Avoid unpinned `latest` in regulated or production repositories.

## Machine-Readable Gate State

Every scan writes `ci_gate_summary` to `agent-manifest.json`, the Markdown report, and SARIF run properties as `agentcsp_ci_gate_summary`.

Use that summary to explain whether a gate failed because of severity thresholds, new findings, expired suppressions, diagnostics, or scan health. It includes severity, confidence, and risk-driver mixes for severity-gated findings, severity mixes for active suppressions excluded from severity gates, and severity plus risk-driver mixes for expired suppressions, so CI dashboards can show blocker and accepted-risk shape without parsing every finding. It also includes bounded blocker ID lists for severity-gated findings, expired suppressions, and diagnostics so CI systems can link directly to the relevant AgentCSP records without reimplementing gate logic. `blocker_id_limit` and the `*_ids_truncated` flags make it explicit when those lists are previews rather than complete blocker inventories. The summary also records the configured `fail_on_scan_health` threshold, actual `scan_health`, and stable `scan_health_reasons`. The summary does not include raw evidence snippets or secret values.
