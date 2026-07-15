# Performance Envelope

AgentCSP v0.2 defines a release envelope of 5,000 files and at least 100 MiB of indexed text with the recommended ruleset and portable JSON artifacts.

Run the reproducible benchmark:

```bash
pnpm benchmark:scale
```

## Release Thresholds

| Measure | Threshold |
| --- | ---: |
| Files indexed | 5,000 |
| Input size | at least 100 MiB |
| Scan health | `complete` |
| Measured runs | 5 |
| Runtime p95 | at most 15 seconds |
| Peak RSS | at most 512 MiB |
| Manifest plus findings JSON | at most 10 MiB |

## v0.2 Reference Run

Reference environment: macOS arm64, 8 logical CPUs, 16 GiB memory, Node.js 26.4.0.

| Measure | Observed |
| --- | ---: |
| Files indexed | 5,000 |
| Input size | 104,860,000 bytes |
| Runtime p95 | 1,841 ms |
| Peak RSS | 188,137,472 bytes |
| Scan health | `complete` |
| Manifest plus findings JSON | 9,523 bytes |

The synthetic scale fixture contains low-complexity text and no findings. Five scans are measured against the same generated fixture and the release gate enforces the nearest-rank p95. It measures traversal, bounded reading, basic detection dispatch, rule loading, manifest construction, and artifact publication. It does not predict runtime for repositories with thousands of large structured agent configurations or high finding volume.

The vulnerable extended fixture separately exercises 383 rules and 1,433 findings. Portable output for that fixture remains under the 10 MiB primary JSON budget; internal artifacts are intentionally larger because they retain normalized metadata for deep local analysis.
