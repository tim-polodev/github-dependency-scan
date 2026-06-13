## Why

`scan.py` is a single 665-line file containing all logic for configuration, GitHub integration, vulnerability scanning, report parsing, MongoDB storage, AWS SNS alerting, and auto-remediation — making it difficult to maintain, test, and extend. Splitting it into focused modules improves cohesion, lowers cognitive load, and enables independent unit testing per concern.

## What Changes

- `scan.py` is split into a Python package `scanner/` with focused modules
- A new `scanner/__main__.py` (or thin `scan.py` entrypoint) replaces the monolith as the runnable entrypoint
- All existing runtime behavior, environment variable contracts, and Dockerfile entrypoints are preserved
- No new external dependencies are introduced; existing imports are redistributed across modules

## Capabilities

### New Capabilities

- `scanner-package`: The `scanner/` Python package encapsulating all scanner logic in domain-focused modules (`config`, `logging_setup`, `github`, `repository`, `report`, `storage`, `alerting`, `remediation`, `utils`)

### Modified Capabilities

_(None — this is a pure refactor; no spec-level behavior changes)_

## Impact

- **Code**: `scan.py` is replaced by the `scanner/` package; the Dockerfile `CMD`/entrypoint must reference the new entry point (e.g., `python -m scanner`)
- **No credential or secret changes**: All environment variable names and their semantics remain identical
- **Non-goals**: No behavioral changes, no new features, no changes to Kubernetes manifests, no new dependencies
