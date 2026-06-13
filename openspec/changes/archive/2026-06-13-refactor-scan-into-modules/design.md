## Context

`scan.py` is a monolithic 665-line Python script responsible for all scanner concerns: configuration loading, logging setup, GitHub API interaction, repository cloning, vulnerability scanning via OWASP Dependency-Check, report parsing, MongoDB persistence, AWS SNS alerting, and auto-remediation (pip-audit + npm audit fix). The file is functional but violates separation-of-concerns principles, making it hard to maintain or test in isolation.

## Goals / Non-Goals

**Goals:**
- Decompose `scan.py` into a `scanner/` Python package with one module per concern
- Preserve 100% of existing runtime behavior, environment variable contracts, and CLI entrypoint
- Structure the package so each module is independently importable for future unit testing
- Update the Dockerfile entrypoint to invoke `python -m scanner`

**Non-Goals:**
- Adding new features or changing any scanning, alerting, or remediation behavior
- Adding unit tests (a separate future change)
- Changing Kubernetes manifests, ConfigMaps, Secrets, or PV/PVC configuration
- Introducing new external Python dependencies

## Decisions

### 1. Package layout: `scanner/` with flat module structure

**Decision**: Use a flat `scanner/` package (no sub-packages).

**Rationale**: The codebase is small enough (≤10 modules) that a flat layout avoids unnecessary nesting. Each module maps cleanly to one domain concern.

**Proposed module breakdown:**

| Module | Responsibility | Key symbols from scan.py |
|---|---|---|
| `scanner/config.py` | Load & validate all env vars, define constants | `get_env_var`, all `GITHUB_*`, `MONGO_*`, `AWS_*`, `SEVERITY_WEIGHTS`, etc. |
| `scanner/logging_setup.py` | Configure root logger, `log_buffer`, handlers | `log_buffer`, `log_formatter`, `logger` |
| `scanner/utils.py` | Generic helpers shared across modules | `run_cmd`, `get_severity_weight` |
| `scanner/github.py` | GitHub API: fetch repos, build clone URLs, create PRs, request reviewers | `fetch_repositories`, `get_auth_clone_url`, PR/reviewer/comment calls |
| `scanner/repository.py` | Clone/update repos, run Dependency-Check binary | `scan_repository` (clone + exec parts) |
| `scanner/report.py` | Parse Dependency-Check JSON output | `parse_report` |
| `scanner/storage.py` | MongoDB persistence | `save_to_mongodb`, `save_execution_logs` |
| `scanner/alerting.py` | AWS SNS alert formatting & publishing | `send_alert` |
| `scanner/remediation.py` | pip-audit / npm audit fix + git branch + PR creation | `remediate_and_create_pr`, `get_node_version`, `run_npm_cmd_with_nvm`, `get_python_version` |
| `scanner/__main__.py` | Entrypoint (`main()` function), orchestration | `main` |

**Alternatives considered:**
- Keep `scan.py` as entrypoint and import from `scanner/` → rejected (creates confusing dual-entry)
- Sub-packages (e.g., `scanner/integrations/github.py`) → rejected (over-engineered for current size)

### 2. Entrypoint: `python -m scanner` via `__main__.py`

**Decision**: Dockerfile `CMD` changes from `["python", "scan.py"]` to `["python", "-m", "scanner"]`.

**Rationale**: Using `python -m scanner` is idiomatic for packages and avoids path issues. The thin `scan.py` at the root will be **deleted** (not kept as a shim) to avoid confusion.

**Alternative**: Keep `scan.py` as a one-line shim `from scanner.__main__ import main; main()` → rejected as unnecessary indirection.

### 3. Shared state: config and logger imported at module level

**Decision**: `config.py` and `logging_setup.py` are imported eagerly at the top of each module that needs them (e.g., `from scanner.config import GITHUB_TOKEN`).

**Rationale**: Matches existing behavior — config is resolved at import time via `os.getenv`. Avoids dependency injection complexity for what is effectively a script-like job runner.

## Risks / Trade-offs

- **Circular imports** → Mitigation: `config` and `logging_setup` import nothing from other scanner modules; all other modules import from `config`/`logging_setup`/`utils` only.
- **Dockerfile regression** → Mitigation: Update and verify `CMD` in Dockerfile; keep old `scan.py` deleted cleanly so no stale entrypoint survives.
- **Log buffer shared state** → `log_buffer` and `logger` are module-level singletons in `logging_setup.py`; `storage.py` imports `log_buffer` directly to capture full execution logs. This preserves existing behavior.

## Migration Plan

1. Create `scanner/` package and all modules
2. Delete `scan.py`
3. Update `Dockerfile` CMD from `["python", "scan.py"]` to `["python", "-m", "scanner"]`
4. Build Docker image locally and verify `docker run` invokes `main()` correctly
5. No Kubernetes manifest changes required
