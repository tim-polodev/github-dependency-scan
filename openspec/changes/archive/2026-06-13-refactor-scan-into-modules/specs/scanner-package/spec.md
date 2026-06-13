## ADDED Requirements

### Requirement: Scanner package structure
The codebase SHALL be organised as a `scanner/` Python package containing one module per domain concern, replacing the monolithic `scan.py`. The package MUST be invocable via `python -m scanner`.

#### Scenario: Package is importable
- **WHEN** a Python process imports `scanner`
- **THEN** no import errors occur and all sub-modules are accessible

#### Scenario: Package entrypoint executes main
- **WHEN** the command `python -m scanner` is run with all required environment variables set
- **THEN** the scanner executes identically to the previous `python scan.py` command

### Requirement: Module-level separation of concerns
Each module in `scanner/` SHALL be responsible for exactly one domain concern. The allowed modules are: `config`, `logging_setup`, `utils`, `github`, `repository`, `report`, `storage`, `alerting`, `remediation`, and `__main__`.

#### Scenario: Config module loaded independently
- **WHEN** `scanner.config` is imported in isolation
- **THEN** all environment-variable constants are resolved without importing any other scanner module

#### Scenario: No circular imports
- **WHEN** any scanner module is imported
- **THEN** no `ImportError` or circular-import exception is raised

### Requirement: Dockerfile entrypoint updated
The Dockerfile CMD MUST be updated to `["python", "-m", "scanner"]` to reflect the new package entrypoint. The old `scan.py` root file SHALL be deleted.

#### Scenario: Docker image runs scanner
- **WHEN** the Docker image is built from the updated Dockerfile and run with required env vars
- **THEN** the scanner starts, completes its scan loop, and exits with the same behavior as before

### Requirement: Behavioral parity with original scan.py
All existing runtime behaviors SHALL be preserved identically after the refactor, including: repository fetching, cloning, OWASP Dependency-Check invocation, report parsing, MongoDB storage, AWS SNS alerting, and auto-remediation via pip-audit and npm audit fix.

#### Scenario: Vulnerability findings identical after refactor
- **WHEN** the refactored scanner runs against the same repository set
- **THEN** the vulnerability findings, severity breakdown, and MongoDB documents are identical to those produced by the original `scan.py`

#### Scenario: SNS alert sent for qualifying vulnerabilities
- **WHEN** repositories with HIGH or CRITICAL vulnerabilities are scanned
- **THEN** an SNS alert is published with the same subject line and body format as before

#### Scenario: Auto-remediation PR created
- **WHEN** HIGH or CRITICAL vulnerabilities are found and remediation tools produce changes
- **THEN** a GitHub pull request is created with the same branch naming, commit message, PR title, body, reviewer assignment, and comment as before
