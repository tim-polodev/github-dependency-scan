## 1. Create Package Scaffold

- [x] 1.1 Create `scanner/` directory and empty `scanner/__init__.py`
- [x] 1.2 Create `scanner/logging_setup.py` — move `log_buffer`, `log_formatter`, handler setup, `logging.basicConfig`, and `logger` from `scan.py`
- [x] 1.3 Create `scanner/config.py` — move `get_env_var` helper and all module-level env var constants (`GITHUB_TOKEN`, `NVD_API_KEY`, `GITHUB_USER`, `GITHUB_ORG`, `GITHUB_REPOS`, `SEVERITY_THRESHOLD`, `DATA_DIR`, `AWS_REGION`, `AWS_SNS_TOPIC_ARN`, `PRESERVE_REPOS`, `FIX_BREAKING_CHANGES`, `MONGO_URI`, `MONGO_DB`, `MONGO_COLLECTION`, `MONGO_LOGS_COLLECTION`, `SEVERITY_WEIGHTS`)

## 2. Implement Domain Modules

- [x] 2.1 Create `scanner/utils.py` — move `run_cmd` and `get_severity_weight`
- [x] 2.2 Create `scanner/github.py` — move `fetch_repositories` and `get_auth_clone_url`; import from `config` and `utils`
- [x] 2.3 Create `scanner/report.py` — move `parse_report`; import from `config`, `utils`, `logging_setup`
- [x] 2.4 Create `scanner/storage.py` — move `save_to_mongodb` and `save_execution_logs`; import `log_buffer` from `logging_setup` and constants from `config`
- [x] 2.5 Create `scanner/alerting.py` — move `send_alert`; import from `config` and `logging_setup`
- [x] 2.6 Create `scanner/remediation.py` — move `get_node_version`, `run_npm_cmd_with_nvm`, `get_python_version`, and `remediate_and_create_pr`; import from `config`, `utils`, `logging_setup`
- [x] 2.7 Create `scanner/repository.py` — move `scan_repository`; import from `config`, `utils`, `logging_setup`, `github`, `report`, `storage`, `remediation`

## 3. Entrypoint and Cleanup

- [x] 3.1 Create `scanner/__main__.py` — move `main()` function; import from all domain modules; preserve `if __name__ == "__main__": main()` guard
- [x] 3.2 Delete `scan.py` from the repository root
- [x] 3.3 Update `Dockerfile` CMD from `["python", "scan.py"]` to `["python", "-m", "scanner"]`

## 4. Security and Pre-commit Verification

- [x] 4.1 Run `pre-commit run --all-files` and confirm Gitleaks and Semgrep checks pass with no secrets or SAST findings introduced
- [x] 4.2 Verify no credential or secret values are accidentally embedded in any new module file

## 5. Docker Build Validation

- [x] 5.1 Build Docker image locally: `docker buildx build --platform linux/amd64 -t scanner:test .`
- [x] 5.2 Run a dry smoke test: `docker run --rm -e GITHUB_TOKEN=xxx -e AWS_SNS_TOPIC_ARN=xxx scanner:test` and confirm the entrypoint resolves (fails gracefully on missing dependencies, not on import errors)

## 6. Kubernetes Ad-hoc Verification

- [x] 6.1 Deploy updated image to Kubernetes using `manual-job.yaml` in the target cluster
- [x] 6.2 Verify scanner pod starts without Python import errors in logs
- [x] 6.3 Confirm scan completes, results are written to MongoDB `scan_results` collection, and execution logs appear in `execution_logs` collection
- [x] 6.4 Confirm SNS alert email is received (if vulnerabilities above threshold exist) or no-alert message is logged
