## Why

Currently, the daily dependency scanner prints execution logs to standard output, which are accessible via Kubernetes logs. However, these logs are ephemeral and get lost when the pod is deleted or when the log rotation limit is reached. Archiving execution logs (including errors, warnings, and command outputs) into MongoDB ensures we have persistent, queryable historical records of every daily scan job run for debugging and auditing purposes.

## What Changes

- Implement an execution log capturing mechanism in `scan.py` that buffers all logging output during a run.
- Add configuration parameters for the MongoDB execution logs collection (`MONGO_LOGS_COLLECTION` defaulting to `execution_logs`).
- Save the accumulated logs as a structured document in MongoDB at the end of the script execution, even if the execution fails or is interrupted.
- Expose this new collection setup in the Kubernetes deployment templates (`k8s-templates/configmap.yaml`).

## Capabilities

### New Capabilities
- `execution-log-archiving`: Automatically captures and archives scanner execution logs into MongoDB at the completion of each run.

### Modified Capabilities
<!-- None -->

## Impact

- **Affected Code**: `scan.py` (logging configuration, main execution wrapper, MongoDB saving).
- **Deployment Manifests**: `k8s-templates/configmap.yaml` and `k8s-templates/secret.yaml` (if needed for extra credentials, though existing Mongo URI is sufficient).
- **Dependencies**: None.
