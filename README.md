# Daily Kubernetes OWASP Dependency-Check Scanner

This service runs OWASP Dependency-Check daily on all your GitHub repositories, using an NVD API key to keep vulnerability data up to date, caches findings in a Kubernetes Persistent Volume to keep scans fast, archives full JSON findings into MongoDB, and sends compact alerts for discovered vulnerabilities via AWS SNS email.

## Features
* **Automated Discovery**: Scans all repositories under a specific GitHub user account, organization, or a custom list.
* **Smart Database Caching**: Persists the NVD vulnerability database in a Kubernetes PersistentVolumeClaim (PVC). Instead of downloading ~2GB+ on every run (which triggers NVD rate limiting and is slow), it only fetches daily incremental updates.
* **MongoDB Report Archiving**: Saves full JSON reports containing granular vulnerability findings, severity breakdowns, and metadata into a MongoDB collection (`scan_results`) automatically.
* **Compact AWS SNS Alerts**: Rather than sending massive raw logs, the scanner aggregates findings and publishes a concise email digest showing the repository name, total CVE count, and severity breakdown (e.g., `1 CRITICAL, 3 HIGH`).
* **Automated Remediation**: Automatically remediates `HIGH` or `CRITICAL` vulnerability findings using ecosystem tools (`npm audit fix` for Node.js, `pip-audit --fix` for Python). By default, this only applies **non-breaking upgrades**. However, you can configure it to fix **all npm audit issues including breaking changes** (via `npm audit fix --force`) and automatically create a pull request.
* **Multi-Version Runtime Environments**: Supports dynamic Python (`3.8` to `3.12`) and Node.js versions (managed via NVM) in the scanner container. It reads `.python-version`, `.nvmrc`, or `.node-version` files per repository to execute audit and remediation tools inside exact matching runtimes.
* **Repository Storage Persistence**: Optionally preserves cloned repository storage inside the Persistent Volume (under `/data/repos`). When enabled, subsequent runs will perform fast local updates (`git fetch` and reset) rather than cloning from scratch, saving network bandwidth and execution time.
* **Subnet Overlap Bypass**: Bypasses Calico CNI packet drops or DNS timeouts in self-hosted bare metal clusters by specifying `dnsPolicy: None` and fallback public nameservers (`8.8.8.8`, `1.1.1.1`) directly inside the pod template.
* **Automated Volume Permissions**: Includes a root-owned `initContainer` (`volume-permissions`) to execute `chown -R 1000:1000 /data` automatically, allowing the non-root scanner main container to read/write to physical cluster persistent storage without host-level privilege modifications.
* **Kubernetes Native**: Runs as a daily non-root Kubernetes `CronJob` with strict resource guidelines.

---

## Prerequisites

Before deploying, ensure you have:
1. **A Kubernetes Cluster**: Self-hosted or cloud-based.
2. **GitHub Personal Access Token (PAT)**: With `repo` scope (for private repositories) or `public_repo` (for public repositories only).
3. **NVD API Key (Optional)**: Request a free key from the [NVD website](https://nvd.nist.gov/developers/request-an-api-key) to bypass anonymous rate limits. If kept empty, the scanner will gracefully run in anonymous mode.
4. **AWS SNS Topic**:
   - Create a standard SNS topic in your AWS console (e.g., `DependencyCheckAlerts`).
   - Subscribe your target email address(es) to this topic and confirm the subscription.
   - Secure an IAM Access Key and Secret Key with permissions to publish to this topic:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Action": "sns:Publish",
           "Resource": "arn:aws:sns:YOUR_REGION:YOUR_ACCOUNT_ID:YOUR_TOPIC_NAME"
         }
       ]
     }
     ```
5. **MongoDB Instance (Optional)**: A MongoDB database server (e.g., MongoDB Atlas or self-hosted) to archive full scan logs.

---

## Repository Structure & Security

This repository separates generic public deployment templates from local, active configuration environments:
* **`k8s-templates/`**: Fully genericized, public-safe templates containing placeholders (e.g., `<BASE64_ENCODED_GITHUB_TOKEN>`). This directory is fully tracked and safe to push to public repositories.
* **`k8s/`**: Your local deployment folder containing active, live secrets, node names, and private connection URIs. **This folder is globally ignored by `.gitignore`** to ensure local production settings never leak.

---

## Step 1: Build and Push the Docker Image

Build the custom scanner Docker image locally for the cluster's architecture and push it directly to your registry:

```bash
# 1. Enable QEMU/binfmt emulation for cross-compiling on your host machine
docker run --privileged --rm tonistiigi/binfmt --install all

# 2. Build for target architecture (e.g., linux/amd64) and push to your registry
docker buildx build --platform linux/amd64 -t your-registry:5000/dependency-scanner:latest --push .
```

---

## Step 2: Configure Kubernetes Manifests

To configure your cluster deployment, copy the generic templates into your private local config folder:

```bash
# Copy clean templates to local k8s directory (which is ignored by Git)
cp -r k8s-templates k8s
```

Now open and customize the local files in `k8s/`:

### 1. Configure Secrets (`k8s/secret.yaml`)
Fill in your base64-encoded credentials. You can generate base64 strings locally using `echo -n "value" | base64`:
```yaml
data:
  GITHUB_TOKEN: "<BASE64_ENCODED_GITHUB_TOKEN>"
  NVD_API_KEY: "<BASE64_ENCODED_NVD_API_KEY>"
  AWS_ACCESS_KEY_ID: "<BASE64_ENCODED_AWS_ACCESS_KEY_ID>"
  AWS_SECRET_ACCESS_KEY: "<BASE64_ENCODED_AWS_SECRET_ACCESS_KEY>"
  # Connection string. Note: if the user database defaults to admin auth, append ?authSource=admin
  # e.g., base64 of 'mongodb://mongo:pass@polodev.cloud:27017/dependency-check?authSource=admin'
  MONGO_URI: "<BASE64_ENCODED_MONGO_URI>"
```

### 2. Configure Settings (`k8s/configmap.yaml`)
* Set `GITHUB_USER` or `GITHUB_ORG` to fetch repositories automatically. Or specify `GITHUB_REPOS` with a comma-separated list of repos (e.g., `owner/repo-a,owner/repo-b`).
* Modify `SEVERITY_THRESHOLD` (choices: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). Only vulnerabilities matching or exceeding this level will trigger email alerts.
* Set your `AWS_REGION` and `AWS_SNS_TOPIC_ARN`.
* Enable or disable optional parameters:
  * `PRESERVE_REPOS`: Set to `"true"` (recommended) to preserve cloned repositories inside the persistent volume (under `/data/repos`) to speed up subsequent scans.
  * `FIX_BREAKING_CHANGES`: Set to `"true"` if you want the automated remediation agent to apply breaking changes when fixing NPM dependencies (`npm audit fix --force`) and push those changes in the PR.

### 3. Setup Persistent Volume (`k8s/pv.yaml`)
* Replace `<YOUR_HOST_PATH_DIRECTORY>` with the directory path on your host node.
* Replace `<YOUR_NODE_HOSTNAME>` with the hostname of the target worker node where this volume will be pinned.

### 4. Update CronJob Image Reference (`k8s/cronjob.yaml`)
* Update the container image path to point to your registry:
```yaml
            - name: scanner
              image: your-registry:5000/dependency-scanner:latest
```

---

## Step 3: Deploy to Kubernetes

Apply the local config manifests from your `k8s` directory:

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Apply the storage, credentials, and settings
kubectl apply -f k8s/pv.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/configmap.yaml

# Schedule the CronJob
kubectl apply -f k8s/cronjob.yaml
```

---

## Step 4: Verification and Testing

You can trigger an ad-hoc Kubernetes Job using the provided manual job manifest or directly from the CronJob definition:

### Option A: Using the Manual Job Manifest (Recommended)
You can customize configuration options in `k8s/configmap.yaml` and trigger a run:
```bash
# Create the manual job
kubectl apply -f k8s/manual-job.yaml
```

### Option B: Spawning from the CronJob Definition
Alternatively, you can trigger a run directly from the scheduled CronJob:
```bash
# Spawn a manual job from the CronJob definition
kubectl create job --from=cronjob/dependency-scanner dependency-scanner-manual -n dependency-check
```

### Watching Logs and Cleaning Up
Once the job is created, you can watch the scanner logs and clean up when complete:
```bash
# Watch the pod initialization and scan logs
kubectl get pods -n dependency-check -w
kubectl logs -f job/dependency-scanner-manual -n dependency-check -c scanner

# Once complete, clean up the manual job
kubectl delete job dependency-scanner-manual -n dependency-check
```

---

## Troubleshooting & Operations

### Stale Database Locks
If a scan pod is forcefully terminated or killed mid-update, a lock file named `odc.update.lock` might be left behind on the Persistent Volume. Subsequent runs will print logs indicating they are waiting for the update to complete and eventually time out:
```
[INFO] Lock file found `/data/odc.update.lock`
[INFO] Existing update in progress; waiting for update to complete
```

**Resolution**:
Since the previous pod is no longer active, you can clear this stale lock immediately by deleting the file. On your storage host node, run:
```bash
ssh <YOUR_STORAGE_NODE> "rm -f /data/dependency-check-nvd-cache/odc.update.lock"
```
The scanner will immediately detect the file deletion and resume scanning.

### Database Initialization
* **First Run**: During the first execution, Dependency-Check will download and seed the entire NVD H2 database into the Persistent Volume. This takes about **5 to 15 minutes** depending on your bandwidth.
* **Subsequent Runs**: Daily incremental updates typically complete in **under 2 minutes** per repository, making execution extremely fast.

### Multi-Version Runtime Support (Remediation)
Different repositories often target distinct language versions. To ensure remediation tools like `npm audit` and `pip-audit` execute successfully without runtime conflicts, the scanner container is equipped with environment tools:
* **Node.js (NVM)**: Node Version Manager is pre-installed. The orchestrator checks each repository for a `.nvmrc` or `.node-version` file. If found, NVM dynamically installs and switches to that Node/npm version before executing audit fixes. The system defaults to Node `20.11.1`.
* **Python (Deadsnakes)**: Pre-compiled binaries for Python `3.8`, `3.9`, `3.11`, and `3.12` (with `3.10` as system default) are installed in the image. The orchestrator checks each repository for a `.python-version` file, creates an isolated virtual environment (`venv`) using that specific interpreter, installs `pip-audit`, performs the remediation, and cleans up the virtual environment before committing.

---

## Pre-commit Security Scans (Git Hooks)

To maintain codebase security and prevent secret leaks or vulnerability introductions, this repository includes automated pre-commit scanning powered by **Gitleaks** and **Semgrep**.

These scans run automatically before every git commit when configured.

### Prerequisites

Ensure you have the required CLI tools installed on your development machine:

```bash
# macOS (using Homebrew)
brew install gitleaks semgrep

# Linux / Other platforms
# Refer to official installation guides:
# - Gitleaks: https://github.com/gitleaks/gitleaks
# - Semgrep: https://github.com/semgrep/semgrep
```

### Setup Git Hooks

Configure Git to use the local `.githooks` directory and make the scripts executable by running:

```bash
./setup-git-hooks.sh
```

Once executed, every time you run `git commit`, the hook will:
1. Scan for hardcoded credentials (API keys, secrets, tokens) via `gitleaks protect --staged`.
2. Analyze the code for security vulnerabilities via `semgrep scan --config=auto`.

If any issues are found, the commit is blocked until they are resolved.

### Alternative: Pre-Commit Framework

If you prefer using the standard `pre-commit` Python package manager, a `.pre-commit-config.yaml` is also provided. You can initialize it by installing the tool and running:

```bash
pip install pre-commit
pre-commit install
```

