# Daily Kubernetes OWASP Dependency-Check Scanner

This service runs OWASP Dependency-Check daily on all your GitHub repositories, using an NVD API key to keep vulnerability data up to date, caches findings in a Kubernetes Persistent Volume to keep scans fast, and sends alerts for discovered vulnerabilities via AWS SNS email.

## Features
* **Automated Discovery**: Scans all repositories under a specific GitHub user account, organization, or a custom list.
* **Smart Database Caching**: Persists the NVD vulnerability database in a Kubernetes PersistentVolumeClaim (PVC). Instead of downloading ~2GB+ on every run (which triggers NVD rate limiting and is slow), it only fetches daily incremental updates.
* **AWS SNS Alerting**: Generates structured security digests and publishes them to an AWS SNS topic, which sends notifications directly to your subscribed email.
* **Kubernetes Native**: Designed to run as a daily non-root Kubernetes `CronJob` with strict resource guidelines.

---

## Prerequisites

Before deploying, ensure you have:
1. **A Self-hosted Kubernetes Cluster**: Named `"kubernetes"`.
2. **GitHub Personal Access Token (PAT)**: With `repo` scope (for private repositories) or `public_repo` (for public repositories only).
3. **NVD API Key**: Request a free key from the [NVD website](https://nvd.nist.gov/developers/request-an-api-key) to bypass anonymous rate limits and speed up downloads.
4. **AWS SNS Topic**:
   - Create a standard FIFO or Standard SNS topic in your AWS console (e.g. `DependencyCheckAlerts`).
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

---

## Step 1: Build and Push the Docker Image

Build the custom scanner Docker image locally for the cluster's x86_64 architecture and push it directly to your private registry:

```bash
# 1. Enable QEMU/binfmt emulation for cross-compiling on your Mac
docker run --privileged --rm tonistiigi/binfmt --install all

# 2. Build for x86_64 architecture and push to your local private registry
docker buildx build --platform linux/amd64 -t 192.168.1.6:5000/dependency-scanner:latest --push .
```

---

## Step 2: Configure Kubernetes Manifests

Navigate to the `k8s` directory and update the config files:

### 1. Configure Secrets (`k8s/secret.yaml`)
Open `k8s/secret.yaml` and fill in your actual credentials. The values must be raw text (Kubernetes will base64-encode them on deployment since they are inside `stringData`):
```yaml
stringData:
  GITHUB_TOKEN: "ghp_yourActualGitHubTokenHere..."
  NVD_API_KEY: "your-nvd-api-key-uuid..."
  AWS_ACCESS_KEY_ID: "AKIA..."
  AWS_SECRET_ACCESS_KEY: "secret-key-..."
```

### 2. Configure Settings (`k8s/configmap.yaml`)
Open `k8s/configmap.yaml` and configure your scan scope and alert settings:
* Set `GITHUB_USER` or `GITHUB_ORG` to fetch repositories automatically. Or specify `GITHUB_REPOS` with a comma-separated list of repos (e.g., `owner/repo-a,owner/repo-b`).
* Modify `SEVERITY_THRESHOLD` (choices: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). Only vulnerabilities matching or exceeding this level will trigger email alerts.
* Set your `AWS_REGION` and `AWS_SNS_TOPIC_ARN`.

### 3. Update CronJob Image Reference (`k8s/cronjob.yaml`)
Open `k8s/cronjob.yaml` and verify the container image reference points to your local registry image:
```yaml
            - name: scanner
              image: 192.168.1.6:5000/dependency-scanner:latest
```

---

## Step 3: Deploy to Kubernetes

Apply the manifests to your cluster. This will create a separate `dependency-check` namespace, deploy the config, secrets, setup persistent caching, and register the CronJob:

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Apply the storage, credentials, and settings
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/configmap.yaml

# Schedule the CronJob
kubectl apply -f k8s/cronjob.yaml
```

---

## Step 4: Verification and Testing

You do not need to wait until the scheduled time (2:00 AM daily) to test the scanner. You can trigger an ad-hoc Kubernetes Job from the CronJob definition immediately:

```bash
# Spawn a manual job from the CronJob
kubectl create job --from=cronjob/dependency-scanner dependency-scanner-manual -n dependency-check

# Watch the pod initialization and scan logs
kubectl get pods -n dependency-check -w
kubectl logs -f job/dependency-scanner-manual -n dependency-check
```

Once the run is complete, clean up the manual test job:
```bash
kubectl delete job dependency-scanner-manual -n dependency-check
```

---

## Database Initialization Note

* **First Run**: During the first execution, Dependency-Check will download and seed the entire NVD H2 database into the Persistent Volume (`/data`). This initial download takes about **5 to 15 minutes** (even with an API key) depending on your self-hosted server's bandwidth.
* **Subsequent Runs**: In all subsequent daily runs, the scanner will mount the existing `/data` directory and perform lightweight, incremental updates. This typically completes in **under 2 minutes** per repository scan, ensuring highly efficient operations.
