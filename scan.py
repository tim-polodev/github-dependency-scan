#!/usr/bin/env python3
import os
import sys
import io
import json
import shutil
import logging
import subprocess
import tempfile
import datetime
import requests
import boto3
from botocore.exceptions import ClientError
from pymongo import MongoClient

# Configure Logging
log_buffer = io.StringIO()
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(log_formatter)

buffer_handler = logging.StreamHandler(log_buffer)
buffer_handler.setFormatter(log_formatter)

logging.basicConfig(
    level=logging.INFO,
    handlers=[
        stdout_handler,
        buffer_handler
    ]
)
logger = logging.getLogger("dependency-scanner")

def get_env_var(name, default=None, required=False):
    val = os.getenv(name, default)
    if required and not val:
        logger.error(f"Missing required environment variable: {name}")
        sys.exit(1)
    return val

def run_cmd(cmd, cwd=None, check=True):
    res = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False
    )
    if res.returncode != 0:
        logger.warning(
            f"Command failed: {' '.join(cmd)} (Exit Code: {res.returncode})\n"
            f"Stdout: {res.stdout.strip() if res.stdout else ''}\n"
            f"Stderr: {res.stderr.strip() if res.stderr else ''}"
        )
        if check:
            raise subprocess.CalledProcessError(res.returncode, cmd, output=res.stdout, stderr=res.stderr)
    return res

# Configuration
GITHUB_TOKEN = get_env_var("GITHUB_TOKEN", required=True)
NVD_API_KEY = get_env_var("NVD_API_KEY")
GITHUB_USER = get_env_var("GITHUB_USER")
GITHUB_ORG = get_env_var("GITHUB_ORG")
GITHUB_REPOS = get_env_var("GITHUB_REPOS")  # Comma-separated list e.g. "owner/repo1,owner/repo2"
SEVERITY_THRESHOLD = get_env_var("SEVERITY_THRESHOLD", "HIGH").upper()
DATA_DIR = get_env_var("DATA_DIR", "/data")
AWS_REGION = get_env_var("AWS_REGION", "us-east-1")
AWS_SNS_TOPIC_ARN = get_env_var("AWS_SNS_TOPIC_ARN", required=True)

# Storage & Remediation Options
PRESERVE_REPOS = get_env_var("PRESERVE_REPOS", "false").lower() == "true"
FIX_BREAKING_CHANGES = get_env_var("FIX_BREAKING_CHANGES", "false").lower() == "true"

# MongoDB Configuration
MONGO_URI = get_env_var("MONGO_URI")  # Optional: e.g., mongodb://host:27017
MONGO_DB = get_env_var("MONGO_DB", "dependency_check")
MONGO_COLLECTION = get_env_var("MONGO_COLLECTION", "scan_results")
MONGO_LOGS_COLLECTION = get_env_var("MONGO_LOGS_COLLECTION", "execution_logs")

# Severity weighting for comparison
SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "UNSPECIFIED": 0
}

def get_severity_weight(severity_str):
    if not severity_str:
        return 0
    return SEVERITY_WEIGHTS.get(severity_str.upper(), 0)

def fetch_repositories():
    """Fetch repositories from GitHub based on configuration."""
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    if GITHUB_REPOS:
        repos_list = [r.strip() for r in GITHUB_REPOS.split(",") if r.strip()]
        logger.info(f"Scanning specified repositories: {repos_list}")
        repos = []
        for repo_name in repos_list:
            url = f"https://api.github.com/repos/{repo_name}"
            res = requests.get(url, headers=headers)
            if res.status_code == 200:
                repos.append(res.json())
            else:
                logger.error(f"Failed to fetch repository {repo_name}: {res.status_code} - {res.text}")
        return repos

    repos = []
    if GITHUB_ORG:
        url = f"https://api.github.com/orgs/{GITHUB_ORG}/repos"
        logger.info(f"Fetching all repositories for organization: {GITHUB_ORG}")
    elif GITHUB_USER:
        url = f"https://api.github.com/users/{GITHUB_USER}/repos"
        logger.info(f"Fetching all public repositories for user: {GITHUB_USER}")
    else:
        url = "https://api.github.com/user/repos"
        logger.info("Fetching all accessible repositories for authenticated user")
        
    params = {"per_page": 100, "page": 1, "type": "all"}
    while True:
        res = requests.get(url, headers=headers, params=params)
        if res.status_code != 200:
            logger.error(f"GitHub API Error: {res.status_code} - {res.text}")
            raise Exception("Failed to list GitHub repositories")
        
        page_repos = res.json()
        if not page_repos:
            break
        repos.extend(page_repos)
        params["page"] += 1
        
    logger.info(f"Discovered {len(repos)} repositories to process")
    return repos

def get_auth_clone_url(repo):
    """Generate authenticated URL for cloning private repositories."""
    raw_url = repo['clone_url']
    if raw_url.startswith("https://github.com/"):
        return raw_url.replace("https://github.com/", f"https://x-access-token:{GITHUB_TOKEN}@github.com/")
    return raw_url

def save_to_mongodb(result):
    """Save scan results to MongoDB if MONGO_URI is configured."""
    if not MONGO_URI:
        return
    
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        db = client[MONGO_DB]
        collection = db[MONGO_COLLECTION]
        
        # Prepare document
        doc = {
            "repo_name": result["repo_name"],
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "total_vulnerabilities": len(result["findings"]),
            "severity_breakdown": result["severity_breakdown"],
            "findings": result["findings"]
        }
        
        # Insert report
        collection.insert_one(doc)
        logger.info(f"Scan report for {result['repo_name']} successfully saved to MongoDB.")
    except Exception as e:
        logger.error(f"Failed to save report to MongoDB for {result['repo_name']}: {str(e)}")

def save_execution_logs(start_time, status):
    """Save execution logs to MongoDB if MONGO_URI is configured."""
    if not MONGO_URI:
        return
    
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        db = client[MONGO_DB]
        collection = db[MONGO_LOGS_COLLECTION]
        
        # Prepare document
        doc = {
            "job_id": f"job_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "start_time": start_time,
            "end_time": datetime.datetime.utcnow().isoformat() + "Z",
            "status": status,
            "logs": log_buffer.getvalue()
        }
        
        # Insert logs
        collection.insert_one(doc)
        print(f"Execution logs successfully saved to MongoDB (Collection: {MONGO_LOGS_COLLECTION}).")
    except Exception as e:
        print(f"Failed to save execution logs to MongoDB: {str(e)}", file=sys.stderr)

def scan_repository(repo):
    """Clone, scan, and parse results of a repository."""
    repo_name = repo['full_name']
    clone_url = get_auth_clone_url(repo)
    
    # Determine directory for cloning
    is_temp_repo = not PRESERVE_REPOS
    if PRESERVE_REPOS:
        repos_base_dir = os.path.join(DATA_DIR, "repos")
        temp_dir = os.path.join(repos_base_dir, repo_name)
    else:
        temp_dir = tempfile.mkdtemp()
        
    report_dir = tempfile.mkdtemp()
    default_branch = repo.get('default_branch', 'main')
    
    try:
        repo_dir_exists = os.path.exists(temp_dir) and os.path.exists(os.path.join(temp_dir, ".git"))
        if PRESERVE_REPOS and repo_dir_exists:
            logger.info(f"Using preserved repository directory for {repo_name}. Updating...")
            try:
                # Clean up any local changes/untracked files from previous runs
                run_cmd(["git", "reset", "--hard"], cwd=temp_dir)
                run_cmd(["git", "clean", "-fdx"], cwd=temp_dir)
                # Checkout default branch
                run_cmd(["git", "checkout", default_branch], cwd=temp_dir)
                # Fetch latest commits
                run_cmd(["git", "fetch", "origin", default_branch, "--depth", "1"], cwd=temp_dir)
                # Reset to latest remote commit
                run_cmd(["git", "reset", "--hard", f"origin/{default_branch}"], cwd=temp_dir)
            except Exception as e:
                logger.warning(f"Failed to update preserved repository for {repo_name}: {str(e)}. Re-cloning...")
                shutil.rmtree(temp_dir, ignore_errors=True)
                repo_dir_exists = False
                
        if not PRESERVE_REPOS or not repo_dir_exists:
            logger.info(f"Cloning {repo_name}...")
            if PRESERVE_REPOS:
                os.makedirs(os.path.dirname(temp_dir), exist_ok=True)
            # Shallow clone to minimize disk and network usage
            run_cmd(["git", "clone", "--depth", "1", clone_url, temp_dir])
        
        logger.info(f"Running Dependency-Check on {repo_name}...")
        # Path to dependency-check CLI (we expect it in PATH, installed in docker image)
        cmd = [
            "dependency-check.sh",
            "--scan", temp_dir,
            "--format", "JSON",
            "--out", report_dir,
            "--data", DATA_DIR,
            "--project", repo_name,
            "--failOnCVSS", "11", # Prevents non-zero exit code due to CVSS score
            "--enableExperimental",
            "--disableKnownExploited"
        ]
        if NVD_API_KEY:
            cmd.extend(["--nvdApiKey", NVD_API_KEY])
        
        # Run scan
        run_cmd(cmd)
        
        report_file = os.path.join(report_dir, "dependency-check-report.json")
        if not os.path.exists(report_file):
            logger.warning(f"No report file generated for {repo_name}")
            return None
            
        with open(report_file, 'r') as f:
            report_data = json.load(f)
            
        report = parse_report(repo_name, report_data)
        if report:
            save_to_mongodb(report)
            # Check for HIGH/CRITICAL issues to trigger auto-remediation
            has_high_or_critical = any(
                f.get("severity") in ["HIGH", "CRITICAL"] for f in report.get("findings", [])
            )
            if has_high_or_critical:
                logger.info(f"[{repo_name}] HIGH/CRITICAL vulnerabilities found. Running auto-remediation...")
                remediate_and_create_pr(repo, temp_dir, report)
        return report
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failure during scan of {repo_name}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error scanning {repo_name}: {str(e)}")
        return None
    finally:
        # Cleanup temp dirs
        if is_temp_repo:
            shutil.rmtree(temp_dir, ignore_errors=True)
        shutil.rmtree(report_dir, ignore_errors=True)

def parse_report(repo_name, report_data):
    """Parse JSON report and extract vulnerabilities above severity threshold."""
    findings = []
    dependencies = report_data.get("dependencies", [])
    
    threshold_weight = get_severity_weight(SEVERITY_THRESHOLD)
    
    # Initialize breakdown
    severity_breakdown = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "UNSPECIFIED": 0
    }
    
    for dep in dependencies:
        vulnerabilities = dep.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNSPECIFIED").upper()
            vuln_weight = get_severity_weight(severity)
            
            if vuln_weight >= threshold_weight:
                severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
                findings.append({
                    "cve": vuln.get("name"),
                    "dependency": dep.get("fileName"),
                    "severity": severity,
                    "cvssv3_score": vuln.get("cvssv3", {}).get("baseScore", "N/A"),
                    "description": vuln.get("description", "No description available.")[:250] + "..."
                })
                
    logger.info(f"Scan complete for {repo_name}. Found {len(findings)} vulnerabilities matching threshold {SEVERITY_THRESHOLD}.")
    return {
        "repo_name": repo_name,
        "findings": findings,
        "severity_breakdown": severity_breakdown
    }

def send_alert(results):
    """Format and send the scan report to AWS SNS."""
    total_repos_scanned = len(results)
    repos_with_vulns = [r for r in results if r and r["findings"]]
    
    if not repos_with_vulns:
        logger.info("No vulnerabilities matching the threshold were found. Skipping email alert.")
        return
        
    logger.info(f"Vulnerabilities found in {len(repos_with_vulns)} repositories. Sending AWS SNS alert...")
    
    # Generate Email Content
    subject = f"[Security Alert] Daily Dependency-Check: {len(repos_with_vulns)} repos have vulnerabilities"
    
    body_lines = [
        "OWASP Dependency-Check Daily Scan Report",
        "========================================",
        f"Total Repositories Scanned: {total_repos_scanned}",
        f"Repositories with Vulnerabilities (Severity >= {SEVERITY_THRESHOLD}): {len(repos_with_vulns)}",
        "",
        "Summary of Findings:",
        "-------------------"
    ]
    
    for r in repos_with_vulns:
        breakdown_strs = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = r["severity_breakdown"].get(sev, 0)
            if count > 0:
                breakdown_strs.append(f"{count} {sev}")
        breakdown_line = ", ".join(breakdown_strs) if breakdown_strs else "None"
        
        body_lines.append(f"\nRepository: {r['repo_name']}")
        body_lines.append(f"  Total Risks: {len(r['findings'])}")
        body_lines.append(f"  Breakdown: {breakdown_line}")
        body_lines.append("")
            
    body_lines.append("\nThis is an automated notification from your Kubernetes Dependency-Check cronjob.")
    email_body = "\n".join(body_lines)
    
    # Publish to AWS SNS
    try:
        # boto3 automatically loads credentials from AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or K8s ServiceAccount IAM roles
        sns_client = boto3.client("sns", region_name=AWS_REGION)
        response = sns_client.publish(
            TopicArn=AWS_SNS_TOPIC_ARN,
            Subject=subject,
            Message=email_body
        )
        logger.info(f"SNS Alert successfully published. Message ID: {response['MessageId']}")
    except ClientError as e:
        logger.error(f"Failed to publish to AWS SNS: {e.response['Error']['Message']}")
    except Exception as e:
        logger.error(f"Unexpected error publishing to AWS SNS: {str(e)}")

def get_node_version(repo_dir):
    """Detect Node.js version from .nvmrc or .node-version."""
    nvmrc_path = os.path.join(repo_dir, ".nvmrc")
    node_version_path = os.path.join(repo_dir, ".node-version")
    
    if os.path.exists(nvmrc_path):
        try:
            with open(nvmrc_path, 'r') as f:
                version = f.read().strip()
                if version:
                    return version
        except Exception:
            pass
            
    if os.path.exists(node_version_path):
        try:
            with open(node_version_path, 'r') as f:
                version = f.read().strip()
                if version:
                    return version
        except Exception:
            pass
            
    return None

def run_npm_cmd_with_nvm(cmd_args, cwd, repo_name):
    """Run an npm command, using nvm to select the correct Node.js version if specified."""
    node_ver = get_node_version(cwd)
    if node_ver:
        logger.info(f"[{repo_name}] Detected Node.js version {node_ver} from config files. Using nvm...")
        node_ver = node_ver.lstrip('v').strip()
        nvm_cmd = [
            "bash", "-c",
            f"source $NVM_DIR/nvm.sh && nvm install {node_ver} && nvm use {node_ver} && {' '.join(cmd_args)}"
        ]
        return run_cmd(nvm_cmd, cwd=cwd, check=False)
    else:
        # Fall back to default Node.js
        return run_cmd(cmd_args, cwd=cwd, check=False)

def get_python_version(repo_dir):
    """Detect Python version from .python-version."""
    py_version_path = os.path.join(repo_dir, ".python-version")
    if os.path.exists(py_version_path):
        try:
            with open(py_version_path, 'r') as f:
                version = f.read().strip()
                if version:
                    parts = version.split('.')
                    if len(parts) >= 2:
                        return f"{parts[0]}.{parts[1]}"
                    return version
        except Exception:
            pass
    return None

def remediate_and_create_pr(repo, temp_dir, report):
    """Run auto-remediation inside temp_dir and create a Pull Request if changes are made."""
    repo_name = repo['full_name']
    default_branch = repo.get('default_branch', 'main')
    
    # 1. Run ecosystem-specific remediation tools
    # Python Requirements Fix
    req_file = os.path.join(temp_dir, "requirements.txt")
    if os.path.exists(req_file):
        py_ver = get_python_version(temp_dir)
        py_binary = sys.executable  # default fallback
        if py_ver:
            candidate_binary = f"python{py_ver}"
            if shutil.which(candidate_binary):
                py_binary = candidate_binary
                logger.info(f"[{repo_name}] Using detected Python version {py_ver} ({py_binary}) for remediation")
            else:
                logger.warning(f"[{repo_name}] Detected Python version {py_ver} but {candidate_binary} is not installed. Falling back to default Python.")
        
        logger.info(f"[{repo_name}] Running pip-audit --fix inside virtual environment...")
        try:
            # Create a virtual environment using the selected python binary
            venv_dir = os.path.join(temp_dir, ".scanner_venv")
            run_cmd([py_binary, "-m", "venv", venv_dir], cwd=temp_dir)
            
            # Path to pip and pip-audit inside virtual environment
            pip_path = os.path.join(venv_dir, "bin", "pip")
            pip_audit_path = os.path.join(venv_dir, "bin", "pip-audit")
            
            # Install pip-audit in the venv
            run_cmd([pip_path, "install", "--upgrade", "pip", "pip-audit"], cwd=temp_dir)
            
            # Run pip-audit to remediate requirements.txt
            run_cmd(
                [pip_audit_path, "-r", "requirements.txt", "--fix"],
                cwd=temp_dir,
                check=False
            )
            # Remove venv before git status/commit so we don't commit it
            shutil.rmtree(venv_dir, ignore_errors=True)
        except Exception as e:
            logger.error(f"[{repo_name}] Failed to run pip-audit remediation: {str(e)}")
            shutil.rmtree(os.path.join(temp_dir, ".scanner_venv"), ignore_errors=True)
            
    # Node.js package.json Fix
    package_file = os.path.join(temp_dir, "package.json")
    if os.path.exists(package_file):
        npm_cmd = ["npm", "audit", "fix"]
        if FIX_BREAKING_CHANGES:
            logger.info(f"[{repo_name}] Found package.json. Running npm audit fix --force...")
            npm_cmd.append("--force")
        else:
            logger.info(f"[{repo_name}] Found package.json. Running npm audit fix...")
        try:
            # Run npm audit fix using NVM wrapper
            run_npm_cmd_with_nvm(npm_cmd, cwd=temp_dir, repo_name=repo_name)
        except Exception as e:
            logger.error(f"[{repo_name}] Failed to run npm audit fix: {str(e)}")

    # 2. Check if git status has any changes
    try:
        status_res = run_cmd(
            ["git", "status", "--porcelain"],
            cwd=temp_dir
        )
        if not status_res.stdout.strip():
            logger.info(f"[{repo_name}] No files were modified during remediation. Skipping branch push and PR creation.")
            return
            
        logger.info(f"[{repo_name}] Dependency changes detected. Preparing commit and pull request...")
        
        # Get last commit SHA before checkout and commit
        last_commit_sha = None
        try:
            sha_res = run_cmd(
                ["git", "rev-parse", "HEAD"],
                cwd=temp_dir
            )
            last_commit_sha = sha_res.stdout.strip()
        except Exception as e:
            logger.warning(f"[{repo_name}] Failed to get HEAD commit SHA: {str(e)}")
            
        # 3. Create a new branch and commit changes
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        branch_name = f"dependency-check/auto-remediations-{timestamp}"
        
        run_cmd(["git", "config", "user.name", "Dependency-Check Bot"], cwd=temp_dir)
        run_cmd(["git", "config", "user.email", "dependency-check-bot@users.noreply.github.com"], cwd=temp_dir)
        
        run_cmd(["git", "checkout", "-b", branch_name], cwd=temp_dir)
        run_cmd(["git", "add", "."], cwd=temp_dir)
        run_cmd(["git", "commit", "-m", "security: auto-remediate high/critical dependencies"], cwd=temp_dir)
        
        # 4. Push to remote
        logger.info(f"[{repo_name}] Pushing branch {branch_name} to remote...")
        run_cmd(["git", "push", "origin", branch_name], cwd=temp_dir)
        
        # 5. Create Pull Request via GitHub API
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        # Build PR description body
        findings_list = []
        for finding in report.get("findings", []):
            if finding.get("severity") in ["HIGH", "CRITICAL"]:
                findings_list.append(
                    f"- **{finding.get('cve')}** ({finding.get('severity')}): "
                    f"`{finding.get('dependency')}` - {finding.get('description')}"
                )
        findings_body = "\n".join(findings_list)
        
        npm_fix_cmd = "npm audit fix --force" if FIX_BREAKING_CHANGES else "npm audit fix"
        pr_body = (
            f"This is an automated pull request to remediate HIGH/CRITICAL dependency vulnerabilities "
            f"found during the daily dependency scan.\n\n"
            f"### Discovered Vulnerabilities:\n{findings_body}\n\n"
            f"### Remediation Actions Applied:\n"
            f"- Checked for and applied ecosystem security updates (e.g. `pip-audit --fix` or `{npm_fix_cmd}`).\n\n"
            f"Please review and merge these changes."
        )
        
        pr_payload = {
            "title": "security: auto-remediate high/critical dependency vulnerabilities",
            "head": branch_name,
            "base": default_branch,
            "body": pr_body
        }
        
        pulls_url = f"https://api.github.com/repos/{repo_name}/pulls"
        pr_res = requests.post(pulls_url, headers=headers, json=pr_payload)
        
        if pr_res.status_code != 201:
            logger.error(f"[{repo_name}] Failed to create Pull Request: {pr_res.status_code} - {pr_res.text}")
            return
            
        pr_data = pr_res.json()
        pr_number = pr_data["number"]
        pr_url = pr_data["html_url"]
        logger.info(f"[{repo_name}] Created Pull Request #{pr_number} successfully: {pr_url}")
        
        # 6. Find the author of the last commit to request review and tag
        author_username = None
        if last_commit_sha:
            try:
                commit_url = f"https://api.github.com/repos/{repo_name}/commits/{last_commit_sha}"
                commit_res = requests.get(commit_url, headers=headers)
                if commit_res.status_code == 200:
                    commit_data = commit_res.json()
                    author_username = commit_data.get("author", {}).get("login")
            except Exception as e:
                logger.warning(f"[{repo_name}] Failed to resolve commit author login: {str(e)}")
            
        if not author_username:
            # Fallback to repo owner
            author_username = repo.get("owner", {}).get("login")
            logger.info(f"[{repo_name}] Falling back to repo owner username: {author_username}")
            
        if author_username:
            # A. Request reviewer assignment
            reviewers_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/requested_reviewers"
            reviewers_payload = {"reviewers": [author_username]}
            rev_res = requests.post(reviewers_url, headers=headers, json=reviewers_payload)
            if rev_res.status_code == 201:
                logger.info(f"[{repo_name}] Assigned reviewer: {author_username}")
            else:
                logger.warning(f"[{repo_name}] Failed to assign reviewer {author_username}: {rev_res.status_code} - {rev_res.text}")
                
            # B. Add comment to tag the author
            comments_url = f"https://api.github.com/repos/{repo_name}/issues/{pr_number}/comments"
            comment_payload = {"body": f"Hey @{author_username}, please review this automated security remediation pull request."}
            comment_res = requests.post(comments_url, headers=headers, json=comment_payload)
            if comment_res.status_code == 201:
                logger.info(f"[{repo_name}] Tagged author in comment.")
            else:
                logger.warning(f"[{repo_name}] Failed to add comment: {comment_res.status_code} - {comment_res.text}")
                
    except subprocess.CalledProcessError as e:
        logger.error(f"[{repo_name}] Command failure during auto-remediation/push: {str(e)}")
    except Exception as e:
        logger.error(f"[{repo_name}] Unexpected error during remediation and PR creation: {str(e)}")

def main():
    start_time = datetime.datetime.utcnow().isoformat() + "Z"
    status = "SUCCESS"
    
    logger.info("Starting Daily OWASP Dependency-Check scan...")
    
    try:
        try:
            repos = fetch_repositories()
        except Exception as e:
            logger.error(f"Initialization failure: {str(e)}")
            status = "FAILED"
            sys.exit(1)
            
        results = []
        for index, repo in enumerate(repos, 1):
            logger.info(f"[{index}/{len(repos)}] Processing {repo['full_name']}...")
            res = scan_repository(repo)
            if res:
                results.append(res)
                
        send_alert(results)
        logger.info("Daily scanning job complete.")
    except SystemExit as e:
        if e.code != 0:
            status = "FAILED"
        raise
    except Exception as e:
        logger.error(f"Unexpected execution failure: {str(e)}")
        status = "FAILED"
        raise
    finally:
        save_execution_logs(start_time, status)

if __name__ == "__main__":
    main()
