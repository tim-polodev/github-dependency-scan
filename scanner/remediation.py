"""
scanner.remediation — Auto-remediation via pip-audit / npm audit fix and GitHub PR creation.
"""
import os
import sys
import shutil
import datetime
import subprocess

import requests

from scanner.config import (
    GITHUB_TOKEN,
    FIX_BREAKING_CHANGES,
)
from scanner.github import get_github_headers
from scanner.logging_setup import logger
from scanner.utils import run_cmd


# ── Node.js helpers ───────────────────────────────────────────────────────────

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


# ── Python helpers ────────────────────────────────────────────────────────────

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


# ── Main remediation entry point ──────────────────────────────────────────────

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
                logger.warning(
                    f"[{repo_name}] Detected Python version {py_ver} but {candidate_binary} is not installed. "
                    f"Falling back to default Python."
                )

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
            logger.info(
                f"[{repo_name}] No files were modified during remediation. "
                f"Skipping branch push and PR creation."
            )
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
        headers = get_github_headers()

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
                logger.warning(
                    f"[{repo_name}] Failed to assign reviewer {author_username}: "
                    f"{rev_res.status_code} - {rev_res.text}"
                )

            # B. Add comment to tag the author
            comments_url = f"https://api.github.com/repos/{repo_name}/issues/{pr_number}/comments"
            comment_payload = {
                "body": f"Hey @{author_username}, please review this automated security remediation pull request."
            }
            comment_res = requests.post(comments_url, headers=headers, json=comment_payload)
            if comment_res.status_code == 201:
                logger.info(f"[{repo_name}] Tagged author in comment.")
            else:
                logger.warning(
                    f"[{repo_name}] Failed to add comment: {comment_res.status_code} - {comment_res.text}"
                )

    except subprocess.CalledProcessError as e:
        logger.error(f"[{repo_name}] Command failure during auto-remediation/push: {str(e)}")
    except Exception as e:
        logger.error(f"[{repo_name}] Unexpected error during remediation and PR creation: {str(e)}")
