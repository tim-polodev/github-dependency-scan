"""
scanner.repository — Repository cloning, updating, and OWASP Dependency-Check invocation.
"""
import os
import json
import shutil
import tempfile
import subprocess

from scanner.config import (
    PRESERVE_REPOS,
    DATA_DIR,
    NVD_API_KEY,
)
from scanner.github import get_auth_clone_url
from scanner.logging_setup import logger
from scanner.remediation import remediate_and_create_pr
from scanner.report import parse_report
from scanner.storage import save_to_mongodb
from scanner.utils import run_cmd


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
                logger.warning(
                    f"Failed to update preserved repository for {repo_name}: {str(e)}. Re-cloning..."
                )
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
            "--failOnCVSS", "11",  # Prevents non-zero exit code due to CVSS score
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
