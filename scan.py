#!/usr/bin/env python3
import os
import sys
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
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("dependency-scanner")

def get_env_var(name, default=None, required=False):
    val = os.getenv(name, default)
    if required and not val:
        logger.error(f"Missing required environment variable: {name}")
        sys.exit(1)
    return val

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

# MongoDB Configuration
MONGO_URI = get_env_var("MONGO_URI")  # Optional: e.g., mongodb://host:27017
MONGO_DB = get_env_var("MONGO_DB", "dependency_check")
MONGO_COLLECTION = get_env_var("MONGO_COLLECTION", "scan_results")

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

def scan_repository(repo):
    """Clone, scan, and parse results of a repository."""
    repo_name = repo['full_name']
    clone_url = get_auth_clone_url(repo)
    
    # Create temp directory for cloning
    temp_dir = tempfile.mkdtemp()
    report_dir = tempfile.mkdtemp()
    
    try:
        logger.info(f"Cloning {repo_name}...")
        # Shallow clone to minimize disk and network usage
        subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, temp_dir],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
        
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
        subprocess.run(cmd, check=True)
        
        report_file = os.path.join(report_dir, "dependency-check-report.json")
        if not os.path.exists(report_file):
            logger.warning(f"No report file generated for {repo_name}")
            return None
            
        with open(report_file, 'r') as f:
            report_data = json.load(f)
            
        report = parse_report(repo_name, report_data)
        if report:
            save_to_mongodb(report)
        return report
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failure during scan of {repo_name}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error scanning {repo_name}: {str(e)}")
        return None
    finally:
        # Cleanup temp dirs
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

def main():
    logger.info("Starting Daily OWASP Dependency-Check scan...")
    
    try:
        repos = fetch_repositories()
    except Exception as e:
        logger.error(f"Initialization failure: {str(e)}")
        sys.exit(1)
        
    results = []
    for index, repo in enumerate(repos, 1):
        logger.info(f"[{index}/{len(repos)}] Processing {repo['full_name']}...")
        res = scan_repository(repo)
        if res:
            results.append(res)
            
    send_alert(results)
    logger.info("Daily scanning job complete.")

if __name__ == "__main__":
    main()
