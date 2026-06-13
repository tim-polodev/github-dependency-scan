"""
scanner.config — Environment variable loading and global constants.

All configuration is resolved at import time from environment variables.
Import individual constants directly:

    from scanner.config import GITHUB_TOKEN, SEVERITY_THRESHOLD
"""
import os
import sys

from scanner.logging_setup import logger


def get_env_var(name, default=None, required=False):
    val = os.getenv(name, default)
    if required and not val:
        logger.error(f"Missing required environment variable: {name}")
        sys.exit(1)
    return val


# ── GitHub ────────────────────────────────────────────────────────────────────
GITHUB_TOKEN = get_env_var("GITHUB_TOKEN", required=True)
NVD_API_KEY = get_env_var("NVD_API_KEY")
GITHUB_USER = get_env_var("GITHUB_USER")
GITHUB_ORG = get_env_var("GITHUB_ORG")
# Comma-separated list e.g. "owner/repo1,owner/repo2"
GITHUB_REPOS = get_env_var("GITHUB_REPOS")

# ── Scanning ──────────────────────────────────────────────────────────────────
SEVERITY_THRESHOLD = get_env_var("SEVERITY_THRESHOLD", "HIGH").upper()
DATA_DIR = get_env_var("DATA_DIR", "/data")

# ── AWS ───────────────────────────────────────────────────────────────────────
AWS_REGION = get_env_var("AWS_REGION", "us-east-1")
AWS_SNS_TOPIC_ARN = get_env_var("AWS_SNS_TOPIC_ARN", required=True)

# ── Storage & Remediation ─────────────────────────────────────────────────────
PRESERVE_REPOS = get_env_var("PRESERVE_REPOS", "false").lower() == "true"
FIX_BREAKING_CHANGES = get_env_var("FIX_BREAKING_CHANGES", "false").lower() == "true"

# ── MongoDB ───────────────────────────────────────────────────────────────────
# Optional: e.g., mongodb://host:27017
MONGO_URI = get_env_var("MONGO_URI")
MONGO_DB = get_env_var("MONGO_DB", "dependency_check")
MONGO_COLLECTION = get_env_var("MONGO_COLLECTION", "scan_results")
MONGO_LOGS_COLLECTION = get_env_var("MONGO_LOGS_COLLECTION", "execution_logs")

# ── Severity weighting for comparison ─────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "UNSPECIFIED": 0
}
