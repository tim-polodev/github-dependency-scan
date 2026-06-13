"""
scanner.report — Parse OWASP Dependency-Check JSON reports into structured findings.
"""
from scanner.config import SEVERITY_THRESHOLD
from scanner.logging_setup import logger
from scanner.utils import get_severity_weight


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

    logger.info(
        f"Scan complete for {repo_name}. "
        f"Found {len(findings)} vulnerabilities matching threshold {SEVERITY_THRESHOLD}."
    )
    return {
        "repo_name": repo_name,
        "findings": findings,
        "severity_breakdown": severity_breakdown
    }
