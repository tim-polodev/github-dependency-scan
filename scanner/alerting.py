"""
scanner.alerting — Format and publish the vulnerability scan report to AWS SNS.
"""
import boto3
from botocore.exceptions import ClientError

from scanner.config import AWS_REGION, AWS_SNS_TOPIC_ARN, SEVERITY_THRESHOLD
from scanner.logging_setup import logger


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
        # boto3 automatically loads credentials from AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
        # or K8s ServiceAccount IAM roles
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
