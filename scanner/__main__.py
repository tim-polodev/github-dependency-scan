"""
scanner.__main__ — Entrypoint for ``python -m scanner``.

Orchestrates the full daily dependency-scan run:
  1. Fetch repositories
  2. Scan each repository
  3. Send SNS alert if vulnerabilities found
  4. Persist execution logs to MongoDB
"""
import sys
import datetime

from scanner.alerting import send_alert
from scanner.github import fetch_repositories
from scanner.logging_setup import logger
from scanner.repository import scan_repository
from scanner.storage import save_execution_logs


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
