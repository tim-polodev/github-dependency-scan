"""
scanner.storage — MongoDB persistence for scan results and execution logs.
"""
import sys
import datetime

from pymongo import MongoClient

from scanner.config import (
    MONGO_URI,
    MONGO_DB,
    MONGO_COLLECTION,
    MONGO_LOGS_COLLECTION,
)
from scanner.logging_setup import logger, log_buffer


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
