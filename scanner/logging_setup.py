"""
scanner.logging_setup — Centralised logging configuration for the dependency scanner.

Provides a shared ``logger`` and ``log_buffer`` used across all modules.
``log_buffer`` captures the full execution log for persistence to MongoDB.
"""
import io
import sys
import logging

# In-memory buffer that accumulates the full run log for MongoDB persistence
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
