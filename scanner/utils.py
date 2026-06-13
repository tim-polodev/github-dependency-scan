"""
scanner.utils — Generic helpers shared across scanner modules.
"""
import subprocess

from scanner.logging_setup import logger


def run_cmd(cmd, cwd=None, check=True):
    """Run a subprocess command, logging failures. Raises on non-zero exit if check=True."""
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


def get_severity_weight(severity_str):
    """Return the numeric weight for a severity string."""
    from scanner.config import SEVERITY_WEIGHTS  # local import avoids potential early-load issues
    if not severity_str:
        return 0
    return SEVERITY_WEIGHTS.get(severity_str.upper(), 0)
