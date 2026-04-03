"""
Logging Infrastructure — Phase 1
Structured JSON logs for security auditing.
Every request, tool call, and response is logged.
"""

import logging
import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)


class JSONFormatter(logging.Formatter):
    """Emits one JSON object per log line — easy to pipe into SIEM/ELK."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(logging.DEBUG)

    # ── Console handler (human-readable) ──
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(
        logging.Formatter("%(asctime)s [%(name)s] %(levelname)s  %(message)s")
    )

    # ── File handler (JSON, for audit) ──
    log_file = LOG_DIR / "agent_audit.jsonl"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JSONFormatter())

    logger.addHandler(console)
    logger.addHandler(file_handler)

    return logger


def log_startup():
    logger = setup_logger("startup")
    logger.info("=" * 60)
    logger.info("🚀 LLM Prompt Injection Scanner starting")
    logger.info("🛡️  Rule-based + heuristic scanner active")
    logger.info("📋 Logging to: logs/agent_audit.jsonl")
    logger.info("=" * 60)


def get_recent_logs(n: int = 50) -> list[dict]:
    """Returns last N log entries from the audit log."""
    log_file = LOG_DIR / "agent_audit.jsonl"
    if not log_file.exists():
        return []

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    recent = lines[-n:] if len(lines) > n else lines
    result = []
    for line in recent:
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return result
