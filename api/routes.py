"""
FastAPI Routes
POST /scan       — Input scanner (rule-based + heuristic detection)
GET  /logs       — Audit log viewer
GET  /health     — Health + scanner status
GET  /stats      — Dashboard data feed
GET  /dashboard  — Live dashboard UI
"""

import time as _time
from collections import defaultdict
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from security.scanner import scan_async
from api.logger import setup_logger, get_recent_logs
from api.dashboard import DASHBOARD_HTML

router = APIRouter()
logger = setup_logger("routes")


class ScanRequest(BaseModel):
    message: str
    history: list[dict] = []


# ─────────────────────────────────────────────────────────────
# In-memory scan history (populated by /scan)
# ─────────────────────────────────────────────────────────────

_scan_history: list[dict] = []   # capped at 500 entries
_rule_counts: dict = defaultdict(int)
_action_counts = {"BLOCK": 0, "WARN": 0, "ALLOW": 0}


def _record_scan(raw_input: str, result) -> None:
    """Update in-memory stats after every scan."""
    global _scan_history
    entry = {
        "id":     f"{_time.time():.6f}",
        "ts":     _time.time(),
        "input":  raw_input,
        "action": result.action,
        "score":  result.risk_score,
        "rules":  [m.rule_id for m in result.rule_matches],
    }
    _scan_history.append(entry)
    if len(_scan_history) > 500:
        _scan_history = _scan_history[-500:]
    _action_counts[result.action] = _action_counts.get(result.action, 0) + 1
    for m in result.rule_matches:
        _rule_counts[m.rule_id] += 1


# ─────────────────────────────────────────────────────────────
# POST /scan — Input scanner
# ─────────────────────────────────────────────────────────────

@router.post("/scan")
async def scan_only(request: ScanRequest):
    """
    Run the input scanner against the provided message.
    Accepts optional history for context-aware multi-turn detection.
    Returns action (BLOCK / WARN / ALLOW), risk score, and full evidence.
    """
    result = await scan_async(request.message, history=request.history)
    _record_scan(request.message, result)

    logger.info(
        f"[/scan] action={result.action} score={result.risk_score:.3f} "
        f"lang={result.language_detected} rules={len(result.rule_matches)}"
    )
    return result.to_dict()


# ─────────────────────────────────────────────────────────────
# GET /logs
# ─────────────────────────────────────────────────────────────

@router.get("/logs")
async def view_logs(n: int = 50):
    logs = get_recent_logs(n)
    return {"count": len(logs), "entries": logs}


# ─────────────────────────────────────────────────────────────
# GET /health
# ─────────────────────────────────────────────────────────────

@router.get("/health")
async def health():
    return {
        "status":   "ok",
        "scanner":  "active",
        "features": {
            "input_scan":     True,
            "context_aware":  True,
            "multi_language": True,
            "deduplication":  True,
            "leetspeak_norm": True,
        },
        "thresholds": {
            "block": 0.65,
            "warn":  0.33,
        },
    }


# ─────────────────────────────────────────────────────────────
# GET /stats — dashboard data feed
# ─────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats():
    total = sum(_action_counts.values())
    block = _action_counts.get("BLOCK", 0)
    warn  = _action_counts.get("WARN",  0)
    allow = _action_counts.get("ALLOW", 0)

    blocked_scores  = [s["score"] for s in _scan_history if s["action"] == "BLOCK"]
    avg_score       = round(sum(blocked_scores) / len(blocked_scores), 3) if blocked_scores else 0.0
    detection_rate  = round((block + warn) / total * 100) if total else 0

    return {
        "total":          total,
        "block":          block,
        "warn":           warn,
        "allow":          allow,
        "avg_score":      avg_score,
        "detection_rate": detection_rate,
        "rule_counts":    dict(_rule_counts),
        "recent_scans":   _scan_history[-40:],
    }


# ─────────────────────────────────────────────────────────────
# GET /dashboard — serve the HTML page
# ─────────────────────────────────────────────────────────────

@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)