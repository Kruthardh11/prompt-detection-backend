"""
Prompt Scanner — Phase 2 (v3) — CLEANED
════════════════════════════════════════════════════════════════
Risk Score: 0.0 – 1.0  (additive, capped)
  BLOCK  : score >= 0.65  OR  any CRITICAL/HIGH rule fires
  WARN   : score >= 0.38  OR  any MEDIUM rule fires  
  ALLOW  : score < 0.38   AND no rules fired

Severity escalation (zero-trust):
  CRITICAL → always BLOCK (unchanged)
  HIGH     → always BLOCK  ← HIGH confirmed attacks must block
  MEDIUM   → always WARN   ← MEDIUM confirmed attacks must warn
  Score    → BLOCK/WARN/ALLOW by threshold

This is correct security architecture: a confirmed attack category
should not be negotiated down by composite weighting.

Other upgrades:
  - Rule deduplication: per rule_id, keep highest-scoring match
  - Multi-language: langdetect + deep-translator (graceful fallback)
  - Context-aware: scan(history=[]) for multi-turn detection
  - scan_output(): output exfiltration scanner
  - Leetspeak normalization in rules.py normalize()

Zero-trust: default to BLOCK on any scanner error.

AI VERDICT LAYER REMOVED — This layer was not cost-effective.
Rules + heuristics are deterministic and sufficient.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from security.rules import RULES, RuleMatch, normalize
from security.heuristics import run_heuristics, HeuristicSignal
from api.logger import setup_logger
import re

logger = setup_logger("scanner")

# ── Score thresholds ──
BLOCK_THRESHOLD = 0.65   # lowered from 0.70
WARN_THRESHOLD  = 0.33   # lowered from 0.38

# ── Score caps ──
RULE_SCORE_CAP      = 0.85
HEURISTIC_SCORE_CAP = 0.60

# ── Severity → minimum action (zero-trust escalation) ──
SEVERITY_FLOOR = {
    "CRITICAL": "BLOCK",
    "HIGH":     "BLOCK",   # ← key fix: HIGH always BLOCKs
    "MEDIUM":   "WARN",
    "LOW":      None,      # score-only
}

# ── Output scan patterns ──
_OUTPUT_LEAK_PATTERNS = [
    (r"root:.*:\d+:\d+:",                                   "CRITICAL", "/etc/passwd content in output"),
    (r"\$[0-9a-z]{1,2}\$[./A-Za-z0-9]{20,}",               "CRITICAL", "Password hash in output"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",    "CRITICAL", "Private key in output"),
    (r"(sk-[a-zA-Z0-9]{32,}|AKIA[A-Z0-9]{16})",            "HIGH",     "API/AWS key in output"),
    (r"(password|passwd|secret)\s*[=:]\s*\S+",              "HIGH",     "Credential assignment in output"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b","LOW",      "Email address in output"),
]

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class ScanResult:
    action:            str
    risk_score:        float
    rule_matches:      list[RuleMatch]       = field(default_factory=list)
    heuristic_signals: list[HeuristicSignal] = field(default_factory=list)
    block_reason:      str                   = ""
    warning_reason:    str                   = ""
    normalized_input:  str                   = ""
    highest_severity:  str                   = "NONE"
    language_detected: str                   = "en"

    def to_dict(self) -> dict:
        return {
            "action":            self.action,
            "risk_score":        round(self.risk_score, 3),
            "block_reason":      self.block_reason,
            "warning_reason":    self.warning_reason,
            "highest_severity":  self.highest_severity,
            "language_detected": self.language_detected,
            "rule_matches": [
                {
                    "rule_id":      r.rule_id,
                    "category":     r.category,
                    "severity":     r.severity,
                    "score":        r.score,
                    "matched_text": r.matched_text,
                    "description":  r.description,
                }
                for r in self.rule_matches
            ],
            "heuristic_signals": [
                {
                    "signal_id": h.signal_id,
                    "name":      h.name,
                    "score":     h.score,
                    "detail":    h.detail,
                }
                for h in self.heuristic_signals
            ],
        }


# ─────────────────────────────────────────────────────────────
# Language Detection
# ─────────────────────────────────────────────────────────────

def _detect_language(text: str) -> str:
    try:
        from langdetect import detect
        return detect(text)
    except Exception:
        return "unknown"


def _translate_to_english(text: str, src_lang: str) -> str:
    try:
        from deep_translator import GoogleTranslator
        return GoogleTranslator(source=src_lang, target="en").translate(text) or text
    except Exception:
        return text


def _prepare_text(raw_input: str) -> tuple[str, str]:
    lang = _detect_language(raw_input)
    if lang not in ("en", "unknown"):
        logger.info(f"[SCANNER] Non-English detected: lang={lang} — translating")
        translated = _translate_to_english(raw_input, lang)
        return translated, lang
    return raw_input, lang


# ─────────────────────────────────────────────────────────────
# Deduplication
# ─────────────────────────────────────────────────────────────

def _deduplicate_rules(matches: list[RuleMatch]) -> list[RuleMatch]:
    """Per rule_id, keep only the highest-scoring match."""
    best: dict[str, RuleMatch] = {}
    for m in matches:
        if m.rule_id not in best or m.score > best[m.rule_id].score:
            best[m.rule_id] = m
    return list(best.values())


# ─────────────────────────────────────────────────────────────
# Main scan()
# ─────────────────────────────────────────────────────────────

def scan(
    raw_input: str,
    history: list[dict] | None = None,
) -> ScanResult:
    """
    Scan user input. Returns ScanResult with action + full evidence.
    Zero-trust: any exception → BLOCK.
    """
    try:
        return _run_scan(raw_input, history or [])
    except Exception as e:
        logger.error(f"[SCANNER] Error — defaulting to BLOCK: {e}", exc_info=True)
        return ScanResult(
            action="BLOCK",
            risk_score=1.0,
            block_reason="Scanner error — blocked by zero-trust default.",
        )


async def scan_async(
    raw_input: str,
    history: list[dict] | None = None,
) -> ScanResult:
    """
    Async version of scan().
    Used by POST /scan and POST /chat endpoints.
    """
    try:
        return _run_scan(raw_input, history or [])
    except Exception as e:
        logger.error(f"[SCANNER] scan_async error — defaulting to BLOCK: {e}", exc_info=True)
        return ScanResult(
            action="BLOCK",
            risk_score=1.0,
            block_reason="Scanner error — blocked by zero-trust default.",
        )


def _run_scan(raw_input: str, history: list[dict]) -> ScanResult:
    logger.info(f"[SCANNER] Scanning ({len(raw_input)} chars, {len(history)} history turns)")

    # ── Step 0: Language detection + translation ──
    scan_text, lang = _prepare_text(raw_input)

    # ── Step 0b: Prepend recent history for context-aware scan ──
    if history:
        parts = [f"{t.get('role','user')}: {t.get('content','')}" for t in history[-3:]]
        parts.append(f"user: {scan_text}")
        scan_text = " | ".join(parts)

    norm = normalize(scan_text)

    # ── Phase A: Rule-based scan ──
    # NOTE: raw_input (original, unmodified) is passed as second arg so that
    # rules like R06 (base64) can operate on the untouched casing.
    raw_matches: list[RuleMatch] = []
    for rule_fn in RULES:
        match = rule_fn(norm, raw_input)
        if match:
            raw_matches.append(match)
            logger.warning(
                f"[SCANNER] Rule: {match.rule_id} [{match.severity}] "
                f"score={match.score} | '{match.matched_text[:60]}'"
            )

    rule_matches = _deduplicate_rules(raw_matches)
    rule_score   = min(sum(m.score for m in rule_matches), RULE_SCORE_CAP)

    # ── Phase B: Heuristics ──
    heuristic_signals = run_heuristics(norm, scan_text)
    heuristic_score   = min(
        sum(h.score for h in heuristic_signals),
        HEURISTIC_SCORE_CAP
    )
    for h in heuristic_signals:
        logger.info(f"[SCANNER] Heuristic: {h.signal_id} score={h.score} | {h.detail}")

    # ── Composite score ──
    composite = min((rule_score * 0.65) + (heuristic_score * 0.35), 1.0)

    # ── Severity escalation (zero-trust floors) ──
    highest_sev = max(
        (r.severity for r in rule_matches),
        key=lambda s: SEVERITY_ORDER.get(s, 0),
        default="NONE"
    )
    severity_floor = SEVERITY_FLOOR.get(highest_sev)

    # ── Determine action ──
    # Priority: severity floor > score threshold
    if severity_floor == "BLOCK" or composite >= BLOCK_THRESHOLD:
        action = "BLOCK"
        # Ensure composite reflects the severity (for reporting)
        composite = max(composite, BLOCK_THRESHOLD)
        top = sorted(rule_matches, key=lambda r: r.score, reverse=True)[:3]
        reasons = [f"{r.category} ({r.rule_id})" for r in top]
        if heuristic_signals:
            reasons += [h.name for h in heuristic_signals[:2]]
        block_reason = (
            "⛔ Request blocked by security scanner.\n"
            f"Risk score: {composite:.2f} | Severity: {highest_sev}\n"
            f"Triggers: {', '.join(reasons)}"
        )
        warning_reason = ""

    elif severity_floor == "WARN" or composite >= WARN_THRESHOLD:
        action = "WARN"
        block_reason = ""
        signals = [r.category for r in rule_matches] + [h.name for h in heuristic_signals]
        warning_reason = (
            f"⚠️  Potentially sensitive request (score: {composite:.2f}). "
            f"Signals: {', '.join(signals[:3])}. Proceeding with caution."
        )

    else:
        action = "ALLOW"
        block_reason = ""
        warning_reason = ""

    logger.info(
        f"[SCANNER] → {action} | score={composite:.3f} | "
        f"severity={highest_sev} | rules={len(rule_matches)} | "
        f"heuristics={len(heuristic_signals)} | lang={lang}"
    )

    return ScanResult(
        action=action,
        risk_score=composite,
        rule_matches=rule_matches,
        heuristic_signals=heuristic_signals,
        block_reason=block_reason,
        warning_reason=warning_reason,
        normalized_input=norm,
        highest_severity=highest_sev,
        language_detected=lang,
    )


# ─────────────────────────────────────────────────────────────
# scan_output() — exfiltration detection
# ─────────────────────────────────────────────────────────────

@dataclass
class OutputScanResult:
    action:          str
    findings:        list[dict] = field(default_factory=list)
    redacted_output: str        = ""

    def to_dict(self) -> dict:
        return {"action": self.action, "findings": self.findings}


def scan_output(output_text: str) -> OutputScanResult:
    try:
        return _run_output_scan(output_text)
    except Exception as e:
        logger.error(f"[OUTPUT SCANNER] Error: {e}", exc_info=True)
        return OutputScanResult(action="WARN", findings=[{"description": "Scanner error"}])


def _run_output_scan(output_text: str) -> OutputScanResult:
    findings = []
    highest = "NONE"

    for pattern, severity, description in _OUTPUT_LEAK_PATTERNS:
        matches = re.findall(pattern, output_text, re.IGNORECASE)
        if matches:
            findings.append({
                "severity":    severity,
                "description": description,
                "sample":      str(matches[0])[:60],
            })
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest, 0):
                highest = severity
            logger.warning(f"[OUTPUT SCANNER] {severity}: {description}")

    if not findings:
        return OutputScanResult(action="ALLOW", redacted_output=output_text)

    if highest == "CRITICAL":
        logger.error("[OUTPUT SCANNER] 🚨 REDACT")
        return OutputScanResult(
            action="REDACT",
            findings=findings,
            redacted_output="[Output redacted — sensitive data detected by security scanner]",
        )

    return OutputScanResult(action="WARN", findings=findings, redacted_output=output_text)