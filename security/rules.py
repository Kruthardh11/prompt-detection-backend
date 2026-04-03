"""
Rule-Based Scanner — Phase 2 (Upgraded)
════════════════════════════════════════════════════════════════
Covers all 20 attack categories from research + advanced evasion.
Each rule returns a RuleMatch if triggered, None otherwise.

Changes from v1:
  - Raised scores on R01 (0.4→0.55), R02 (0.35→0.50), R05 (0.45→0.55),
    R15 (0.4→0.50) to push HIGH-severity attacks over BLOCK threshold alone
  - R06: expanded danger_words to catch "previous instructions" base64
  - R11: fixed regex to match "passwords" plural + added standalone keywords
  - R-PT: added /etc/shadow, /etc/sudoers as explicit CRITICAL paths
  - R17: broadened patterns to catch "as admin, run" and "red teamer" variants
  - normalize(): added leetspeak substitution pass
  - All rules deduplicated by rule_id in scanner (highest score kept)

Zero-trust principle: assume every input is hostile until proven clean.
Rules run BEFORE the LLM sees the message.
"""

import re
import base64
import unicodedata
import html
from dataclasses import dataclass


@dataclass
class RuleMatch:
    rule_id:      str    # e.g. "R01"
    category:     str    # e.g. "Instruction Override"
    severity:     str    # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    score:        float  # 0.0–1.0 contribution to risk score
    matched_text: str    # what triggered it
    description:  str    # human-readable explanation


# ─────────────────────────────────────────────────────────────
# Normalizer — applied before every rule check
# ─────────────────────────────────────────────────────────────

_LEET_TABLE = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '@': 'a',
    '$': 's', '!': 'i', '+': 't',
})

def normalize(text: str) -> str:
    """
    Multi-pass normalizer to defeat obfuscation:
      1. Unicode NFKC  — collapses homoglyphs (𝙄𝙜𝙣𝙤𝙧𝙚 → ignore)
      2. HTML unescape — &#101; → e
      3. Lowercase
      4. Leetspeak     — 1gn0r3 → ignore
      5. Collapse whitespace
    """
    text = unicodedata.normalize("NFKC", text)
    text = html.unescape(text)
    text = text.lower()
    text = text.translate(_LEET_TABLE)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def try_decode_base64(text: str) -> str | None:
    """Attempt to decode any base64-looking chunks in the text."""
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
    for match in b64_pattern.finditer(text):
        try:
            decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
            if decoded and decoded.isprintable():
                return decoded.lower()
        except Exception:
            pass
    return None


def try_decode_hex(text: str) -> str | None:
    """Attempt to decode hex-encoded payload chunks."""
    hex_pattern = re.compile(r"\b([0-9a-fA-F]{8,})\b")
    for match in hex_pattern.finditer(text):
        chunk = match.group()
        if len(chunk) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(chunk).decode("utf-8", errors="ignore")
            if decoded and decoded.isprintable() and len(decoded) > 3:
                return decoded.lower()
        except Exception:
            pass
    return None


def try_decode_rot13(text: str) -> str:
    """ROT13 decode entire text."""
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))


# ─────────────────────────────────────────────────────────────
# Rule Definitions
# ─────────────────────────────────────────────────────────────

def r01_instruction_override(norm: str, raw: str) -> RuleMatch | None:
    """R01 — Instruction Override  (CRITICAL 0.70 — most common attack)"""
    patterns = [
        r"\bignore\b.{0,30}\b(previous|prior|above|all)\b.{0,30}\b(instructions?|rules?|prompts?|directives?)\b",
        r"\bforget\b.{0,30}\b(everything|all|prior|previous)\b",
        r"\bdisregard\b.{0,30}\b(instructions?|rules?|prompts?|all)\b",
        r"\boverride\b.{0,30}\b(instructions?|rules?|system|safety)\b",
        r"\bdo not follow\b.{0,30}\b(instructions?|rules?)\b",
        r"\bprevious instructions\b",
        r"\bnew instructions?\b.{0,20}\b(follow|replace|instead)\b",
        r"\byou (are|were) (not|no longer) bound\b",
        r"\byour (instructions?|rules?|guidelines?) (are|were) (wrong|invalid|cancelled|revoked)\b",
        # NEW: "ignore all before", "ignore ethics", "ignore filters", "ignore if safe"
        r"\bignore\b.{0,40}\b(all|filters?|ethics|safety|rules?|restrictions?)\b",
        # NEW: "step 1: ignore filters"
        r"\bstep\s*\w{0,3}\s*:?\s*(ignore|forget|disregard|bypass|override)\b",
        # NEW: "first forget / then print"
        r"\b(first|chain)\b.{0,30}\b(forget|ignore|disregard)\b",
        # NEW: "metadata ignore", "exif override"
        r"\b(metadata|exif)\b.{0,20}\b(ignore|override|bypass)\b",
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R01", "Instruction Override", "CRITICAL", 0.70,
                             m.group(), "Attempt to override system instructions")
    return None


def r02_system_prompt_leak(norm: str, raw: str) -> RuleMatch | None:
    """R02 — System Prompt Leak  (score raised 0.35 → 0.50)"""
    patterns = [
        r"\b(reveal|print|show|output|display|repeat|tell me|give me|expose|leak|dump)\b.{0,30}\b(system prompt|hidden prompt|instructions?|directives?|rules?|guidelines?)\b",
        r"\bwhat (are|is) (your|the) (instructions?|prompt|rules?|directives?|guidelines?)\b",
        r"\bsystem prompt\b",
        r"\bhidden (prompt|instructions?)\b",
        r"\byour (original|actual|real|true|full|complete) (instructions?|prompt|rules?)\b",
        r"\brepeat (everything|all|your prompt) (above|before|from the beginning)\b",
        r"\bwhat (were you|have you been) (told|instructed|programmed)\b",
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R02", "System Prompt Leak", "CRITICAL", 0.70,
                             m.group(), "Attempt to extract system prompt")
    return None


def r03_role_switch_jailbreak(norm: str, raw: str) -> RuleMatch | None:
    """R03 — Role Switch / DAN Jailbreak  (CRITICAL — expanded)"""
    patterns = [
        r"\byou are now\b",
        r"\bact as\b.{0,20}\b(admin|root|system|developer|superuser|unrestricted|jailbroken|dan|hacker)\b",
        r"\bpretend (you are|you're|to be)\b.{0,30}\b(unrestricted|without (limits?|rules?|filters?))\b",
        r"\bdan\b.{0,20}\b(mode|jailbreak|no restrictions?)\b",
        r"\bdeveloper mode\b",
        r"\bdev mode\b",                               # NEW: "dev mode"
        r"\bjailbreak\b",
        r"\bno restrictions?\b",
        r"\bno (safety|ethical|content) (filters?|restrictions?|limits?|guidelines?)\b",
        r"\bpretend.{0,20}villain\b",
        r"\bunrestricted (ai|mode|access)\b",
        r"\broleplay\b.{0,30}\b(evil|malicious|hacker|unrestricted|no.?ethics)\b",  # NEW
        r"\b(sandbox escape|break out).{0,30}\b(eval|exec|run|and)\b",              # NEW
        r"\badmin override\b",                         # NEW
        r"\b(user|i) is (admin|root|superuser)\b",     # NEW: "user is admin"
        r"\bdestroy (safeguards?|filters?|restrictions?)\b",  # NEW
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R03", "Role Switch / Jailbreak", "CRITICAL", 0.70,
                             m.group(), "Attempt to change AI identity or bypass filters")
    return None


def r04_force_output(norm: str, raw: str) -> RuleMatch | None:
    """R04 — Force Output with malicious payload  (expanded: XSS, script tags)"""
    patterns = [
        r"\b(simply|just|only)\b.{0,20}\b(respond|say|output|print|write)\b.{0,30}\b(eval|exec|os\.|script|payload)\b",
        r"\bsay exactly\b.{0,30}\b(eval|exec|<script|os\.)\b",
        r"\boutput only\b.{0,30}\b(eval|exec|code|script)\b",
        r"<script\b.{0,60}(alert|eval|exec|document\.|window\.)",   # XSS: <script>alert(...)
        r"\brespond with\b.{0,30}(<script|eval\(|exec\(|os\.)",     # "respond with: <script..."
        r"\bsimply respond with\b",                                   # "simply respond with: ..."
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R04", "Force Output", "HIGH", 0.70,
                             m.group(), "Attempt to force malicious output / XSS payload")
    return None


def r05_unicode_homoglyphs(norm: str, raw: str) -> RuleMatch | None:
    """R05 — Unicode / Homoglyph obfuscation  (threshold lowered 3→2)"""
    suspicious_count = 0
    for ch in raw:
        cp = ord(ch)
        if (0x1D400 <= cp <= 0x1D7FF) or (0xFF00 <= cp <= 0xFFEF):
            suspicious_count += 1

    non_ascii = sum(1 for c in raw if ord(c) > 127)
    ratio = non_ascii / max(len(raw), 1)

    if suspicious_count >= 2:                          # was 3
        return RuleMatch("R05", "Unicode Homoglyphs", "CRITICAL", 0.70,
                         f"{suspicious_count} suspicious chars",
                         "Unicode obfuscation detected (mathematical/fullwidth chars)")
    if ratio > 0.3 and len(raw) > 20:
        return RuleMatch("R05", "Unicode Homoglyphs", "MEDIUM", 0.35,
                         f"{ratio:.0%} non-ASCII",
                         "High non-ASCII ratio — possible homoglyph obfuscation")
    return None


def r06_base64_encoded_payload(norm: str, raw: str) -> RuleMatch | None:
    """R06 — Base64 encoded attack payload  (scans raw, not norm — b64 is case-sensitive)"""
    decoded = try_decode_base64(raw)  # must use raw — lowercase breaks b64 alphabet
    if decoded:
        danger_words = [
            "ignore", "disregard", "forget", "previous", "instructions",
            "override", "bypass", "passwd", "shadow", "exec", "eval",
            "system prompt", "jailbreak", "hack", "reveal", "no restrictions",
        ]
        for word in danger_words:
            if word in decoded:
                return RuleMatch("R06", "Base64 Encoding", "CRITICAL", 0.70,
                                 f"decoded: '{decoded[:60]}'",
                                 f"Base64 payload decodes to suspicious content: '{word}'")
    return None


def r06b_hex_rot13_payload(norm: str, raw: str) -> RuleMatch | None:
    """R06b — Hex / ROT13 encoded attack payload"""
    _DANGER = ["ignore", "prompt", "bypass", "exec", "eval", "passwd", "shadow",
               "instructions", "jailbreak", "reveal", "override", "hack"]

    # Hex decode
    hex_decoded = try_decode_hex(raw)
    if hex_decoded:
        for word in _DANGER:
            if word in hex_decoded:
                return RuleMatch("R06b", "Hex Encoding", "CRITICAL", 0.70,
                                 f"hex decoded: '{hex_decoded[:60]}'",
                                 f"Hex payload decodes to suspicious content: '{word}'")

    # ROT13 — check both the raw and norm
    for src in (raw.lower(), norm):
        rot = try_decode_rot13(src)
        for word in _DANGER:
            if word in rot:
                return RuleMatch("R06b", "ROT13 Encoding", "HIGH", 0.55,
                                 f"rot13 decoded: '{rot[:60]}'",
                                 f"ROT13 payload decodes to suspicious content: '{word}'")
    return None


def r07_html_entity_obfuscation(norm: str, raw: str) -> RuleMatch | None:
    """R07 — HTML entity obfuscation"""
    entity_count = len(re.findall(r"&#?\w+;", raw))
    if entity_count >= 3:
        return RuleMatch("R07", "HTML Entity Obfuscation", "MEDIUM", 0.3,
                         f"{entity_count} entities found",
                         "HTML entity encoding used to obfuscate payload")
    return None


def r08_token_flooding(norm: str, raw: str) -> RuleMatch | None:
    """R08 — Token flooding / DoS"""
    token_estimate = len(raw.split())
    words = raw.lower().split()
    if len(words) > 50:
        unique_ratio = len(set(words)) / len(words)
        if unique_ratio < 0.1:
            return RuleMatch("R08", "Token Flooding", "HIGH", 0.4,
                             f"{token_estimate} tokens, {unique_ratio:.0%} unique",
                             "Extreme repetition detected — likely token flood attack")
    if token_estimate > 800:
        return RuleMatch("R08", "Token Flooding", "MEDIUM", 0.25,
                         f"{token_estimate} estimated tokens",
                         "Unusually long input — possible context overflow attempt")
    return None


def r09_nesting_recursion(norm: str, raw: str) -> RuleMatch | None:
    """R09 — Deep nesting / parenthesis recursion"""
    max_depth = depth = 0
    for ch in raw:
        if ch in "([{":
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch in ")]}":
            depth = max(0, depth - 1)
    if max_depth > 15:
        return RuleMatch("R09", "Deep Nesting", "HIGH", 0.35,
                         f"max depth {max_depth}",
                         "Abnormally deep nesting — possible recursion attack")
    return None


def r10_recursive_self_prompt(norm: str, raw: str) -> RuleMatch | None:
    """R10 — Recursive self-prompting / intention keywords"""
    patterns = [
        r"\bgenerate\b.{0,30}\b(a prompt|instructions?|payload)\b.{0,30}\b(to|that will|which)\b",
        r"\bwrite\b.{0,30}\b(a prompt|instructions?)\b.{0,30}\b(bypass|override|ignore|hack)\b",
        r"\bcreate\b.{0,30}\b(a jailbreak|exploit|attack prompt)\b",
        r"\bprompt\b.{0,20}\b(to reveal|to bypass|to ignore|that ignores)\b",
        # NEW: "generate malicious prompt", "generate malicious" anything
        r"\bgenerate\b.{0,20}\b(malicious|harmful|dangerous|attack|exploit)\b",
        r"\bmalicious\b.{0,20}\b(prompt|payload|code|script|input)\b",
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R10", "Recursive Self-Prompt", "HIGH", 0.70,
                             m.group(), "Attempt to generate attack prompts or malicious content")
    return None


def r11_sensitive_data_request(norm: str, raw: str) -> RuleMatch | None:
    """R11 — Sensitive data / credential fishing  (fixed plural + broadened)"""
    patterns = [
        r"\bpasswords?\b",                                          # FIX: was "password" only
        r"\bpasswd\b",
        r"\bcredentials?\b",
        r"\bapi[_\s]?keys?\b",
        r"\bsecret[_\s]?keys?\b",
        r"\bauth[_\s]?tokens?\b",
        r"\benv(ironment)?\s*(vars?|variables?|file)\b",
        r"\b\.env\b",
        r"\b(database|db)\s*(password|credentials?|connection string)\b",
        r"\b(credit card|ssn|social security)\b",
        r"(?<!\w)/etc/(passwd|shadow|sudoers)",
        r"\b(aws|gcp|azure)\s*(keys?|credentials?|secrets?)\b",
        r"\bprivate[_\s]?keys?\b",
        r"\baccess[_\s]?tokens?\b",
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R11", "Sensitive Data Request", "CRITICAL", 0.70,
                             m.group(), "Request targets sensitive credentials or PII")
    return None


def r12_rce_code_hints(norm: str, raw: str) -> RuleMatch | None:
    """R12 — Remote Code Execution hints  (CRITICAL — unchanged)"""
    patterns = [
        r"\bos\.(popen|system|exec|spawn|getenv)\b",
        r"\bsubprocess\.(run|call|popen|check_output)\b",
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\b__import__\b",
        r"\bcurl\s+https?://",
        r"\bwget\s+https?://",
        r"\bpowershell\b.{0,30}\b(invoke|iex|download|exec)\b",
        r"\bchmod\s+[0-7]+\s*\+x\b",
        r"\brm\s+-rf\b",
        r"\b(bash|sh|cmd)\s*-c\b",
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R12", "RCE / Code Execution", "CRITICAL", 0.5,
                             m.group(), "Code execution pattern detected")
    return None


def r13_indirect_comment_injection(norm: str, raw: str) -> RuleMatch | None:
    """R13 — Indirect injection via comments/markup  (also scans raw for HTML comments)"""
    norm_patterns = [
        r"//\s*(ignore|forget|disregard|bypass|reveal).{0,100}",
        r"#\s*(ignore|forget|disregard|bypass|reveal).{0,100}",
        r"/\*.{0,200}(ignore|bypass|reveal).{0,200}\*/",
    ]
    for p in norm_patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R13", "Comment Injection", "HIGH", 0.70,
                             m.group()[:80], "Injection attempt hidden in code comments")

    # Scan RAW for HTML comments — normalizer corrupts <!-- → <i--
    raw_lower = raw.lower()
    raw_patterns = [
        r"<!--.{0,200}(ignore|forget|disregard|reveal|bypass).{0,200}-->",
    ]
    for p in raw_patterns:
        m = re.search(p, raw_lower)
        if m:
            return RuleMatch("R13", "Comment Injection", "HIGH", 0.70,
                             m.group()[:80], "Injection attempt hidden in HTML comment")
    return None


def r15_chain_of_thought_jailbreak(norm: str, raw: str) -> RuleMatch | None:
    """R15 — Chain of Thought jailbreak  (score raised 0.4 → 0.50)"""
    patterns = [
        r"\bstep[\s-]by[\s-]step\b.{0,60}\b(ignore|bypass|override|hack|exec)\b",
        r"\b(first|step 1).{0,40}(ignore|forget).{0,40}(then|step 2).{0,40}(exec|run|reveal)\b",
        r"\blet'?s think\b.{0,40}\b(step by step|carefully)\b.{0,60}\b(bypass|ignore|override)\b",
        r"\breasoning\b.{0,40}\b(bypass|ignore|override)\b",
        r"\b(think|reason).{0,30}step.{0,30}(ignore|bypass|override|exec)\b",
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R15", "Chain of Thought Jailbreak", "HIGH", 0.50,
                             m.group(), "Step-wise reasoning used to construct bypass")
    return None


def r16_sandwich_payload(norm: str, raw: str) -> RuleMatch | None:
    """R16 — Sandwich / payload wrap"""
    patterns = [
        r"ignore all.{0,200}end ignore",
        r"(begin|start) ignore.{0,200}(end|stop) ignore",
        r"\[ignore\].{0,200}\[/ignore\]",
        r"<!--ignore-->.{0,200}<!--/ignore-->",
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R16", "Sandwich Payload", "MEDIUM", 0.3,
                             m.group()[:80], "Payload buried between ignore markers")
    return None


def r17_authority_impersonation(norm: str, raw: str) -> RuleMatch | None:
    """R17 — Authority / identity impersonation  (broadened patterns)"""
    patterns = [
        # Original — slightly loosened spacing
        r"\bas (an? )?(admin|administrator|root|superuser|system|developer|operator|moderator)\b",
        r"\bi (am|have) (admin|root|system|developer|operator) (access|privileges?|permissions?|rights?)\b",
        r"\bauthorized (to|for) (access|read|execute|run)\b",
        # FIX: catch "as admin, run" (comma between role and action)
        r"\bas (admin|root|developer|system|operator)[,\s].{0,30}\b(run|exec|read|access|show|give|provide)\b",
        # FIX: catch "red teamer" / "red team" variants
        r"\b(red.?team(er|ing|s)?|penetration tester|pen tester|security (researcher|auditor|tester))\b",
        r"\bsecurity (researcher|tester|auditor)\b",
        r"\bi'?m (testing|auditing|assessing) (your|this) (security|system|api)\b",
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R17", "Authority Impersonation", "MEDIUM", 0.45,
                             m.group(), "False authority claim to gain elevated access")
    return None


def r18_output_format_manipulation(norm: str, raw: str) -> RuleMatch | None:
    """R18 — Output format manipulation with malicious content"""
    patterns = [
        r"\bjson only\b.{0,60}\b(script|eval|exec|rce|payload)\b",
        r"\b(no sentences|code only|raw output)\b.{0,60}\b(os\.|eval|exec)\b",
        r"\brespond only in\b.{0,30}\b(code|json|xml)\b.{0,60}\b(ignore|bypass)\b",
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R18", "Output Format Manipulation", "MEDIUM", 0.25,
                             m.group(), "Format constraint combined with malicious payload")
    return None


def r19_context_bias_injection(norm: str, raw: str) -> RuleMatch | None:
    """R19 — Context/bias injection with pivot to attack"""
    patterns = [
        r"(hoax|fake|false|lie).{0,60}(now|therefore|so).{0,40}(ignore|bypass|answer)\b",
        r"(everyone knows|it is known|fact:).{0,60}(ignore|bypass|override|reveal)\b",
        r"\bactually.{0,30}(rules?|instructions?).{0,30}(don'?t apply|not apply|are wrong)\b",
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R19", "Context Bias Injection", "MEDIUM", 0.25,
                             m.group(), "False context used to justify bypassing rules")
    return None


def r20_logical_confusion_evasion(norm: str, raw: str) -> RuleMatch | None:
    """R20 — Logical confusion / test framing / social engineering evasion"""
    patterns = [
        r"\b(testing|test|just testing|hypothetically|theoretically)\b.{0,60}\b(eval|exec|os\.|bypass|ignore)\b",
        r"\bnot (actually|really) (breaking|hacking|bypassing)\b.{0,40}\b(but|just|only)\b.{0,40}\b(run|exec|eval)\b",
        r"\bfor (educational|research|testing) purposes?\b.{0,60}\b(bypass|ignore|override|read /etc)\b",
        r"\bhypothetically\b.{0,60}\b(bypass|ignore|override|hack)\b",
        # NEW: "how to hack" + imperative do it
        r"\bhow to hack\b.{0,30}\b(do it|now|please|just)\b",
        # NEW: debug/verbose mode fishing
        r"\b(debug mode|verbose mode)\b.{0,30}\b(on|enabled?|activate|system info|secrets?)\b",
        # NEW: social engineering — "story where you leak"
        r"\b(story|scenario|roleplay|imagine)\b.{0,40}\b(leak|reveal|print|expose|output)\b.{0,20}\b(prompt|instructions?|secrets?|keys?)\b",
        # NEW: SQL injection intent
        r"\b(select|union|insert|drop|delete)\b.{0,20}\b(from|into|table|users|database)\b",
    ]
    for p in patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R20", "Logical Confusion / Evasion", "HIGH", 0.55,
                             m.group(), "Evasion framing, SQL injection, or social engineering")
    return None


def r_path_traversal(norm: str, raw: str) -> RuleMatch | None:
    """R-PT — Path traversal  (added /etc/shadow, /etc/sudoers as explicit CRITICAL)"""
    # CRITICAL standalone sensitive files first
    critical_paths = [
        r"(?<!\w)/etc/shadow",
        r"(?<!\w)/etc/sudoers",
        r"(?<!\w)/etc/passwd",
        r"(?<!\w)/proc/(version|cmdline|environ|net)",
        r"(?<!\w)/root/",
        r"\b(~|/home/[^/]+)/\.(ssh|aws|bash_history|zsh_history|config)\b",
    ]
    for p in critical_paths:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R-PT", "Path Traversal", "CRITICAL", 0.70,
                             m.group(), "Sensitive system path access attempt")

    # Traversal patterns
    traversal_patterns = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e",
        r"\b/etc/(hosts|ssh|cron)\b",
        r"\bC:\\(Windows|Users|Program Files|System32)\b",
    ]
    for p in traversal_patterns:
        m = re.search(p, norm)
        if m:
            return RuleMatch("R-PT", "Path Traversal", "CRITICAL", 0.5,
                             m.group(), "Filesystem traversal attempt")
    return None


# ─────────────────────────────────────────────────────────────
# Rule Registry — ordered by priority (CRITICAL first)
# ─────────────────────────────────────────────────────────────

RULES = [
    r03_role_switch_jailbreak,      # CRITICAL — jailbreak/persona
    r12_rce_code_hints,             # CRITICAL — code execution
    r_path_traversal,               # CRITICAL — filesystem
    r01_instruction_override,       # CRITICAL — most common
    r02_system_prompt_leak,         # CRITICAL — exfiltration
    r04_force_output,               # CRITICAL/HIGH — XSS + force output
    r06_base64_encoded_payload,     # CRITICAL — obfuscation
    r06b_hex_rot13_payload,         # CRITICAL/HIGH — obfuscation
    r05_unicode_homoglyphs,         # CRITICAL/MEDIUM — obfuscation
    r11_sensitive_data_request,     # CRITICAL — credentials
    r15_chain_of_thought_jailbreak, # HIGH
    r10_recursive_self_prompt,      # HIGH
    r13_indirect_comment_injection, # HIGH
    r20_logical_confusion_evasion,  # HIGH
    r09_nesting_recursion,          # HIGH
    r08_token_flooding,             # HIGH/MEDIUM
    r17_authority_impersonation,    # MEDIUM
    r07_html_entity_obfuscation,    # MEDIUM
    r16_sandwich_payload,           # MEDIUM
    r18_output_format_manipulation, # MEDIUM
    r19_context_bias_injection,     # MEDIUM
]