from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

INJECTION_PATTERNS = [
    (r"ignore (all |any )?(previous|prior|above) (instructions|prompts)", "ignore-previous"),
    (r"disregard (your )?(system|developer) (prompt|message)", "disregard-system"),
    (r"you are now (DAN|jailbroken|unrestricted)", "role-override"),
    (r"reveal (your )?(system )?prompt", "prompt-exfil"),
    (r"<\|im_start\|>|</s>|\[INST\]", "chat-markup"),
    (r"developer mode|jailbreak", "jailbreak-lexicon"),
    (r"new instructions?:\s", "instruction-swap"),
    (r"do not follow (the )?(original|prior) rules", "rule-nullify"),
]

URGENCY = re.compile(
    r"\b(urgent|immediately|act now|suspend(ed)?|verify (your )?account|last chance|within 24 hours)\b",
    re.I,
)
CREDS = re.compile(
    r"\b(password|otp|one[- ]time code|ssn|login here|verify credentials|reset (your )?password)\b",
    re.I,
)

TYPE_FIELDS = {
    "url": ["url", "page_title", "registrar_notes"],
    "domain": ["domain", "whois_notes", "nameservers"],
    "email": ["from_address", "subject", "headers", "body"],
    "social": ["platform", "handle", "profile_url", "bio"],
    "text": ["raw_text", "claimed_source"],
    "document": ["filename", "excerpt", "claimed_issuer"],
    "image": ["description", "reverse_search_notes", "claimed_origin"],
}

CRITICAL = {
    "url": ["url"],
    "domain": ["domain"],
    "email": ["from_address", "body"],
    "social": ["platform", "handle"],
    "text": ["raw_text"],
    "document": ["excerpt"],
    "image": ["description"],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_host(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    host = urlparse(raw).hostname or ""
    return host[4:] if host.startswith("www.") else host


def _corpus(artifact: dict[str, Any]) -> str:
    return " ".join(str(v) for v in artifact.values() if v)


def _lookalike(candidate: str, official: list[str]) -> bool:
    cand = _norm_host(candidate)
    if not cand:
        return False
    for item in official:
        host = _norm_host(item)
        if not host:
            continue
        if cand == host:
            return False
        if host in cand or cand.replace("-", "") == host.replace("-", ""):
            return True
        if abs(len(cand) - len(host)) <= 2 and _lev(cand, host) <= 2:
            return True
    return False


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def detect_injection(text: str) -> dict[str, Any]:
    signals = []
    for pattern, code in INJECTION_PATTERNS:
        if re.search(pattern, text, re.I):
            signals.append(code)
    return {"detected": bool(signals), "signals": signals}


def missing_fields(artifact_type: str, artifact: dict[str, Any]) -> list[dict[str, str]]:
    gaps = []
    for field in TYPE_FIELDS.get(artifact_type, []):
        if not str(artifact.get(field) or "").strip():
            severity = "critical" if field in CRITICAL.get(artifact_type, []) else "supporting"
            gaps.append(
                {
                    "field": field,
                    "severity": severity,
                    "reason": f"{field} not supplied for {artifact_type} artifact",
                }
            )
    return gaps


def analyze(payload: dict[str, Any]) -> dict[str, Any]:
    artifact_type = payload.get("artifact_type") or "text"
    baseline = payload.get("brand_baseline") or {}
    artifact = payload.get("artifact") or {}
    text = _corpus(artifact)
    domains = list(baseline.get("official_domains") or [])
    emails = list(baseline.get("official_emails") or [])
    brand = (baseline.get("brand_name") or "").strip()

    findings: list[dict[str, Any]] = []
    score = 8
    injection = detect_injection(text)
    gaps = missing_fields(artifact_type, artifact)

    host = _norm_host(artifact.get("url") or artifact.get("domain") or artifact.get("profile_url") or "")
    official_hosts = [_norm_host(d) for d in domains if d]

    if host and official_hosts:
        if host in official_hosts:
            findings.append(
                {
                    "id": "domain-match",
                    "severity": "info",
                    "title": "Host matches brand baseline",
                    "detail": host,
                }
            )
        elif _lookalike(host, domains):
            score += 28
            findings.append(
                {
                    "id": "lookalike-domain",
                    "severity": "high",
                    "title": "Lookalike or nested brand host",
                    "detail": host,
                }
            )
        else:
            score += 36
            findings.append(
                {
                    "id": "domain-mismatch",
                    "severity": "high",
                    "title": "Host is not in official domains",
                    "detail": host,
                }
            )
    elif artifact_type in {"url", "domain"} and not host:
        findings.append(
            {
                "id": "no-host",
                "severity": "medium",
                "title": "No parseable host for network artifact",
                "detail": "URL/domain evidence is incomplete",
            }
        )

    sender = (artifact.get("from_address") or "").lower()
    if sender and emails:
        if sender in [e.lower() for e in emails]:
            findings.append(
                {
                    "id": "sender-match",
                    "severity": "info",
                    "title": "Sender matches official mailbox",
                    "detail": sender,
                }
            )
        else:
            score += 22
            findings.append(
                {
                    "id": "sender-mismatch",
                    "severity": "high",
                    "title": "Sender is outside official mailboxes",
                    "detail": sender,
                }
            )

    if brand and brand.lower() in text.lower() and score >= 30:
        findings.append(
            {
                "id": "brand-impersonation",
                "severity": "high",
                "title": "Brand string appears on untrusted artifact",
                "detail": brand,
            }
        )
        score += 12

    if URGENCY.search(text):
        score += 10
        findings.append(
            {
                "id": "urgency",
                "severity": "medium",
                "title": "Urgency / disruption language",
                "detail": "Classic phishing pressure pattern",
            }
        )

    if CREDS.search(text):
        score += 18
        findings.append(
            {
                "id": "credential-harvest",
                "severity": "high",
                "title": "Credential or identity harvest cues",
                "detail": "Requests secrets or account verification",
            }
        )

    if injection["detected"]:
        score += 30
        findings.append(
            {
                "id": "prompt-injection",
                "severity": "critical",
                "title": "Prompt injection markers in evidence",
                "detail": ", ".join(injection["signals"]),
            }
        )

    critical_missing = [g for g in gaps if g["severity"] == "critical"]
    if critical_missing:
        score = min(score, 62)

    score = max(0, min(100, score))
    if score >= 75:
        verdict = "malicious"
    elif score >= 45:
        verdict = "suspicious"
    elif critical_missing:
        verdict = "inconclusive"
    else:
        verdict = "benign"

    confidence = round(0.92 - 0.12 * len(critical_missing) - 0.04 * max(0, len(gaps) - len(critical_missing)), 2)
    confidence = max(0.25, min(0.95, confidence))

    return {
        "assessment_id": str(uuid.uuid4()),
        "created_at": _now(),
        "artifact_type": artifact_type,
        "brand_baseline": baseline,
        "artifact": artifact,
        "verdict": verdict,
        "risk_score": score,
        "confidence": confidence,
        "findings": findings,
        "missing_data": gaps,
        "prompt_injection": injection,
        "evidence": {
            "parsed_host": host or None,
            "corpus_chars": len(text),
            "official_domain_count": len(official_hosts),
        },
        "approval": {
            "state": "pending_review",
            "reviewer": None,
            "notes": "",
            "updated_at": None,
        },
    }
