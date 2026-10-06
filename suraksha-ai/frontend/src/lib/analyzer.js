const INJECTION = [
  [/ignore (all |any )?(previous|prior|above) (instructions|prompts)/i, "ignore-previous"],
  [/disregard (your )?(system|developer) (prompt|message)/i, "disregard-system"],
  [/you are now (DAN|jailbroken|unrestricted)/i, "role-override"],
  [/reveal (your )?(system )?prompt/i, "prompt-exfil"],
  [/<\|\s?im_start\s?\|>|\[INST\]/i, "chat-markup"],
  [/developer mode|jailbreak/i, "jailbreak-lexicon"],
  [/new instructions?:\s/i, "instruction-swap"],
  [/do not follow (the )?(original|prior) rules/i, "rule-nullify"],
];

export const TYPE_FIELDS = {
  url: ["url", "page_title", "registrar_notes"],
  domain: ["domain", "whois_notes", "nameservers"],
  email: ["from_address", "subject", "headers", "body"],
  social: ["platform", "handle", "profile_url", "bio"],
  text: ["raw_text", "claimed_source"],
  document: ["filename", "excerpt", "claimed_issuer"],
  image: ["description", "reverse_search_notes", "claimed_origin"],
};

const CRITICAL = {
  url: ["url"],
  domain: ["domain"],
  email: ["from_address", "body"],
  social: ["platform", "handle"],
  text: ["raw_text"],
  document: ["excerpt"],
  image: ["description"],
};

const URGENCY = /\b(urgent|immediately|act now|suspend(ed)?|verify (your )?account|last chance|within 24 hours)\b/i;
const CREDS = /\b(password|otp|one[- ]time code|ssn|login here|verify credentials|reset (your )?password)\b/i;

function now() {
  return new Date().toISOString();
}

export function emptyArtifact(type) {
  return Object.fromEntries((TYPE_FIELDS[type] || []).map((k) => [k, ""]));
}

function hostOf(value) {
  const raw = (value || "").trim().toLowerCase();
  if (!raw) return "";
  try {
    const url = new URL(raw.includes("://") ? raw : `https://${raw}`);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

function lev(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return dp[a.length][b.length];
}

function lookalike(candidate, official) {
  const cand = hostOf(candidate);
  if (!cand) return false;
  return official.some((item) => {
    const host = hostOf(item);
    if (!host || cand === host) return false;
    if (host.includes(cand) || cand.includes(host)) return true;
    if (cand.replaceAll("-", "") === host.replaceAll("-", "")) return true;
    return Math.abs(cand.length - host.length) <= 2 && lev(cand, host) <= 2;
  });
}

export function detectInjection(text) {
  const signals = INJECTION.filter(([re]) => re.test(text)).map(([, code]) => code);
  return { detected: signals.length > 0, signals };
}

export function missingFields(type, artifact) {
  return (TYPE_FIELDS[type] || [])
    .filter((field) => !String(artifact[field] || "").trim())
    .map((field) => ({
      field,
      severity: (CRITICAL[type] || []).includes(field) ? "critical" : "supporting",
      reason: `${field} not supplied for ${type} artifact`,
    }));
}

export function analyzeLocal(payload) {
  const artifact_type = payload.artifact_type || "text";
  const baseline = payload.brand_baseline || {};
  const artifact = payload.artifact || {};
  const text = Object.values(artifact).filter(Boolean).join(" ");
  const domains = baseline.official_domains || [];
  const emails = baseline.official_emails || [];
  const brand = (baseline.brand_name || "").trim();
  const findings = [];
  let score = 8;
  const injection = detectInjection(text);
  const gaps = missingFields(artifact_type, artifact);
  const host = hostOf(artifact.url || artifact.domain || artifact.profile_url || "");
  const officialHosts = domains.map(hostOf).filter(Boolean);

  if (host && officialHosts.length) {
    if (officialHosts.includes(host)) {
      findings.push({ id: "domain-match", severity: "info", title: "Host matches brand baseline", detail: host });
    } else if (lookalike(host, domains)) {
      score += 28;
      findings.push({ id: "lookalike-domain", severity: "high", title: "Lookalike or nested brand host", detail: host });
    } else {
      score += 36;
      findings.push({ id: "domain-mismatch", severity: "high", title: "Host is not in official domains", detail: host });
    }
  } else if (["url", "domain"].includes(artifact_type) && !host) {
    findings.push({
      id: "no-host",
      severity: "medium",
      title: "No parseable host for network artifact",
      detail: "URL/domain evidence is incomplete",
    });
  }

  const sender = (artifact.from_address || "").toLowerCase();
  if (sender && emails.length) {
    if (emails.map((e) => e.toLowerCase()).includes(sender)) {
      findings.push({ id: "sender-match", severity: "info", title: "Sender matches official mailbox", detail: sender });
    } else {
      score += 22;
      findings.push({
        id: "sender-mismatch",
        severity: "high",
        title: "Sender is outside official mailboxes",
        detail: sender,
      });
    }
  }

  if (brand && text.toLowerCase().includes(brand.toLowerCase()) && score >= 30) {
    findings.push({
      id: "brand-impersonation",
      severity: "high",
      title: "Brand string appears on untrusted artifact",
      detail: brand,
    });
    score += 12;
  }

  if (URGENCY.test(text)) {
    score += 10;
    findings.push({
      id: "urgency",
      severity: "medium",
      title: "Urgency / disruption language",
      detail: "Classic phishing pressure pattern",
    });
  }

  if (CREDS.test(text)) {
    score += 18;
    findings.push({
      id: "credential-harvest",
      severity: "high",
      title: "Credential or identity harvest cues",
      detail: "Requests secrets or account verification",
    });
  }

  if (injection.detected) {
    score += 30;
    findings.push({
      id: "prompt-injection",
      severity: "critical",
      title: "Prompt injection markers in evidence",
      detail: injection.signals.join(", "),
    });
  }

  const criticalMissing = gaps.filter((g) => g.severity === "critical");
  if (criticalMissing.length) score = Math.min(score, 62);
  score = Math.max(0, Math.min(100, score));

  let verdict = "benign";
  if (score >= 75) verdict = "malicious";
  else if (score >= 45) verdict = "suspicious";
  else if (criticalMissing.length) verdict = "inconclusive";

  const confidence = Math.max(
    0.25,
    Math.min(0.95, 0.92 - 0.12 * criticalMissing.length - 0.04 * Math.max(0, gaps.length - criticalMissing.length)),
  );

  return {
    assessment_id: crypto.randomUUID(),
    created_at: now(),
    artifact_type,
    brand_baseline: baseline,
    artifact,
    verdict,
    risk_score: score,
    confidence: Number(confidence.toFixed(2)),
    findings,
    missing_data: gaps,
    prompt_injection: injection,
    evidence: {
      parsed_host: host || null,
      corpus_chars: text.length,
      official_domain_count: officialHosts.length,
    },
    approval: { state: "pending_review", reviewer: null, notes: "", updated_at: null },
    engine: "local-heuristic",
  };
}
