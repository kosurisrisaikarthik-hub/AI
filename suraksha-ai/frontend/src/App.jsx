import { useEffect, useMemo, useState } from "react";
import { emptyArtifact, TYPE_FIELDS } from "./lib/analyzer";
import { fetchAssessments, patchApproval, submitAnalyze } from "./lib/api";
import { loadHistory, upsertHistory } from "./lib/storage";

const TYPES = ["url", "domain", "email", "social", "text", "document", "image"];

const DEFAULT_BASELINE = {
  brand_name: "Aether Bank",
  official_domains: "aetherbank.com, www.aetherbank.com",
  official_emails: "security@aetherbank.com, noreply@aetherbank.com",
  social_handles: "x:@AetherBank, linkedin:aether-bank",
  keywords: "Aether, AetherBank, AB-Secure",
};

const LABELS = {
  url: "URL",
  page_title: "Page title",
  registrar_notes: "Registrar notes",
  domain: "Domain",
  whois_notes: "WHOIS notes",
  nameservers: "Nameservers",
  from_address: "From",
  subject: "Subject",
  headers: "Headers",
  body: "Body",
  platform: "Platform",
  handle: "Handle",
  profile_url: "Profile URL",
  bio: "Bio",
  raw_text: "Raw text",
  claimed_source: "Claimed source",
  filename: "Filename",
  excerpt: "Excerpt",
  claimed_issuer: "Claimed issuer",
  description: "Description",
  reverse_search_notes: "Reverse-search notes",
  claimed_origin: "Claimed origin",
};

function splitList(value) {
  return String(value)
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseHandles(value) {
  const out = {};
  splitList(value).forEach((pair) => {
    const [k, ...rest] = pair.split(":");
    if (k && rest.length) out[k.trim()] = rest.join(":").trim();
  });
  return out;
}

function verdictTone(verdict) {
  if (verdict === "malicious") return "text-kinetic";
  if (verdict === "suspicious") return "text-warn";
  if (verdict === "benign") return "text-ok";
  return "text-mute";
}

function Field({ id, label, value, onChange, multiline }) {
  const cls =
    "w-full bg-black/60 border border-stroke px-3 py-2 text-xs text-white outline-none focus:border-signal/70 transition-colors";
  return (
    <label className="block space-y-1">
      <span className="text-[10px] uppercase tracking-[0.18em] text-mute">{label}</span>
      {multiline ? (
        <textarea
          data-testid={`${id}-input`}
          rows={4}
          className={`${cls} resize-y min-h-[88px]`}
          value={value}
          onChange={(e) => onChange(e.target.value)}
        />
      ) : (
        <input
          data-testid={`${id}-input`}
          className={cls}
          value={value}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
    </label>
  );
}

export default function App() {
  const [baseline, setBaseline] = useState(DEFAULT_BASELINE);
  const [type, setType] = useState("url");
  const [artifact, setArtifact] = useState(() => ({
    ...emptyArtifact("url"),
    url: "https://aetherbank-secure-login.tk/reset",
    page_title: "Urgent: verify your Aether Bank password",
    registrar_notes: "",
  }));
  const [history, setHistory] = useState(() => loadHistory());
  const [active, setActive] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notes, setNotes] = useState("");
  const [reviewer, setReviewer] = useState("soc-analyst");
  const [engine, setEngine] = useState("idle");
  const [clock, setClock] = useState(() => new Date());

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    fetchAssessments().then((rows) => {
      if (Array.isArray(rows) && rows.length) {
        setHistory(rows);
      }
    });
  }, []);

  const jsonView = useMemo(() => (active ? JSON.stringify(active, null, 2) : "// no assessment selected"), [active]);

  function setBaselineField(key, value) {
    setBaseline((prev) => ({ ...prev, [key]: value }));
  }

  function changeType(next) {
    setType(next);
    setArtifact(emptyArtifact(next));
  }

  async function onAnalyze(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const payload = {
      artifact_type: type,
      brand_baseline: {
        brand_name: baseline.brand_name,
        official_domains: splitList(baseline.official_domains),
        official_emails: splitList(baseline.official_emails),
        social_handles: parseHandles(baseline.social_handles),
        keywords: splitList(baseline.keywords),
      },
      artifact,
    };
    try {
      const result = await submitAnalyze(payload);
      setEngine(result.engine || "unknown");
      setActive(result);
      setHistory((prev) => upsertHistory(prev, result));
      setNotes("");
    } catch (err) {
      setError(err.message || "Analyze failed");
    } finally {
      setBusy(false);
    }
  }

  async function onApprove(state) {
    if (!active) return;
    const body = { state, reviewer, notes };
    const patched = await patchApproval(active.assessment_id, body);
    const next = {
      ...active,
      approval: patched.approval || {
        ...body,
        updated_at: new Date().toISOString(),
      },
    };
    setActive(next);
    setHistory((prev) => upsertHistory(prev, next));
  }

  const missing = active?.missing_data || [];
  const injection = active?.prompt_injection;

  return (
    <div className="relative min-h-screen bg-ink text-white overflow-hidden">
      <div className="absolute inset-0 grid-wash opacity-70" />
      <div className="absolute inset-0 scanlines" />
      <div className="relative z-10 min-h-screen grid grid-cols-[280px_minmax(0,1fr)_320px]">
        <aside className="border-r border-stroke bg-surface/90 backdrop-blur-xl flex flex-col">
          <div className="px-4 py-4 border-b border-stroke">
            <p className="font-display text-3xl font-black tracking-tight leading-none">
              SURAKSHA<span className="text-kinetic">.AI</span>
            </p>
            <p className="mt-1 text-[10px] uppercase tracking-[0.22em] text-mute">Enterprise DRP · SOC</p>
          </div>
          <div className="px-4 py-3 border-b border-stroke text-[10px] text-mute flex justify-between">
            <span>HISTORY</span>
            <span data-testid="history-count">{history.length} saved</span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {history.length === 0 && (
              <p className="px-4 py-6 text-xs text-mute">No stored assessments. Submit an artifact to seed the rail.</p>
            )}
            {history.map((item) => (
              <button
                key={item.assessment_id}
                type="button"
                data-testid={`history-item-${item.assessment_id}`}
                onClick={() => {
                  setActive(item);
                  setNotes(item.approval?.notes || "");
                }}
                className={`w-full text-left px-4 py-3 border-b border-stroke/80 hover:bg-white/5 transition-colors ${
                  active?.assessment_id === item.assessment_id ? "bg-white/5 border-l-2 border-l-kinetic" : ""
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] uppercase tracking-widest text-mute">{item.artifact_type}</span>
                  <span className={`text-[10px] uppercase ${verdictTone(item.verdict)}`}>{item.verdict}</span>
                </div>
                <p className="mt-1 text-xs truncate">{item.brand_baseline?.brand_name || "unscoped"}</p>
                <p className="text-[10px] text-mute truncate">{item.approval?.state}</p>
              </button>
            ))}
          </div>
        </aside>

        <main className="flex flex-col min-h-screen">
          <header className="h-14 border-b border-stroke bg-black/80 backdrop-blur-xl flex items-center justify-between px-6">
            <div className="flex items-center gap-6">
              <h1 className="font-display text-2xl font-bold tracking-tight">THREAT INTAKE</h1>
              <span className="text-[10px] uppercase tracking-[0.2em] text-mute">
                single artifact · brand baseline lock
              </span>
            </div>
            <div className="flex items-center gap-4 text-[10px] uppercase tracking-[0.18em] text-mute">
              <span data-testid="engine-status">engine {engine}</span>
              <span className="text-kinetic drop-shadow-[0_0_8px_rgba(255,59,48,0.3)]">
                {clock.toISOString().slice(11, 19)}Z
              </span>
            </div>
          </header>

          <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-0 flex-1 min-h-0">
            <section className="border-r border-stroke overflow-y-auto p-5 space-y-5">
              <form onSubmit={onAnalyze} className="space-y-5">
                <div>
                  <p className="font-display text-xl font-bold tracking-tight">Brand baseline</p>
                  <div className="mt-3 grid grid-cols-2 gap-3">
                    <Field
                      id="brand-name"
                      label="Brand"
                      value={baseline.brand_name}
                      onChange={(v) => setBaselineField("brand_name", v)}
                    />
                    <Field
                      id="brand-keywords"
                      label="Keywords"
                      value={baseline.keywords}
                      onChange={(v) => setBaselineField("keywords", v)}
                    />
                    <Field
                      id="official-domains"
                      label="Official domains"
                      value={baseline.official_domains}
                      onChange={(v) => setBaselineField("official_domains", v)}
                    />
                    <Field
                      id="official-emails"
                      label="Official emails"
                      value={baseline.official_emails}
                      onChange={(v) => setBaselineField("official_emails", v)}
                    />
                    <div className="col-span-2">
                      <Field
                        id="social-handles"
                        label="Social handles (platform:handle)"
                        value={baseline.social_handles}
                        onChange={(v) => setBaselineField("social_handles", v)}
                      />
                    </div>
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between">
                    <p className="font-display text-xl font-bold tracking-tight">Artifact</p>
                    <select
                      data-testid="artifact-type-select"
                      className="bg-black border border-stroke text-xs px-2 py-1"
                      value={type}
                      onChange={(e) => changeType(e.target.value)}
                    >
                      {TYPES.map((t) => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="mt-3 space-y-3">
                    {(TYPE_FIELDS[type] || []).map((field) => (
                      <Field
                        key={field}
                        id={`artifact-${field.replaceAll("_", "-")}`}
                        label={LABELS[field] || field}
                        value={artifact[field] || ""}
                        multiline={["body", "headers", "excerpt", "raw_text", "bio", "description"].includes(field)}
                        onChange={(v) => setArtifact((prev) => ({ ...prev, [field]: v }))}
                      />
                    ))}
                  </div>
                </div>

                {error && (
                  <p data-testid="analyze-error" className="text-xs text-kinetic">
                    {error}
                  </p>
                )}

                <button
                  type="submit"
                  data-testid="submit-artifact-btn"
                  disabled={busy}
                  className="w-full h-11 bg-kinetic text-white font-display text-lg font-bold tracking-wide hover:brightness-110 disabled:opacity-50 transition-all shadow-terminal"
                >
                  {busy ? "ANALYZING…" : "RUN ANALYSIS"}
                </button>
              </form>
            </section>

            <section className="overflow-hidden flex flex-col bg-black/50">
              <div className="px-4 py-3 border-b border-stroke flex items-center justify-between">
                <p className="text-[10px] uppercase tracking-[0.2em] text-mute">Strict JSON result</p>
                {active && (
                  <span data-testid="verdict-chip" className={`text-xs uppercase ${verdictTone(active.verdict)}`}>
                    {active.verdict} · {active.risk_score}
                  </span>
                )}
              </div>
              <pre
                data-testid="json-result-panel"
                className="flex-1 overflow-auto p-4 text-[11px] leading-5 text-[#d7d7d7]"
              >
                {jsonView}
              </pre>
            </section>
          </div>
        </main>

        <aside className="border-l border-stroke bg-surface/90 backdrop-blur-xl flex flex-col">
          <div className="px-4 py-4 border-b border-stroke">
            <p className="font-display text-2xl font-bold tracking-tight">OPS DESK</p>
            <p className="text-[10px] uppercase tracking-[0.18em] text-mute">missing data · human gate</p>
          </div>

          <div className="p-4 border-b border-stroke space-y-2">
            <p className="text-[10px] uppercase tracking-[0.18em] text-mute">Prompt injection</p>
            <p
              data-testid="injection-status"
              className={`text-sm ${injection?.detected ? "text-kinetic" : "text-ok"}`}
            >
              {active ? (injection?.detected ? `DETECTED · ${injection.signals.join(", ")}` : "CLEAR") : "STANDBY"}
            </p>
          </div>

          <div className="p-4 border-b border-stroke flex-1 overflow-y-auto">
            <p className="text-[10px] uppercase tracking-[0.18em] text-mute mb-3">Missing data</p>
            <div data-testid="missing-data-list" className="space-y-2">
              {!active && <p className="text-xs text-mute">Awaiting first run.</p>}
              {active && missing.length === 0 && <p className="text-xs text-ok">Evidence package complete.</p>}
              {missing.map((gap) => (
                <div key={gap.field} className="border border-stroke px-3 py-2">
                  <div className="flex justify-between text-[10px] uppercase">
                    <span>{gap.field}</span>
                    <span className={gap.severity === "critical" ? "text-kinetic" : "text-warn"}>{gap.severity}</span>
                  </div>
                  <p className="mt-1 text-xs text-mute">{gap.reason}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="p-4 space-y-3">
            <Field id="reviewer" label="Reviewer" value={reviewer} onChange={setReviewer} />
            <Field id="approval-notes" label="Analyst notes" value={notes} onChange={setNotes} multiline />
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                data-testid="approval-approve-btn"
                disabled={!active}
                onClick={() => onApprove("approved")}
                className="h-9 border border-ok text-ok text-[10px] uppercase tracking-widest hover:bg-ok/10 disabled:opacity-40 transition-colors"
              >
                Approve
              </button>
              <button
                type="button"
                data-testid="approval-reject-btn"
                disabled={!active}
                onClick={() => onApprove("rejected")}
                className="h-9 border border-kinetic text-kinetic text-[10px] uppercase tracking-widest hover:bg-kinetic/10 disabled:opacity-40 transition-colors"
              >
                Reject
              </button>
              <button
                type="button"
                data-testid="approval-needs-data-btn"
                disabled={!active}
                onClick={() => onApprove("needs_more_data")}
                className="col-span-2 h-9 border border-warn text-warn text-[10px] uppercase tracking-widest hover:bg-warn/10 disabled:opacity-40 transition-colors"
              >
                Needs more data
              </button>
            </div>
            <p data-testid="approval-state" className="text-[10px] uppercase tracking-[0.16em] text-mute">
              state {active?.approval?.state || "n/a"}
            </p>
          </div>
        </aside>
      </div>
    </div>
  );
}
