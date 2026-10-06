import { analyzeLocal } from "./analyzer";

const BASE = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");

async function request(path, options) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(options?.headers || {}) },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}

export async function submitAnalyze(payload) {
  try {
    const remote = await request("/api/analyze", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    return { ...remote, engine: "api" };
  } catch {
    return analyzeLocal(payload);
  }
}

export async function fetchAssessments() {
  try {
    return await request("/api/assessments");
  } catch {
    return null;
  }
}

export async function patchApproval(id, body) {
  try {
    return await request(`/api/assessments/${id}/approval`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  } catch {
    return {
      local: true,
      approval: { ...body, updated_at: new Date().toISOString() },
    };
  }
}
