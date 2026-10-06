const KEY = "suraksha.assessments.v1";

export function loadHistory() {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function saveHistory(items) {
  localStorage.setItem(KEY, JSON.stringify(items.slice(0, 200)));
}

export function upsertHistory(items, next) {
  const rest = items.filter((x) => x.assessment_id !== next.assessment_id);
  const merged = [next, ...rest];
  saveHistory(merged);
  return merged;
}
