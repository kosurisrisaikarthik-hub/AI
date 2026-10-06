# Suraksha.ai Enterprise DRP

SOC command center for **single-artifact** digital risk analysis against a brand baseline.

## What it does

- Submits one artifact (URL, domain, email, social, text, document, image) against official brand assets
- Returns a **strict JSON** assessment: verdict, risk score, findings, evidence
- Reports **missing evidence fields** (critical vs supporting)
- Flags **prompt injection** markers in collected text
- Human approval states: `pending_review` · `approved` · `rejected` · `needs_more_data`
- Persists history in `localStorage` (and Mongo if the API is up)

## Run

Backend (Python 3.11+):

```bash
cd backend
pip install -r requirements.txt
uvicorn server:app --reload --port 8000
```

Frontend (Node 20+):

```bash
cd frontend
npm install
npm run dev
```

Vite proxies `/api` to `http://127.0.0.1:8000`. If the API is down, the UI still analyzes locally with the same heuristic engine.

MongoDB is optional. Without it, assessments live in process memory plus the browser history rail.
