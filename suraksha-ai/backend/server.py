from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analyzer import analyze

load_dotenv()

app = FastAPI(title="Suraksha.ai DRP Analyzer")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STORE: dict[str, dict[str, Any]] = {}
mongo_client = None
mongo_col = None

try:
    from motor.motor_asyncio import AsyncIOMotorClient

    mongo_url = os.environ.get("MONGO_URL")
    if mongo_url:
        mongo_client = AsyncIOMotorClient(mongo_url)
        mongo_col = mongo_client[os.environ.get("DB_NAME", "suraksha")].assessments
except Exception:
    mongo_col = None


class BrandBaseline(BaseModel):
    brand_name: str = ""
    official_domains: list[str] = Field(default_factory=list)
    official_emails: list[str] = Field(default_factory=list)
    social_handles: dict[str, str] = Field(default_factory=dict)
    keywords: list[str] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    artifact_type: Literal["url", "domain", "email", "social", "text", "document", "image"]
    brand_baseline: BrandBaseline
    artifact: dict[str, Any] = Field(default_factory=dict)


class ApprovalUpdate(BaseModel):
    state: Literal["pending_review", "approved", "rejected", "needs_more_data"]
    reviewer: str = "soc-analyst"
    notes: str = ""


async def persist(doc: dict[str, Any]) -> None:
    STORE[doc["assessment_id"]] = doc
    if mongo_col is not None:
        await mongo_col.replace_one({"assessment_id": doc["assessment_id"]}, doc, upsert=True)


async def load_all() -> list[dict[str, Any]]:
    if mongo_col is not None:
        rows = await mongo_col.find({}, {"_id": 0}).to_list(500)
        for row in rows:
            STORE[row["assessment_id"]] = row
        return rows
    return list(STORE.values())


@app.get("/api/")
async def root():
    return {"message": "Suraksha.ai DRP analyzer online", "engine": "heuristic-v1"}


@app.post("/api/analyze")
async def create_analysis(req: AnalyzeRequest):
    result = analyze(req.model_dump())
    await persist(result)
    return result


@app.get("/api/assessments")
async def list_assessments():
    rows = await load_all()
    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    return rows


@app.get("/api/assessments/{assessment_id}")
async def get_assessment(assessment_id: str):
    if assessment_id in STORE:
        return STORE[assessment_id]
    if mongo_col is not None:
        doc = await mongo_col.find_one({"assessment_id": assessment_id}, {"_id": 0})
        if doc:
            STORE[assessment_id] = doc
            return doc
    raise HTTPException(status_code=404, detail="Assessment not found")


@app.patch("/api/assessments/{assessment_id}/approval")
async def update_approval(assessment_id: str, body: ApprovalUpdate):
    doc = STORE.get(assessment_id)
    if not doc and mongo_col is not None:
        doc = await mongo_col.find_one({"assessment_id": assessment_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Assessment not found")
    doc["approval"] = {
        "state": body.state,
        "reviewer": body.reviewer,
        "notes": body.notes,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    await persist(doc)
    return doc


@app.on_event("shutdown")
async def shutdown():
    if mongo_client is not None:
        mongo_client.close()
