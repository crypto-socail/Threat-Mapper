import asyncio
import csv
import io
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.orm import Session

import models
from auth import (
    create_access_token,
    encrypt_secret,
    get_current_user,
    hash_password,
    validate_outbound_siem_url,
    verify_password,
    verify_tenant_access,
)
from connectors import fetch_abuseipdb, fetch_hibp, fetch_misp, fetch_urlhaus, fetch_virustotal
from database import engine, get_db
from engine import AllowedIOCType, evaluate_sources, validate_and_normalize_ioc
from jobs import start_scheduler

models.Base.metadata.create_all(bind=engine)
CACHE_TTL_MINUTES = int(os.getenv("IOC_CACHE_TTL_MINUTES", "60"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    yield
    print("Shutting down background jobs...")


app = FastAPI(
    title="ThreatMapper v2 API",
    description="Multi-tenant Threat Intelligence & Monitoring Platform with JWT Authentication",
    version="2.0.0",
    lifespan=lifespan,
)

allowed_origins = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Pydantic Data Models ---
class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=72)
    org_id: int
    email: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    org_id: int
    role: str


class WatchlistCreate(BaseModel):
    org_id: int
    ioc_value: str
    ioc_type: AllowedIOCType


class IOCRequest(BaseModel):
    ioc_value: str
    ioc_type: AllowedIOCType
    force_refresh: bool = False


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)


class SiemConfigCreate(BaseModel):
    siem_type: str
    endpoint_url: Optional[HttpUrl] = None
    auth_token: str
    sync_mode: str = "push"


def _escape_stix_value(val: str) -> str:
    return val.replace("\\", "\\\\").replace("'", "\\'")


# --- Health Check ---
@app.get("/api/health")
async def health_check():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


# --- Authentication Endpoints ---
@app.post("/api/auth/register", response_model=TokenResponse)
async def register_user(req: UserRegister, db: Session = Depends(get_db)):
    org = db.query(models.Organization).filter(models.Organization.id == req.org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if db.query(models.User).filter(models.User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")

    if req.email and db.query(models.User).filter(models.User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Always assign 'analyst' role on public registration to prevent privilege escalation
    new_user = models.User(
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
        org_id=req.org_id,
        role="analyst",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token(data={
        "sub": new_user.username,
        "org_id": new_user.org_id,
        "role": new_user.role,
    })
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": new_user.username,
        "org_id": new_user.org_id,
        "role": new_user.role,
    }


@app.post("/api/auth/login", response_model=TokenResponse)
async def login_json(credentials: UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == credentials.username).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    token = create_access_token(data={"sub": user.username, "org_id": user.org_id, "role": user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "org_id": user.org_id,
        "role": user.role,
    }


@app.post("/api/auth/token")
async def login_oauth2(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    token = create_access_token(data={"sub": user.username, "org_id": user.org_id, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/api/auth/me")
async def get_current_user_profile(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    org = db.query(models.Organization).filter(models.Organization.id == current_user.org_id).first()
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "org_id": current_user.org_id,
        "org_name": org.name if org else None,
        "created_at": current_user.created_at,
    }


# --- Core IOC Lookup Endpoint (Cache-Aware) ---
@app.post("/api/lookup")
async def lookup_ioc(
    request: IOCRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    try:
        clean_ioc = validate_and_normalize_ioc(request.ioc_value, request.ioc_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    now = datetime.now(timezone.utc)
    existing_record = db.query(models.IOCRecord).filter(models.IOCRecord.ioc_value == clean_ioc).first()

    if existing_record and not request.force_refresh and existing_record.last_seen:
        last_seen = (
            existing_record.last_seen.replace(tzinfo=timezone.utc)
            if existing_record.last_seen.tzinfo is None
            else existing_record.last_seen
        )
        if now - last_seen < timedelta(minutes=CACHE_TTL_MINUTES):
            breakdown = json.loads(existing_record.source_breakdown) if existing_record.source_breakdown else {}
            return {
                "ioc": clean_ioc,
                "type": existing_record.ioc_type,
                "verdict": existing_record.verdict,
                "confidence_score": existing_record.confidence_score,
                "sources_queried": [k for k, v in breakdown.items() if v.get("applicable", True)],
                "source_breakdown": breakdown,
                "warnings": [],
                "cached": True,
            }

    results = await asyncio.gather(
        fetch_virustotal(clean_ioc, request.ioc_type),
        fetch_abuseipdb(clean_ioc, request.ioc_type),
        fetch_urlhaus(clean_ioc, request.ioc_type),
        fetch_misp(clean_ioc, request.ioc_type),
        fetch_hibp(clean_ioc, request.ioc_type),
    )
    live_source_results = dict(zip(["virustotal", "abuseipdb", "urlhaus", "misp", "hibp"], results))
    score, verdict, evaluated_sources, warnings = evaluate_sources(live_source_results)

    if existing_record:
        existing_record.confidence_score = score
        existing_record.verdict = verdict
        existing_record.source_breakdown = json.dumps(live_source_results)
        existing_record.last_seen = now
    else:
        db.add(
            models.IOCRecord(
                ioc_value=clean_ioc,
                ioc_type=request.ioc_type,
                verdict=verdict,
                confidence_score=score,
                source_breakdown=json.dumps(live_source_results),
                last_seen=now,
            )
        )
    db.commit()

    return {
        "ioc": clean_ioc,
        "type": request.ioc_type,
        "verdict": verdict,
        "confidence_score": score,
        "sources_queried": evaluated_sources,
        "source_breakdown": live_source_results,
        "warnings": warnings,
        "cached": False,
    }


# --- Watchlist Endpoints ---
@app.post("/api/watchlist")
async def add_to_watchlist(
    request: WatchlistCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    verify_tenant_access(current_user, request.org_id)

    try:
        clean_ioc = validate_and_normalize_ioc(request.ioc_value, request.ioc_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    org = db.query(models.Organization).filter(models.Organization.id == request.org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    existing = (
        db.query(models.WatchlistRecord)
        .filter(
            models.WatchlistRecord.org_id == request.org_id,
            models.WatchlistRecord.ioc_value == clean_ioc,
        )
        .first()
    )
    if existing:
        return {"status": "info", "watchlist_id": existing.id, "message": "IOC is already on the watchlist"}

    new_watch = models.WatchlistRecord(
        org_id=request.org_id,
        ioc_value=clean_ioc,
        ioc_type=request.ioc_type,
    )
    db.add(new_watch)
    db.commit()
    db.refresh(new_watch)

    return {
        "status": "success",
        "watchlist_id": new_watch.id,
        "message": f"{clean_ioc} added to watchlist for org {request.org_id}",
    }


@app.get("/api/organizations/{org_id}/watchlist")
async def get_watchlist(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    verify_tenant_access(current_user, org_id)
    watchlist = db.query(models.WatchlistRecord).filter(models.WatchlistRecord.org_id == org_id).all()
    return {
        "org_id": org_id,
        "watchlist": [
            {
                "id": w.id,
                "ioc_value": w.ioc_value,
                "ioc_type": w.ioc_type,
                "added_at": w.added_at,
                "last_checked": w.last_checked,
            }
            for w in watchlist
        ],
    }


@app.delete("/api/watchlist/{watchlist_id}")
async def delete_watchlist_item(
    watchlist_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    record = db.query(models.WatchlistRecord).filter(models.WatchlistRecord.id == watchlist_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Watchlist item not found")
    verify_tenant_access(current_user, record.org_id)

    db.delete(record)
    db.commit()
    return {"status": "success", "message": "Removed from watchlist"}


# --- Multi-Tenant Organization & SIEM Endpoints ---
@app.post("/api/organizations")
async def create_organization(
    org: OrganizationCreate,
    db: Session = Depends(get_db),
    x_admin_key: Optional[str] = Header(default=None),
):
    required_admin_key = os.getenv("ORG_CREATION_SECRET")
    if required_admin_key and x_admin_key != required_admin_key:
        raise HTTPException(status_code=403, detail="Valid X-Admin-Key header required to create organizations")

    new_org = models.Organization(name=org.name)
    db.add(new_org)
    db.commit()
    db.refresh(new_org)
    return {"message": "Organization created", "org_id": new_org.id, "name": new_org.name}


@app.post("/api/organizations/{org_id}/siem/config")
async def update_siem_config(
    org_id: int,
    config: SiemConfigCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    verify_tenant_access(current_user, org_id)

    safe_url = None
    if config.endpoint_url:
        try:
            safe_url = validate_outbound_siem_url(str(config.endpoint_url))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    encrypted_token = encrypt_secret(config.auth_token)
    existing_config = (
        db.query(models.SiemConfigRecord)
        .filter(
            models.SiemConfigRecord.org_id == org_id,
            models.SiemConfigRecord.siem_type == config.siem_type,
        )
        .first()
    )

    if existing_config:
        existing_config.endpoint_url = safe_url
        existing_config.auth_token = encrypted_token
        existing_config.sync_mode = config.sync_mode
        existing_config.updated_at = datetime.now(timezone.utc)
        message = "Configuration updated"
    else:
        db.add(
            models.SiemConfigRecord(
                org_id=org_id,
                siem_type=config.siem_type,
                endpoint_url=safe_url,
                auth_token=encrypted_token,
                sync_mode=config.sync_mode,
            )
        )
        message = "Configuration created"

    db.commit()
    return {"status": "success", "message": f"{config.siem_type} {message} for org {org_id}"}


@app.get("/api/organizations/{org_id}/siem/config")
async def get_siem_configs(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    verify_tenant_access(current_user, org_id)
    configs = db.query(models.SiemConfigRecord).filter(models.SiemConfigRecord.org_id == org_id).all()
    return {
        "org_id": org_id,
        "configs": [
            {
                "siem_type": c.siem_type,
                "endpoint_url": c.endpoint_url,
                "sync_mode": c.sync_mode,
                "updated_at": c.updated_at,
            }
            for c in configs
        ],
    }


# --- STIX 2.1 & CSV Export Endpoints ---
@app.get("/api/export/stix21/{watchlist_id}")
async def export_stix21(
    watchlist_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    record = db.query(models.WatchlistRecord).filter(models.WatchlistRecord.id == watchlist_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Watchlist record not found")
    verify_tenant_access(current_user, record.org_id)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    ioc_type_clean = record.ioc_type.lower()
    escaped_val = _escape_stix_value(record.ioc_value)

    if ioc_type_clean == "ip":
        pattern = f"[ipv4-addr:value = '{escaped_val}']"
    elif ioc_type_clean == "domain":
        pattern = f"[domain-name:value = '{escaped_val}']"
    elif ioc_type_clean == "url":
        pattern = f"[url:value = '{escaped_val}']"
    elif ioc_type_clean == "email":
        pattern = f"[email-addr:value = '{escaped_val}']"
    elif ioc_type_clean == "hash":
        hash_algo = {32: "MD5", 40: "'SHA-1'", 64: "SHA-256"}.get(len(record.ioc_value), "SHA-256")
        pattern = f"[file:hashes.{hash_algo} = '{escaped_val}']"
    else:
        pattern = f"[x-threatmapper-ioc:value = '{escaped_val}']"

    return {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid4()}",
                "created": now_iso,
                "modified": now_iso,
                "name": f"ThreatMapper Alert - {record.ioc_value}",
                "description": f"Automated STIX 2.1 export for organization {record.org_id}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now_iso,
            }
        ],
    }


@app.get("/api/export/csv")
async def export_watchlist_csv(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    watched = (
        db.query(models.WatchlistRecord)
        .filter(models.WatchlistRecord.org_id == current_user.org_id)
        .all()
    )
    ioc_map = {
        r.ioc_value: r
        for r in db.query(models.IOCRecord)
        .filter(models.IOCRecord.ioc_value.in_([w.ioc_value for w in watched]))
        .all()
    }

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ioc_value", "ioc_type", "verdict", "confidence_score", "added_at", "last_checked"])
    for w in watched:
        cached = ioc_map.get(w.ioc_value)
        writer.writerow([
            w.ioc_value,
            w.ioc_type,
            cached.verdict if cached else "pending",
            cached.confidence_score if cached else 0.0,
            w.added_at.isoformat() if w.added_at else "",
            w.last_checked.isoformat() if w.last_checked else "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=threatmapper_org_{current_user.org_id}.csv"},
    )


# --- SIEM Live Feed (Pull Mode) ---
@app.get("/api/feed")
async def get_live_feed(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    watched = (
        db.query(models.WatchlistRecord.ioc_value)
        .filter(models.WatchlistRecord.org_id == current_user.org_id)
        .all()
    )
    watched_values = [w[0] for w in watched]
    if not watched_values:
        return {"org_id": current_user.org_id, "feed": []}

    active_threats = (
        db.query(models.IOCRecord)
        .filter(
            models.IOCRecord.ioc_value.in_(watched_values),
            models.IOCRecord.verdict.in_(["malicious", "suspicious"]),
        )
        .all()
    )
    return {
        "org_id": current_user.org_id,
        "feed": [
            {
                "ioc_value": t.ioc_value,
                "ioc_type": t.ioc_type,
                "verdict": t.verdict,
                "confidence_score": t.confidence_score,
                "last_seen": t.last_seen,
            }
            for t in active_threats
        ],
    }


# --- Threat Correlation & Dashboard Analytics ---
@app.get("/api/correlation")
async def get_correlation(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    watched = (
        db.query(models.WatchlistRecord)
        .filter(models.WatchlistRecord.org_id == current_user.org_id)
        .all()
    )
    type_distribution = {}
    for w in watched:
        type_distribution[w.ioc_type] = type_distribution.get(w.ioc_type, 0) + 1

    return {
        "org_id": current_user.org_id,
        "total_monitored": len(watched),
        "distribution": type_distribution,
    }


# --- Analyst Alerts ---
@app.get("/api/alerts")
async def get_alerts(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    alerts = (
        db.query(models.AlertRecord)
        .filter(models.AlertRecord.org_id == current_user.org_id)
        .order_by(models.AlertRecord.created_at.desc())
        .all()
    )
    return {
        "org_id": current_user.org_id,
        "alerts": [
            {
                "id": a.id,
                "ioc_value": a.ioc_value,
                "ioc_type": a.ioc_type,
                "threat_score": a.threat_score,
                "message": a.message,
                "acknowledged": a.acknowledged,
                "created_at": a.created_at,
            }
            for a in alerts
        ],
    }


@app.patch("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    alert = db.query(models.AlertRecord).filter(models.AlertRecord.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    verify_tenant_access(current_user, alert.org_id)

    alert.acknowledged = True
    db.commit()
    return {"status": "success", "id": alert.id, "acknowledged": True}