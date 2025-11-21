import os
import asyncio
import logging
import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

import psutil
import requests
import jwt
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import socketio

from database import db, create_document, get_documents

# -----------------
# App and Realtime
# -----------------
logger = logging.getLogger("betkido")
logger.setLevel(logging.INFO)
os.makedirs("logs", exist_ok=True)
file_handler = logging.FileHandler("logs/app.log")
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
sio_app = socketio.ASGIApp(sio)

class SocketIOHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            # fire and forget
            asyncio.create_task(sio.emit('log', { 'message': msg, 'level': record.levelname, 'ts': datetime.utcnow().isoformat() + 'Z'}))
        except Exception:
            pass

socket_handler = SocketIOHandler()
socket_handler.setFormatter(formatter)
logger.addHandler(socket_handler)

app = FastAPI(title="Betkido API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Socket.IO under /ws
app.mount("/ws", sio_app)

# -----------------
# Auth
# -----------------
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "60"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@betkido.local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "adminpass")

security = HTTPBearer()

def create_token(sub: str) -> str:
    payload = {
        "sub": sub,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MIN),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def require_auth(creds: HTTPAuthorizationCredentials = Depends(security)):
    token = creds.credentials
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return decoded
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    token: str
    email: str

@app.post("/auth/login", response_model=LoginResponse)
def login(req: LoginRequest):
    if req.email == ADMIN_EMAIL and req.password == ADMIN_PASSWORD:
        token = create_token(req.email)
        logger.info(f"User logged in: {req.email}")
        return LoginResponse(token=token, email=req.email)
    raise HTTPException(status_code=401, detail="Invalid credentials")

# -----------------
# Schemas
# -----------------
class SettingsUpdate(BaseModel):
    github_keys: List[str] = Field(default_factory=list)

class ValidateKeyRequest(BaseModel):
    key: str

class StartScanRequest(BaseModel):
    query: str = Field(default="pushed:>=" + (datetime.utcnow() - timedelta(days=365)).strftime('%Y-%m-%d'))
    max_repos: int = 50

# -----------------
# Helpers
# -----------------
SETTINGS_COLLECTION = "settings"
SCANS_COLLECTION = "scans"
FINDINGS_COLLECTION = "findings"
KEYS_COLLECTION = "keys"
CACHE_COLLECTION = "repo_cache"

async def broadcast_metrics():
    """Emit CPU and Memory metrics periodically."""
    while True:
        try:
            mem = psutil.virtual_memory()
            cpu = psutil.cpu_percent(interval=None)
            await sio.emit('metrics', {
                'cpu': cpu,
                'memory': {
                    'total': mem.total,
                    'used': mem.used,
                    'percent': mem.percent
                },
                'ts': datetime.utcnow().isoformat() + 'Z'
            })
        except Exception:
            pass
        await asyncio.sleep(1)

@app.on_event("startup")
async def on_startup():
    asyncio.create_task(broadcast_metrics())
    logger.info("Betkido backend started.")

# -----------------
# Settings
# -----------------
@app.get("/settings", dependencies=[Depends(require_auth)])
def get_settings():
    doc = db[SETTINGS_COLLECTION].find_one({}) or {"github_keys": []}
    return {"github_keys": doc.get("github_keys", [])}

@app.post("/settings", dependencies=[Depends(require_auth)])
def update_settings(payload: SettingsUpdate):
    db[SETTINGS_COLLECTION].update_one({}, {"$set": {"github_keys": payload.github_keys}}, upsert=True)
    logger.info(f"Updated GitHub keys count: {len(payload.github_keys)}")
    return {"ok": True}

# -----------------
# Metrics
# -----------------
@app.get("/metrics", dependencies=[Depends(require_auth)])
def get_metrics():
    mem = psutil.virtual_memory()
    cpu = psutil.cpu_percent(interval=None)
    return {
        'cpu': cpu,
        'memory': {
            'total': mem.total,
            'used': mem.used,
            'percent': mem.percent
        }
    }

# -----------------
# Overview Stats
# -----------------
@app.get("/overview", dependencies=[Depends(require_auth)])
def overview():
    total_searches = db[SCANS_COLLECTION].count_documents({})
    total_keys = db[FINDINGS_COLLECTION].count_documents({})
    total_validated = db[KEYS_COLLECTION].count_documents({"validated": True})
    scans = list(db[SCANS_COLLECTION].find({}, {"_id": 0}).sort("created_at", -1).limit(25))
    return {
        "total_searches": total_searches,
        "total_keys_found": total_keys,
        "total_validated_keys": total_validated,
        "recent_scans": scans
    }

# -----------------
# Keys
# -----------------
@app.get("/keys", dependencies=[Depends(require_auth)])
def list_keys():
    keys = list(db[KEYS_COLLECTION].find({}, {"_id": 0}))
    return {"items": keys}

@app.post("/validate/github-key", dependencies=[Depends(require_auth)])
def validate_github_key(req: ValidateKeyRequest):
    ok = _validate_github_token(req.key)
    return {"valid": ok}

# -----------------
# Scans
# -----------------
_active_scan_lock = asyncio.Lock()

@app.get("/scan/active", dependencies=[Depends(require_auth)])
def get_active_scan():
    scan = db[SCANS_COLLECTION].find_one({"status": {"$in": ["running", "queued"]}}, {"_id": 0})
    return scan or {}

@app.post("/scan/start", dependencies=[Depends(require_auth)])
async def start_scan(req: StartScanRequest, background_tasks: BackgroundTasks):
    existing = db[SCANS_COLLECTION].find_one({"status": {"$in": ["running", "queued"]}})
    if existing:
        raise HTTPException(409, detail="A scan is already in progress")
    scan_doc = {
        "id": datetime.utcnow().strftime('%Y%m%d%H%M%S'),
        "query": req.query,
        "status": "queued",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "max_repos": req.max_repos,
        "stats": {"scanned": 0, "findings": 0, "validated": 0}
    }
    db[SCANS_COLLECTION].insert_one(scan_doc)
    logger.info(f"Scan queued: {scan_doc['id']} query={req.query}")
    background_tasks.add_task(_run_scan, scan_doc["id"])
    return {"ok": True, "scan": {k: v for k, v in scan_doc.items() if k != "_id"}}

# -----------------
# Core scan logic
# -----------------

def _get_github_keys() -> List[str]:
    doc = db[SETTINGS_COLLECTION].find_one({}) or {}
    return doc.get("github_keys", [])


def _validate_github_token(token: str) -> bool:
    try:
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
        r = requests.get("https://api.github.com/rate_limit", headers=headers, timeout=10)
        return r.status_code == 200
    except Exception:
        return False


def _search_repositories(query: str, token: str, page: int) -> Dict[str, Any]:
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    params = {"q": query, "sort": "indexed", "order": "desc", "per_page": 10, "page": page}
    r = requests.get("https://api.github.com/search/repositories", headers=headers, params=params, timeout=20)
    if r.status_code != 200:
        logger.warning(f"GitHub search error {r.status_code}: {r.text[:100]}")
        return {"items": []}
    return r.json()


def _is_repo_cached(full_name: str, pushed_at: str) -> bool:
    doc = db[CACHE_COLLECTION].find_one({"full_name": full_name})
    if not doc:
        return False
    try:
        prev = datetime.fromisoformat(doc.get("pushed_at").replace('Z','+00:00'))
        current = datetime.fromisoformat(pushed_at.replace('Z','+00:00'))
        return current <= prev
    except Exception:
        return True


def _cache_repo(full_name: str, pushed_at: str):
    db[CACHE_COLLECTION].update_one({"full_name": full_name}, {"$set": {"full_name": full_name, "pushed_at": pushed_at, "updated_at": datetime.utcnow()}}, upsert=True)


def _run_trufflehog(repo_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        # Try python package import; fallback to CLI via subprocess
        try:
            from trufflehog import trufflehog as th
            results = th.run(repo_url, json=True)
            if isinstance(results, str):
                for line in results.splitlines():
                    try:
                        findings.append(json.loads(line))
                    except Exception:
                        pass
            elif isinstance(results, list):
                findings = results
        except Exception:
            import subprocess
            proc = subprocess.run(["trufflehog", "git", repo_url, "--json"], capture_output=True, text=True, timeout=600)
            for line in proc.stdout.splitlines():
                try:
                    findings.append(json.loads(line))
                except Exception:
                    pass
    except Exception as e:
        logger.warning(f"TruffleHog error: {e}")
    return findings


def _validate_finding_via_http(finding: Dict[str, Any]) -> bool:
    # naive validation attempts for URLs / tokens if present
    try:
        data = finding.get("DetectorName") or finding.get("SourceMetadata", {}).get("Data") or ""
        if isinstance(data, str) and data.startswith("http"):
            r = requests.get(data, timeout=5)
            return r.status_code < 400
    except Exception:
        pass
    return False


async def _run_scan(scan_id: str):
    async with _active_scan_lock:
        db[SCANS_COLLECTION].update_one({"id": scan_id}, {"$set": {"status": "running", "updated_at": datetime.utcnow()}})
        logger.info(f"Scan started: {scan_id}")
        keys = [k for k in _get_github_keys() if _validate_github_token(k)]
        if not keys:
            logger.error("No valid GitHub API keys configured. Aborting scan.")
            db[SCANS_COLLECTION].update_one({"id": scan_id}, {"$set": {"status": "failed", "updated_at": datetime.utcnow(), "error": "No valid GitHub keys"}})
            return
        scanned = 0
        findings_count = 0
        validated_count = 0
        max_repos = db[SCANS_COLLECTION].find_one({"id": scan_id}).get("max_repos", 50)
        query = db[SCANS_COLLECTION].find_one({"id": scan_id}).get("query")
        page = 1
        key_index = 0
        try:
            while scanned < max_repos:
                token = keys[key_index % len(keys)]
                key_index += 1
                res = _search_repositories(query, token, page)
                page += 1
                items = res.get("items", [])
                if not items:
                    break
                for repo in items:
                    if scanned >= max_repos:
                        break
                    full_name = repo.get("full_name")
                    pushed_at = repo.get("pushed_at") or datetime.utcnow().isoformat()+"Z"
                    if _is_repo_cached(full_name, pushed_at):
                        continue
                    repo_url = repo.get("html_url")
                    logger.info(f"Scanning repo: {full_name}")
                    db[SCANS_COLLECTION].update_one({"id": scan_id}, {"$set": {"stats.scanned": scanned+1, "updated_at": datetime.utcnow()}})
                    scanned += 1
                    _cache_repo(full_name, pushed_at)
                    # Run trufflehog
                    th_findings = _run_trufflehog(repo.get("clone_url") or repo_url)
                    for f in th_findings:
                        finding_doc = {
                            "repo": full_name,
                            "url": repo_url,
                            "raw": f,
                            "scan_id": scan_id,
                            "created_at": datetime.utcnow(),
                        }
                        db[FINDINGS_COLLECTION].insert_one(finding_doc)
                        findings_count += 1
                        # Try to extract token-like strings and validate
                        valid = _validate_finding_via_http(f)
                        key_doc = {
                            "repo": full_name,
                            "scan_id": scan_id,
                            "validated": bool(valid),
                            "source": f,
                            "created_at": datetime.utcnow(),
                        }
                        db[KEYS_COLLECTION].insert_one(key_doc)
                        if valid:
                            validated_count += 1
                        db[SCANS_COLLECTION].update_one({"id": scan_id}, {"$set": {"stats.findings": findings_count, "stats.validated": validated_count, "updated_at": datetime.utcnow()}})
                        await sio.emit('scan_event', {"type": "finding", "repo": full_name})
                await asyncio.sleep(0)  # yield
        except Exception as e:
            logger.exception(f"Scan failed: {e}")
            db[SCANS_COLLECTION].update_one({"id": scan_id}, {"$set": {"status": "failed", "error": str(e), "updated_at": datetime.utcnow()}})
            return
        db[SCANS_COLLECTION].update_one({"id": scan_id}, {"$set": {"status": "completed", "updated_at": datetime.utcnow()}})
        logger.info(f"Scan completed: {scan_id} - scanned={scanned} findings={findings_count} validated={validated_count}")
        await sio.emit('scan_event', {"type": "completed", "scan_id": scan_id})

# -----------------
# Basic routes
# -----------------
@app.get("/")
def root():
    return {"name": "Betkido", "message": "Backend running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
