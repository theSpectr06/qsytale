import hashlib
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "qsytale.db"

DATA_DIR.mkdir(exist_ok=True)

app = FastAPI(
    title="Qsytale",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

invite = None
invite_hash = None
invite_expires = None
invite_failures = 0


def connect():
    return sqlite3.connect(DB_PATH)


def init_db():
    with closing(connect()) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                rsa_pk TEXT NOT NULL,
                mlkem_pk TEXT NOT NULL,
                created TEXT NOT NULL
            )
        """)
        db.commit()


@app.on_event("startup")
def startup():
    global invite, invite_hash, invite_expires

    init_db()
    invite = secrets.token_urlsafe(12)
    invite_hash = hashlib.sha256(invite.encode()).hexdigest()
    invite_expires = datetime.now(timezone.utc) + timedelta(minutes=15)

    print(f"\nQsytale enrolment invite (15 min, one use): {invite}\n")


class EnrollRequest(BaseModel):
    invite_code: str
    name: str = Field(min_length=1, max_length=40)
    rsa_pk: str
    mlkem_pk: str


def authenticate(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")

    token = authorization[7:]
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    with closing(connect()) as db:
        row = db.execute(
            "SELECT id, name FROM devices WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()

    if not row:
        raise HTTPException(401, "Invalid token")

    return {"id": row[0], "name": row[1]}


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/enroll")
def enroll(payload: EnrollRequest):
    global invite, invite_hash, invite_failures

    if invite is None or datetime.now(timezone.utc) > invite_expires:
        raise HTTPException(401, "Invite expired; restart the server")

    supplied_hash = hashlib.sha256(payload.invite_code.encode()).hexdigest()

    if not secrets.compare_digest(supplied_hash, invite_hash):
        invite_failures += 1
        if invite_failures >= 5:
            invite = None
            invite_hash = None
        raise HTTPException(401, "Invalid invite code")

    device_id = secrets.token_hex(8)
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    created = datetime.now(timezone.utc).isoformat()

    with closing(connect()) as db:
        db.execute(
            """INSERT INTO devices
               (id, name, token_hash, rsa_pk, mlkem_pk, created)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                device_id, payload.name, token_hash,
                payload.rsa_pk, payload.mlkem_pk, created,
            ),
        )
        db.commit()

    invite = None
    invite_hash = None

    return {"device_id": device_id, "token": token}


@app.get("/api/devices")
def list_devices(device=Depends(authenticate)):
    with closing(connect()) as db:
        rows = db.execute(
            "SELECT id, name, rsa_pk, mlkem_pk, created FROM devices"
        ).fetchall()

    return [
        {
            "id": row[0],
            "name": row[1],
            "rsa_pk": row[2],
            "mlkem_pk": row[3],
            "fingerprint": hashlib.sha256(
                (row[2] + row[3]).encode()
            ).hexdigest()[:8],
            "created": row[4],
        }
        for row in rows
    ]


@app.get("/api/health")
def health(device=Depends(authenticate)):
    return {"status": "ok", "app": "Qsytale", "device": device["name"]}
