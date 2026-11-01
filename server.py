import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import (
    FastAPI,
    Depends,
    Header,
    HTTPException,
    UploadFile,
    File,
    Form,
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "qsytale.db"

MAX_FILE_SIZE = 20 * 1024 * 1024

# File IDs are chosen by the client (so they can be bound into AES-GCM AAD
# and the HKDF info string before upload) and validated strictly here.
FILE_ID_RE = re.compile(r"[0-9a-f]{32}")

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


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def connect():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    return db


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

        db.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                nonce TEXT NOT NULL,
                meta_nonce TEXT NOT NULL,
                meta_ct TEXT NOT NULL,
                size INTEGER NOT NULL,
                uploader TEXT NOT NULL,
                created TEXT NOT NULL,
                FOREIGN KEY (uploader) REFERENCES devices(id)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS wraps (
                file_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                wrap_json TEXT NOT NULL,
                PRIMARY KEY (file_id, device_id),
                FOREIGN KEY (file_id) REFERENCES files(id),
                FOREIGN KEY (device_id) REFERENCES devices(id)
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


# --------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------

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


# --------------------------------------------------
# SECURITY HEADERS
# --------------------------------------------------

@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "no-referrer"

    return response


# --------------------------------------------------
# FRONTEND
# --------------------------------------------------

@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


# --------------------------------------------------
# DEVICE ENROLMENT
# --------------------------------------------------

@app.post("/api/enroll")
def enroll(payload: EnrollRequest):
    global invite, invite_hash, invite_failures

    if invite is None or datetime.now(timezone.utc) > invite_expires:
        raise HTTPException(401, "Invite expired; restart the server")

    supplied_hash = hashlib.sha256(
        payload.invite_code.encode()
    ).hexdigest()

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
                device_id,
                payload.name,
                token_hash,
                payload.rsa_pk,
                payload.mlkem_pk,
                created,
            ),
        )
        db.commit()

    invite = None
    invite_hash = None

    return {
        "device_id": device_id,
        "token": token,
    }


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
    return {
        "status": "ok",
        "app": "Qsytale",
        "device": device["name"],
    }


# --------------------------------------------------
# FILE UPLOAD
# --------------------------------------------------

@app.post("/api/files")
async def upload_file(
    blob: UploadFile = File(...),
    metadata: str = Form(...),
    wraps: str = Form(...),
    device=Depends(authenticate),
):
    # Parse encrypted metadata and key wraps.
    try:
        meta = json.loads(metadata)
        wrap_list = json.loads(wraps)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(400, "Invalid JSON metadata or wraps")

    if not isinstance(meta, dict) or not isinstance(wrap_list, list):
        raise HTTPException(400, "Invalid upload structure")

    required = {"file_id", "mode", "nonce", "meta_nonce", "meta_ct", "size"}

    if not required.issubset(meta):
        raise HTTPException(400, "Missing metadata fields")

    if meta["mode"] not in ("classical", "post-quantum"):
        raise HTTPException(400, "Invalid encryption mode")

    file_id = meta["file_id"]

    if not isinstance(file_id, str) or not FILE_ID_RE.fullmatch(file_id):
        raise HTTPException(400, "Invalid file id")

    if (
        not isinstance(meta["size"], int)
        or isinstance(meta["size"], bool)
        or not 0 <= meta["size"] <= MAX_FILE_SIZE
    ):
        raise HTTPException(400, "Invalid plaintext file size")

    # Validate encrypted metadata fields.
    try:
        nonce = base64.b64decode(meta["nonce"], validate=True)
        meta_nonce = base64.b64decode(meta["meta_nonce"], validate=True)
        meta_ct = base64.b64decode(meta["meta_ct"], validate=True)
    except (ValueError, TypeError):
        raise HTTPException(400, "Invalid base64 metadata")

    if len(nonce) != 12 or len(meta_nonce) != 12:
        raise HTTPException(400, "AES-GCM nonces must be 12 bytes")

    if len(meta_ct) < 16:
        raise HTTPException(400, "Invalid encrypted file metadata")

    # Read ciphertext, allowing room for the AES-GCM tag.
    blob_data = await blob.read(MAX_FILE_SIZE + 17)
    await blob.close()

    if len(blob_data) > MAX_FILE_SIZE + 16:
        raise HTTPException(413, "File exceeds 20 MiB limit")

    # Verify that every enrolled device has a key wrap.
    with closing(connect()) as db:
        registered_ids = {
            row[0]
            for row in db.execute("SELECT id FROM devices").fetchall()
        }

        already_exists = db.execute(
            "SELECT 1 FROM files WHERE id = ?",
            (file_id,),
        ).fetchone()

    if already_exists:
        raise HTTPException(409, "File id already exists")

    supplied_ids = set()

    for item in wrap_list:
        if not isinstance(item, dict):
            raise HTTPException(400, "Invalid key wrap entry")

        device_id = item.get("device_id")
        wrap_json = item.get("wrap_json")

        if not isinstance(device_id, str) or not isinstance(wrap_json, dict):
            raise HTTPException(400, "Invalid key wrap structure")

        if device_id in supplied_ids:
            raise HTTPException(400, "Duplicate device key wrap")

        supplied_ids.add(device_id)

    if supplied_ids != registered_ids:
        raise HTTPException(
            400,
            "A key wrap is required for every enrolled device",
        )

    created = datetime.now(timezone.utc).isoformat()

    final_path = DATA_DIR / f"{file_id}.bin"
    temp_path = DATA_DIR / f"{file_id}.tmp"

    try:
        # Store ciphertext on disk.
        temp_path.write_bytes(blob_data)
        os.replace(temp_path, final_path)

        with closing(connect()) as db:
            db.execute(
                """INSERT INTO files
                   (id, mode, nonce, meta_nonce, meta_ct,
                    size, uploader, created)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    file_id,
                    meta["mode"],
                    meta["nonce"],
                    meta["meta_nonce"],
                    meta["meta_ct"],
                    meta["size"],
                    device["id"],
                    created,
                ),
            )

            for item in wrap_list:
                db.execute(
                    """INSERT INTO wraps
                       (file_id, device_id, wrap_json)
                       VALUES (?, ?, ?)""",
                    (
                        file_id,
                        item["device_id"],
                        json.dumps(item["wrap_json"]),
                    ),
                )

            db.commit()

    except Exception:
        temp_path.unlink(missing_ok=True)
        final_path.unlink(missing_ok=True)
        raise

    return {
        "status": "uploaded",
        "id": file_id,
        "stored_bytes": len(blob_data),
        "wrapped_for": len(wrap_list),
    }


# --------------------------------------------------
# FILE LIST
# --------------------------------------------------

@app.get("/api/files")
def list_files(device=Depends(authenticate)):
    with closing(connect()) as db:
        rows = db.execute(
            """SELECT id, mode, size, uploader,
                      nonce, meta_ct, meta_nonce, created
               FROM files
               ORDER BY created DESC"""
        ).fetchall()

    return [
        {
            "id": row[0],
            "mode": row[1],
            "size": row[2],
            "uploader": row[3],
            "nonce": row[4],
            "meta_ct": row[5],
            "meta_nonce": row[6],
            "created": row[7],
        }
        for row in rows
    ]


# --------------------------------------------------
# DOWNLOAD ENCRYPTED FILE
# --------------------------------------------------

@app.get("/api/files/{file_id}/blob")
def download_blob(file_id: str, device=Depends(authenticate)):
    with closing(connect()) as db:
        row = db.execute(
            "SELECT id FROM files WHERE id = ?",
            (file_id,),
        ).fetchone()

    if not row:
        raise HTTPException(404, "File not found")

    path = DATA_DIR / f"{file_id}.bin"

    if not path.is_file():
        raise HTTPException(404, "File blob missing")

    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=f"{file_id}.bin",
    )


# --------------------------------------------------
# GET CALLER'S KEY WRAP
# --------------------------------------------------

@app.get("/api/files/{file_id}/wrap")
def get_file_wrap(file_id: str, device=Depends(authenticate)):
    with closing(connect()) as db:
        row = db.execute(
            """SELECT wrap_json FROM wraps
               WHERE file_id = ? AND device_id = ?""",
            (file_id, device["id"]),
        ).fetchone()

    if not row:
        raise HTTPException(404, "Key wrap not found for this device")

    return {
        "file_id": file_id,
        "wrap": json.loads(row[0]),
    }
