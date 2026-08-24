from __future__ import annotations
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, HttpUrl
import uvicorn


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DB_PATH = BASE_DIR / "database.sqlite3"
INDEX_PATH = BASE_DIR / "index.html"
ADMIN_INDEX_PATH = BASE_DIR / "admin.html"

BOT_TOKEN = os.getenv("BOT_TOKEN", "8075824870:AAF049XTC0E2w8znaDCYgYvRYKix7NOyk4w").strip()

try:
    ADMIN_ID = int(os.getenv("ADMIN_ID", "802560745"))
except ValueError:
    ADMIN_ID = 0

# Сколько секунд считаем initData свежим.
INIT_DATA_MAX_AGE = 300

# Лимиты запросов.
RATE_WINDOW = 10
RATE_LIMIT_GENERAL = 30
RATE_LIMIT_ADMIN = 10

# Размер тела запроса.
MAX_BODY_SIZE = 64 * 1024


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("telegram-mini-app")


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


# ============================================================
# DATABASE
# ============================================================

def get_db() -> sqlite3.Connection:
    db = sqlite3.connect(
        DB_PATH,
        timeout=10,
        check_same_thread=False,
    )

    db.row_factory = sqlite3.Row

    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA busy_timeout = 5000")

    return db


@contextmanager
def db_connection():
    db = get_db()

    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_database():
    with db_connection() as db:

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                telegram_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                language_code TEXT,
                is_premium INTEGER DEFAULT 0,
                coins INTEGER DEFAULT 0,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            )
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS cards (
                card_key TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                url TEXT NOT NULL,
                image_url TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS action_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER,
                action TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT,
                details TEXT,
                created_at INTEGER NOT NULL
            )
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                telegram_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_activity INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_logs_user
            ON action_logs(telegram_id)
            """
        )

        db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_logs_time
            ON action_logs(created_at)
            """
        )

        # Начальная карточка.
        db.execute(
            """
            INSERT OR IGNORE INTO cards
            (
                card_key,
                title,
                description,
                url,
                image_url,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "chessmood",
                "Шахматный портал",
                "Играйте и обучайтесь шахматам",
                "https://t.me/Chelsgameappbot",
                "https://via.placeholder.com/96",
                int(time.time()),
                int(time.time()),
            ),
        )


init_database()


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.middleware("http")
async def security_headers(request: Request, call_next):

    # Ограничиваем размер body.
    content_length = request.headers.get("content-length")

    if content_length:

        try:
            if int(content_length) > MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request too large"},
                )
        except ValueError:
            pass

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    response.headers["Cache-Control"] = "no-store"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' https: data:; "
        "script-src 'self' https://telegram.org https://sad.adsgram.ai; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' https:; "
        "frame-ancestors 'self' https://web.telegram.org https://*.telegram.org;"
    )

    return response


# ============================================================
# RATE LIMIT
# ============================================================

rate_limit_storage: dict[str, list[float]] = {}


def check_rate_limit(
    ip: str,
    limit: int = RATE_LIMIT_GENERAL,
):

    now = time.time()

    history = rate_limit_storage.get(ip, [])

    history = [
        timestamp
        for timestamp in history
        if now - timestamp < RATE_WINDOW
    ]

    if len(history) >= limit:
        raise HTTPException(
            status_code=429,
            detail="Слишком много запросов.",
        )

    history.append(now)

    rate_limit_storage[ip] = history


# ============================================================
# LOGGING ACTIONS
# ============================================================

def log_action(
    request: Request,
    action: str,
    telegram_id: Optional[int] = None,
    details: Optional[dict] = None,
):

    try:
        ip = request.client.host if request.client else None

        user_agent = request.headers.get(
            "user-agent",
            "",
        )[:500]

        with db_connection() as db:

            db.execute(
                """
                INSERT INTO action_logs
                (
                    telegram_id,
                    action,
                    ip,
                    user_agent,
                    details,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    telegram_id,
                    action,
                    ip,
                    user_agent,
                    json.dumps(
                        details or {},
                        ensure_ascii=False,
                    ),
                    int(time.time()),
                ),
            )

    except Exception:
        logger.exception("Ошибка записи лога")


# ============================================================
# TELEGRAM AUTH
# ============================================================

def verify_telegram_init_data(
    init_data_raw: str,
) -> Optional[dict]:

    if not BOT_TOKEN:
        logger.error("BOT_TOKEN не установлен")
        return None

    if not init_data_raw:
        return None

    try:

        pairs = parse_qsl(
            init_data_raw,
            keep_blank_values=True,
            strict_parsing=True,
        )

        data = dict(pairs)

        received_hash = data.pop("hash", None)

        if not received_hash:
            return None

        auth_date_raw = data.get("auth_date")

        if not auth_date_raw:
            return None

        auth_date = int(auth_date_raw)

        now = int(time.time())

        # Защита от повторного использования старого initData.
        if abs(now - auth_date) > INIT_DATA_MAX_AGE:
            return None

        data_check_string = "\n".join(
            f"{key}={value}"
            for key, value in sorted(data.items())
        )

        # Telegram WebApp validation.
        secret_key = hmac.new(
            key=b"WebAppData",
            msg=BOT_TOKEN.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()

        calculated_hash = hmac.new(
            key=secret_key,
            msg=data_check_string.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(
            calculated_hash,
            received_hash,
        ):
            return None

        user_raw = data.get("user")

        if not user_raw:
            return None

        user = json.loads(user_raw)

        if not isinstance(user, dict):
            return None

        telegram_id = user.get("id")

        if not isinstance(telegram_id, int):
            return None

        return {
            "user": user,
            "auth_date": auth_date,
        }

    except Exception:
        logger.exception("Ошибка Telegram authentication")
        return None


# ============================================================
# USER REGISTRATION
# ============================================================

def register_user(
    user: dict,
    request: Request,
):

    telegram_id = int(user["id"])

    now = int(time.time())

    with db_connection() as db:

        db.execute(
            """
            INSERT INTO users
            (
                telegram_id,
                username,
                first_name,
                last_name,
                language_code,
                is_premium,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(telegram_id)
            DO UPDATE SET
                username = excluded.username,
                first_name = excluded.first_name,
                last_name = excluded.last_name,
                language_code = excluded.language_code,
                is_premium = excluded.is_premium,
                last_seen = excluded.last_seen
            """,
            (
                telegram_id,
                user.get("username"),
                user.get("first_name"),
                user.get("last_name"),
                user.get("language_code"),
                1 if user.get("is_premium") else 0,
                now,
                now,
            ),
        )
# ============================================================
# AUTH DEPENDENCY
# ============================================================

def authenticate_request(
    request: Request,
    init_data: Optional[str],
) -> dict:

    if not init_data:
        raise HTTPException(
            status_code=401,
            detail="Telegram authentication required",
        )

    result = verify_telegram_init_data(init_data)

    if not result:
        log_action(
            request,
            "authentication_failed",
        )

        raise HTTPException(
            status_code=401,
            detail="Недействительная авторизация Telegram.",
        )

    user = result["user"]

    register_user(
        user,
        request,
    )

    log_action(
        request,
        "user_request",
        int(user["id"]),
    )

    return user


# ============================================================
# ADMIN AUTH
# ============================================================

def authenticate_admin(
    request: Request,
    init_data: Optional[str],
) -> dict:

    check_rate_limit(
        request.client.host if request.client else "unknown",
        RATE_LIMIT_ADMIN,
    )

    user = authenticate_request(
        request,
        init_data,
    )

    telegram_id = int(user["id"])

    if telegram_id != ADMIN_ID:

        log_action(
            request,
            "admin_access_denied",
            telegram_id,
        )

        raise HTTPException(
            status_code=403,
            detail="Недостаточно прав.",
        )

    log_action(
        request,
        "admin_authenticated",
        telegram_id,
    )

    return user


# ============================================================
# MODELS
# ============================================================

class CardUpdateModel(BaseModel):

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    card_key: str = Field(
        min_length=1,
        max_length=30,
        pattern=r"^[a-zA-Z0-9_-]+$",
    )

    title: str = Field(
        min_length=1,
        max_length=50,
    )

    description: str = Field(
        min_length=1,
        max_length=150,
    )

    url: HttpUrl

    image_url: HttpUrl


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():

    if not INDEX_PATH.exists():

        raise HTTPException(
            status_code=404,
            detail="index.html не найден.",
        )

    return FileResponse(
        INDEX_PATH,
        headers={
            "Cache-Control": "no-store",
        },
    )


# ============================================================
# ADMIN PAGE
# ============================================================

@app.get("/admin")
async def admin_page():

    if not ADMIN_INDEX_PATH.exists():

        raise HTTPException(
            status_code=404,
            detail="admin.html не найден.",
        )

    return FileResponse(
        ADMIN_INDEX_PATH,
        headers={
            "Cache-Control": "no-store",
        },
    )


# ============================================================
# GET CARDS
# ============================================================

@app.get("/api/get-cards")
async def get_cards(
    request: Request,
    x_telegram_init_data: Optional[str] = Header(
        default=None,
    ),
):

    check_rate_limit(
        request.client.host if request.client else "unknown",
    )

    authenticate_request(
        request,
        x_telegram_init_data,
    )

    with db_connection() as db:

        rows = db.execute(
            """
            SELECT
                card_key,
                title,
                description,
                url,
                image_url
            FROM cards
            ORDER BY rowid ASC
            """
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]
# ============================================================
# UPDATE CARD
# ============================================================

@app.post("/api/admin/update-card")
async def update_card(
    data: CardUpdateModel,
    request: Request,
    x_telegram_init_data: Optional[str] = Header(
        default=None,
    ),
):

    user = authenticate_admin(
        request,
        x_telegram_init_data,
    )

    now = int(time.time())

    with db_connection() as db:

        cursor = db.execute(
            """
            UPDATE cards
            SET
                title = ?,
                description = ?,
                url = ?,
                image_url = ?,
                updated_at = ?
            WHERE card_key = ?
            """,
            (
                data.title,
                data.description,
                str(data.url),
                str(data.image_url),
                now,
                data.card_key,
            ),
        )

        if cursor.rowcount == 0:

            raise HTTPException(
                status_code=404,
                detail="Карточка не найдена.",
            )

    log_action(
        request,
        "card_updated",
        int(user["id"]),
        {
            "card_key": data.card_key,
        },
    )

    return {
        "status": "success",
    }


# ============================================================
# CREATE CARD
# ============================================================

@app.post("/api/admin/create-card")
async def create_card(
    data: CardUpdateModel,
    request: Request,
    x_telegram_init_data: Optional[str] = Header(
        default=None,
    ),
):

    user = authenticate_admin(
        request,
        x_telegram_init_data,
    )

    now = int(time.time())

    try:

        with db_connection() as db:

            db.execute(
                """
                INSERT INTO cards
                (
                    card_key,
                    title,
                    description,
                    url,
                    image_url,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data.card_key,
                    data.title,
                    data.description,
                    str(data.url),
                    str(data.image_url),
                    now,
                    now,
                ),
            )

    except sqlite3.IntegrityError:

        raise HTTPException(
            status_code=409,
            detail="Карточка с таким ключом уже существует.",
        )

    log_action(
        request,
        "card_created",
        int(user["id"]),
        {
            "card_key": data.card_key,
        },
    )

    return {
        "status": "success",
    }


# ============================================================
# DELETE CARD
# ============================================================

@app.delete("/api/admin/delete-card/{card_key}")
async def delete_card(
    card_key: str,
    request: Request,
    x_telegram_init_data: Optional[str] = Header(
        default=None,
    ),
):

    user = authenticate_admin(
        request,
        x_telegram_init_data,
    )

    if not card_key.isascii() or len(card_key) > 30:
        raise HTTPException(
            status_code=400,
            detail="Некорректный card_key.",
        )

    with db_connection() as db:

        cursor = db.execute(
            """
            DELETE FROM cards
            WHERE card_key = ?
            """,
            (card_key,),
        )

        if cursor.rowcount == 0:

            raise HTTPException(
                status_code=404,
                detail="Карточка не найдена.",
            )

    log_action(
        request,
        "card_deleted",
        int(user["id"]),
        {
            "card_key": card_key,
        },
    )

    return {
        "status": "success",
    }
# ============================================================
# ADMIN LOGS
# ============================================================

@app.get("/api/admin/logs")
async def get_admin_logs(
    request: Request,
    x_telegram_init_data: Optional[str] = Header(
        default=None,
    ),
):

    user = authenticate_admin(
        request,
        x_telegram_init_data,
    )

    with db_connection() as db:

        rows = db.execute(
            """
            SELECT
                id,
                telegram_id,
                action,
                ip,
                user_agent,
                details,
                created_at
            FROM action_logs
            ORDER BY id DESC
            LIMIT 200
            """
        ).fetchall()

    log_action(
        request,
        "admin_logs_viewed",
        int(user["id"]),
    )

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# USERS
# ============================================================

@app.get("/api/admin/users")
async def get_users(
    request: Request,
    x_telegram_init_data: Optional[str] = Header(
        default=None,
    ),
):

    user = authenticate_admin(
        request,
        x_telegram_init_data,
    )

    with db_connection() as db:

        rows = db.execute(
            """
            SELECT
                telegram_id,
                username,
                first_name,
                last_name,
                language_code,
                is_premium,
                coins,
                first_seen,
                last_seen
            FROM users
            ORDER BY last_seen DESC
            LIMIT 1000
            """
        ).fetchall()

    log_action(
        request,
        "admin_users_viewed",
        int(user["id"]),
    )

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# USER PROFILE
# ============================================================

@app.get("/api/me")
async def me(
    request: Request,
    x_telegram_init_data: Optional[str] = Header(
        default=None,
    ),
):

    user = authenticate_request(
        request,
        x_telegram_init_data,
    )

    telegram_id = int(user["id"])

    with db_connection() as db:

        row = db.execute(
            """
            SELECT
                telegram_id,
                username,
                first_name,
                last_name,
                coins,
                first_seen,
                last_seen
            FROM users
            WHERE telegram_id = ?
            """,
            (telegram_id,),
        ).fetchone()

    return dict(row)


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
    }


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    if not BOT_TOKEN:
        raise RuntimeError(
            "BOT_TOKEN не установлен. "
            "Перед запуском установите переменную окружения BOT_TOKEN."
        )

    if not ADMIN_ID:
        raise RuntimeError(
            "ADMIN_ID не установлен."
        )

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )
