from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pathlib import Path
from typing import Optional
import sqlite3
import hashlib
import secrets
import re
from datetime import datetime, timezone

# =========================================================
# JOB MART - THEME 2
# COMPLETE SINGLE-FILE APPLICATION
# Save this file as: main.py
# Run:
#   pip install fastapi uvicorn
#   uvicorn main:app --reload --host 0.0.0.0 --port 5000
# Open:
#   http://127.0.0.1:5000
# =========================================================

app = FastAPI(title="Job Mart", version="2.0.0")

# Same-origin frontend is used, so CORS is mainly for API testing.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "job_mart.db"

# Development session store.
# For production, use a persistent session store such as Redis.
SESSIONS = {}


# =========================================================
# DATABASE
# =========================================================

def db():
    conn = sqlite3.connect(
        DB_FILE,
        timeout=30,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def now():
    return datetime.now(timezone.utc).isoformat()


def column_exists(conn, table, column):
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def init_db():
    conn = db()

    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'jobseeker',
        phone TEXT DEFAULT '',
        country TEXT DEFAULT '',
        city TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employer_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        company TEXT NOT NULL,
        category TEXT NOT NULL,
        country TEXT NOT NULL,
        location TEXT DEFAULT '',
        job_type TEXT NOT NULL,
        work_mode TEXT NOT NULL,
        salary TEXT DEFAULT '',
        description TEXT NOT NULL,
        skills TEXT DEFAULT '',
        application_email TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL,
        FOREIGN KEY(employer_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        applicant_id INTEGER NOT NULL,
        cover_letter TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'applied',
        created_at TEXT NOT NULL,
        UNIQUE(job_id, applicant_id),
        FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
        FOREIGN KEY(applicant_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS saved_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(job_id, user_id),
        FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
    CREATE INDEX IF NOT EXISTS idx_jobs_employer ON jobs(employer_id);
    CREATE INDEX IF NOT EXISTS idx_apps_applicant ON applications(applicant_id);
    CREATE INDEX IF NOT EXISTS idx_apps_job ON applications(job_id);
    CREATE INDEX IF NOT EXISTS idx_saved_user ON saved_jobs(user_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
    """)

    # Small compatibility migration for databases created by an older
    # version of this single-file application.
    migrations = {
        "users": {
            "phone": "TEXT DEFAULT ''",
            "country": "TEXT DEFAULT ''",
            "city": "TEXT DEFAULT ''",
            "bio": "TEXT DEFAULT ''",
            "created_at": "TEXT NOT NULL DEFAULT ''",
        },
        "jobs": {
            "application_email": "TEXT DEFAULT ''",
            "status": "TEXT NOT NULL DEFAULT 'active'",
            "created_at": "TEXT NOT NULL DEFAULT ''",
        },
        "applications": {
            "cover_letter": "TEXT DEFAULT ''",
            "status": "TEXT NOT NULL DEFAULT 'applied'",
            "created_at": "TEXT NOT NULL DEFAULT ''",
        },
    }

    for table, columns in migrations.items():
        for name, definition in columns.items():
            if not column_exists(conn, table, name):
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
                )

    conn.commit()
    conn.close()


init_db()


# =========================================================
# SECURITY / AUTH
# =========================================================

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000
    ).hex()
    return f"{salt}${hashed}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, saved_hash = stored.split("$", 1)
        check = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            120000
        ).hex()
        return secrets.compare_digest(check, saved_hash)
    except Exception:
        return False


def valid_email(email: str) -> bool:
    return bool(
        re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email)
    )


def clean_text(value: str) -> str:
    return value.strip() if isinstance(value, str) else ""


def public_user(user):
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "phone": user["phone"],
        "country": user["country"],
        "city": user["city"],
        "bio": user["bio"],
        "created_at": user["created_at"],
    }


def current_user(request: Request):
    token = request.cookies.get("jobmart_session")

    if not token:
        return None

    user_id = SESSIONS.get(token)

    if not user_id:
        return None

    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,)
    ).fetchone()
    conn.close()

    if not user:
        SESSIONS.pop(token, None)
        return None

    return user


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Please login first"
        )
    return user


def require_employer(request: Request):
    user = require_user(request)
    if user["role"] not in ("employer", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Employer account required"
        )
    return user


def add_notification(user_id, title, message, conn=None):
    owns_connection = conn is None
    if owns_connection:
        conn = db()

    conn.execute(
        """
        INSERT INTO notifications
        (user_id, title, message, is_read, created_at)
        VALUES (?,?,?,?,?)
        """,
        (user_id, title, message, 0, now())
    )

    if owns_connection:
        conn.commit()
        conn.close()


def parse_skills(value):
    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


# =========================================================
# PYDANTIC MODELS
# =========================================================

class RegisterData(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=200)
    password: str = Field(min_length=6, max_length=128)
    role: str = "jobseeker"
    phone: str = Field(default="", max_length=30)
    country: str = Field(default="", max_length=80)
    city: str = Field(default="", max_length=100)


class LoginData(BaseModel):
    email: str = Field(min_length=5, max_length=200)
    password: str = Field(min_length=1, max_length=128)


class ProfileData(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    phone: str = Field(default="", max_length=30)
    country: str = Field(default="", max_length=80)
    city: str = Field(default="", max_length=100)
    bio: str = Field(default="", max_length=1000)


class PasswordData(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=6, max_length=128)


class JobData(BaseModel):
    title: str = Field(min_length=2, max_length=150)
    company: str = Field(min_length=2, max_length=150)
    category: str = Field(min_length=2, max_length=100)
    country: str = Field(min_length=2, max_length=80)
    location: str = Field(default="", max_length=150)
    job_type: str = Field(min_length=2, max_length=50)
    work_mode: str = Field(min_length=2, max_length=50)
    salary: str = Field(default="", max_length=100)
    description: str = Field(min_length=5, max_length=5000)
    skills: str = Field(default="", max_length=1000)
    application_email: str = Field(default="", max_length=200)


class ApplicationData(BaseModel):
    cover_letter: str = Field(default="", max_length=5000)


class ApplicationStatusData(BaseModel):
    status: str = Field(min_length=2, max_length=30)


# =========================================================
# AUTH API
# =========================================================

@app.post("/api/register")
def register(data: RegisterData):
    name = clean_text(data.name)
    email = clean_text(data.email).lower()
    password = data.password

    if not valid_email(email):
        raise HTTPException(
            status_code=400,
            detail="Please enter a valid email address"
        )

    role = clean_text(data.role).lower()
    if role not in ("jobseeker", "employer"):
        role = "jobseeker"

    conn = db()

    existing = conn.execute(
        "SELECT id FROM users WHERE email=?",
        (email,)
    ).fetchone()

    if existing:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    cur = conn.execute(
        """
        INSERT INTO users
        (name,email,password,role,phone,country,city,bio,created_at)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        (
            name,
            email,
            hash_password(password),
            role,
            clean_text(data.phone),
            clean_text(data.country),
            clean_text(data.city),
            "",
            now()
        )
    )

    user_id = cur.lastrowid

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Registration successful",
        "user_id": user_id
    }


@app.post("/api/login")
def login(data: LoginData):
    email = clean_text(data.email).lower()

    if not valid_email(email):
        raise HTTPException(
            status_code=400,
            detail="Invalid email address"
        )

    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE email=?",
        (email,)
    ).fetchone()
    conn.close()

    if not user or not verify_password(
        data.password,
        user["password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    token = secrets.token_urlsafe(32)
    SESSIONS[token] = user["id"]

    response = JSONResponse({
        "ok": True,
        "message": "Login successful",
        "user": public_user(user)
    })

    response.set_cookie(
        key="jobmart_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
        path="/"
    )

    return response


@app.post("/api/logout")
def logout(request: Request):
    token = request.cookies.get("jobmart_session")

    if token:
        SESSIONS.pop(token, None)

    response = JSONResponse({
        "ok": True,
        "message": "Logged out"
    })

    response.delete_cookie(
        "jobmart_session",
        path="/"
    )

    return response


@app.get("/api/me")
def me(request: Request):
    user = current_user(request)

    if not user:
        return {
            "logged_in": False,
            "user": None
        }

    return {
        "logged_in": True,
        "user": public_user(user)
    }


# =========================================================
# PROFILE API
# =========================================================

@app.put("/api/profile")
def update_profile(
    data: ProfileData,
    request: Request
):
    user = require_user(request)

    conn = db()
    conn.execute(
        """
        UPDATE users
        SET name=?, phone=?, country=?, city=?, bio=?
        WHERE id=?
        """,
        (
            clean_text(data.name),
            clean_text(data.phone),
            clean_text(data.country),
            clean_text(data.city),
            clean_text(data.bio),
            user["id"]
        )
    )
    conn.commit()

    updated = conn.execute(
        "SELECT * FROM users WHERE id=?",
        (user["id"],)
    ).fetchone()

    conn.close()

    return {
        "ok": True,
        "message": "Profile updated",
        "user": public_user(updated)
    }


@app.put("/api/password")
def change_password(
    data: PasswordData,
    request: Request
):
    user = require_user(request)

    if not verify_password(
        data.current_password,
        user["password"]
    ):
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect"
        )

    if data.current_password == data.new_password:
        raise HTTPException(
            status_code=400,
            detail="New password must be different"
        )

    conn = db()
    conn.execute(
        "UPDATE users SET password=? WHERE id=?",
        (hash_password(data.new_password), user["id"])
    )
    conn.commit()
    conn.close()

    # Invalidate all local sessions for this user.
    for token, user_id in list(SESSIONS.items()):
        if user_id == user["id"]:
            SESSIONS.pop(token, None)

    return {
        "ok": True,
        "message": "Password changed. Please login again."
    }


# =========================================================
# JOB API
# =========================================================

def job_dict(row, applied=False, saved=False):
    result = dict(row)
    result["skills_list"] = parse_skills(result.get("skills", ""))
    result["applied"] = bool(applied)
    result["saved"] = bool(saved)
    return result


@app.post("/api/jobs")
def create_job(
    data: JobData,
    request: Request
):
    user = require_employer(request)

    application_email = clean_text(data.application_email)

    if application_email and not valid_email(application_email):
        raise HTTPException(
            status_code=400,
            detail="Invalid application email"
        )

    conn = db()

    cur = conn.execute(
        """
        INSERT INTO jobs
        (
            employer_id,title,company,category,country,
            location,job_type,work_mode,salary,description,
            skills,application_email,status,created_at
        )
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            user["id"],
            clean_text(data.title),
            clean_text(data.company),
            clean_text(data.category),
            clean_text(data.country),
            clean_text(data.location),
            clean_text(data.job_type),
            clean_text(data.work_mode),
            clean_text(data.salary),
            clean_text(data.description),
            clean_text(data.skills),
            application_email,
            "active",
            now()
        )
    )

    job_id = cur.lastrowid

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Job posted successfully",
        "job_id": job_id
    }


@app.get("/api/jobs")
def list_jobs(
    q: str = "",
    category: str = "",
    country: str = "",
    job_type: str = "",
    work_mode: str = "",
    mine: bool = False,
    include_closed: bool = False,
    request: Optional[Request] = None
):
    conn = db()

    sql = """
        SELECT j.*, u.name AS employer_name
        FROM jobs j
        JOIN users u ON u.id=j.employer_id
        WHERE 1=1
    """

    params = []

    if not include_closed:
        sql += " AND j.status='active'"

    search = clean_text(q).lower()

    if search:
        sql += """
        AND (
            LOWER(j.title) LIKE ?
            OR LOWER(j.company) LIKE ?
            OR LOWER(j.description) LIKE ?
            OR LOWER(j.skills) LIKE ?
            OR LOWER(j.location) LIKE ?
            OR LOWER(j.category) LIKE ?
        )
        """
        value = f"%{search}%"
        params.extend([
            value, value, value,
            value, value, value
        ])

    if clean_text(category):
        sql += " AND LOWER(j.category)=LOWER(?)"
        params.append(clean_text(category))

    if clean_text(country):
        sql += " AND LOWER(j.country)=LOWER(?)"
        params.append(clean_text(country))

    if clean_text(job_type):
        sql += " AND LOWER(j.job_type)=LOWER(?)"
        params.append(clean_text(job_type))

    if clean_text(work_mode):
        sql += " AND LOWER(j.work_mode)=LOWER(?)"
        params.append(clean_text(work_mode))

    user = current_user(request) if request else None

    if mine:
        if not user:
            conn.close()
            raise HTTPException(
                status_code=401,
                detail="Login required"
            )

        if user["role"] not in ("employer", "admin"):
            conn.close()
            raise HTTPException(
                status_code=403,
                detail="Employer account required"
            )

        sql += " AND j.employer_id=?"
        params.append(user["id"])

    sql += " ORDER BY j.id DESC"

    rows = conn.execute(sql, params).fetchall()

    result = []

    for row in rows:
        applied = False
        saved = False

        if user:
            applied = bool(conn.execute(
                """
                SELECT id FROM applications
                WHERE job_id=? AND applicant_id=?
                """,
                (row["id"], user["id"])
            ).fetchone())

            saved = bool(conn.execute(
                """
                SELECT id FROM saved_jobs
                WHERE job_id=? AND user_id=?
                """,
                (row["id"], user["id"])
            ).fetchone())

        result.append(job_dict(row, applied, saved))

    conn.close()

    return {
        "ok": True,
        "jobs": result,
        "count": len(result)
    }


@app.get("/api/jobs/{job_id}")
def get_job(
    job_id: int,
    request: Request
):
    conn = db()

    job = conn.execute(
        """
        SELECT j.*, u.name AS employer_name, u.email AS employer_email
        FROM jobs j
        JOIN users u ON u.id=j.employer_id
        WHERE j.id=?
        """,
        (job_id,)
    ).fetchone()

    if not job:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Job not found"
        )

    user = current_user(request)
    applied = False
    saved = False

    if user:
        applied = bool(conn.execute(
            """
            SELECT id FROM applications
            WHERE job_id=? AND applicant_id=?
            """,
            (job_id, user["id"])
        ).fetchone())

        saved = bool(conn.execute(
            """
            SELECT id FROM saved_jobs
            WHERE job_id=? AND user_id=?
            """,
            (job_id, user["id"])
        ).fetchone())

    result = job_dict(job, applied, saved)
    conn.close()

    return {
        "ok": True,
        "job": result
    }


@app.put("/api/jobs/{job_id}")
def update_job(
    job_id: int,
    data: JobData,
    request: Request
):
    user = require_employer(request)

    application_email = clean_text(data.application_email)

    if application_email and not valid_email(application_email):
        raise HTTPException(
            status_code=400,
            detail="Invalid application email"
        )

    conn = db()

    job = conn.execute(
        "SELECT * FROM jobs WHERE id=?",
        (job_id,)
    ).fetchone()

    if not job:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Job not found"
        )

    if job["employer_id"] != user["id"] and user["role"] != "admin":
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Not allowed"
        )

    conn.execute(
        """
        UPDATE jobs
        SET title=?, company=?, category=?, country=?, location=?,
            job_type=?, work_mode=?, salary=?, description=?,
            skills=?, application_email=?
        WHERE id=?
        """,
        (
            clean_text(data.title),
            clean_text(data.company),
            clean_text(data.category),
            clean_text(data.country),
            clean_text(data.location),
            clean_text(data.job_type),
            clean_text(data.work_mode),
            clean_text(data.salary),
            clean_text(data.description),
            clean_text(data.skills),
            application_email,
            job_id
        )
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Job updated successfully"
    }


@app.delete("/api/jobs/{job_id}")
def close_job(
    job_id: int,
    request: Request
):
    user = require_employer(request)

    conn = db()

    job = conn.execute(
        "SELECT * FROM jobs WHERE id=?",
        (job_id,)
    ).fetchone()

    if not job:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Job not found"
        )

    if job["employer_id"] != user["id"] and user["role"] != "admin":
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Not allowed"
        )

    conn.execute(
        "UPDATE jobs SET status='closed' WHERE id=?",
        (job_id,)
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Job closed"
    }


@app.post("/api/jobs/{job_id}/reopen")
def reopen_job(
    job_id: int,
    request: Request
):
    user = require_employer(request)

    conn = db()

    job = conn.execute(
        "SELECT * FROM jobs WHERE id=?",
        (job_id,)
    ).fetchone()

    if not job:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Job not found"
        )

    if job["employer_id"] != user["id"] and user["role"] != "admin":
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Not allowed"
        )

    conn.execute(
        "UPDATE jobs SET status='active' WHERE id=?",
        (job_id,)
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Job reopened"
    }


# =========================================================
# APPLICATION API
# =========================================================

@app.post("/api/jobs/{job_id}/apply")
def apply_job(
    job_id: int,
    data: ApplicationData,
    request: Request
):
    user = require_user(request)

    if user["role"] in ("employer", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Employer accounts cannot apply"
        )

    conn = db()

    job = conn.execute(
        """
        SELECT * FROM jobs
        WHERE id=? AND status='active'
        """,
        (job_id,)
    ).fetchone()

    if not job:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Active job not found"
        )

    if job["employer_id"] == user["id"]:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="You cannot apply to your own job"
        )

    existing = conn.execute(
        """
        SELECT id FROM applications
        WHERE job_id=? AND applicant_id=?
        """,
        (job_id, user["id"])
    ).fetchone()

    if existing:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Already applied"
        )

    cur = conn.execute(
        """
        INSERT INTO applications
        (job_id,applicant_id,cover_letter,status,created_at)
        VALUES (?,?,?,?,?)
        """,
        (
            job_id,
            user["id"],
            clean_text(data.cover_letter),
            "applied",
            now()
        )
    )

    application_id = cur.lastrowid

    add_notification(
        job["employer_id"],
        "New job application",
        f'{user["name"]} applied for "{job["title"]}".',
        conn
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Application submitted",
        "application_id": application_id
    }


@app.get("/api/applications/mine")
def my_applications(request: Request):
    user = require_user(request)

    conn = db()

    rows = conn.execute(
        """
        SELECT
            a.*,
            j.title,
            j.company,
            j.location,
            j.country,
            j.work_mode,
            j.job_type,
            j.salary,
            j.status AS job_status
        FROM applications a
        JOIN jobs j ON j.id=a.job_id
        WHERE a.applicant_id=?
        ORDER BY a.id DESC
        """,
        (user["id"],)
    ).fetchall()

    conn.close()

    return {
        "ok": True,
        "applications": [dict(row) for row in rows],
        "count": len(rows)
    }


@app.get("/api/jobs/{job_id}/applications")
def job_applications(
    job_id: int,
    request: Request
):
    user = require_employer(request)

    conn = db()

    job = conn.execute(
        "SELECT * FROM jobs WHERE id=?",
        (job_id,)
    ).fetchone()

    if not job:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Job not found"
        )

    if job["employer_id"] != user["id"] and user["role"] != "admin":
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Not allowed"
        )

    rows = conn.execute(
        """
        SELECT
            a.*,
            u.name AS applicant_name,
            u.email AS applicant_email,
            u.phone AS applicant_phone,
            u.country AS applicant_country,
            u.city AS applicant_city,
            u.bio AS applicant_bio
        FROM applications a
        JOIN users u ON u.id=a.applicant_id
        WHERE a.job_id=?
        ORDER BY a.id DESC
        """,
        (job_id,)
    ).fetchall()

    conn.close()

    return {
        "ok": True,
        "job": dict(job),
        "applications": [dict(row) for row in rows],
        "count": len(rows)
    }


@app.put("/api/applications/{application_id}/status")
def update_application_status(
    application_id: int,
    data: ApplicationStatusData,
    request: Request
):
    user = require_employer(request)

    allowed = {
        "applied",
        "reviewing",
        "shortlisted",
        "rejected",
        "hired"
    }

    status = clean_text(data.status).lower()

    if status not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Invalid application status"
        )

    conn = db()

    row = conn.execute(
        """
        SELECT a.*, j.title, j.employer_id
        FROM applications a
        JOIN jobs j ON j.id=a.job_id
        WHERE a.id=?
        """,
        (application_id,)
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Application not found"
        )

    if row["employer_id"] != user["id"] and user["role"] != "admin":
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Not allowed"
        )

    conn.execute(
        "UPDATE applications SET status=? WHERE id=?",
        (status, application_id)
    )

    add_notification(
        row["applicant_id"],
        "Application updated",
        f'Your application for "{row["title"]}" is now {status}.',
        conn
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Application status updated"
    }


# =========================================================
# SAVED JOBS API
# =========================================================

@app.post("/api/jobs/{job_id}/save")
def save_job(
    job_id: int,
    request: Request
):
    user = require_user(request)

    if user["role"] in ("employer", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Only jobseekers can save jobs"
        )

    conn = db()

    job = conn.execute(
        "SELECT id FROM jobs WHERE id=?",
        (job_id,)
    ).fetchone()

    if not job:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Job not found"
        )

    existing = conn.execute(
        """
        SELECT id FROM saved_jobs
        WHERE job_id=? AND user_id=?
        """,
        (job_id, user["id"])
    ).fetchone()

    if existing:
        conn.execute(
            "DELETE FROM saved_jobs WHERE id=?",
            (existing["id"],)
        )
        saved = False
        message = "Job removed from saved jobs"
    else:
        conn.execute(
            """
            INSERT INTO saved_jobs
            (job_id,user_id,created_at)
            VALUES (?,?,?)
            """,
            (job_id, user["id"], now())
        )
        saved = True
        message = "Job saved"

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "saved": saved,
        "message": message
    }


@app.get("/api/saved-jobs")
def saved_jobs(request: Request):
    user = require_user(request)

    conn = db()

    rows = conn.execute(
        """
        SELECT
            j.*,
            u.name AS employer_name
        FROM saved_jobs s
        JOIN jobs j ON j.id=s.job_id
        JOIN users u ON u.id=j.employer_id
        WHERE s.user_id=?
        ORDER BY s.id DESC
        """,
        (user["id"],)
    ).fetchall()

    conn.close()

    return {
        "ok": True,
        "jobs": [job_dict(row, saved=True) for row in rows],
        "count": len(rows)
    }


# =========================================================
# NOTIFICATIONS API
# =========================================================

@app.get("/api/notifications")
def notifications(request: Request):
    user = require_user(request)

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM notifications
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 100
        """,
        (user["id"],)
    ).fetchall()

    unread = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM notifications
        WHERE user_id=? AND is_read=0
        """,
        (user["id"],)
    ).fetchone()["count"]

    conn.close()

    return {
        "ok": True,
        "notifications": [dict(row) for row in rows],
        "unread": unread
    }


@app.post("/api/notifications/read-all")
def read_all_notifications(request: Request):
    user = require_user(request)

    conn = db()
    conn.execute(
        """
        UPDATE notifications
        SET is_read=1
        WHERE user_id=?
        """,
        (user["id"],)
    )
    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Notifications marked as read"
    }


@app.post("/api/notifications/{notification_id}/read")
def read_notification(
    notification_id: int,
    request: Request
):
    user = require_user(request)

    conn = db()

    result = conn.execute(
        """
        UPDATE notifications
        SET is_read=1
        WHERE id=? AND user_id=?
        """,
        (notification_id, user["id"])
    )

    conn.commit()
    conn.close()

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Notification not found"
        )

    return {
        "ok": True,
        "message": "Notification marked as read"
    }


# =========================================================
# DASHBOARD API
# =========================================================

@app.get("/api/dashboard")
def dashboard(request: Request):
    user = require_user(request)

    conn = db()

    if user["role"] in ("employer", "admin"):
        total_jobs = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM jobs
            WHERE employer_id=?
            """,
            (user["id"],)
        ).fetchone()["count"]

        active_jobs = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM jobs
            WHERE employer_id=? AND status='active'
            """,
            (user["id"],)
        ).fetchone()["count"]

        total_applications = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM applications a
            JOIN jobs j ON j.id=a.job_id
            WHERE j.employer_id=?
            """,
            (user["id"],)
        ).fetchone()["count"]

        unread = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM notifications
            WHERE user_id=? AND is_read=0
            """,
            (user["id"],)
        ).fetchone()["count"]

        conn.close()

        return {
            "ok": True,
            "role": "employer",
            "stats": {
                "total_jobs": total_jobs,
                "active_jobs": active_jobs,
                "total_applications": total_applications,
                "unread_notifications": unread
            }
        }

    total_applications = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM applications
        WHERE applicant_id=?
        """,
        (user["id"],)
    ).fetchone()["count"]

    saved_count = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM saved_jobs
        WHERE user_id=?
        """,
        (user["id"],)
    ).fetchone()["count"]

    unread = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM notifications
        WHERE user_id=? AND is_read=0
        """,
        (user["id"],)
    ).fetchone()["count"]

    conn.close()

    return {
        "ok": True,
        "role": "jobseeker",
        "stats": {
            "total_applications": total_applications,
            "saved_jobs": saved_count,
            "unread_notifications": unread
        }
    }


# =========================================================
# FRONTEND
# =========================================================

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0757c9">
<title>Job Mart - Theme 2</title>

<style>
*{
    box-sizing:border-box;
}

:root{
    --blue:#0757c9;
    --blue2:#0a70e8;
    --dark:#12335d;
    --text:#172033;
    --muted:#68758a;
    --bg:#f3f6fb;
    --card:#ffffff;
    --line:#dfe6f0;
    --success:#159447;
    --danger:#d9363e;
    --warning:#b77700;
    --shadow:0 8px 28px rgba(15,45,90,.10);
    --radius:16px;
}

html{
    scroll-behavior:smooth;
}

body{
    margin:0;
    background:var(--bg);
    color:var(--text);
    font-family:Arial,"Noto Sans",sans-serif;
}

button,
input,
select,
textarea{
    font:inherit;
}

button{
    cursor:pointer;
}

a{
    color:inherit;
    text-decoration:none;
}

.hidden{
    display:none !important;
}

.app-header{
    position:sticky;
    top:0;
    z-index:1000;
    height:66px;
    background:linear-gradient(90deg,#064db8,#0a66d8);
    color:#fff;
    box-shadow:0 3px 14px rgba(0,0,0,.15);
}

.header-inner{
    max-width:1500px;
    height:100%;
    margin:auto;
    display:flex;
    align-items:center;
    gap:16px;
    padding:0 18px;
}

.menu-btn{
    width:42px;
    height:42px;
    border:0;
    border-radius:10px;
    color:#fff;
    background:rgba(255,255,255,.12);
    font-size:25px;
    display:grid;
    place-items:center;
}

.logo{
    font-size:20px;
    font-weight:800;
    white-space:nowrap;
    letter-spacing:.3px;
}

.header-search{
    flex:1;
    max-width:510px;
    display:flex;
    background:#fff;
    border-radius:10px;
    overflow:hidden;
}

.header-search input{
    width:100%;
    min-width:0;
    border:0;
    outline:0;
    padding:12px 14px;
}

.header-search button{
    width:52px;
    border:0;
    color:#fff;
    background:#063f9e;
    font-size:19px;
}

.header-links{
    display:flex;
    align-items:center;
    gap:5px;
    margin-left:auto;
}

.header-link{
    border:0;
    background:transparent;
    color:#fff;
    padding:10px 11px;
    border-radius:9px;
}

.header-link:hover{
    background:rgba(255,255,255,.12);
}

.icon-btn{
    position:relative;
    width:42px;
    height:42px;
    border:0;
    border-radius:10px;
    color:#fff;
    background:transparent;
    font-size:20px;
}

.badge{
    position:absolute;
    right:2px;
    top:1px;
    min-width:18px;
    height:18px;
    border-radius:99px;
    padding:1px 5px;
    display:grid;
    place-items:center;
    background:#ff334f;
    color:#fff;
    font-size:10px;
    font-weight:800;
}

.profile-btn{
    display:flex;
    align-items:center;
    gap:9px;
    border:0;
    color:#fff;
    background:transparent;
    padding:6px 8px;
    border-radius:10px;
}

.avatar{
    width:35px;
    height:35px;
    border-radius:50%;
    background:#fff;
    color:#0757c9;
    display:grid;
    place-items:center;
    font-weight:800;
}

.profile-menu{
    position:absolute;
    right:16px;
    top:58px;
    width:225px;
    background:#fff;
    color:var(--text);
    border:1px solid var(--line);
    border-radius:14px;
    box-shadow:var(--shadow);
    overflow:hidden;
}

.profile-head{
    padding:15px;
    border-bottom:1px solid var(--line);
}

.profile-head strong{
    display:block;
}

.profile-head small{
    color:var(--muted);
}

.profile-item{
    width:100%;
    border:0;
    background:#fff;
    text-align:left;
    padding:12px 15px;
}

.profile-item:hover{
    background:#f3f7ff;
}

.drawer-backdrop{
    position:fixed;
    inset:0;
    z-index:1090;
    background:rgba(0,0,0,.42);
    display:none;
}

.drawer-backdrop.show{
    display:block;
}

.side-drawer{
    position:fixed;
    z-index:1100;
    top:0;
    left:-320px;
    width:300px;
    height:100dvh;
    background:#fff;
    box-shadow:8px 0 30px rgba(0,0,0,.18);
    transition:left .22s ease;
    overflow-y:auto;
}

.side-drawer.open{
    left:0;
}

.drawer-top{
    min-height:66px;
    padding:0 18px;
    color:#fff;
    background:linear-gradient(90deg,#064db8,#0a66d8);
    display:flex;
    align-items:center;
    justify-content:space-between;
}

.drawer-top strong{
    font-size:19px;
}

.drawer-close{
    border:0;
    background:transparent;
    color:#fff;
    font-size:25px;
}

.drawer-user{
    padding:18px;
    display:flex;
    gap:12px;
    align-items:center;
    background:#f5f8ff;
    border-bottom:1px solid var(--line);
}

.drawer-user .avatar{
    background:var(--blue);
    color:#fff;
}

.drawer-nav{
    padding:12px;
}

.nav-item{
    width:100%;
    display:flex;
    align-items:center;
    gap:13px;
    padding:12px 13px;
    margin-bottom:4px;
    border:0;
    background:#fff;
    color:#1f2b3c;
    text-align:left;
    border-radius:10px;
}

.nav-item:hover,
.nav-item.active{
    background:#e9f2ff;
    color:#064db8;
}

.nav-icon{
    width:23px;
    text-align:center;
    font-size:18px;
}

.page{
    max-width:1500px;
    margin:auto;
    padding:22px;
}

.hero{
    border-radius:22px;
    background:linear-gradient(125deg,#064db8,#0a70e8);
    color:#fff;
    padding:38px;
    box-shadow:var(--shadow);
}

.hero h1{
    margin:0 0 8px;
    font-size:38px;
}

.hero p{
    margin:0 0 24px;
    opacity:.92;
}

.hero-search{
    max-width:850px;
    display:flex;
    background:#fff;
    border-radius:12px;
    overflow:hidden;
}

.hero-search input{
    flex:1;
    min-width:0;
    border:0;
    outline:0;
    padding:15px;
}

.hero-search button{
    border:0;
    color:#fff;
    background:#06449f;
    padding:0 24px;
    font-weight:700;
}

.section{
    margin-top:24px;
}

.section-head{
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:15px;
    margin-bottom:13px;
}

.section-head h2{
    margin:0;
    font-size:23px;
}

.cards{
    display:grid;
    grid-template-columns:repeat(3,minmax(0,1fr));
    gap:16px;
}

.card{
    background:var(--card);
    border:1px solid var(--line);
    border-radius:var(--radius);
    box-shadow:0 4px 15px rgba(20,50,90,.05);
}

.job-card{
    padding:18px;
}

.job-card h3{
    margin:0 0 7px;
    color:#0757c9;
    font-size:19px;
}

.company{
    font-weight:700;
    margin-bottom:9px;
}

.meta{
    color:var(--muted);
    font-size:13px;
    display:flex;
    flex-wrap:wrap;
    gap:7px;
    margin:9px 0;
}

.tag{
    display:inline-flex;
    align-items:center;
    border-radius:99px;
    background:#eef4ff;
    color:#164d98;
    padding:5px 9px;
    font-size:12px;
    font-weight:700;
}

.salary{
    font-weight:800;
    margin:10px 0;
}

.card-actions{
    display:flex;
    gap:8px;
    flex-wrap:wrap;
    margin-top:13px;
}

.btn{
    border:0;
    border-radius:9px;
    padding:10px 14px;
    font-weight:700;
}

.btn-primary{
    color:#fff;
    background:var(--blue);
}

.btn-primary:hover{
    background:#0446a5;
}

.btn-secondary{
    color:#0a4da7;
    background:#eaf2ff;
}

.btn-danger{
    color:#fff;
    background:var(--danger);
}

.btn-success{
    color:#fff;
    background:var(--success);
}

.btn-outline{
    color:#184c8e;
    background:#fff;
    border:1px solid #bfd0e8;
}

.btn:disabled{
    opacity:.55;
    cursor:not-allowed;
}

.filters{
    display:grid;
    grid-template-columns:2fr repeat(4,1fr) auto;
    gap:9px;
    margin-bottom:17px;
}

.field,
.textarea{
    width:100%;
    border:1px solid #ccd7e7;
    border-radius:9px;
    background:#fff;
    outline:none;
    padding:11px 12px;
}

.field:focus,
.textarea:focus{
    border-color:#0a66d8;
    box-shadow:0 0 0 3px rgba(10,102,216,.09);
}

.textarea{
    min-height:120px;
    resize:vertical;
}

.form-card{
    max-width:850px;
    padding:22px;
    margin:auto;
}

.form-grid{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:14px;
}

.form-group{
    display:flex;
    flex-direction:column;
    gap:7px;
}

.form-group.full{
    grid-column:1/-1;
}

.form-group label{
    font-weight:700;
    font-size:14px;
}

.stats{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:14px;
}

.stat{
    padding:20px;
}

.stat strong{
    display:block;
    font-size:30px;
    color:#0757c9;
}

.stat span{
    color:var(--muted);
}

.table-wrap{
    overflow:auto;
    border-radius:var(--radius);
    border:1px solid var(--line);
    background:#fff;
}

table{
    width:100%;
    border-collapse:collapse;
    min-width:720px;
}

th,
td{
    padding:12px 14px;
    border-bottom:1px solid var(--line);
    text-align:left;
    vertical-align:top;
}

th{
    background:#f1f6ff;
    color:#16457e;
}

.status{
    display:inline-block;
    border-radius:99px;
    padding:5px 9px;
    font-size:12px;
    font-weight:800;
    background:#edf2f7;
}

.status.applied{background:#e9f2ff;color:#1557a8}
.status.reviewing{background:#fff5d8;color:#8b6100}
.status.shortlisted{background:#e7f7ed;color:#17753b}
.status.rejected{background:#fde9ea;color:#b4262f}
.status.hired{background:#dff7e8;color:#087236}
.status.active{background:#e5f7eb;color:#087236}
.status.closed{background:#edf0f3;color:#586270}

.empty{
    padding:40px 20px;
    text-align:center;
    color:var(--muted);
    background:#fff;
    border:1px dashed #c8d3e2;
    border-radius:var(--radius);
}

.modal{
    position:fixed;
    inset:0;
    z-index:2000;
    background:rgba(0,0,0,.5);
    display:flex;
    align-items:center;
    justify-content:center;
    padding:18px;
}

.modal-box{
    width:min(760px,100%);
    max-height:90dvh;
    overflow:auto;
    background:#fff;
    border-radius:18px;
    box-shadow:var(--shadow);
}

.modal-head{
    padding:18px 20px;
    border-bottom:1px solid var(--line);
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:10px;
}

.modal-head h3{
    margin:0;
}

.modal-close{
    border:0;
    background:transparent;
    font-size:24px;
}

.modal-body{
    padding:20px;
}

.toast{
    position:fixed;
    z-index:3000;
    right:18px;
    bottom:18px;
    max-width:360px;
    padding:13px 16px;
    color:#fff;
    background:#16263d;
    border-radius:10px;
    box-shadow:var(--shadow);
}

.toast.error{
    background:#a9212a;
}

.loading{
    padding:25px;
    text-align:center;
    color:var(--muted);
}

.footer{
    padding:35px 20px;
    text-align:center;
    color:var(--muted);
}

.mobile-bottom{
    display:none;
}

@media(max-width:1100px){
    .cards{
        grid-template-columns:repeat(2,minmax(0,1fr));
    }

    .filters{
        grid-template-columns:repeat(2,1fr);
    }

    .filters input{
        grid-column:1/-1;
    }
}

@media(max-width:760px){
    .app-header{
        height:58px;
    }

    .header-inner{
        padding:0 10px;
        gap:7px;
    }

    .logo{
        font-size:17px;
    }

    .header-search{
        display:none;
    }

    .header-links{
        gap:0;
    }

    .header-link{
        display:none;
    }

    .profile-btn span:not(.avatar){
        display:none;
    }

    .page{
        padding:13px 10px 80px;
    }

    .hero{
        padding:25px 18px;
        border-radius:16px;
    }

    .hero h1{
        font-size:28px;
    }

    .hero-search button{
        padding:0 16px;
    }

    .cards{
        grid-template-columns:1fr;
    }

    .form-grid{
        grid-template-columns:1fr;
    }

    .form-group.full{
        grid-column:auto;
    }

    .stats{
        grid-template-columns:1fr 1fr;
    }

    .filters{
        grid-template-columns:1fr;
    }

    .filters input{
        grid-column:auto;
    }

    .side-drawer{
        width:min(310px,88vw);
    }

    .mobile-bottom{
        position:fixed;
        display:grid;
        grid-template-columns:repeat(4,1fr);
        left:0;
        right:0;
        bottom:0;
        z-index:900;
        background:#fff;
        border-top:1px solid var(--line);
        box-shadow:0 -4px 16px rgba(0,0,0,.08);
    }

    .mobile-bottom button{
        border:0;
        background:#fff;
        padding:8px 3px;
        color:#44536a;
        font-size:11px;
    }

    .mobile-bottom button strong{
        display:block;
        font-size:18px;
    }
}

@media(min-width:761px){
    .side-drawer{
        top:66px;
        height:calc(100dvh - 66px);
    }
}
</style>
</head>

<body>

<header class="app-header">
    <div class="header-inner">

        <button class="menu-btn" onclick="toggleDrawer()" aria-label="Menu">
            ☰
        </button>

        <button
            class="logo"
            style="border:0;background:transparent;color:#fff"
            onclick="go('home')">
            JOB MART
        </button>

        <div class="header-search">
            <input
                id="topSearch"
                placeholder="Search jobs, skills, companies..."
                onkeydown="if(event.key==='Enter') searchFromHeader()">
            <button onclick="searchFromHeader()">⌕</button>
        </div>

        <div class="header-links">
            <button class="header-link" onclick="go('jobs')">Jobs</button>
            <button class="header-link" onclick="go('jobs')">Employers</button>
            <button class="header-link" onclick="go('jobs')">Categories</button>

            <button class="icon-btn" onclick="go('notifications')" aria-label="Notifications">
                🔔
                <span id="notificationBadge" class="badge hidden">0</span>
            </button>

            <button class="profile-btn" onclick="toggleProfileMenu()">
                <span id="headerAvatar" class="avatar">?</span>
                <span id="headerName">Guest</span>
                <span>⌄</span>
            </button>
        </div>

        <div id="profileMenu" class="profile-menu hidden">
            <div class="profile-head">
                <strong id="profileMenuName">Guest</strong>
                <small id="profileMenuEmail">Not logged in</small>
            </div>
            <button class="profile-item" onclick="go('profile')">👤 My Profile</button>
            <button class="profile-item" onclick="go('settings')">⚙️ Settings</button>
            <button class="profile-item" onclick="go('password')">🔒 Change Password</button>
            <button class="profile-item" onclick="logout()">⏻ Logout</button>
        </div>

    </div>
</header>

<div id="drawerBackdrop" class="drawer-backdrop" onclick="closeDrawer()"></div>

<aside id="sideDrawer" class="side-drawer">
    <div class="drawer-top">
        <strong>JOB MART</strong>
        <button class="drawer-close" onclick="closeDrawer()">×</button>
    </div>

    <div class="drawer-user">
        <span id="drawerAvatar" class="avatar">?</span>
        <div>
            <strong id="drawerName">Guest</strong>
            <div id="drawerRole" style="font-size:12px;color:#68758a">Not logged in</div>
        </div>
    </div>

    <nav class="drawer-nav">
        <button class="nav-item" data-page="home" onclick="go('home')">
            <span class="nav-icon">⌂</span> Dashboard
        </button>

        <button class="nav-item" data-page="jobs" onclick="go('jobs')">
            <span class="nav-icon">⌕</span> Browse Jobs
        </button>

        <button class="nav-item" data-page="applications" onclick="go('applications')">
            <span class="nav-icon">▤</span> My Applications
        </button>

        <button class="nav-item" data-page="saved" onclick="go('saved')">
            <span class="nav-icon">♡</span> Saved Jobs
        </button>

        <button id="postJobNav" class="nav-item hidden" data-page="post-job" onclick="go('post-job')">
            <span class="nav-icon">⊞</span> Post a Job
        </button>

        <button id="myJobsNav" class="nav-item hidden" data-page="my-jobs" onclick="go('my-jobs')">
            <span class="nav-icon">▣</span> My Jobs
        </button>

        <button class="nav-item" data-page="profile" onclick="go('profile')">
            <span class="nav-icon">♙</span> Profile
        </button>

        <button class="nav-item" data-page="notifications" onclick="go('notifications')">
            <span class="nav-icon">♧</span> Notifications
        </button>

        <button class="nav-item" onclick="logout()">
            <span class="nav-icon">⏻</span> Logout
        </button>
    </nav>
</aside>

<main id="app" class="page"></main>

<nav class="mobile-bottom">
    <button onclick="go('home')"><strong>⌂</strong>Home</button>
    <button onclick="go('jobs')"><strong>⌕</strong>Jobs</button>
    <button onclick="go('applications')"><strong>▤</strong>Applications</button>
    <button onclick="go('profile')"><strong>♙</strong>Profile</button>
</nav>

<div id="modalRoot"></div>
<div id="toastRoot"></div>

<script>
const state = {
    user: null,
    page: "home",
    jobs: [],
    editingJobId: null
};


function escapeHtml(value){
    return String(value ?? "")
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");
}


function initials(name){
    const text = String(name || "?").trim();
    if(!text) return "?";
    return text
        .split(/\s+/)
        .slice(0,2)
        .map(x => x[0])
        .join("")
        .toUpperCase();
}


function toast(message, error=false){
    const root = document.getElementById("toastRoot");
    root.innerHTML =
        `<div class="toast ${error ? "error" : ""}">
            ${escapeHtml(message)}
         </div>`;

    setTimeout(() => {
        root.innerHTML = "";
    }, 2800);
}


async function api(url, options={}){
    const config = {
        credentials: "same-origin",
        ...options
    };

    config.headers = {
        ...(options.headers || {})
    };

    if(
        config.body &&
        typeof config.body === "object" &&
        !(config.body instanceof FormData)
    ){
        config.headers["Content-Type"] = "application/json";
        config.body = JSON.stringify(config.body);
    }

    const response = await fetch(url, config);

    let data = {};
    try{
        data = await response.json();
    }catch(e){
        data = {};
    }

    if(!response.ok){
        throw new Error(
            data.detail ||
            data.message ||
            `Request failed (${response.status})`
        );
    }

    return data;
}


function toggleDrawer(){
    document.getElementById("sideDrawer").classList.toggle("open");
    document.getElementById("drawerBackdrop").classList.toggle("show");
}


function closeDrawer(){
    document.getElementById("sideDrawer").classList.remove("open");
    document.getElementById("drawerBackdrop").classList.remove("show");
}


function toggleProfileMenu(){
    document.getElementById("profileMenu").classList.toggle("hidden");
}


document.addEventListener("click", (event) => {
    const menu = document.getElementById("profileMenu");
    const button = event.target.closest(".profile-btn");

    if(!button && !event.target.closest("#profileMenu")){
        menu.classList.add("hidden");
    }
});


function updateHeader(){
    const user = state.user;

    const name = user ? user.name : "Guest";
    const email = user ? user.email : "Not logged in";
    const role = user ? user.role : "Not logged in";

    document.getElementById("headerName").textContent =
        user ? user.name : "Guest";

    document.getElementById("headerAvatar").textContent =
        user ? initials(user.name) : "?";

    document.getElementById("profileMenuName").textContent = name;
    document.getElementById("profileMenuEmail").textContent = email;

    document.getElementById("drawerName").textContent = name;
    document.getElementById("drawerRole").textContent = role;
    document.getElementById("drawerAvatar").textContent =
        user ? initials(user.name) : "?";

    const employer = user &&
        (user.role === "employer" || user.role === "admin");

    document.getElementById("postJobNav")
        .classList.toggle("hidden", !employer);

    document.getElementById("myJobsNav")
        .classList.toggle("hidden", !employer);
}


function setActiveNav(page){
    document.querySelectorAll(".nav-item[data-page]")
        .forEach(button => {
            button.classList.toggle(
                "active",
                button.dataset.page === page
            );
        });
}


function go(page){
    state.page = page;
    closeDrawer();
    document.getElementById("profileMenu").classList.add("hidden");
    setActiveNav(page);

    const pages = {
        home: renderHome,
        jobs: renderJobs,
        applications: renderApplications,
        saved: renderSaved,
        "post-job": renderPostJob,
        "my-jobs": renderMyJobs,
        profile: renderProfile,
        password: renderPassword,
        notifications: renderNotifications,
    };

    if(pages[page]){
        pages[page]();
    }else{
        renderHome();
    }
}


function searchFromHeader(){
    const value = document.getElementById("topSearch").value.trim();

    go("jobs");

    setTimeout(() => {
        const input = document.getElementById("jobSearch");
        if(input){
            input.value = value;
            loadJobs();
        }
    }, 30);
}


async function loadMe(){
    try{
        const data = await api("/api/me");
        state.user = data.logged_in ? data.user : null;
        updateHeader();
        await updateNotificationBadge();
    }catch(error){
        state.user = null;
        updateHeader();
    }
}


async function updateNotificationBadge(){
    const badge = document.getElementById("notificationBadge");

    if(!state.user){
        badge.classList.add("hidden");
        return;
    }

    try{
        const data = await api("/api/notifications");
        if(data.unread > 0){
            badge.textContent = data.unread > 99 ? "99+" : data.unread;
            badge.classList.remove("hidden");
        }else{
            badge.classList.add("hidden");
        }
    }catch(error){
        badge.classList.add("hidden");
    }
}


function renderHome(){
    const app = document.getElementById("app");

    app.innerHTML = `
        <section class="hero">
            <h1>Find Your Dream Job</h1>
            <p>Explore job opportunities, apply online and manage your career.</p>

            <div class="hero-search">
                <input
                    id="homeSearch"
                    placeholder="Search jobs, skills, companies..."
                    onkeydown="if(event.key==='Enter') homeSearch()">
                <button onclick="homeSearch()">Search</button>
            </div>
        </section>

        <section class="section">
            <div class="section-head">
                <h2>${state.user ? "Dashboard" : "Featured Jobs"}</h2>
                <button class="btn btn-secondary" onclick="go('jobs')">
                    View all jobs
                </button>
            </div>

            ${
                state.user
                ? `<div id="dashboardArea" class="loading">Loading dashboard...</div>`
                : `<div id="homeJobs" class="cards">
                       <div class="loading">Loading jobs...</div>
                   </div>`
            }
        </section>

        <section class="section">
            <div class="cards">
                <div class="card" style="padding:20px">
                    <h3>🔎 Search</h3>
                    <p>Search jobs by title, skill, company or location.</p>
                </div>

                <div class="card" style="padding:20px">
                    <h3>📄 Apply</h3>
                    <p>Submit applications and track their status.</p>
                </div>

                <div class="card" style="padding:20px">
                    <h3>🔔 Alerts</h3>
                    <p>Receive notifications about your applications.</p>
                </div>
            </div>
        </section>

        <div class="footer">
            Job Mart • Theme 2 • Responsive job marketplace
        </div>
    `;

    if(state.user){
        loadDashboard();
    }else{
        loadFeaturedJobs();
    }
}


function homeSearch(){
    const value = document.getElementById("homeSearch").value.trim();
    go("jobs");

    setTimeout(() => {
        const input = document.getElementById("jobSearch");
        if(input){
            input.value = value;
            loadJobs();
        }
    }, 30);
}


async function loadFeaturedJobs(){
    const box = document.getElementById("homeJobs");
    if(!box) return;

    try{
        const data = await api("/api/jobs");
        const jobs = data.jobs.slice(0,6);

        if(!jobs.length){
            box.innerHTML = `<div class="empty" style="grid-column:1/-1">
                No jobs posted yet.
            </div>`;
            return;
        }

        box.innerHTML = jobs.map(jobCard).join("");
    }catch(error){
        box.innerHTML = `<div class="empty" style="grid-column:1/-1">
            ${escapeHtml(error.message)}
        </div>`;
    }
}


async function loadDashboard(){
    const box = document.getElementById("dashboardArea");
    if(!box) return;

    try{
        const data = await api("/api/dashboard");
        const s = data.stats;

        if(data.role === "employer"){
            box.innerHTML = `
                <div class="stats">
                    <div class="card stat">
                        <strong>${s.total_jobs}</strong>
                        <span>Total Jobs</span>
                    </div>
                    <div class="card stat">
                        <strong>${s.active_jobs}</strong>
                        <span>Active Jobs</span>
                    </div>
                    <div class="card stat">
                        <strong>${s.total_applications}</strong>
                        <span>Applications</span>
                    </div>
                    <div class="card stat">
                        <strong>${s.unread_notifications}</strong>
                        <span>Unread Alerts</span>
                    </div>
                </div>

                <div class="card" style="padding:20px;margin-top:15px">
                    <h3>Employer shortcuts</h3>
                    <div class="card-actions">
                        <button class="btn btn-primary" onclick="go('post-job')">
                            + Post a Job
                        </button>
                        <button class="btn btn-secondary" onclick="go('my-jobs')">
                            Manage My Jobs
                        </button>
                    </div>
                </div>
            `;
        }else{
            box.innerHTML = `
                <div class="stats">
                    <div class="card stat">
                        <strong>${s.total_applications}</strong>
                        <span>Applications</span>
                    </div>
                    <div class="card stat">
                        <strong>${s.saved_jobs}</strong>
                        <span>Saved Jobs</span>
                    </div>
                    <div class="card stat">
                        <strong>${s.unread_notifications}</strong>
                        <span>Unread Alerts</span>
                    </div>
                    <div class="card stat">
                        <strong>✓</strong>
                        <span>Profile Ready</span>
                    </div>
                </div>

                <div class="card" style="padding:20px;margin-top:15px">
                    <h3>Jobseeker shortcuts</h3>
                    <div class="card-actions">
                        <button class="btn btn-primary" onclick="go('jobs')">
                            Browse Jobs
                        </button>
                        <button class="btn btn-secondary" onclick="go('applications')">
                            My Applications
                        </button>
                        <button class="btn btn-outline" onclick="go('saved')">
                            Saved Jobs
                        </button>
                    </div>
                </div>
            `;
        }
    }catch(error){
        box.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
}


function jobCard(job){
    const skillTags = (job.skills_list || [])
        .slice(0,4)
        .map(skill => `<span class="tag">${escapeHtml(skill)}</span>`)
        .join("");

    const canApply = state.user &&
        state.user.role === "jobseeker";

    return `
        <article class="card job-card">
            <h3>${escapeHtml(job.title)}</h3>
            <div class="company">${escapeHtml(job.company)}</div>

            <div class="meta">
                <span>📍 ${escapeHtml(job.location || job.country)}</span>
                <span>• ${escapeHtml(job.job_type)}</span>
                <span>• ${escapeHtml(job.work_mode)}</span>
            </div>

            <div class="meta">
                <span class="tag">${escapeHtml(job.category)}</span>
                ${skillTags}
            </div>

            <div class="salary">
                ${escapeHtml(job.salary || "Salary not specified")}
            </div>

            <p style="color:#68758a;line-height:1.55">
                ${escapeHtml(
                    job.description.length > 180
                    ? job.description.slice(0,180) + "..."
                    : job.description
                )}
            </p>

            <div class="card-actions">
                <button class="btn btn-primary"
                        onclick="openJob(${job.id})">
                    View Details
                </button>

                ${
                    canApply
                    ? `<button
                        class="btn btn-secondary"
                        onclick="saveJob(${job.id})">
                        ${job.saved ? "♥ Saved" : "♡ Save"}
                       </button>`
                    : ""
                }
            </div>
        </article>
    `;
}


async function renderJobs(){
    const app = document.getElementById("app");

    app.innerHTML = `
        <div class="section-head">
            <h2>Browse Jobs</h2>
        </div>

        <div class="card" style="padding:15px">
            <div class="filters">
                <input id="jobSearch"
                       class="field"
                       placeholder="Search jobs, skills, companies..."
                       onkeydown="if(event.key==='Enter') loadJobs()">

                <select id="jobCategory" class="field">
                    <option value="">All categories</option>
                    <option>IT & Software</option>
                    <option>Sales</option>
                    <option>Marketing</option>
                    <option>Finance</option>
                    <option>Healthcare</option>
                    <option>Education</option>
                    <option>Engineering</option>
                    <option>Design</option>
                    <option>Customer Support</option>
                    <option>Other</option>
                </select>

                <input id="jobCountry"
                       class="field"
                       placeholder="Country">

                <select id="jobType" class="field">
                    <option value="">All job types</option>
                    <option>Full-time</option>
                    <option>Part-time</option>
                    <option>Contract</option>
                    <option>Internship</option>
                    <option>Freelance</option>
                </select>

                <select id="workMode" class="field">
                    <option value="">All work modes</option>
                    <option>On-site</option>
                    <option>Remote</option>
                    <option>Hybrid</option>
                </select>

                <button class="btn btn-primary" onclick="loadJobs()">
                    Search
                </button>
            </div>
        </div>

        <section class="section">
            <div id="jobsResult" class="cards">
                <div class="loading" style="grid-column:1/-1">
                    Loading jobs...
                </div>
            </div>
        </section>
    `;

    await loadJobs();
}


async function loadJobs(){
    const box = document.getElementById("jobsResult");
    if(!box) return;

    box.innerHTML = `
        <div class="loading" style="grid-column:1/-1">
            Loading jobs...
        </div>
    `;

    const params = new URLSearchParams();

    const values = {
        q: document.getElementById("jobSearch")?.value || "",
        category: document.getElementById("jobCategory")?.value || "",
        country: document.getElementById("jobCountry")?.value || "",
        job_type: document.getElementById("jobType")?.value || "",
        work_mode: document.getElementById("workMode")?.value || ""
    };

    Object.entries(values).forEach(([key,value]) => {
        if(value.trim()) params.set(key,value.trim());
    });

    try{
        const data = await api(
            "/api/jobs?" + params.toString()
        );

        state.jobs = data.jobs;

        if(!data.jobs.length){
            box.innerHTML = `
                <div class="empty" style="grid-column:1/-1">
                    No jobs found. Try another search.
                </div>
            `;
            return;
        }

        box.innerHTML = data.jobs.map(jobCard).join("");
    }catch(error){
        box.innerHTML = `
            <div class="empty" style="grid-column:1/-1">
                ${escapeHtml(error.message)}
            </div>
        `;
    }
}


async function openJob(id){
    try{
        const data = await api(`/api/jobs/${id}`);
        const job = data.job;

        const skills = (job.skills_list || [])
            .map(x => `<span class="tag">${escapeHtml(x)}</span>`)
            .join(" ");

        const canApply = state.user &&
            state.user.role === "jobseeker" &&
            !job.applied &&
            job.status === "active";

        document.getElementById("modalRoot").innerHTML = `
            <div class="modal" onclick="if(event.target===this)closeModal()">
                <div class="modal-box">
                    <div class="modal-head">
                        <h3>${escapeHtml(job.title)}</h3>
                        <button class="modal-close"
                                onclick="closeModal()">×</button>
                    </div>

                    <div class="modal-body">
                        <p><strong>Company:</strong>
                           ${escapeHtml(job.company)}</p>

                        <p><strong>Category:</strong>
                           ${escapeHtml(job.category)}</p>

                        <p><strong>Location:</strong>
                           ${escapeHtml(job.location || job.country)}</p>

                        <p><strong>Job type:</strong>
                           ${escapeHtml(job.job_type)}</p>

                        <p><strong>Work mode:</strong>
                           ${escapeHtml(job.work_mode)}</p>

                        <p><strong>Salary:</strong>
                           ${escapeHtml(job.salary || "Not specified")}</p>

                        <p><strong>Employer:</strong>
                           ${escapeHtml(job.employer_name)}</p>

                        <p><strong>Description:</strong></p>
                        <p style="white-space:pre-wrap;line-height:1.6">
                            ${escapeHtml(job.description)}
                        </p>

                        <p><strong>Skills:</strong></p>
                        <div class="meta">${skills || "Not specified"}</div>

                        <div class="card-actions">
                            ${
                                canApply
                                ? `<button class="btn btn-primary"
                                    onclick="showApply(${job.id})">
                                    Apply Now
                                   </button>`
                                : ""
                            }

                            ${
                                state.user &&
                                state.user.role === "jobseeker"
                                ? `<button class="btn btn-secondary"
                                    onclick="saveJob(${job.id})">
                                    ${job.saved ? "♥ Saved" : "♡ Save Job"}
                                   </button>`
                                : ""
                            }

                            ${
                                job.applied
                                ? `<span class="tag">✓ Already Applied</span>`
                                : ""
                            }

                            ${
                                !state.user
                                ? `<button class="btn btn-primary"
                                    onclick="closeModal();showLogin()">
                                    Login to Apply
                                   </button>`
                                : ""
                            }
                        </div>
                    </div>
                </div>
            </div>
        `;
    }catch(error){
        toast(error.message,true);
    }
}


function closeModal(){
    document.getElementById("modalRoot").innerHTML = "";
}


function showApply(jobId){
    document.getElementById("modalRoot").innerHTML = `
        <div class="modal">
            <div class="modal-box">
                <div class="modal-head">
                    <h3>Apply for Job</h3>
                    <button class="modal-close"
                            onclick="closeModal()">×</button>
                </div>

                <div class="modal-body">
                    <div class="form-group">
                        <label>Cover Letter</label>
                        <textarea
                            id="coverLetter"
                            class="textarea"
                            placeholder="Write a short cover letter..."></textarea>
                    </div>

                    <div class="card-actions" style="margin-top:15px">
                        <button class="btn btn-primary"
                                onclick="submitApplication(${jobId})">
                            Submit Application
                        </button>
                        <button class="btn btn-outline"
                                onclick="closeModal()">
                            Cancel
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
}


async function submitApplication(jobId){
    const cover = document.getElementById("coverLetter")?.value || "";

    try{
        const data = await api(
            `/api/jobs/${jobId}/apply`,
            {
                method:"POST",
                body:{cover_letter:cover}
            }
        );

        closeModal();
        toast(data.message);
        await updateNotificationBadge();
        go("applications");
    }catch(error){
        toast(error.message,true);
    }
}


async function saveJob(id){
    if(!state.user){
        showLogin();
        return;
    }

    try{
        const data = await api(
            `/api/jobs/${id}/save`,
            {method:"POST"}
        );

        toast(data.message);

        if(state.page === "jobs"){
            await loadJobs();
        }else if(state.page === "saved"){
            await renderSaved();
        }

        await updateNotificationBadge();
    }catch(error){
        toast(error.message,true);
    }
}


async function renderApplications(){
    const app = document.getElementById("app");

    if(!state.user){
        showLogin();
        return;
    }

    app.innerHTML = `
        <div class="section-head">
            <h2>My Applications</h2>
        </div>
        <div id="applicationsArea">
            <div class="loading">Loading applications...</div>
        </div>
    `;

    try{
        const data = await api("/api/applications/mine");

        if(!data.applications.length){
            document.getElementById("applicationsArea").innerHTML =
                `<div class="empty">
                    You have not applied to any jobs yet.
                    <br><br>
                    <button class="btn btn-primary"
                            onclick="go('jobs')">
                        Browse Jobs
                    </button>
                 </div>`;
            return;
        }

        document.getElementById("applicationsArea").innerHTML = `
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Job</th>
                            <th>Company</th>
                            <th>Location</th>
                            <th>Status</th>
                            <th>Applied</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.applications.map(a => `
                            <tr>
                                <td>
                                    <strong>${escapeHtml(a.title)}</strong>
                                    <br>
                                    <small>${escapeHtml(a.job_type)}
                                    • ${escapeHtml(a.work_mode)}</small>
                                </td>
                                <td>${escapeHtml(a.company)}</td>
                                <td>${escapeHtml(a.location || a.country)}</td>
                                <td>
                                    <span class="status ${escapeHtml(a.status)}">
                                        ${escapeHtml(a.status)}
                                    </span>
                                </td>
                                <td>${formatDate(a.created_at)}</td>
                            </tr>
                        `).join("")}
                    </tbody>
                </table>
            </div>
        `;
    }catch(error){
        document.getElementById("applicationsArea").innerHTML =
            `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
}


async function renderSaved(){
    const app = document.getElementById("app");

    if(!state.user){
        showLogin();
        return;
    }

    app.innerHTML = `
        <div class="section-head">
            <h2>Saved Jobs</h2>
        </div>
        <div id="savedArea" class="cards">
            <div class="loading" style="grid-column:1/-1">
                Loading saved jobs...
            </div>
        </div>
    `;

    try{
        const data = await api("/api/saved-jobs");
        const box = document.getElementById("savedArea");

        if(!data.jobs.length){
            box.innerHTML = `
                <div class="empty" style="grid-column:1/-1">
                    No saved jobs yet.
                    <br><br>
                    <button class="btn btn-primary"
                            onclick="go('jobs')">
                        Browse Jobs
                    </button>
                </div>
            `;
            return;
        }

        box.innerHTML = data.jobs.map(jobCard).join("");
    }catch(error){
        document.getElementById("savedArea").innerHTML =
            `<div class="empty" style="grid-column:1/-1">
                ${escapeHtml(error.message)}
             </div>`;
    }
}


function renderPostJob(){
    if(!state.user ||
       !["employer","admin"].includes(state.user.role)){
        showLogin();
        return;
    }

    state.editingJobId = null;

    document.getElementById("app").innerHTML =
        jobFormHtml(false);
}


function jobFormHtml(editing, job={}){
    return `
        <div class="section-head">
            <h2>${editing ? "Edit Job" : "Post a Job"}</h2>
        </div>

        <form class="card form-card"
              onsubmit="submitJob(event,${editing ? job.id : "null"})">

            <div class="form-grid">

                <div class="form-group">
                    <label>Job Title *</label>
                    <input id="fTitle" class="field" required
                           maxlength="150"
                           value="${escapeHtml(job.title || "")}">
                </div>

                <div class="form-group">
                    <label>Company *</label>
                    <input id="fCompany" class="field" required
                           maxlength="150"
                           value="${escapeHtml(job.company || "")}">
                </div>

                <div class="form-group">
                    <label>Category *</label>
                    <select id="fCategory" class="field" required>
                        ${categoryOptions(job.category || "")}
                    </select>
                </div>

                <div class="form-group">
                    <label>Country *</label>
                    <input id="fCountry" class="field" required
                           maxlength="80"
                           value="${escapeHtml(job.country || "")}">
                </div>

                <div class="form-group">
                    <label>Location</label>
                    <input id="fLocation" class="field"
                           maxlength="150"
                           value="${escapeHtml(job.location || "")}">
                </div>

                <div class="form-group">
                    <label>Job Type *</label>
                    <select id="fJobType" class="field" required>
                        ${selectOptions(
                            ["Full-time","Part-time","Contract","Internship","Freelance"],
                            job.job_type || ""
                        )}
                    </select>
                </div>

                <div class="form-group">
                    <label>Work Mode *</label>
                    <select id="fWorkMode" class="field" required>
                        ${selectOptions(
                            ["On-site","Remote","Hybrid"],
                            job.work_mode || ""
                        )}
                    </select>
                </div>

                <div class="form-group">
                    <label>Salary</label>
                    <input id="fSalary" class="field"
                           maxlength="100"
                           placeholder="Example: ₹6 - ₹12 LPA"
                           value="${escapeHtml(job.salary || "")}">
                </div>

                <div class="form-group full">
                    <label>Skills</label>
                    <input id="fSkills" class="field"
                           maxlength="1000"
                           placeholder="Python, FastAPI, SQL, JavaScript"
                           value="${escapeHtml(job.skills || "")}">
                </div>

                <div class="form-group full">
                    <label>Application Email</label>
                    <input id="fEmail" class="field"
                           type="email"
                           maxlength="200"
                           placeholder="hr@example.com"
                           value="${escapeHtml(job.application_email || "")}">
                </div>

                <div class="form-group full">
                    <label>Description *</label>
                    <textarea id="fDescription"
                              class="textarea"
                              required
                              maxlength="5000"
                              placeholder="Describe the role, responsibilities and requirements...">${escapeHtml(job.description || "")}</textarea>
                </div>

            </div>

            <div class="card-actions">
                <button class="btn btn-primary" type="submit">
                    ${editing ? "Update Job" : "Publish Job"}
                </button>
                <button class="btn btn-outline"
                        type="button"
                        onclick="go('${editing ? "my-jobs" : "home"}')">
                    Cancel
                </button>
            </div>
        </form>
    `;
}


function categoryOptions(selected){
    const items = [
        "IT & Software",
        "Sales",
        "Marketing",
        "Finance",
        "Healthcare",
        "Education",
        "Engineering",
        "Design",
        "Customer Support",
        "Other"
    ];

    return `
        <option value="">Select category</option>
        ${items.map(x =>
            `<option value="${escapeHtml(x)}"
                ${x===selected ? "selected" : ""}>
                ${escapeHtml(x)}
             </option>`
        ).join("")}
    `;
}


function selectOptions(items, selected){
    return `
        <option value="">Select</option>
        ${items.map(x =>
            `<option value="${escapeHtml(x)}"
                ${x===selected ? "selected" : ""}>
                ${escapeHtml(x)}
             </option>`
        ).join("")}
    `;
}


async function submitJob(event, jobId){
    event.preventDefault();

    const body = {
        title: document.getElementById("fTitle").value,
        company: document.getElementById("fCompany").value,
        category: document.getElementById("fCategory").value,
        country: document.getElementById("fCountry").value,
        location: document.getElementById("fLocation").value,
        job_type: document.getElementById("fJobType").value,
        work_mode: document.getElementById("fWorkMode").value,
        salary: document.getElementById("fSalary").value,
        skills: document.getElementById("fSkills").value,
        application_email: document.getElementById("fEmail").value,
        description: document.getElementById("fDescription").value
    };

    try{
        const data = jobId
            ? await api(`/api/jobs/${jobId}`,{
                method:"PUT",
                body
            })
            : await api("/api/jobs",{
                method:"POST",
                body
            });

        toast(data.message);
        go("my-jobs");
    }catch(error){
        toast(error.message,true);
    }
}


async function renderMyJobs(){
    const app = document.getElementById("app");

    if(!state.user ||
       !["employer","admin"].includes(state.user.role)){
        showLogin();
        return;
    }

    app.innerHTML = `
        <div class="section-head">
            <h2>My Jobs</h2>
            <button class="btn btn-primary"
                    onclick="go('post-job')">
                + Post a Job
            </button>
        </div>

        <div id="myJobsArea">
            <div class="loading">Loading jobs...</div>
        </div>
    `;

    try{
        const data = await api("/api/jobs?mine=true&include_closed=true");
        const box = document.getElementById("myJobsArea");

        if(!data.jobs.length){
            box.innerHTML = `
                <div class="empty">
                    No jobs posted yet.
                    <br><br>
                    <button class="btn btn-primary"
                            onclick="go('post-job')">
                        Post Your First Job
                    </button>
                </div>
            `;
            return;
        }

        box.innerHTML = `
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Job</th>
                            <th>Status</th>
                            <th>Applications</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.jobs.map(job => `
                            <tr>
                                <td>
                                    <strong>${escapeHtml(job.title)}</strong>
                                    <br>
                                    <small>${escapeHtml(job.company)}</small>
                                </td>
                                <td>
                                    <span class="status ${escapeHtml(job.status)}">
                                        ${escapeHtml(job.status)}
                                    </span>
                                </td>
                                <td>
                                    <button class="btn btn-secondary"
                                            onclick="viewApplicants(${job.id})">
                                        View
                                    </button>
                                </td>
                                <td>${formatDate(job.created_at)}</td>
                                <td>
                                    <div class="card-actions">
                                        <button class="btn btn-outline"
                                                onclick="editJob(${job.id})">
                                            Edit
                                        </button>
                                        ${
                                            job.status === "active"
                                            ? `<button class="btn btn-danger"
                                                onclick="closeJob(${job.id})">
                                                Close
                                               </button>`
                                            : `<button class="btn btn-success"
                                                onclick="reopenJob(${job.id})">
                                                Reopen
                                               </button>`
                                        }
                                    </div>
                                </td>
                            </tr>
                        `).join("")}
                    </tbody>
                </table>
            </div>
        `;
    }catch(error){
        document.getElementById("myJobsArea").innerHTML =
            `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
}


async function editJob(id){
    try{
        const data = await api(`/api/jobs/${id}`);
        state.editingJobId = id;

        document.getElementById("app").innerHTML =
            jobFormHtml(true,data.job);
    }catch(error){
        toast(error.message,true);
    }
}


async function closeJob(id){
    if(!confirm("Close this job?")){
        return;
    }

    try{
        const data = await api(
            `/api/jobs/${id}`,
            {method:"DELETE"}
        );
        toast(data.message);
        await renderMyJobs();
    }catch(error){
        toast(error.message,true);
    }
}


async function reopenJob(id){
    try{
        const data = await api(
            `/api/jobs/${id}/reopen`,
            {method:"POST"}
        );
        toast(data.message);
        await renderMyJobs();
    }catch(error){
        toast(error.message,true);
    }
}


async function viewApplicants(jobId){
    try{
        const data = await api(
            `/api/jobs/${jobId}/applications`
        );

        const list = data.applications;

        document.getElementById("modalRoot").innerHTML = `
            <div class="modal">
                <div class="modal-box">
                    <div class="modal-head">
                        <h3>
                            Applications -
                            ${escapeHtml(data.job.title)}
                        </h3>
                        <button class="modal-close"
                                onclick="closeModal()">×</button>
                    </div>

                    <div class="modal-body">
                        ${
                            !list.length
                            ? `<div class="empty">
                                No applications yet.
                               </div>`
                            : list.map(a => `
                                <div class="card"
                                     style="padding:15px;margin-bottom:12px">
                                    <strong>${escapeHtml(a.applicant_name)}</strong>
                                    <div style="color:#68758a">
                                        ${escapeHtml(a.applicant_email)}
                                        ${a.applicant_phone
                                            ? " • " + escapeHtml(a.applicant_phone)
                                            : ""}
                                    </div>

                                    <p>
                                        <strong>Status:</strong>
                                        <span class="status ${escapeHtml(a.status)}">
                                            ${escapeHtml(a.status)}
                                        </span>
                                    </p>

                                    <p style="white-space:pre-wrap">
                                        ${escapeHtml(
                                            a.cover_letter || "No cover letter"
                                        )}
                                    </p>

                                    <select
                                        class="field"
                                        onchange="changeApplicationStatus(
                                            ${a.id},this.value)">
                                        ${selectOptions(
                                            ["applied","reviewing","shortlisted","rejected","hired"],
                                            a.status
                                        )}
                                    </select>
                                </div>
                              `).join("")
                        }
                    </div>
                </div>
            </div>
        `;
    }catch(error){
        toast(error.message,true);
    }
}


async function changeApplicationStatus(id,status){
    try{
        const data = await api(
            `/api/applications/${id}/status`,
            {
                method:"PUT",
                body:{status}
            }
        );
        toast(data.message);
        await updateNotificationBadge();
    }catch(error){
        toast(error.message,true);
    }
}


function renderProfile(){
    if(!state.user){
        showLogin();
        return;
    }

    const u = state.user;

    document.getElementById("app").innerHTML = `
        <div class="section-head">
            <h2>My Profile</h2>
        </div>

        <form class="card form-card"
              onsubmit="saveProfile(event)">

            <div class="form-grid">

                <div class="form-group full">
                    <label>Name *</label>
                    <input id="pName"
                           class="field"
                           required
                           maxlength="100"
                           value="${escapeHtml(u.name)}">
                </div>

                <div class="form-group">
                    <label>Email</label>
                    <input class="field"
                           disabled
                           value="${escapeHtml(u.email)}">
                </div>

                <div class="form-group">
                    <label>Phone</label>
                    <input id="pPhone"
                           class="field"
                           maxlength="30"
                           value="${escapeHtml(u.phone)}">
                </div>

                <div class="form-group">
                    <label>Country</label>
                    <input id="pCountry"
                           class="field"
                           maxlength="80"
                           value="${escapeHtml(u.country)}">
                </div>

                <div class="form-group">
                    <label>City</label>
                    <input id="pCity"
                           class="field"
                           maxlength="100"
                           value="${escapeHtml(u.city)}">
                </div>

                <div class="form-group full">
                    <label>Bio</label>
                    <textarea id="pBio"
                              class="textarea"
                              maxlength="1000">${escapeHtml(u.bio)}</textarea>
                </div>

            </div>

            <div class="card-actions">
                <button class="btn btn-primary" type="submit">
                    Save Profile
                </button>
            </div>
        </form>
    `;
}


async function saveProfile(event){
    event.preventDefault();

    try{
        const data = await api(
            "/api/profile",
            {
                method:"PUT",
                body:{
                    name:document.getElementById("pName").value,
                    phone:document.getElementById("pPhone").value,
                    country:document.getElementById("pCountry").value,
                    city:document.getElementById("pCity").value,
                    bio:document.getElementById("pBio").value
                }
            }
        );

        state.user = data.user;
        updateHeader();
        toast(data.message);
    }catch(error){
        toast(error.message,true);
    }
}


function renderPassword(){
    if(!state.user){
        showLogin();
        return;
    }

    document.getElementById("app").innerHTML = `
        <div class="section-head">
            <h2>Change Password</h2>
        </div>

        <form class="card form-card"
              onsubmit="changePassword(event)">

            <div class="form-group">
                <label>Current Password</label>
                <input id="oldPassword"
                       class="field"
                       type="password"
                       required>
            </div>

            <div class="form-group" style="margin-top:14px">
                <label>New Password</label>
                <input id="newPassword"
                       class="field"
                       type="password"
                       minlength="6"
                       required>
            </div>

            <div class="card-actions">
                <button class="btn btn-primary">
                    Change Password
                </button>
            </div>
        </form>
    `;
}


async function changePassword(event){
    event.preventDefault();

    try{
        const data = await api(
            "/api/password",
            {
                method:"PUT",
                body:{
                    current_password:
                        document.getElementById("oldPassword").value,
                    new_password:
                        document.getElementById("newPassword").value
                }
            }
        );

        toast(data.message);
        setTimeout(() => {
            state.user = null;
            updateHeader();
            go("home");
            showLogin();
        },700);
    }catch(error){
        toast(error.message,true);
    }
}


function renderSettings(){
    document.getElementById("app").innerHTML = `
        <div class="section-head">
            <h2>Settings</h2>
        </div>

        <div class="card form-card">
            <h3>Job Mart Settings</h3>
            <p style="color:#68758a">
                Your account, profile and notifications can be managed
                from the menu.
            </p>

            <div class="card-actions">
                <button class="btn btn-secondary"
                        onclick="go('profile')">
                    Profile
                </button>

                <button class="btn btn-secondary"
                        onclick="go('password')">
                    Change Password
                </button>

                <button class="btn btn-secondary"
                        onclick="go('notifications')">
                    Notifications
                </button>
            </div>
        </div>
    `;
}


async function renderNotifications(){
    if(!state.user){
        showLogin();
        return;
    }

    document.getElementById("app").innerHTML = `
        <div class="section-head">
            <h2>Notifications</h2>
            <button class="btn btn-secondary"
                    onclick="markAllRead()">
                Mark all read
            </button>
        </div>

        <div id="notificationsArea">
            <div class="loading">Loading notifications...</div>
        </div>
    `;

    try{
        const data = await api("/api/notifications");
        const box = document.getElementById("notificationsArea");

        if(!data.notifications.length){
            box.innerHTML = `
                <div class="empty">
                    No notifications yet.
                </div>
            `;
            return;
        }

        box.innerHTML = data.notifications.map(n => `
            <div class="card"
                 style="padding:16px;margin-bottom:10px;
                 ${n.is_read ? "" : "border-left:4px solid #0757c9;"}">
                <div style="display:flex;
                            justify-content:space-between;
                            gap:15px">
                    <div>
                        <strong>${escapeHtml(n.title)}</strong>
                        <p style="margin:7px 0;color:#68758a">
                            ${escapeHtml(n.message)}
                        </p>
                        <small style="color:#8a95a5">
                            ${formatDate(n.created_at)}
                        </small>
                    </div>

                    ${
                        !n.is_read
                        ? `<button class="btn btn-secondary"
                            onclick="markRead(${n.id})">
                            Mark read
                           </button>`
                        : `<span class="tag">Read</span>`
                    }
                </div>
            </div>
        `).join("");

        await updateNotificationBadge();
    }catch(error){
        document.getElementById("notificationsArea").innerHTML =
            `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
}


async function markRead(id){
    try{
        await api(
            `/api/notifications/${id}/read`,
            {method:"POST"}
        );
        await renderNotifications();
    }catch(error){
        toast(error.message,true);
    }
}


async function markAllRead(){
    try{
        await api(
            "/api/notifications/read-all",
            {method:"POST"}
        );
        toast("Notifications marked as read");
        await renderNotifications();
    }catch(error){
        toast(error.message,true);
    }
}


function showLogin(){
    document.getElementById("modalRoot").innerHTML = `
        <div class="modal">
            <div class="modal-box">
                <div class="modal-head">
                    <h3>Login to Job Mart</h3>
                    <button class="modal-close"
                            onclick="closeModal()">×</button>
                </div>

                <div class="modal-body">
                    <form onsubmit="login(event)">
                        <div class="form-group">
                            <label>Email</label>
                            <input id="loginEmail"
                                   class="field"
                                   type="email"
                                   required>
                        </div>

                        <div class="form-group" style="margin-top:14px">
                            <label>Password</label>
                            <input id="loginPassword"
                                   class="field"
                                   type="password"
                                   required>
                        </div>

                        <div class="card-actions"
                             style="margin-top:15px">
                            <button class="btn btn-primary">
                                Login
                            </button>

                            <button type="button"
                                    class="btn btn-outline"
                                    onclick="showRegister()">
                                Create Account
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    `;
}


async function login(event){
    event.preventDefault();

    try{
        const data = await api(
            "/api/login",
            {
                method:"POST",
                body:{
                    email:document.getElementById("loginEmail").value,
                    password:document.getElementById("loginPassword").value
                }
            }
        );

        state.user = data.user;
        updateHeader();
        closeModal();
        toast(data.message);
        go("home");
    }catch(error){
        toast(error.message,true);
    }
}


function showRegister(){
    document.getElementById("modalRoot").innerHTML = `
        <div class="modal">
            <div class="modal-box">
                <div class="modal-head">
                    <h3>Create Job Mart Account</h3>
                    <button class="modal-close"
                            onclick="closeModal()">×</button>
                </div>

                <div class="modal-body">
                    <form onsubmit="registerUser(event)">

                        <div class="form-group">
                            <label>Full Name</label>
                            <input id="regName"
                                   class="field"
                                   minlength="2"
                                   maxlength="100"
                                   required>
                        </div>

                        <div class="form-group" style="margin-top:12px">
                            <label>Email</label>
                            <input id="regEmail"
                                   class="field"
                                   type="email"
                                   required>
                        </div>

                        <div class="form-group" style="margin-top:12px">
                            <label>Password</label>
                            <input id="regPassword"
                                   class="field"
                                   type="password"
                                   minlength="6"
                                   required>
                        </div>

                        <div class="form-group" style="margin-top:12px">
                            <label>Account Type</label>
                            <select id="regRole"
                                    class="field">
                                <option value="jobseeker">Jobseeker</option>
                                <option value="employer">Employer</option>
                            </select>
                        </div>

                        <div class="form-group" style="margin-top:12px">
                            <label>Phone</label>
                            <input id="regPhone"
                                   class="field"
                                   maxlength="30">
                        </div>

                        <div class="form-grid"
                             style="margin-top:12px">

                            <div class="form-group">
                                <label>Country</label>
                                <input id="regCountry"
                                       class="field"
                                       maxlength="80">
                            </div>

                            <div class="form-group">
                                <label>City</label>
                                <input id="regCity"
                                       class="field"
                                       maxlength="100">
                            </div>

                        </div>

                        <div class="card-actions"
                             style="margin-top:16px">

                            <button class="btn btn-primary">
                                Register
                            </button>

                            <button type="button"
                                    class="btn btn-outline"
                                    onclick="showLogin()">
                                Back to Login
                            </button>

                        </div>
                    </form>
                </div>
            </div>
        </div>
    `;
}


async function registerUser(event){
    event.preventDefault();

    try{
        const data = await api(
            "/api/register",
            {
                method:"POST",
                body:{
                    name:document.getElementById("regName").value,
                    email:document.getElementById("regEmail").value,
                    password:document.getElementById("regPassword").value,
                    role:document.getElementById("regRole").value,
                    phone:document.getElementById("regPhone").value,
                    country:document.getElementById("regCountry").value,
                    city:document.getElementById("regCity").value
                }
            }
        );

        toast(data.message);
        showLogin();

        document.getElementById("loginEmail").value =
            document.getElementById("regEmail")?.value || "";
    }catch(error){
        toast(error.message,true);
    }
}


async function logout(){
    try{
        await api(
            "/api/logout",
            {method:"POST"}
        );
    }catch(error){
        // Logout locally even if the server is unavailable.
    }

    state.user = null;
    updateHeader();
    closeModal();
    closeDrawer();
    toast("Logged out");
    go("home");
}


function formatDate(value){
    if(!value) return "-";

    try{
        const date = new Date(value);
        if(Number.isNaN(date.getTime())) return value;

        return date.toLocaleString();
    }catch(error){
        return value;
    }
}


async function boot(){
    await loadMe();
    go("home");
}


boot();
</script>

</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(HTML)


@app.get("/health")
def health():
    return {
        "ok": True,
        "app": "Job Mart",
        "version": "2.0.0"
    }
