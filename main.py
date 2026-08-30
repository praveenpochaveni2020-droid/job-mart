from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from pathlib import Path
import sqlite3
import hashlib
import secrets
import json
from datetime import datetime, timezone
from typing import Optional

app = FastAPI(title="Job Mart")

DB_FILE = Path("job_mart.db")

# =========================================================
# DATABASE
# =========================================================

def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now():
    return datetime.now(timezone.utc).isoformat()


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
        is_read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    conn.commit()
    conn.close()


init_db()

# =========================================================
# SECURITY
# =========================================================

def hash_password(password: str):
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        120000
    ).hex()
    return f"{salt}${key}"


def verify_password(password: str, stored: str):
    try:
        salt, key = stored.split("$", 1)
        check = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            120000
        ).hex()
        return secrets.compare_digest(check, key)
    except Exception:
        return False


# Simple server-side session store.
# For production, replace with Redis/database-backed sessions.
SESSIONS = {}


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

    return user


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Please login first")
    return user


def require_employer(request: Request):
    user = require_user(request)
    if user["role"] not in ("employer", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Employer account required"
        )
    return user


# =========================================================
# MODELS
# =========================================================

class RegisterData(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str
    password: str = Field(min_length=6)
    role: str = "jobseeker"
    phone: str = ""
    country: str = ""
    city: str = ""


class LoginData(BaseModel):
    email: str
    password: str


class ProfileData(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    phone: str = ""
    country: str = ""
    city: str = ""
    bio: str = ""


class JobData(BaseModel):
    title: str = Field(min_length=2, max_length=150)
    company: str = Field(min_length=2, max_length=150)
    category: str
    country: str
    location: str = ""
    job_type: str
    work_mode: str
    salary: str = ""
    description: str = Field(min_length=5)
    skills: str = ""
    application_email: str = ""


class ApplicationData(BaseModel):
    cover_letter: str = ""


# =========================================================
# AUTH
# =========================================================

@app.post("/api/register")
def register(data: RegisterData):
    role = data.role.lower().strip()

    if role not in ("jobseeker", "employer"):
        role = "jobseeker"

    email = data.email.strip().lower()

    conn = db()

    exists = conn.execute(
        "SELECT id FROM users WHERE email=?",
        (email,)
    ).fetchone()

    if exists:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    cur = conn.execute("""
        INSERT INTO users
        (name,email,password,role,phone,country,city,created_at)
        VALUES (?,?,?,?,?,?,?,?)
    """, (
        data.name.strip(),
        email,
        hash_password(data.password),
        role,
        data.phone.strip(),
        data.country.strip(),
        data.city.strip(),
        now()
    ))

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
    email = data.email.strip().lower()

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

    response = {
        "ok": True,
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }

    return {
        **response,
        "_session_token": token
    }


@app.post("/api/logout")
def logout(request: Request):
    token = request.cookies.get("jobmart_session")

    if token:
        SESSIONS.pop(token, None)

    return {"ok": True}


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
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "phone": user["phone"],
            "country": user["country"],
            "city": user["city"],
            "bio": user["bio"]
        }
    }


# =========================================================
# PROFILE
# =========================================================

@app.put("/api/profile")
def update_profile(
    data: ProfileData,
    request: Request
):
    user = require_user(request)

    conn = db()

    conn.execute("""
        UPDATE users
        SET name=?, phone=?, country=?, city=?, bio=?
        WHERE id=?
    """, (
        data.name.strip(),
        data.phone.strip(),
        data.country.strip(),
        data.city.strip(),
        data.bio.strip(),
        user["id"]
    ))

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Profile updated"
    }


# =========================================================
# JOBS
# =========================================================

@app.post("/api/jobs")
def create_job(
    data: JobData,
    request: Request
):
    user = require_employer(request)

    conn = db()

    cur = conn.execute("""
        INSERT INTO jobs
        (
            employer_id,
            title,
            company,
            category,
            country,
            location,
            job_type,
            work_mode,
            salary,
            description,
            skills,
            application_email,
            status,
            created_at
        )
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        user["id"],
        data.title.strip(),
        data.company.strip(),
        data.category.strip(),
        data.country.strip(),
        data.location.strip(),
        data.job_type.strip(),
        data.work_mode.strip(),
        data.salary.strip(),
        data.description.strip(),
        data.skills.strip(),
        data.application_email.strip(),
        "active",
        now()
    ))

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
    request: Request = None
):
    conn = db()

    sql = """
        SELECT
            j.*,
            u.name AS employer_name
        FROM jobs j
        JOIN users u ON u.id=j.employer_id
        WHERE j.status='active'
    """

    params = []

    if q.strip():
        sql += """
            AND (
                LOWER(j.title) LIKE ?
                OR LOWER(j.company) LIKE ?
                OR LOWER(j.description) LIKE ?
                OR LOWER(j.skills) LIKE ?
            )
        """

        value = f"%{q.strip().lower()}%"

        params.extend([
            value,
            value,
            value,
            value
        ])

    if category.strip():
        sql += " AND LOWER(j.category)=LOWER(?)"
        params.append(category.strip())

    if country.strip():
        sql += " AND LOWER(j.country)=LOWER(?)"
        params.append(country.strip())

    if job_type.strip():
        sql += " AND LOWER(j.job_type)=LOWER(?)"
        params.append(job_type.strip())

    if work_mode.strip():
        sql += " AND LOWER(j.work_mode)=LOWER(?)"
        params.append(work_mode.strip())

    user = current_user(request)

    if mine:
        if not user:
            conn.close()
            raise HTTPException(
                status_code=401,
                detail="Login required"
            )

        sql += " AND j.employer_id=?"
        params.append(user["id"])

    sql += " ORDER BY j.id DESC"

    rows = conn.execute(sql, params).fetchall()

    result = [dict(row) for row in rows]

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

    job = conn.execute("""
        SELECT
            j.*,
            u.name AS employer_name,
            u.email AS employer_email
        FROM jobs j
        JOIN users u ON u.id=j.employer_id
        WHERE j.id=?
    """, (job_id,)).fetchone()

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
        applied = bool(conn.execute("""
            SELECT id FROM applications
            WHERE job_id=? AND applicant_id=?
        """, (
            job_id,
            user["id"]
        )).fetchone())

        saved = bool(conn.execute("""
            SELECT id FROM saved_jobs
            WHERE job_id=? AND user_id=?
        """, (
            job_id,
            user["id"]
        )).fetchone())

    result = dict(job)

    result["applied"] = applied
    result["saved"] = saved

    conn.close()

    return {
        "ok": True,
        "job": result
    }


@app.delete("/api/jobs/{job_id}")
def delete_job(
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

    if (
        job["employer_id"] != user["id"]
        and user["role"] != "admin"
    ):
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


# =========================================================
# APPLICATIONS
# =========================================================

@app.post("/api/jobs/{job_id}/apply")
def apply_job(
    job_id: int,
    data: ApplicationData,
    request: Request
):
    user = require_user(request)

    if user["role"] == "employer":
        raise HTTPException(
            status_code=403,
            detail="Employer accounts cannot apply"
        )

    conn = db()

    job = conn.execute(
        "SELECT * FROM jobs WHERE id=? AND status='active'",
        (job_id,)
    ).fetchone()

    if not job:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Job not found"
        )

    exists = conn.execute("""
        SELECT id FROM applications
        WHERE job_id=? AND applicant_id=?
    """, (
        job_id,
        user["id"]
    )).fetchone()

    if exists:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Already applied"
        )

    conn.execute("""
        INSERT INTO applications
        (job_id,applicant_id,cover_letter,status,created_at)
        VALUES (?,?,?,?,?)
    """, (
        job_id,
        user["id"],
        data.cover_letter.strip(),
        "applied",
        now()
    ))

    conn.execute("""
        INSERT INTO notifications
        (user_id,title,message,created_at)
        VALUES (?,?,?,?)
    """, (
        job["employer_id"],
        "New job application",
        f"{user['name']} applied for {job['title']}",
        now()
    ))

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Application submitted"
    }


@app.get("/api/applications")
def applications(request: Request):
    user = require_user(request)

    conn = db()

    if user["role"] == "employer":
        rows = conn.execute("""
            SELECT
                a.*,
                j.title,
                j.company,
                u.name AS applicant_name,
                u.email AS applicant_email,
                u.phone AS applicant_phone
            FROM applications a
            JOIN jobs j ON j.id=a.job_id
            JOIN users u ON u.id=a.applicant_id
            WHERE j.employer_id=?
            ORDER BY a.id DESC
        """, (user["id"],)).fetchall()
    else:
        rows = conn.execute("""
            SELECT
                a.*,
                j.title,
                j.company,
                j.country,
                j.location
            FROM applications a
            JOIN jobs j ON j.id=a.job_id
            WHERE a.applicant_id=?
            ORDER BY a.id DESC
        """, (user["id"],)).fetchall()

    result = [dict(row) for row in rows]

    conn.close()

    return {
        "ok": True,
        "applications": result
    }


# =========================================================
# SAVED JOBS
# =========================================================

@app.post("/api/jobs/{job_id}/save")
def save_job(
    job_id: int,
    request: Request
):
    user = require_user(request)

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

    exists = conn.execute("""
        SELECT id FROM saved_jobs
        WHERE job_id=? AND user_id=?
    """, (
        job_id,
        user["id"]
    )).fetchone()

    if exists:
        conn.execute("""
            DELETE FROM saved_jobs
            WHERE job_id=? AND user_id=?
        """, (
            job_id,
            user["id"]
        ))

        message = "Removed from saved jobs"
    else:
        conn.execute("""
            INSERT INTO saved_jobs
            (job_id,user_id,created_at)
            VALUES (?,?,?)
        """, (
            job_id,
            user["id"],
            now()
        ))

        message = "Job saved"

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": message
    }


@app.get("/api/saved-jobs")
def saved_jobs(request: Request):
    user = require_user(request)

    conn = db()

    rows = conn.execute("""
        SELECT
            j.*,
            s.created_at AS saved_at
        FROM saved_jobs s
        JOIN jobs j ON j.id=s.job_id
        WHERE s.user_id=?
        ORDER BY s.id DESC
    """, (user["id"],)).fetchall()

    result = [dict(row) for row in rows]

    conn.close()

    return {
        "ok": True,
        "jobs": result
    }


# =========================================================
# NOTIFICATIONS
# =========================================================

@app.get("/api/notifications")
def notifications(request: Request):
    user = require_user(request)

    conn = db()

    rows = conn.execute("""
        SELECT *
        FROM notifications
        WHERE user_id=?
        ORDER BY id DESC
    """, (user["id"],)).fetchall()

    result = [dict(row) for row in rows]

    conn.close()

    return {
        "ok": True,
        "notifications": result
    }


@app.post("/api/notifications/read")
def notifications_read(request: Request):
    user = require_user(request)

    conn = db()

    conn.execute("""
        UPDATE notifications
        SET is_read=1
        WHERE user_id=?
    """, (user["id"],))

    conn.commit()
    conn.close()

    return {"ok": True}


# =========================================================
# DASHBOARD
# =========================================================

@app.get("/api/dashboard")
def dashboard(request: Request):
    user = require_user(request)

    conn = db()

    if user["role"] == "employer":
        jobs_count = conn.execute("""
            SELECT COUNT(*) AS c
            FROM jobs
            WHERE employer_id=?
        """, (user["id"],)).fetchone()["c"]

        applications_count = conn.execute("
