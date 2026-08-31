from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from pathlib import Path
from typing import Optional
import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone

# =========================================================
# JOB MART - THEME 2
# Complete single-file FastAPI application
# =========================================================

app = FastAPI(title="Job Mart", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "job_mart.db"

# In-memory sessions for local development.
# A cookie contains only a random session token.
SESSIONS = {}


# =========================================================
# DATABASE
# =========================================================

def db():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    conn = db()
    conn.executescript(
        """
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
        """
    )
    conn.commit()
    conn.close()


init_db()


# =========================================================
# AUTH HELPERS
# =========================================================

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000,
    ).hex()
    return f"{salt}${key}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, key = stored.split("$", 1)
        check = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            120000,
        ).hex()
        return secrets.compare_digest(check, key)
    except Exception:
        return False


def current_user(request: Request):
    token = request.cookies.get("jobmart_session")
    if not token:
        return None
    user_id = SESSIONS.get(token)
    if not user_id:
        return None
    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    if not user:
        SESSIONS.pop(token, None)
    return user


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Please login first")
    return user


def require_employer(request: Request):
    user = require_user(request)
    if user["role"] not in ("employer", "admin"):
        raise HTTPException(status_code=403, detail="Employer account required")
    return user


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
    }


# =========================================================
# PYDANTIC MODELS
# =========================================================

class RegisterData(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    role: str = "jobseeker"
    phone: str = Field(default="", max_length=30)
    country: str = Field(default="", max_length=80)
    city: str = Field(default="", max_length=100)


class LoginData(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ProfileData(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    phone: str = Field(default="", max_length=30)
    country: str = Field(default="", max_length=80)
    city: str = Field(default="", max_length=100)
    bio: str = Field(default="", max_length=1000)


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
    status: str


# =========================================================
# API - AUTH
# =========================================================

@app.post("/api/register")
def register(data: RegisterData):
    role = data.role.strip().lower()
    if role not in ("jobseeker", "employer"):
        role = "jobseeker"

    email = str(data.email).strip().lower()
    conn = db()

    if conn.execute(
        "SELECT id FROM users WHERE email = ?", (email,)
    ).fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    cur = conn.execute(
        """
        INSERT INTO users
        (name,email,password,role,phone,country,city,created_at)
        VALUES (?,?,?,?,?,?,?,?)
        """,
        (
            data.name.strip(),
            email,
            hash_password(data.password),
            role,
            data.phone.strip(),
            data.country.strip(),
            data.city.strip(),
            now(),
        ),
    )
    user_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Registration successful",
        "user_id": user_id,
    }


@app.post("/api/login")
def login(data: LoginData):
    email = str(data.email).strip().lower()
    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()
    conn.close()

    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = secrets.token_urlsafe(32)
    SESSIONS[token] = user["id"]

    response = {
        "ok": True,
        "message": "Login successful",
        "user": public_user(user),
    }

    # Set cookie in a normal HTTP response below.
    from fastapi.responses import JSONResponse
    json_response = JSONResponse(response)
    json_response.set_cookie(
        key="jobmart_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
        path="/",
    )
    return json_response


@app.post("/api/logout")
def logout(request: Request):
    token = request.cookies.get("jobmart_session")
    if token:
        SESSIONS.pop(token, None)

    from fastapi.responses import JSONResponse
    response = JSONResponse({"ok": True, "message": "Logged out"})
    response.delete_cookie("jobmart_session", path="/")
    return response


@app.get("/api/me")
def me(request: Request):
    user = current_user(request)
    if not user:
        return {"logged_in": False, "user": None}
    return {"logged_in": True, "user": public_user(user)}


# =========================================================
# API - PROFILE
# =========================================================

@app.put("/api/profile")
def update_profile(data: ProfileData, request: Request):
    user = require_user(request)
    conn = db()
    conn.execute(
        """
        UPDATE users
        SET name=?, phone=?, country=?, city=?, bio=?
        WHERE id=?
        """,
        (
            data.name.strip(),
            data.phone.strip(),
            data.country.strip(),
            data.city.strip(),
            data.bio.strip(),
            user["id"],
        ),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "message": "Profile updated"}


# =========================================================
# API - JOBS
# =========================================================

@app.post("/api/jobs")
def create_job(data: JobData, request: Request):
    user = require_employer(request)

    application_email = data.application_email.strip()
    if application_email:
        try:
            EmailStr._validate(application_email)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Application email is invalid",
            )

    conn = db()
    cur = conn.execute(
        """
        INSERT INTO jobs
        (employer_id,title,company,category,country,location,job_type,
         work_mode,salary,description,skills,application_email,status,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
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
            application_email,
            "active",
            now(),
        ),
    )
    job_id = cur.lastrowid
    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Job posted successfully",
        "job_id": job_id,
    }


@app.get("/api/jobs")
def list_jobs(
    q: str = "",
    category: str = "",
    country: str = "",
    job_type: str = "",
    work_mode: str = "",
    mine: bool = False,
    request: Request = None,
):
    conn = db()
    sql = """
        SELECT j.*, u.name AS employer_name
        FROM jobs j
        JOIN users u ON u.id = j.employer_id
        WHERE j.status = 'active'
    """
    params = []

    if q.strip():
        sql += """
            AND (
                LOWER(j.title) LIKE ?
                OR LOWER(j.company) LIKE ?
                OR LOWER(j.description) LIKE ?
                OR LOWER(j.skills) LIKE ?
                OR LOWER(j.location) LIKE ?
            )
        """
        value = f"%{q.strip().lower()}%"
        params.extend([value] * 5)

    if category.strip():
        sql += " AND LOWER(j.category) = LOWER(?)"
        params.append(category.strip())

    if country.strip():
        sql += " AND LOWER(j.country) = LOWER(?)"
        params.append(country.strip())

    if job_type.strip():
        sql += " AND LOWER(j.job_type) = LOWER(?)"
        params.append(job_type.strip())

    if work_mode.strip():
        sql += " AND LOWER(j.work_mode) = LOWER(?)"
        params.append(work_mode.strip())

    user = current_user(request)

    if mine:
        if not user:
            conn.close()
            raise HTTPException(status_code=401, detail="Login required")
        if user["role"] not in ("employer", "admin"):
            conn.close()
            raise HTTPException(
                status_code=403,
                detail="Employer account required",
            )
        sql += " AND j.employer_id = ?"
        params.append(user["id"])

    sql += " ORDER BY j.id DESC"

    rows = conn.execute(sql, params).fetchall()
    result = [dict(row) for row in rows]
    conn.close()

    return {"ok": True, "jobs": result, "count": len(result)}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: int, request: Request):
    conn = db()
    job = conn.execute(
        """
        SELECT j.*, u.name AS employer_name, u.email AS employer_email
        FROM jobs j
        JOIN users u ON u.id = j.employer_id
        WHERE j.id = ?
        """,
        (job_id,),
    ).fetchone()

    if not job:
        conn.close()
        raise HTTPException(status_code=404, detail="Job not found")

    user = current_user(request)
    applied = False
    saved = False

    if user:
        applied = bool(
            conn.execute(
                """
                SELECT id FROM applications
                WHERE job_id=? AND applicant_id=?
                """,
                (job_id, user["id"]),
            ).fetchone()
        )
        saved = bool(
            conn.execute(
                """
                SELECT id FROM saved_jobs
                WHERE job_id=? AND user_id=?
                """,
                (job_id, user["id"]),
            ).fetchone()
        )

    result = dict(job)
    result["applied"] = applied
    result["saved"] = saved

    conn.close()
    return {"ok": True, "job": result}


@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: int, request: Request):
    user = require_employer(request)
    conn = db()
    job = conn.execute(
        "SELECT * FROM jobs WHERE id=?", (job_id,)
    ).fetchone()

    if not job:
        conn.close()
        raise HTTPException(status_code=404, detail="Job not found")

    if job["employer_id"] != user["id"] and user["role"] != "admin":
        conn.close()
        raise HTTPException(status_code=403, detail="Not allowed")

    conn.execute(
        "UPDATE jobs SET status='closed' WHERE id=?", (job_id,)
    )
    conn.commit()
    conn.close()

    return {"ok": True, "message": "Job closed"}


# =========================================================
# API - APPLICATIONS
# =========================================================

@app.post("/api/jobs/{job_id}/apply")
def apply_job(job_id: int, data: ApplicationData, request: Request):
    user = require_user(request)

    if user["role"] in ("employer", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Employer accounts cannot apply",
        )

    conn = db()

    job = conn.execute(
        """
        SELECT * FROM jobs
        WHERE id=? AND status='active'
        """,
        (job_id,),
    ).fetchone()

    if not job:
        conn.close()
        raise HTTPException(status_code=404, detail="Job not found")

    if conn.execute(
        """
        SELECT id FROM applications
        WHERE job_id=? AND applicant_id=?
        """,
        (job_id, user["id"]),
    ).fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Already applied")

    conn.execute(
        """
        INSERT INTO applications
        (job_id,applicant_id,cover_letter,status,created_at)
        VALUES (?,?,?,?,?)
        """,
        (
            job_id,
            user["id"],
            data.cover_letter.strip(),
            "applied",
            now(),
        ),
    )

    conn.execute(
        """
        INSERT INTO notifications
        (user_id,title,message,created_at)
        VALUES (?,?,?,?)
        """,
        (
            job["employer_id"],
            "New job application",
            f"{user['name']} applied for {job['title']}",
            now(),
        ),
    )

    conn.commit()
    conn.close()

    return {"ok": True, "message": "Application submitted"}


@app.get("/api/applications")
def applications(request: Request):
    user = require_user(request)
    conn = db()

    if user["role"] in ("employer", "admin"):
        if user["role"] == "admin":
            rows = conn.execute(
                """
                SELECT a.*, j.title, j.company, j.country, j.location,
                       u.name AS applicant_name, u.email AS applicant_email,
                       u.phone AS applicant_phone
                FROM applications a
                JOIN jobs j ON j.id=a.job_id
                JOIN users u ON u.id=a.applicant_id
                ORDER BY a.id DESC
                """
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT a.*, j.title, j.company, j.country, j.location,
                       u.name AS applicant_name, u.email AS applicant_email,
                       u.phone AS applicant_phone
                FROM applications a
                JOIN jobs j ON j.id=a.job_id
                JOIN users u ON u.id=a.applicant_id
                WHERE j.employer_id=?
                ORDER BY a.id DESC
                """,
                (user["id"],),
            ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT a.*, j.title, j.company, j.country, j.location,
                   j.work_mode, j.job_type
            FROM applications a
            JOIN jobs j ON j.id=a.job_id
            WHERE a.applicant_id=?
            ORDER BY a.id DESC
            """,
            (user["id"],),
        ).fetchall()

    result = [dict(row) for row in rows]
    conn.close()

    return {"ok": True, "applications": result}


@app.put("/api/applications/{application_id}/status")
def update_application_status(
    application_id: int,
    data: ApplicationStatusData,
    request: Request,
):
    user = require_employer(request)
    allowed = {
        "applied",
        "viewed",
        "shortlisted",
        "rejected",
        "selected",
    }

    status = data.status.strip().lower()
    if status not in allowed:
        raise HTTPException(status_code=400, detail="Invalid application status")

    conn = db()
    row = conn.execute(
        """
        SELECT a.*, j.title, j.employer_id
        FROM applications a
        JOIN jobs j ON j.id=a.job_id
        WHERE a.id=?
        """,
        (application_id,),
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Application not found")

    if user["role"] != "admin" and row["employer_id"] != user["id"]:
        conn.close()
        raise HTTPException(status_code=403, detail="Not allowed")

    conn.execute(
        "UPDATE applications SET status=? WHERE id=?",
        (status, application_id),
    )

    conn.execute(
        """
        INSERT INTO notifications
        (user_id,title,message,created_at)
        VALUES (?,?,?,?)
        """,
        (
            row["applicant_id"],
            "Application status updated",
            f"Your application for {row['title']} is now {status}.",
            now(),
        ),
    )

    conn.commit()
    conn.close()

    return {"ok": True, "message": "Application status updated"}


# =========================================================
# API - SAVED JOBS
# =========================================================

@app.post("/api/jobs/{job_id}/save")
def save_job(job_id: int, request: Request):
    user = require_user(request)
    conn = db()

    if not conn.execute(
        "SELECT id FROM jobs WHERE id=?", (job_id,)
    ).fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Job not found")

    existing = conn.execute(
        """
        SELECT id FROM saved_jobs
        WHERE job_id=? AND user_id=?
        """,
        (job_id, user["id"]),
    ).fetchone()

    if existing:
        conn.execute(
            """
            DELETE FROM saved_jobs
            WHERE job_id=? AND user_id=?
            """,
            (job_id, user["id"]),
        )
        message = "Removed from saved jobs"
        saved = False
    else:
        conn.execute(
            """
            INSERT INTO saved_jobs
            (job_id,user_id,created_at)
            VALUES (?,?,?)
            """,
            (job_id, user["id"], now()),
        )
        message = "Job saved"
        saved = True

    conn.commit()
    conn.close()

    return {"ok": True, "message": message, "saved": saved}


@app.get("/api/saved-jobs")
def saved_jobs(request: Request):
    user = require_user(request)
    conn = db()

    rows = conn.execute(
        """
        SELECT j.*, s.created_at AS saved_at,
               u.name AS employer_name
        FROM saved_jobs s
        JOIN jobs j ON j.id=s.job_id
        JOIN users u ON u.id=j.employer_id
        WHERE s.user_id=?
        ORDER BY s.id DESC
        """,
        (user["id"],),
    ).fetchall()

    result = [dict(row) for row in rows]
    conn.close()

    return {"ok": True, "jobs": result}


# =========================================================
# API - NOTIFICATIONS
# =========================================================

@app.get("/api/notifications")
def notifications(request: Request):
    user = require_user(request)
    conn = db()

    rows = conn.execute(
        """
        SELECT * FROM notifications
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (user["id"],),
    ).fetchall()

    result = [dict(row) for row in rows]
    conn.close()

    return {"ok": True, "notifications": result}


@app.post("/api/notifications/read")
def notifications_read(request: Request):
    user = require_user(request)
    conn = db()

    conn.execute(
        "UPDATE notifications SET is_read=1 WHERE user_id=?",
        (user["id"],),
    )

    conn.commit()
    conn.close()

    return {"ok": True}


# =========================================================
# API - DASHBOARD
# =========================================================

@app.get("/api/dashboard")
def dashboard(request: Request):
    user = require_user(request)
    conn = db()

    if user["role"] in ("employer", "admin"):
        if user["role"] == "admin":
            jobs_count = conn.execute(
                "SELECT COUNT(*) AS c FROM jobs"
            ).fetchone()["c"]
            active_jobs = conn.execute(
                "SELECT COUNT(*) AS c FROM jobs WHERE status='active'"
            ).fetchone()["c"]
            applications_count = conn.execute(
                "SELECT COUNT(*) AS c FROM applications"
            ).fetchone()["c"]
        else:
            jobs_count = conn.execute(
                "SELECT COUNT(*) AS c FROM jobs WHERE employer_id=?",
                (user["id"],),
            ).fetchone()["c"]
            active_jobs = conn.execute(
                """
                SELECT COUNT(*) AS c FROM jobs
                WHERE employer_id=? AND status='active'
                """,
                (user["id"],),
            ).fetchone()["c"]
            applications_count = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM applications a
                JOIN jobs j ON j.id=a.job_id
                WHERE j.employer_id=?
                """,
                (user["id"],),
            ).fetchone()["c"]

        unread = conn.execute(
            """
            SELECT COUNT(*) AS c FROM notifications
            WHERE user_id=? AND is_read=0
            """,
            (user["id"],),
        ).fetchone()["c"]

        result = {
            "role": user["role"],
            "jobs_posted": jobs_count,
            "active_jobs": active_jobs,
            "applications": applications_count,
            "notifications": unread,
        }
    else:
        applied = conn.execute(
            """
            SELECT COUNT(*) AS c FROM applications
            WHERE applicant_id=?
            """,
            (user["id"],),
        ).fetchone()["c"]

        saved = conn.execute(
            """
            SELECT COUNT(*) AS c FROM saved_jobs
            WHERE user_id=?
            """,
            (user["id"],),
        ).fetchone()["c"]

        unread = conn.execute(
            """
            SELECT COUNT(*) AS c FROM notifications
            WHERE user_id=? AND is_read=0
            """,
            (user["id"],),
        ).fetchone()["c"]

        result = {
            "role": "jobseeker",
            "applications": applied,
            "saved_jobs": saved,
            "notifications": unread,
        }

    conn.close()
    return {"ok": True, "dashboard": result}


# =========================================================
# FRONTEND - THEME 2
# =========================================================

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Job Mart - Find The Job That Fits Your Life</title>
<style>
:root{
    --navy:#082b4c;
    --navy2:#0c3b63;
    --blue:#146be8;
    --blue2:#0b63ce;
    --light:#f5f7fb;
    --line:#e5e9f0;
    --text:#172033;
    --muted:#6b7280;
    --green:#159b65;
    --red:#d64545;
    --white:#fff;
    --shadow:0 8px 28px rgba(19,43,74,.08);
    --radius:14px;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
    font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
    background:var(--light);
    color:var(--text);
}
button,input,select,textarea{font:inherit}
button{cursor:pointer}
button:disabled{opacity:.55;cursor:not-allowed}
a{text-decoration:none;color:inherit}
.hidden{display:none!important}
.app{min-height:100vh}
.public-header{
    height:66px;background:#fff;border-bottom:1px solid var(--line);
    display:flex;align-items:center;justify-content:space-between;
    padding:0 28px;position:sticky;top:0;z-index:50;
}
.brand{display:flex;align-items:center;gap:8px;font-weight:800;color:#152238;font-size:18px}
.brand-mark{
    width:30px;height:30px;border-radius:8px;background:var(--blue);
    color:#fff;display:grid;place-items:center;font-weight:900;
}
.public-nav{display:flex;align-items:center;gap:24px;font-size:12px;color:#39465a}
.public-nav a:hover{color:var(--blue)}
.header-actions{display:flex;gap:8px}
.btn{
    border:1px solid transparent;border-radius:8px;padding:10px 16px;
    font-weight:700;transition:.15s;
}
.btn-primary{background:var(--blue);color:#fff}
.btn-primary:hover{background:var(--blue2)}
.btn-outline{background:#fff;border-color:#dbe2ec;color:var(--text)}
.btn-light{background:#edf4ff;color:var(--blue)}
.btn-danger{background:#fff1f1;color:var(--red);border-color:#ffd6d6}
.btn-small{padding:7px 10px;font-size:12px}
.hero{
    max-width:1200px;margin:0 auto;padding:55px 34px 20px;
    display:grid;grid-template-columns:1.1fr .9fr;align-items:center;gap:25px;
}
.hero h1{font-size:43px;line-height:1.08;margin:0 0 15px;letter-spacing:-1.2px}
.hero p{font-size:14px;line-height:1.7;color:var(--muted);max-width:530px;margin:0 0 20px}
.hero-art{
    min-height:270px;border-radius:24px;
    background:linear-gradient(145deg,#e9f1ff,#f8fbff);
    display:grid;place-items:center;position:relative;overflow:hidden;
}
.hero-person{font-size:120px;filter:drop-shadow(0 15px 12px rgba(20,107,232,.12))}
.search-box{
    max-width:1200px;margin:0 auto 24px;padding:0 34px;
}
.search-row{
    background:#fff;border:1px solid #e5e9f0;border-radius:12px;
    box-shadow:var(--shadow);padding:10px;display:grid;
    grid-template-columns:2fr 1fr 1fr auto;gap:8px;
}
.field,.select{
    width:100%;border:1px solid #dfe4eb;border-radius:8px;
    padding:11px 12px;background:#fff;color:var(--text);outline:none;
}
.field:focus,.select:focus,textarea:focus{border-color:#7aaaf4;box-shadow:0 0 0 3px #eaf2ff}
.section{max-width:1200px;margin:0 auto;padding:12px 34px 30px}
.section-title{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.section-title h2{font-size:17px;margin:0}
.link{color:var(--blue);font-size:12px;font-weight:700}
.chips{display:flex;gap:9px;overflow:auto;padding-bottom:3px}
.chip{
    white-space:nowrap;border:1px solid #e1e6ee;background:#fff;
    border-radius:20px;padding:8px 12px;font-size:12px;color:#3e4b5d;
}
.chip:hover{border-color:#b8d0f7;color:var(--blue)}
.job-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}
.job-card{
    background:#fff;border:1px solid var(--line);border-radius:12px;
    padding:17px;box-shadow:0 3px 13px rgba(20,40,70,.04)
}
.job-card:hover{box-shadow:var(--shadow)}
.job-head{display:flex;gap:12px;align-items:flex-start}
.company-icon{
    width:38px;height:38px;border-radius:9px;background:#edf4ff;color:var(--blue);
    display:grid;place-items:center;font-weight:900;flex:0 0 auto
}
.job-title{font-size:14px;font-weight:800;margin:0 0 4px}
.company{font-size:12px;color:var(--muted)}
.tags{display:flex;gap:5px;flex-wrap:wrap;margin-top:10px}
.tag{
    padding:4px 7px;border-radius:5px;background:#f3f6fa;color:#556174;
    font-size:10px
}
.job-actions{display:flex;justify-content:flex-end;gap:7px;margin-top:13px}
.empty{
    background:#fff;border:1px solid var(--line);border-radius:12px;
    padding:45px 20px;text-align:center;color:var(--muted)
}

/* Auth */
.auth-page{min-height:calc(100vh - 66px);display:grid;place-items:center;padding:30px}
.auth-card{
    width:min(850px,100%);background:#fff;border:1px solid var(--line);
    border-radius:15px;box-shadow:var(--shadow);display:grid;grid-template-columns:.8fr 1.2fr;
    overflow:hidden;min-height:500px
}
.auth-side{
    background:linear-gradient(155deg,#eef4ff,#f9fbff);
    display:flex;align-items:center;justify-content:center;flex-direction:column;padding:30px;
}
.auth-side .big{font-size:95px}
.auth-side h2{margin:10px 0 6px}
.auth-side p{color:var(--muted);font-size:12px;text-align:center;line-height:1.6}
.auth-form{padding:38px}
.auth-form h1{font-size:23px;margin:0 0 8px}
.sub{font-size:12px;color:var(--muted);margin-bottom:22px}
.form-group{margin-bottom:14px}
.form-label{display:block;font-size:11px;font-weight:800;margin-bottom:6px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.check{display:flex;gap:7px;align-items:center;font-size:11px;color:var(--muted)}
.check input{width:auto}
.full{width:100%}
.msg{min-height:18px;font-size:12px;margin:10px 0}
.msg.error{color:var(--red)}
.msg.ok{color:var(--green)}

/* App shell */
.shell{min-height:100vh;display:flex}
.sidebar{
    width:220px;background:linear-gradient(180deg,var(--navy),#063052);
    color:#fff;position:fixed;left:0;top:0;bottom:0;z-index:70;
    display:flex;flex-direction:column;padding:18px 12px
}
.sidebar .brand{color:#fff;padding:8px 10px 24px}
.sidebar .brand-mark{background:#fff;color:var(--navy)}
.side-label{font-size:9px;text-transform:uppercase;letter-spacing:1.2px;color:#91abc3;padding:12px 12px 7px}
.side-btn{
    width:100%;display:flex;align-items:center;gap:10px;
    background:transparent;border:0;color:#d8e5f1;padding:10px 11px;
    border-radius:8px;text-align:left;font-size:12px;margin:2px 0
}
.side-btn:hover,.side-btn.active{background:var(--blue);color:#fff}
.side-spacer{flex:1}
.shell-main{margin-left:220px;width:calc(100% - 220px);min-width:0}
.topbar{
    height:66px;background:#fff;border-bottom:1px solid var(--line);
    display:flex;align-items:center;justify-content:space-between;padding:0 25px;
    position:sticky;top:0;z-index:40
}
.mobile-menu{display:none;border:0;background:#edf4ff;color:var(--blue);border-radius:8px;padding:8px 10px}
.user-mini{display:flex;align-items:center;gap:9px;font-size:12px;font-weight:700}
.avatar{width:32px;height:32px;border-radius:50%;background:#e7effc;display:grid;place-items:center}
.page{padding:25px;max-width:1250px;margin:auto}
.page-title{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.page-title h1{font-size:21px;margin:0}
.page-title p{font-size:12px;color:var(--muted);margin:5px 0 0}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:13px;margin-bottom:20px}
.stat{
    background:#fff;border:1px solid var(--line);border-radius:12px;padding:18px;
    box-shadow:0 3px 12px rgba(20,40,70,.03)
}
.stat .n{font-size:24px;font-weight:800;margin-bottom:3px}
.stat .l{font-size:11px;color:var(--muted)}
.panel{
    background:#fff;border:1px solid var(--line);border-radius:12px;
    padding:18px;box-shadow:0 3px 12px rgba(20,40,70,.03);margin-bottom:15px
}
.panel h3{font-size:14px;margin:0 0 14px}
.table-wrap{overflow:auto}
table{width:100%;border-collapse:collapse;font-size:11px}
th,td{padding:12px 8px;border-bottom:1px solid #edf0f4;text-align:left;white-space:nowrap}
th{font-size:10px;color:#667085}
.status{
    display:inline-block;padding:4px 7px;border-radius:5px;background:#eaf8f1;
    color:var(--green);font-size:10px;font-weight:700
}
.status.red{background:#fff0f0;color:var(--red)}
.status.blue{background:#edf4ff;color:var(--blue)}
.detail-grid{display:grid;grid-template-columns:1fr 280px;gap:15px}
.detail-card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:20px}
.detail-card h1{font-size:24px;margin:0 0 5px}
.detail-card h2{font-size:14px;margin:20px 0 8px}
.detail-card p{font-size:12px;line-height:1.8;color:#4f5b6c;white-space:pre-line}
.action-stack{display:grid;gap:8px}
.form-panel{max-width:850px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form-field{margin-bottom:13px}
.form-field label{display:block;font-size:11px;font-weight:800;margin-bottom:6px}
textarea{width:100%;min-height:105px;border:1px solid #dfe4eb;border-radius:8px;padding:11px;resize:vertical;outline:none}
.notice{
    padding:12px;border-radius:8px;background:#edf4ff;color:#24548c;
    font-size:11px;margin-bottom:13px
}
.profile-grid{display:grid;grid-template-columns:260px 1fr;gap:15px}
.profile-box{text-align:center}
.profile-avatar{width:92px;height:92px;border-radius:50%;background:#e9f1ff;display:grid;place-items:center;font-size:44px;margin:5px auto 15px}
.muted{color:var(--muted);font-size:12px}
.mobile-bottom{
    display:none;position:fixed;left:0;right:0;bottom:0;height:62px;background:#fff;
    border-top:1px solid var(--line);z-index:80;grid-template-columns:repeat(5,1fr)
}
.mobile-bottom button{border:0;background:#fff;font-size:9px;color:#5d6878}
.mobile-bottom button.active{color:var(--blue);font-weight:800}

@media(max-width:900px){
    .public-nav{display:none}
    .hero{grid-template-columns:1fr;padding-top:35px}
    .hero-art{min-height:180px}
    .search-row{grid-template-columns:1fr 1fr}
    .job-grid{grid-template-columns:1fr}
    .sidebar{transform:translateX(-100%);transition:.2s}
    .sidebar.open{transform:translateX(0)}
    .shell-main{margin-left:0;width:100%}
    .mobile-menu{display:block}
    .mobile-bottom{display:grid}
    .page{padding:18px 14px 85px}
    .stats{grid-template-columns:repeat(3,1fr)}
    .detail-grid,.profile-grid{grid-template-columns:1fr}
}
@media(max-width:620px){
    .public-header{padding:0 14px;height:60px}
    .header-actions .btn{padding:8px 11px;font-size:11px}
    .hero{padding:30px 16px 12px}
    .hero h1{font-size:31px}
    .hero-art{display:none}
    .search-box{padding:0 16px}
    .search-row{grid-template-columns:1fr}
    .section{padding:10px 16px 22px}
    .auth-page{padding:15px}
    .auth-card{grid-template-columns:1fr}
    .auth-side{display:none}
    .auth-form{padding:26px 20px}
    .form-grid,.form-row{grid-template-columns:1fr}
    .stats{grid-template-columns:1fr}
    .topbar{padding:0 14px}
    .topbar .user-mini span{display:none}
    .page-title h1{font-size:19px}
    .job-actions{justify-content:stretch}
    .job-actions .btn{flex:1}
}
</style>
</head>

<body>
<div id="app"></div>

<script>
const app = document.getElementById("app");
let me = null;
let jobsCache = [];
let currentJob = null;

const icons = {
    home:"⌂", jobs:"▣", saved:"♡", applications:"▤",
    notifications:"♧", profile:"♙", logout:"↪", post:"＋",
    dashboard:"▦"
};

function esc(value){
    return String(value ?? "").replace(/[&<>"']/g, c => ({
        "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
    }[c]));
}

function initials(name){
    const s = String(name || "U").trim().split(/\s+/);
    return (s[0][0] + (s[1] ? s[1][0] : "")).toUpperCase();
}

function fmtDate(v){
    if(!v) return "";
    const d = new Date(v);
    if(Number.isNaN(d.getTime())) return "";
    return d.toLocaleDateString(undefined,{day:"2-digit",month:"short",year:"numeric"});
}

async function api(url, options={}){
    const opts = {...options, headers:{...(options.headers||{})}};
    if(opts.body && typeof opts.body !== "string"){
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(opts.body);
    }
    const res = await fetch(url, opts);
    let data = {};
    try { data = await res.json(); } catch(e) {}
    if(!res.ok) throw new Error(data.detail || "Something went wrong");
    return data;
}

async function loadMe(){
    try{
        const data = await api("/api/me");
        me = data.logged_in ? data.user : null;
    }catch(e){ me = null; }
}

function publicHeader(){
    return `
    <header class="public-header">
        <div class="brand"><span class="brand-mark">JM</span> Job Mart</div>
        <nav class="public-nav">
            <a href="#" onclick="showHome();return false">Home</a>
            <a href="#" onclick="showJobs();return false">Jobs</a>
            <a href="#" onclick="showHome();return false">Employers</a>
            <a href="#" onclick="showHome();return false">About Us</a>
            <a href="#" onclick="showHome();return false">Contact</a>
        </nav>
        <div class="header-actions">
            <button class="btn btn-outline btn-small" onclick="showLogin()">Login</button>
            <button class="btn btn-primary btn-small" onclick="showRegister()">Register</button>
        </div>
    </header>`;
}

function renderPublicHome(){
    app.innerHTML = `
    ${publicHeader()}
    <main>
      <section class="hero">
        <div>
          <h1>Find The Job<br>That Fits Your Life</h1>
          <p>Search jobs posted by verified employers and build your career.</p>
        </div>
        <div class="hero-art"><div class="hero-person">🧑‍💻</div></div>
      </section>

      <section class="search-box">
        <div class="search-row">
          <input id="homeQ" class="field" placeholder="Job title, keyword, or company">
          <select id="homeCountry" class="select">
            <option value="">All Countries</option>
            <option>India</option><option>USA</option><option>UAE</option><option>UK</option><option>Other</option>
          </select>
          <select id="homeType" class="select">
            <option value="">All Job Types</option>
            <option>Full-time</option><option>Part-time</option><option>Contract</option><option>Freelance</option>
          </select>
          <button class="btn btn-primary" onclick="homeSearch()">Search</button>
        </div>
      </section>

      <section class="section">
        <div class="section-title">
          <h2>Popular Categories</h2><a class="link" href="#" onclick="showJobs();return false">View all</a>
        </div>
        <div class="chips">
          ${["IT & Software","Design","Marketing","Sales","Finance","HR","Customer Support","Engineering"].map(c =>
            `<button class="chip" onclick="categorySearch('${esc(c)}')">${esc(c)}</button>`).join("")}
        </div>
      </section>

      <section class="section">
        <div class="section-title">
          <h2>Latest Jobs</h2><a class="link" href="#" onclick="showJobs();return false">View all</a>
        </div>
        <div id="publicJobs" class="job-grid"></div>
      </section>
    </main>`;
    loadPublicJobs();
}

async function loadPublicJobs(params={}){
    const box = document.getElementById("publicJobs");
    if(!box) return;
    box.innerHTML = `<div class="empty">Loading jobs...</div>`;
    try{
        const q = new URLSearchParams(params).toString();
        const data = await api("/api/jobs" + (q ? "?" + q : ""));
        jobsCache = data.jobs || [];
        box.innerHTML = jobsCache.length
            ? jobsCache.slice(0,6).map(jobCard).join("")
            : `<div class="empty" style="grid-column:1/-1">No jobs posted yet.<br><small>Jobs will appear here after an employer posts them.</small></div>`;
    }catch(e){
        box.innerHTML = `<div class="empty">${esc(e.message)}</div>`;
    }
}

function jobCard(j){
    return `
    <article class="job-card">
      <div class="job-head">
        <div class="company-icon">▣</div>
        <div style="min-width:0;flex:1">
          <h3 class="job-title">${esc(j.title)}</h3>
          <div class="company">${esc(j.company)}</div>
          <div class="tags">
            <span class="tag">${esc(j.country)}</span>
            <span class="tag">${esc(j.job_type)}</span>
            <span class="tag">${esc(j.work_mode)}</span>
          </div>
        </div>
      </div>
      <div class="meta" style="margin-top:10px;font-size:11px;color:#7a8492">
        ${esc(j.location || j.country)} ${j.salary ? " · " + esc(j.salary) : ""}
      </div>
      <div class="job-actions">
        <button class="btn btn-outline btn-small" onclick="showJob(${j.id})">View Job</button>
      </div>
    </article>`;
}

function showLogin(){
    app.innerHTML = `
    ${publicHeader()}
    <main class="auth-page">
      <div class="auth-card">
        <aside class="auth-side">
          <div class="big">🔐</div>
          <h2>Welcome Back!</h2>
          <p>Login to your account<br>and explore thousands of jobs.</p>
        </aside>
        <section class="auth-form">
          <h1>Welcome Back!</h1>
          <div class="sub">Login to your account and explore thousands of jobs.</div>
          <div class="form-group">
            <label class="form-label">Email</label>
            <input id="loginEmail" class="field" type="email" placeholder="you@example.com">
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input id="loginPassword" class="field" type="password" placeholder="Your password">
          </div>
          <label class="check"><input type="checkbox" id="remember"> Remember me</label>
          <div id="loginMsg" class="msg"></div>
          <button class="btn btn-primary full" onclick="doLogin()">Login</button>
          <p class="muted" style="text-align:center;margin-top:15px">
            Don't have an account?
            <a class="link" href="#" onclick="showRegister();return false">Register</a>
          </p>
        </section>
      </div>
    </main>`;
}

function showRegister(){
    app.innerHTML = `
    ${publicHeader()}
    <main class="auth-page">
      <div class="auth-card">
        <aside class="auth-side">
          <div class="big">👩‍💼</div>
          <h2>Join Job Mart</h2>
          <p>Join thousands of job seekers<br>and employers today.</p>
        </aside>
        <section class="auth-form">
          <h1>Create your Account</h1>
          <div class="sub">Join thousands of job seekers and employers today!</div>
          <div class="form-grid">
            <div class="form-group">
              <label class="form-label">Full Name</label>
              <input id="regName" class="field" placeholder="Your name">
            </div>
            <div class="form-group">
              <label class="form-label">Email</label>
              <input id="regEmail" class="field" type="email" placeholder="you@example.com">
            </div>
          </div>
          <div class="form-grid">
            <div class="form-group">
              <label class="form-label">Password</label>
              <input id="regPassword" class="field" type="password" placeholder="Minimum 6 characters">
            </div>
            <div class="form-group">
              <label class="form-label">Confirm Password</label>
              <input id="regConfirm" class="field" type="password" placeholder="Repeat password">
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">Account Type</label>
            <select id="regRole" class="select">
              <option value="jobseeker">Job Seeker</option>
              <option value="employer">Employer / Recruiter</option>
            </select>
          </div>
          <div class="form-grid">
            <div class="form-group">
              <label class="form-label">Phone</label>
              <input id="regPhone" class="field" placeholder="Phone number">
            </div>
            <div class="form-group">
              <label class="form-label">Country</label>
              <input id="regCountry" class="field" value="India">
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">City</label>
            <input id="regCity" class="field" placeholder="City">
          </div>
          <label class="check"><input id="terms" type="checkbox"> I agree to the Terms & Conditions</label>
          <div id="regMsg" class="msg"></div>
          <button class="btn btn-primary full" onclick="doRegister()">Register</button>
          <p class="muted" style="text-align:center;margin-top:15px">
            Already have an account?
            <a class="link" href="#" onclick="showLogin();return false">Login</a>
          </p>
        </section>
      </div>
    </main>`;
}

async function doLogin(){
    const msg = document.getElementById("loginMsg");
    msg.className = "msg";
    msg.textContent = "";
    try{
        const data = await api("/api/login",{
            method:"POST",
            body:{
                email:document.getElementById("loginEmail").value.trim(),
                password:document.getElementById("loginPassword").value
            }
        });
        me = data.user;
        showDashboard();
    }catch(e){
        msg.className = "msg error";
        msg.textContent = e.message;
    }
}

async function doRegister(){
    const msg = document.getElementById("regMsg");
    msg.className = "msg";
    msg.textContent = "";

    const password = document.getElementById("regPassword").value;
    const confirm = document.getElementById("regConfirm").value;

    if(password !== confirm){
        msg.className = "msg error";
        msg.textContent = "Passwords do not match";
        return;
    }
    if(!document.getElementById("terms").checked){
        msg.className = "msg error";
        msg.textContent = "Please accept the Terms & Conditions";
        return;
    }

    try{
        await api("/api/register",{
            method:"POST",
            body:{
                name:document.getElementById("regName").value.trim(),
                email:document.getElementById("regEmail").value.trim(),
                password,
                role:document.getElementById("regRole").value,
                phone:document.getElementById("regPhone").value.trim(),
                country:document.getElementById("regCountry").value.trim(),
                city:document.getElementById("regCity").value.trim()
            }
        });
        msg.className = "msg ok";
        msg.textContent = "Account created. Opening login...";
        setTimeout(showLogin,600);
    }catch(e){
        msg.className = "msg error";
        msg.textContent = e.message;
    }
}

function sidebar(){
    const employer = me && (me.role === "employer" || me.role === "admin");
    return `
    <aside id="sidebar" class="sidebar">
      <div class="brand"><span class="brand-mark">JM</span> Job Mart</div>
      <div class="side-label">Menu</div>
      <button class="side-btn" data-page="dashboard" onclick="showDashboard()">${icons.dashboard} Dashboard</button>
      <button class="side-btn" data-page="jobs" onclick="showJobs()">${icons.jobs} Jobs</button>
      ${employer ? `<button class="side-btn" data-page="post" onclick="showPostJob()">${icons.post} Post Job</button>` : ""}
      <button class="side-btn" data-page="saved" onclick="showSaved()">${icons.saved} Saved Jobs</button>
      <button class="side-btn" data-page="applications" onclick="showApplications()">${icons.applications} Applications</button>
      <button class="side-btn" data-page="notifications" onclick="showNotifications()">${icons.notifications} Notifications <span id="notifBadge"></span></button>
      <button class="side-btn" data-page="profile" onclick="showProfile()">${icons.profile} Profile</button>
      <div class="side-spacer"></div>
      <button class="side-btn" onclick="doLogout()">${icons.logout} Logout</button>
    </aside>`;
}

function shell(content,page){
    app.innerHTML = `
    <div class="shell">
      ${sidebar()}
      <div class="shell-main">
        <header class="topbar">
          <button class="mobile-menu" onclick="toggleSidebar()">☰</button>
          <div></div>
          <div class="user-mini">
            <span>🔔</span>
            <span>${esc(me.name)}</span>
            <div class="avatar">${esc(initials(me.name))}</div>
          </div>
        </header>
        ${content}
      </div>
    </div>
    <nav class="mobile-bottom">
      <button data-page="dashboard" onclick="showDashboard()">⌂<br>Home</button>
      <button data-page="jobs" onclick="showJobs()">▣<br>Jobs</button>
      <button data-page="saved" onclick="showSaved()">♡<br>Saved</button>
      <button data-page="applications" onclick="showApplications()">▤<br>Applications</button>
      <button data-page="profile" onclick="showProfile()">♙<br>Profile</button>
    </nav>`;
    setActive(page);
}

function setActive(page){
    document.querySelectorAll(".side-btn,.mobile-bottom button").forEach(b=>{
        b.classList.toggle("active",b.dataset.page === page);
    });
}

function toggleSidebar(){
    document.getElementById("sidebar")?.classList.toggle("open");
}

function closeSidebar(){
    document.getElementById("sidebar")?.classList.remove("open");
}

async function showDashboard(){
    if(!me){showLogin();return}
    closeSidebar();
    let data;
    try{ data = await api("/api/dashboard"); }catch(e){ showLogin();return; }
    const d = data.dashboard;
    const employer = me.role === "employer" || me.role === "admin";

    const stats = employer ? `
      <div class="stats">
        <div class="stat"><div class="n">${d.applications}</div><div class="l">Applications</div></div>
        <div class="stat"><div class="n">${d.active_jobs}</div><div class="l">Active Jobs</div></div>
        <div class="stat"><div class="n">${d.notifications}</div><div class="l">Notifications</div></div>
      </div>` : `
      <div class="stats">
        <div class="stat"><div class="n">${d.applications}</div><div class="l">Jobs you applied</div></div>
        <div class="stat"><div class="n">${d.saved_jobs}</div><div class="l">Saved Jobs</div></div>
        <div class="stat"><div class="n">${d.notifications}</div><div class="l">Notifications</div></div>
      </div>`;

    shell(`
      <main class="page">
        <div class="page-title">
          <div><h1>Dashboard</h1><p>Welcome back, ${esc(me.name)}</p></div>
          ${employer ? `<button class="btn btn-primary" onclick="showPostJob()">+ Post New Job</button>` : `<button class="btn btn-primary" onclick="showJobs()">Find Jobs</button>`}
        </div>
        ${stats}
        <div class="panel">
          <div class="section-title"><h2>${employer ? "Recent Applications" : "Latest Jobs"}</h2><a class="link" href="#" onclick="${employer ? "showApplications()" : "showJobs()"};return false">View all</a></div>
          <div id="dashboardList"></div>
        </div>
      </main>`, "dashboard");

    if(employer){
        loadEmployerRecent();
    }else{
        loadDashboardJobs();
    }
}

async function loadDashboardJobs(){
    const box = document.getElementById("dashboardList");
    if(!box)return;
    try{
        const data = await api("/api/jobs");
        const jobs = (data.jobs||[]).slice(0,3);
        box.innerHTML = jobs.length ? jobs.map(jobCard).join("") : `<div class="empty">No jobs posted yet.</div>`;
    }catch(e){box.innerHTML=`<div class="empty">${esc(e.message)}</div>`}
}

async function loadEmployerRecent(){
    const box = document.getElementById("dashboardList");
    if(!box)return;
    try{
        const data = await api("/api/applications");
        const rows = (data.applications||[]).slice(0,5);
        box.innerHTML = rows.length ? `
          <div class="table-wrap"><table>
            <thead><tr><th>Applicant</th><th>Job Title</th><th>Email</th><th>Status</th></tr></thead>
            <tbody>${rows.map(a=>`
              <tr><td>${esc(a.applicant_name)}</td><td>${esc(a.title)}</td><td>${esc(a.applicant_email)}</td>
              <td><span class="status">${esc(a.status)}</span></td></tr>`).join("")}</tbody>
          </table></div>` : `<div class="empty">No applications yet.</div>`;
    }catch(e){box.innerHTML=`<div class="empty">${esc(e.message)}</div>`}
}

async function showJobs(){
    if(!me){showPublicJobs();return}
    closeSidebar();
    shell(`
      <main class="page">
        <div class="page-title"><div><h1>Jobs</h1><p>Browse available opportunities</p></div></div>
        <div class="panel">
          <div class="search-row" style="box-shadow:none;padding:0;border:0">
            <input id="jobsQ" class="field" placeholder="Search jobs...">
            <select id="jobsCountry" class="select"><option value="">All Countries</option><option>India</option><option>USA</option><option>UAE</option><option>UK</option><option>Other</option></select>
            <select id="jobsType" class="select"><option value="">All Types</option><option>Full-time</option><option>Part-time</option><option>Contract</option><option>Freelance</option></select>
            <button class="btn btn-primary" onclick="searchJobs()">Search</button>
          </div>
        </div>
        <div id="jobsResults" class="job-grid"></div>
      </main>`, "jobs");
    loadJobsResults();
}

function showPublicJobs(){
    renderPublicHome();
    setTimeout(()=>document.querySelector(".section")?.scrollIntoView({behavior:"smooth"}),100);
}

async function searchJobs(){
    await loadJobsResults({
        q:document.getElementById("jobsQ").value.trim(),
        country:document.getElementById("jobsCountry").value,
        job_type:document.getElementById("jobsType").value
    });
}

async function loadJobsResults(params={}){
    const box = document.getElementById("jobsResults");
    if(!box)return;
    box.innerHTML=`<div class="empty">Loading jobs...</div>`;
    try{
        const qs = new URLSearchParams(params).toString();
        const data = await api("/api/jobs" + (qs ? "?" + qs : ""));
        box.innerHTML = data.jobs?.length ? data.jobs.map(jobCard).join("") : `<div class="empty" style="grid-column:1/-1">No jobs found.</div>`;
    }catch(e){box.innerHTML=`<div class="empty">${esc(e.message)}</div>`}
}

function homeSearch(){
    const q=document.getElementById("homeQ").value.trim();
    const country=document.getElementById("homeCountry").value;
    const job_type=document.getElementById("homeType").value;
    if(me){showJobs();setTimeout(()=>loadJobsResults({q,country,job_type}),80)}
    else{loadPublicJobs({q,country,job_type});document.getElementById("publicJobs")?.scrollIntoView({behavior:"smooth"})}
}

function categorySearch(category){
    if(me){
        showJobs();
        setTimeout(()=>loadJobsResults({category}),80);
    }else{
        loadPublicJobs({category});
        document.getElementById("publicJobs")?.scrollIntoView({behavior:"smooth"});
    }
}

async function showJob(id){
    try{
        const data=await api("/api/jobs/"+id);
        currentJob=data.job;
        if(!me){
            renderPublicJob(currentJob);
        }else{
            renderAppJob(currentJob);
        }
    }catch(e){alert(e.message)}
}

function renderPublicJob(j){
    app.innerHTML=`
    ${publicHeader()}
    <main class="page">
      <div style="margin-bottom:12px"><a class="link" href="#" onclick="showPublicJobs();return false">← Back to Jobs</a></div>
      <div class="detail-grid">
        <article class="detail-card">
          <div class="job-head"><div class="company-icon">▣</div><div><h1>${esc(j.title)}</h1><div class="company">${esc(j.company)}</div></div></div>
          <div class="tags"><span class="tag">${esc(j.country)}</span><span class="tag">${esc(j.job_type)}</span><span class="tag">${esc(j.work_mode)}</span></div>
          <h2>Description</h2><p>${esc(j.description)}</p>
          <h2>Skills</h2><p>${esc(j.skills || "Not specified")}</p>
          <h2>Salary</h2><p>${esc(j.salary || "Not specified")}</p>
        </article>
        <aside class="detail-card">
          <h3>Actions</h3>
          <div class="action-stack">
            <button class="btn btn-primary" onclick="showLogin()">Login to Apply</button>
            <button class="btn btn-outline" onclick="showRegister()">Create Account</button>
          </div>
        </aside>
      </div>
    </main>`;
}

function renderAppJob(j){
    shell(`
    <main class="page">
      <div style="margin-bottom:12px"><a class="link" href="#" onclick="showJobs();return false">← Back to Jobs</a></div>
      <div class="detail-grid">
        <article class="detail-card">
          <div class="job-head">
            <div class="company-icon">▣</div>
            <div><h1>${esc(j.title)}</h1><div class="company">${esc(j.company)}</div></div>
          </div>
          <div class="tags"><span class="tag">${esc(j.country)}</span><span class="tag">${esc(j.job_type)}</span><span class="tag">${esc(j.work_mode)}</span></div>
          <h2>Description</h2><p>${esc(j.description)}</p>
          <h2>Skills</h2><p>${esc(j.skills || "Not specified")}</p>
          <h2>Salary</h2><p>${esc(j.salary || "Not specified")}</p>
          <h2>Location</h2><p>${esc(j.location || j.country)}</p>
        </article>
        <aside class="detail-card">
          <h3>Actions</h3>
          <div class="action-stack">
            ${me.role === "jobseeker" ? `
              <button class="btn btn-primary" ${j.applied ? "disabled" : ""} onclick="applyJob(${j.id})">${j.applied ? "Already Applied" : "Apply Now"}</button>
              <button class="btn btn-outline" onclick="saveCurrent(${j.id})">${j.saved ? "♥ Saved" : "♡ Save Job"}</button>
            ` : ""}
            ${me.id === j.employer_id || me.role === "admin" ? `<button class="btn btn-danger" onclick="closeJob(${j.id})">Close Job</button>` : ""}
          </div>
        </aside>
      </div>
    </main>`, "jobs");
}

async function applyJob(id){
    const cover=prompt("Optional cover letter:");
    if(cover===null)return;
    try{
        await api("/api/jobs/"+id+"/apply",{method:"POST",body:{cover_letter:cover}});
        alert("Application submitted successfully.");
        await showJob(id);
    }catch(e){alert(e.message)}
}

async function saveCurrent(id){
    try{
        const d=await api("/api/jobs/"+id+"/save",{method:"POST"});
        alert(d.message);
        await showJob(id);
    }catch(e){alert(e.message)}
}

async function closeJob(id){
    if(!confirm("Close this job?"))return;
    try{
        await api("/api/jobs/"+id,{method:"DELETE"});
        alert("Job closed.");
        showJobs();
    }catch(e){alert(e.message)}
}

async function showSaved(){
    if(!me){showLogin();return}
    closeSidebar();
    shell(`
      <main class="page">
        <div class="page-title"><div><h1>Saved Jobs</h1><p>Your saved opportunities</p></div></div>
        <div id="savedResults" class="job-grid"></div>
      </main>`, "saved");
    const box=document.getElementById("savedResults");
    try{
        const d=await api("/api/saved-jobs");
        box.innerHTML=d.jobs?.length ? d.jobs.map(jobCard).join("") : `<div class="empty" style="grid-column:1/-1">No saved jobs yet.</div>`;
    }catch(e){box.innerHTML=`<div class="empty">${esc(e.message)}</div>`}
}

async function showApplications(){
    if(!me){showLogin();return}
    closeSidebar();
    shell(`
      <main class="page">
        <div class="page-title"><div><h1>Applications</h1><p>${me.role==="jobseeker" ? "Track your job applications" : "Applications received from candidates"}</p></div></div>
        <div class="panel"><div id="applicationsResults"></div></div>
      </main>`, "applications");
    const box=document.getElementById("applicationsResults");
    try{
        const d=await api("/api/applications");
        const rows=d.applications||[];
        if(!rows.length){box.innerHTML=`<div class="empty">No applications yet.</div>`;return}
        if(me.role==="jobseeker"){
            box.innerHTML=`<div class="table-wrap"><table>
              <thead><tr><th>Job</th><th>Company</th><th>Location</th><th>Applied</th><th>Status</th></tr></thead>
              <tbody>${rows.map(a=>`
                <tr><td><b>${esc(a.title)}</b></td><td>${esc(a.company)}</td><td>${esc(a.location||a.country)}</td>
                <td>${fmtDate(a.created_at)}</td><td><span class="status">${esc(a.status)}</span></td></tr>`).join("")}</tbody>
            </table></div>`;
        }else{
            box.innerHTML=`<div class="table-wrap"><table>
              <thead><tr><th>Applicant</th><th>Job</th><th>Email</th><th>Phone</th><th>Date</th><th>Status</th></tr></thead>
              <tbody>${rows.map(a=>`
                <tr><td><b>${esc(a.applicant_name)}</b></td><td>${esc(a.title)}</td><td>${esc(a.applicant_email)}</td>
                <td>${esc(a.applicant_phone||"-")}</td><td>${fmtDate(a.created_at)}</td>
                <td>
                  <select class="select" style="width:auto;padding:6px;font-size:10px" onchange="changeStatus(${a.id},this.value)">
                    ${["applied","viewed","shortlisted","rejected","selected"].map(s=>`<option ${a.status===s?"selected":""}>${s}</option>`).join("")}
                  </select>
                </td></tr>`).join("")}</tbody>
            </table></div>`;
        }
    }catch(e){box.innerHTML=`<div class="empty">${esc(e.message)}</div>`}
}

async function changeStatus(id,status){
    try{
        await api("/api/applications/"+id+"/status",{method:"PUT",body:{status}});
    }catch(e){alert(e.message);showApplications()}
}

async function showNotifications(){
    if(!me){showLogin();return}
    closeSidebar();
    shell(`
      <main class="page">
        <div class="page-title">
          <div><h1>Notifications</h1><p>Your latest updates</p></div>
          <button class="btn btn-outline btn-small" onclick="markNotificationsRead()">Mark all as read</button>
        </div>
        <div id="notificationResults"></div>
      </main>`, "notifications");
    const box=document.getElementById("notificationResults");
    try{
        const d=await api("/api/notifications");
        const rows=d.notifications||[];
        box.innerHTML=rows.length ? rows.map(n=>`
          <div class="panel" style="${n.is_read ? "" : "border-left:3px solid var(--blue)"}">
            <div style="display:flex;gap:12px">
              <div class="company-icon">♧</div>
              <div><b style="font-size:12px">${esc(n.title)}</b>
              <div class="muted" style="margin-top:5px">${esc(n.message)}</div>
              <div class="muted" style="margin-top:7px;font-size:10px">${fmtDate(n.created_at)}</div></div>
            </div>
          </div>`).join("") : `<div class="empty">No notifications yet.</div>`;
    }catch(e){box.innerHTML=`<div class="empty">${esc(e.message)}</div>`}
}

async function markNotificationsRead(){
    try{await api("/api/notifications/read",{method:"POST"});showNotifications()}catch(e){alert(e.message)}
}

function showPostJob(){
    if(!me || !["employer","admin"].includes(me.role)){showLogin();return}
    closeSidebar();
    shell(`
      <main class="page">
        <div class="page-title"><div><h1>Post a New Job</h1><p>Reach candidates looking for their next opportunity</p></div></div>
        <div class="panel form-panel">
          <div id="postMsg" class="msg"></div>
          <div class="form-row">
            <div class="form-field"><label>Job Title *</label><input id="jTitle" class="field" placeholder="Backend Developer"></div>
            <div class="form-field"><label>Company *</label><input id="jCompany" class="field" value="${esc(me.name)}"></div>
          </div>
          <div class="form-row">
            <div class="form-field"><label>Category *</label><select id="jCategory" class="select">
              <option>IT & Software</option><option>Design</option><option>Marketing</option><option>Sales</option><option>Finance</option><option>HR</option><option>Engineering</option><option>Customer Support</option>
            </select></div>
            <div class="form-field"><label>Country *</label><select id="jCountry" class="select">
              <option>India</option><option>USA</option><option>UAE</option><option>UK</option><option>Other</option>
            </select></div>
          </div>
          <div class="form-row">
            <div class="form-field"><label>Job Type *</label><select id="jType" class="select">
              <option>Full-time</option><option>Part-time</option><option>Contract</option><option>Freelance</option>
            </select></div>
            <div class="form-field"><label>Work Mode *</label><select id="jMode" class="select">
              <option>Remote</option><option>Onsite</option><option>Hybrid</option>
            </select></div>
          </div>
          <div class="form-row">
            <div class="form-field"><label>Location</label><input id="jLocation" class="field" placeholder="Hyderabad"></div>
            <div class="form-field"><label>Salary</label><input id="jSalary" class="field" placeholder="₹5,00,000 - ₹8,00,000 / year"></div>
          </div>
          <div class="form-field"><label>Skills</label><input id="jSkills" class="field" placeholder="Python, FastAPI, SQL, PostgreSQL"></div>
          <div class="form-field"><label>Application Email</label><input id="jEmail" class="field" type="email" placeholder="hr@company.com"></div>
          <div class="form-field"><label>Description *</label><textarea id="jDescription" placeholder="Describe the role, responsibilities and requirements..."></textarea></div>
          <button class="btn btn-primary full" onclick="postJob()">Post Job</button>
        </div>
      </main>`, "post");
}

async function postJob(){
    const msg=document.getElementById("postMsg");
    msg.className="msg";msg.textContent="";
    try{
        await api("/api/jobs",{method:"POST",body:{
            title:document.getElementById("jTitle").value.trim(),
            company:document.getElementById("jCompany").value.trim(),
            category:document.getElementById("jCategory").value,
            country:document.getElementById("jCountry").value,
            location:document.getElementById("jLocation").value.trim(),
            job_type:document.getElementById("jType").value,
            work_mode:document.getElementById("jMode").value,
            salary:document.getElementById("jSalary").value.trim(),
            skills:document.getElementById("jSkills").value.trim(),
            application_email:document.getElementById("jEmail").value.trim(),
            description:document.getElementById("jDescription").value.trim()
        }});
        msg.className="msg ok";
        msg.textContent="Job posted successfully!";
        setTimeout(showJobs,700);
    }catch(e){msg.className="msg error";msg.textContent=e.message}
}

async function showProfile(){
    if(!me){showLogin();return}
    closeSidebar();
    shell(`
      <main class="page">
        <div class="page-title"><div><h1>Profile</h1><p>Manage your Job Mart profile</p></div></div>
        <div class="profile-grid">
          <div class="panel profile-box">
            <div class="profile-avatar">${esc(initials(me.name))}</div>
            <h3 style="margin:0">${esc(me.name)}</h3>
            <div class="muted">${esc(me.role === "employer" ? "Employer / Recruiter" : "Job Seeker")}</div>
            <div class="muted" style="margin-top:8px">${esc(me.email)}</div>
          </div>
          <div class="panel">
            <div id="profileMsg" class="msg"></div>
            <div class="form-row">
              <div class="form-field"><label>Full Name</label><input id="pName" class="field" value="${esc(me.name)}"></div>
              <div class="form-field"><label>Country</label><input id="pCountry" class="field" value="${esc(me.country)}"></div>
            </div>
            <div class="form-row">
              <div class="form-field"><label>Email</label><input class="field" value="${esc(me.email)}" disabled></div>
              <div class="form-field"><label>City</label><input id="pCity" class="field" value="${esc(me.city)}"></div>
            </div>
            <div class="form-row">
              <div class="form-field"><label>Phone</label><input id="pPhone" class="field" value="${esc(me.phone)}"></div>
              <div class="form-field"><label>Account Type</label><input class="field" value="${esc(me.role)}" disabled></div>
            </div>
            <div class="form-field"><label>Bio</label><textarea id="pBio">${esc(me.bio)}</textarea></div>
            <button class="btn btn-primary" onclick="updateProfile()">Update Profile</button>
          </div>
        </div>
      </main>`, "profile");
}

async function updateProfile(){
    const msg=document.getElementById("profileMsg");
    try{
        await api("/api/profile",{method:"PUT",body:{
            name:document.getElementById("pName").value.trim(),
            phone:document.getElementById("pPhone").value.trim(),
            country:document.getElementById("pCountry").value.trim(),
            city:document.getElementById("pCity").value.trim(),
            bio:document.getElementById("pBio").value.trim()
        }});
        await loadMe();
        msg.className="msg ok";msg.textContent="Profile updated successfully.";
        setTimeout(showProfile,500);
    }catch(e){msg.className="msg error";msg.textContent=e.message}
}

async function doLogout(){
    try{await api("/api/logout",{method:"POST"})}catch(e){}
    me=null;
    renderPublicHome();
}

async function start(){
    await loadMe();
    if(me) showDashboard();
    else renderPublicHome();
}

start();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(HTML)


@app.get("/health")
def health():
    return {"ok": True, "service": "Job Mart", "version": "2.0"}


# =========================================================
# END
# =========================================================
