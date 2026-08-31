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
# COMPLETE SINGLE FILE APP
# =========================================================

app = FastAPI(
    title="Job Mart",
    version="2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "job_mart.db"

# Local development sessions
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
        FOREIGN KEY(employer_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        applicant_id INTEGER NOT NULL,
        cover_letter TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'applied',
        created_at TEXT NOT NULL,
        UNIQUE(job_id, applicant_id),
        FOREIGN KEY(job_id)
            REFERENCES jobs(id)
            ON DELETE CASCADE,
        FOREIGN KEY(applicant_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS saved_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(job_id, user_id),
        FOREIGN KEY(job_id)
            REFERENCES jobs(id)
            ON DELETE CASCADE,
        FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_jobs_status
        ON jobs(status);

    CREATE INDEX IF NOT EXISTS idx_jobs_employer
        ON jobs(employer_id);

    CREATE INDEX IF NOT EXISTS idx_apps_applicant
        ON applications(applicant_id);

    CREATE INDEX IF NOT EXISTS idx_apps_job
        ON applications(job_id);

    CREATE INDEX IF NOT EXISTS idx_saved_user
        ON saved_jobs(user_id);

    CREATE INDEX IF NOT EXISTS idx_notifications_user
        ON notifications(user_id);
    """)

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

        return secrets.compare_digest(
            check,
            saved_hash
        )

    except Exception:
        return False


def valid_email(email: str) -> bool:
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return bool(re.match(pattern, email))


def public_user(user):
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "phone": user["phone"],
        "country": user["country"],
        "city": user["city"],
        "bio": user["bio"]
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


# =========================================================
# MODELS
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
# AUTH API
# =========================================================

@app.post("/api/register")
def register(data: RegisterData):

    name = data.name.strip()
    email = data.email.strip().lower()
    password = data.password

    if not valid_email(email):
        raise HTTPException(
            status_code=400,
            detail="Please enter a valid email address"
        )

    role = data.role.strip().lower()

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
        (name,email,password,role,phone,country,city,created_at)
        VALUES (?,?,?,?,?,?,?,?)
        """,
        (
            name,
            email,
            hash_password(password),
            role,
            data.phone.strip(),
            data.country.strip(),
            data.city.strip(),
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

    email = data.email.strip().lower()

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

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not verify_password(
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

    token = request.cookies.get(
        "jobmart_session"
    )

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
        SET name=?,
            phone=?,
            country=?,
            city=?,
            bio=?
        WHERE id=?
        """,
        (
            data.name.strip(),
            data.phone.strip(),
            data.country.strip(),
            data.city.strip(),
            data.bio.strip(),
            user["id"]
        )
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Profile updated"
    }


# =========================================================
# JOB API
# =========================================================

@app.post("/api/jobs")
def create_job(
    data: JobData,
    request: Request
):

    user = require_employer(request)

    application_email = data.application_email.strip()

    if application_email and not valid_email(
        application_email
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid application email"
        )

    conn = db()

    cur = conn.execute(
        """
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
    request: Optional[Request] = None
):

    conn = db()

    sql = """
        SELECT
            j.*,
            u.name AS employer_name
        FROM jobs j
        JOIN users u
            ON u.id=j.employer_id
        WHERE j.status='active'
    """

    params = []

    search = q.strip().lower()

    if search:

        sql += """
        AND (
            LOWER(j.title) LIKE ?
            OR LOWER(j.company) LIKE ?
            OR LOWER(j.description) LIKE ?
            OR LOWER(j.skills) LIKE ?
            OR LOWER(j.location) LIKE ?
        )
        """

        value = f"%{search}%"

        params.extend([
            value,
            value,
            value,
            value,
            value
        ])

    if category.strip():
        sql += """
        AND LOWER(j.category)=LOWER(?)
        """
        params.append(category.strip())

    if country.strip():
        sql += """
        AND LOWER(j.country)=LOWER(?)
        """
        params.append(country.strip())

    if job_type.strip():
        sql += """
        AND LOWER(j.job_type)=LOWER(?)
        """
        params.append(job_type.strip())

    if work_mode.strip():
        sql += """
        AND LOWER(j.work_mode)=LOWER(?)
        """
        params.append(work_mode.strip())

    user = current_user(request) if request else None

    if mine:

        if not user:
            conn.close()
            raise HTTPException(
                status_code=401,
                detail="Login required"
            )

        if user["role"] not in (
            "employer",
            "admin"
        ):
            conn.close()
            raise HTTPException(
                status_code=403,
                detail="Employer account required"
            )

        sql += """
        AND j.employer_id=?
        """

        params.append(user["id"])

    sql += """
    ORDER BY j.id DESC
    """

    rows = conn.execute(
        sql,
        params
    ).fetchall()

    result = [
        dict(row)
        for row in rows
    ]

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
        SELECT
            j.*,
            u.name AS employer_name,
            u.email AS employer_email
        FROM jobs j
        JOIN users u
            ON u.id=j.employer_id
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

        applied = bool(
            conn.execute(
                """
                SELECT id
                FROM applications
                WHERE job_id=?
                  AND applicant_id=?
                """,
                (
                    job_id,
                    user["id"]
                )
            ).fetchone()
        )

        saved = bool(
            conn.execute(
                """
                SELECT id
                FROM saved_jobs
                WHERE job_id=?
                  AND user_id=?
                """,
                (
                    job_id,
                    user["id"]
                )
            ).fetchone()
        )

    result = dict(job)

    result["applied"] = applied
    result["saved"] = saved

    conn.close()

    return {
        "ok": True,
        "job": result
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
        """
        UPDATE jobs
        SET status='closed'
        WHERE id=?
        """,
        (job_id,)
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Job closed"
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

    if user["role"] in (
        "employer",
        "admin"
    ):
        raise HTTPException(
            status_code=403,
            detail="Employer accounts cannot apply"
        )

    conn = db()

    job = conn.execute(
        """
        SELECT *
        FROM jobs
        WHERE id=?
          AND status='active'
        """,
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
        SELECT id
        FROM applications
        WHERE job_id=?
          AND applicant_id=?
        """,
        (
            job_id,
            user["id"]
        )
    ).fetchone()

    if existing:
        conn.close()

        raise HTTPException(
            status_code=400,
            detail="Already applied"
        )

    conn.execute(
        """
        INSERT INTO applications
        (
            job_id,
            applicant_id,
            cover_letter,
            status,
            created_at
        )
        VALUES (?,?,?,?,?)
        """,
        (
            job_id,
            user["id"],
            data.cover_letter.strip(),
            "applied",
            now()
        )
    )

    conn.execute(
        """
        INSERT INTO notifications
        (
            user_id,
            title,
            message,
            created_at
        )
        VALUES (?,?,?,?)
        """,
        (
            job["employer_id"],
            "New job application",
            (
                f"{user['name']} applied "
                f"for {job['title']}"
            ),
            now()
        )
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Application submitted"
    }


@app.get("/api/applications")
def get_applications(
    request: Request
):

    user = require_user(request)

    conn = db()

    if user["role"] in (
        "employer",
        "admin"
    ):

        if user["role"] == "admin":

            rows = conn.execute(
                """
                SELECT
                    a.*,
                    j.title,
                    j.company,
                    j.country,
                    j.location,
                    u.name AS applicant_name,
                    u.email AS applicant_email,
                    u.phone AS applicant_phone
                FROM applications a
                JOIN jobs j
                    ON j.id=a.job_id
                JOIN users u
                    ON u.id=a.applicant_id
                ORDER BY a.id DESC
                """
            ).fetchall()

        else:

            rows = conn.execute(
                """
                SELECT
                    a.*,
                    j.title,
                    j.company,
                    j.country,
                    j.location,
                    u.name AS applicant_name,
                    u.email AS applicant_email,
                    u.phone AS applicant_phone
                FROM applications a
                JOIN jobs j
                    ON j.id=a.job_id
                JOIN users u
                    ON u.id=a.applicant_id
                WHERE j.employer_id=?
                ORDER BY a.id DESC
                """,
                (user["id"],)
            ).fetchall()

    else:

        rows = conn.execute(
            """
            SELECT
                a.*,
                j.title,
                j.company,
                j.country,
                j.location,
                j.work_mode,
                j.job_type
            FROM applications a
            JOIN jobs j
                ON j.id=a.job_id
            WHERE a.applicant_id=?
            ORDER BY a.id DESC
            """,
            (user["id"],)
        ).fetchall()

    result = [
        dict(row)
        for row in rows
    ]

    conn.close()

    return {
        "ok": True,
        "applications": result
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
        "viewed",
        "shortlisted",
        "rejected",
        "selected"
    }

    status = data.status.strip().lower()

    if status not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Invalid status"
        )

    conn = db()

    row = conn.execute(
        """
        SELECT
            a.*,
            j.title,
            j.employer_id
        FROM applications a
        JOIN jobs j
            ON j.id=a.job_id
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

    if (
        user["role"] != "admin"
        and row["employer_id"] != user["id"]
    ):
        conn.close()

        raise HTTPException(
            status_code=403,
            detail="Not allowed"
        )

    conn.execute(
        """
        UPDATE applications
        SET status=?
        WHERE id=?
        """,
        (
            status,
            application_id
        )
    )

    conn.execute(
        """
        INSERT INTO notifications
        (
            user_id,
            title,
            message,
            created_at
        )
        VALUES (?,?,?,?)
        """,
        (
            row["applicant_id"],
            "Application status updated",
            (
                f"Your application for "
                f"{row['title']} is now {status}."
            ),
            now()
        )
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Application status updated"
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

    existing = conn.execute(
        """
        SELECT id
        FROM saved_jobs
        WHERE job_id=?
          AND user_id=?
        """,
        (
            job_id,
            user["id"]
        )
    ).fetchone()

    if existing:

        conn.execute(
            """
            DELETE FROM saved_jobs
            WHERE job_id=?
              AND user_id=?
            """,
            (
                job_id,
                user["id"]
            )
        )

        saved = False
        message = "Removed from saved jobs"

    else:

        conn.execute(
            """
            INSERT INTO saved_jobs
            (
                job_id,
                user_id,
                created_at
            )
            VALUES (?,?,?)
            """,
            (
                job_id,
                user["id"],
                now()
            )
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
def get_saved_jobs(
    request: Request
):

    user = require_user(request)

    conn = db()

    rows = conn.execute(
        """
        SELECT
            j.*,
            s.created_at AS saved_at,
            u.name AS employer_name
        FROM saved_jobs s
        JOIN jobs j
            ON j.id=s.job_id
        JOIN users u
            ON u.id=j.employer_id
        WHERE s.user_id=?
        ORDER BY s.id DESC
        """,
        (user["id"],)
    ).fetchall()

    result = [
        dict(row)
        for row in rows
    ]

    conn.close()

    return {
        "ok": True,
        "jobs": result
    }


# =========================================================
# NOTIFICATIONS
# =========================================================

@app.get("/api/notifications")
def get_notifications(
    request: Request
):

    user = require_user(request)

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM notifications
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (user["id"],)
    ).fetchall()

    result = [
        dict(row)
        for row in rows
    ]

    conn.close()

    return {
        "ok": True,
        "notifications": result
    }


@app.post("/api/notifications/read")
def read_notifications(
    request: Request
):

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
        "ok": True
    }


# =========================================================
# DASHBOARD
# =========================================================

@app.get("/api/dashboard")
def dashboard(
    request: Request
):

    user = require_user(request)

    conn = db()

    if user["role"] in (
        "employer",
        "admin"
    ):

        if user["role"] == "admin":

            jobs_count = conn.execute(
                "SELECT COUNT(*) c FROM jobs"
            ).fetchone()["c"]

            active_jobs = conn.execute(
                """
                SELECT COUNT(*) c
                FROM jobs
                WHERE status='active'
                """
            ).fetchone()["c"]

            applications = conn.execute(
                "SELECT COUNT(*) c FROM applications"
            ).fetchone()["c"]

        else:

            jobs_count = conn.execute(
                """
                SELECT COUNT(*) c
                FROM jobs
                WHERE employer_id=?
                """,
                (user["id"],)
            ).fetchone()["c"]

            active_jobs = conn.execute(
                """
                SELECT COUNT(*) c
                FROM jobs
                WHERE employer_id=?
                  AND status='active'
                """,
                (user["id"],)
            ).fetchone()["c"]

            applications = conn.execute(
                """
                SELECT COUNT(*) c
                FROM applications a
                JOIN jobs j
                    ON j.id=a.job_id
                WHERE j.employer_id=?
                """,
                (user["id"],)
            ).fetchone()["c"]

        unread = conn.execute(
            """
            SELECT COUNT(*) c
            FROM notifications
            WHERE user_id=?
              AND is_read=0
            """,
            (user["id"],)
        ).fetchone()["c"]

        data = {
            "role": user["role"],
            "jobs_posted": jobs_count,
            "active_jobs": active_jobs,
            "applications": applications,
            "notifications": unread
        }

    else:

        applications = conn.execute(
            """
            SELECT COUNT(*) c
            FROM applications
            WHERE applicant_id=?
            """,
            (user["id"],)
        ).fetchone()["c"]

        saved = conn.execute(
            """
            SELECT COUNT(*) c
            FROM saved_jobs
            WHERE user_id=?
            """,
            (user["id"],)
        ).fetchone()["c"]

        unread = conn.execute(
            """
            SELECT COUNT(*) c
            FROM notifications
            WHERE user_id=?
              AND is_read=0
            """,
            (user["id"],)
        ).fetchone()["c"]

        data = {
            "role": "jobseeker",
            "applications": applications,
            "saved_jobs": saved,
            "notifications": unread
        }

    conn.close()

    return {
        "ok": True,
        "dashboard": data
    }


# =========================================================
# FRONTEND
# =========================================================

HTML = r"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1,viewport-fit=cover"
>

<title>Job Mart</title>

<style>

:root{
    --blue:#146be8;
    --blue2:#075bc7;
    --navy:#062b4c;
    --navy2:#0b3c64;
    --bg:#f5f7fb;
    --text:#182131;
    --muted:#6b7280;
    --line:#e4e8ef;
    --white:#fff;
    --green:#159b65;
    --red:#d64545;
    --shadow:0 8px 28px rgba(20,45,80,.08);
}

*{
    box-sizing:border-box;
}

html,body{
    margin:0;
    padding:0;
}

body{
    font-family:
    Inter,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    Arial,
    sans-serif;

    background:var(--bg);
    color:var(--text);
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

button:disabled{
    opacity:.55;
}

a{
    text-decoration:none;
}

.hidden{
    display:none!important;
}

#app{
    min-height:100vh;
}

/* =====================================================
   COMMON
===================================================== */

.brand{
    display:flex;
    align-items:center;
    gap:8px;
    font-weight:800;
    font-size:18px;
    color:#172238;
}

.brand-mark{
    width:31px;
    height:31px;
    border-radius:8px;
    display:grid;
    place-items:center;
    background:var(--blue);
    color:white;
    font-size:10px;
    font-weight:900;
}

.btn{
    border:1px solid transparent;
    border-radius:8px;
    padding:10px 16px;
    font-weight:700;
    transition:.15s;
}

.btn-primary{
    background:var(--blue);
    color:white;
}

.btn-primary:hover{
    background:var(--blue2);
}

.btn-outline{
    background:white;
    border-color:#dbe1ea;
    color:var(--text);
}

.btn-light{
    background:#edf4ff;
    color:var(--blue);
}

.btn-danger{
    background:#fff0f0;
    color:var(--red);
    border-color:#ffd5d5;
}

.btn-small{
    padding:7px 11px;
    font-size:12px;
}

.full{
    width:100%;
}

.field,
.select{
    width:100%;
    border:1px solid #dce2ea;
    border-radius:8px;
    background:white;
    padding:11px 12px;
    outline:none;
    color:var(--text);
}

.field:focus,
.select:focus,
textarea:focus{
    border-color:var(--blue);
    box-shadow:0 0 0 3px rgba(20,107,232,.08);
}

textarea{
    width:100%;
    border:1px solid #dce2ea;
    border-radius:8px;
    padding:11px;
    min-height:110px;
    resize:vertical;
    outline:none;
}

.muted{
    color:var(--muted);
    font-size:12px;
}

.link{
    color:var(--blue);
    font-weight:700;
}

.empty{
    background:white;
    border:1px solid var(--line);
    border-radius:12px;
    padding:40px 20px;
    text-align:center;
    color:var(--muted);
}

.msg{
    display:none;
    margin:10px 0;
    padding:10px;
    border-radius:7px;
    font-size:12px;
}

.msg.ok{
    display:block;
    background:#eaf8f1;
    color:var(--green);
}

.msg.error{
    display:block;
    background:#fff0f0;
    color:var(--red);
}


/* =====================================================
   PUBLIC HEADER
===================================================== */

.public-header{
    height:66px;
    background:white;
    border-bottom:1px solid var(--line);
    display:flex;
    align-items:center;
    justify-content:space-between;
    padding:0 30px;
    position:sticky;
    top:0;
    z-index:100;
}

.public-nav{
    display:flex;
    gap:24px;
    font-size:12px;
    color:#4d596a;
}

.public-nav a:hover{
    color:var(--blue);
}

.header-actions{
    display:flex;
    gap:8px;
}


/* =====================================================
   HOME
===================================================== */

.hero{
    max-width:1200px;
    margin:auto;
    padding:55px 30px 25px;
    display:grid;
    grid-template-columns:1.05fr .95fr;
    gap:35px;
    align-items:center;
}

.hero h1{
    margin:0 0 16px;
    font-size:44px;
    line-height:1.08;
    letter-spacing:-1.4px;
}

.hero p{
    margin:0;
    max-width:540px;
    color:var(--muted);
    font-size:14px;
    line-height:1.7;
}

.hero-art{
    min-height:280px;
    border-radius:25px;
    background:
        linear-gradient(
            145deg,
            #eaf2ff,
            #f9fbff
        );
    display:grid;
    place-items:center;
    overflow:hidden;
}

.hero-person{
    font-size:125px;
    filter:drop-shadow(
        0 16px 12px
        rgba(20,107,232,.12)
    );
}

.search-box{
    max-width:1200px;
    margin:auto;
    padding:0 30px 20px;
}

.search-row{
    background:white;
    border:1px solid var(--line);
    border-radius:12px;
    box-shadow:var(--shadow);
    padding:10px;
    display:grid;
    grid-template-columns:1.6fr .8fr .8fr .5fr;
    gap:8px;
}

.section{
    max-width:1200px;
    margin:auto;
    padding:12px 30px 24px;
}

.section-title{
    display:flex;
    justify-content:space-between;
    align-items:center;
    margin-bottom:12px;
}

.section-title h2{
    margin:0;
    font-size:16px;
}

.chips{
    display:flex;
    gap:8px;
    flex-wrap:wrap;
}

.chip{
    border:1px solid var(--line);
    background:white;
    border-radius:20px;
    padding:8px 12px;
    font-size:11px;
    color:#445066;
}

.chip:hover{
    border-color:var(--blue);
    color:var(--blue);
}

.job-grid{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:14px;
}

.job-card{
    background:white;
    border:1px solid var(--line);
    border-radius:12px;
    padding:16px;
    box-shadow:0 3px 12px rgba(20,40,70,.03);
}

.job-head{
    display:flex;
    gap:11px;
}

.company-icon{
    flex:0 0 40px;
    width:40px;
    height:40px;
    border-radius:9px;
    background:#edf4ff;
    color:var(--blue);
    display:grid;
    place-items:center;
    font-weight:900;
}

.job-title{
    margin:0 0 4px;
    font-size:14px;
}

.company{
    color:var(--muted);
    font-size:11px;
}

.tags{
    display:flex;
    gap:5px;
    flex-wrap:wrap;
    margin-top:8px;
}

.tag{
    background:#f4f6f9;
    padding:4px 6px;
    border-radius:4px;
    color:#5d6878;
    font-size:9px;
}

.job-actions{
    display:flex;
    justify-content:flex-end;
    gap:7px;
    margin-top:13px;
}


/* =====================================================
   AUTH
===================================================== */

.auth-page{
    min-height:calc(100vh - 66px);
    display:flex;
    justify-content:center;
    align-items:center;
    padding:35px 20px;
}

.auth-card{
    width:min(850px,100%);
    background:white;
    border:1px solid var(--line);
    border-radius:12px;
    box-shadow:var(--shadow);
    overflow:hidden;
    display:grid;
    grid-template-columns:.72fr 1.28fr;
}

.auth-side{
    background:
        linear-gradient(
            145deg,
            #eef4ff,
            #f8fbff
        );
    padding:35px;
    display:flex;
    flex-direction:column;
    justify-content:center;
    align-items:center;
    text-align:center;
}

.auth-side .big{
    font-size:95px;
    margin-bottom:15px;
}

.auth-side h2{
    margin:0 0 8px;
    font-size:21px;
}

.auth-side p{
    color:var(--muted);
    font-size:12px;
    line-height:1.7;
}

.auth-form{
    padding:32px;
}

.auth-form h1{
    margin:0 0 6px;
    font-size:23px;
}

.sub{
    color:var(--muted);
    font-size:11px;
    margin-bottom:22px;
}

.form-group{
    margin-bottom:13px;
}

.form-label{
    display:block;
    font-size:11px;
    font-weight:800;
    margin-bottom:6px;
}

.form-grid{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:12px;
}

.check{
    display:flex;
    align-items:center;
    gap:7px;
    font-size:11px;
    color:#5e6979;
    margin:10px 0;
}


/* =====================================================
   DASHBOARD
===================================================== */

.shell{
    min-height:100vh;
}

.sidebar{
    position:fixed;
    left:0;
    top:0;
    bottom:0;
    width:220px;
    background:var(--navy);
    color:white;
    padding:20px 13px;
    z-index:200;
    display:flex;
    flex-direction:column;
}

.sidebar .brand{
    color:white;
    padding:0 9px 25px;
}

.sidebar .brand-mark{
    background:#1975f1;
}

.side-label{
    color:#8da5bc;
    font-size:9px;
    text-transform:uppercase;
    letter-spacing:1px;
    padding:0 11px 8px;
}

.side-btn{
    width:100%;
    border:0;
    background:transparent;
    color:#c6d5e5;
    text-align:left;
    padding:11px 10px;
    border-radius:7px;
    margin-bottom:3px;
    font-size:11px;
    display:flex;
    align-items:center;
    gap:9px;
}

.side-btn:hover,
.side-btn.active{
    background:#1169dc;
    color:white;
}

.side-spacer{
    flex:1;
}

.shell-main{
    margin-left:220px;
    min-height:100vh;
}

.topbar{
    height:62px;
    background:white;
    border-bottom:1px solid var(--line);
    display:flex;
    justify-content:space-between;
    align-items:center;
    padding:0 25px;
    position:sticky;
    top:0;
    z-index:50;
}

.mobile-menu{
    display:none;
    border:0;
    background:#edf4ff;
    color:var(--blue);
    border-radius:8px;
    padding:8px 11px;
}

.user-mini{
    display:flex;
    align-items:center;
    gap:8px;
    font-size:12px;
    font-weight:700;
}

.avatar{
    width:32px;
    height:32px;
    border-radius:50%;
    background:#e7effc;
    display:grid;
    place-items:center;
    color:var(--blue);
}

.page{
    max-width:1250px;
    margin:auto;
    padding:25px;
}

.page-title{
    display:flex;
    justify-content:space-between;
    align-items:center;
    margin-bottom:20px;
}

.page-title h1{
    margin:0;
    font-size:21px;
}

.page-title p{
    margin:5px 0 0;
    color:var(--muted);
    font-size:11px;
}

.stats{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:13px;
    margin-bottom:20px;
}

.stat{
    background:white;
    border:1px solid var(--line);
    border-radius:12px;
    padding:18px;
}

.stat .n{
    font-size:25px;
    font-weight:800;
}

.stat .l{
    font-size:10px;
    color:var(--muted);
    margin-top:3px;
}

.panel{
    background:white;
    border:1px solid var(--line);
    border-radius:12px;
    padding:18px;
    margin-bottom:15px;
}

.panel h3{
    margin:0 0 14px;
    font-size:14px;
}

.table-wrap{
    overflow:auto;
}

table{
    width:100%;
    border-collapse:collapse;
    font-size:11px;
}

th,
td{
    padding:11px 8px;
    border-bottom:1px solid #edf0f4;
    text-align:left;
    white-space:nowrap;
}

th{
    color:#667085;
    font-size:10px;
}

.status{
    display:inline-block;
    padding:4px 7px;
    border-radius:5px;
    background:#eaf8f1;
    color:var(--green);
    font-size:10px;
    font-weight:700;
}

.detail-grid{
    display:grid;
    grid-template-columns:1fr 280px;
    gap:15px;
}

.detail-card{
    background:white;
    border:1px solid var(--line);
    border-radius:12px;
    padding:20px;
}

.detail-card h1{
    font-size:24px;
    margin:0 0 5px;
}

.detail-card h2{
    font-size:14px;
    margin:20px 0 8px;
}

.detail-card p{
    font-size:12px;
    color:#4f5b6c;
    line-height:1.8;
    white-space:pre-line;
}

.action-stack{
    display:grid;
    gap:8px;
}

.form-panel{
    max-width:900px;
}

.form-row{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:12px;
}

.form-field{
    margin-bottom:13px;
}

.form-field label{
    display:block;
    font-size:11px;
    font-weight:800;
    margin-bottom:6px;
}

.profile-grid{
    display:grid;
    grid-template-columns:260px 1fr;
    gap:15px;
}

.profile-box{
    text-align:center;
}

.profile-avatar{
    width:92px;
    height:92px;
    margin:5px auto 15px;
    border-radius:50%;
    background:#e9f1ff;
    color:var(--blue);
    display:grid;
    place-items:center;
    font-size:30px;
    font-weight:800;
}

.mobile-bottom{
    display:none;
}


/* =====================================================
   MOBILE
===================================================== */

@media(max-width:900px){

    .public-nav{
        display:none;
    }

    .hero{
        grid-template-columns:1fr;
    }

    .hero-art{
        min-height:190px;
    }

    .search-row{
        grid-template-columns:1fr 1fr;
    }

    .job-grid{
        grid-template-columns:1fr 1fr;
    }

    .sidebar{
        transform:translateX(-100%);
        transition:.2s;
    }

    .sidebar.open{
        transform:translateX(0);
    }

    .shell-main{
        margin-left:0;
    }

    .mobile-menu{
        display:block;
    }

    .mobile-bottom{
        display:grid;
        position:fixed;
        left:0;
        right:0;
        bottom:0;
        height:62px;
        background:white;
        border-top:1px solid var(--line);
        z-index:250;
        grid-template-columns:repeat(5,1fr);
    }

    .mobile-bottom button{
        border:0;
        background:white;
        color:#5d6878;
        font-size:9px;
    }

    .mobile-bottom button.active{
        color:var(--blue);
        font-weight:800;
    }

    .page{
        padding-bottom:85px;
    }

}

@media(max-width:620px){

    .public-header{
        height:60px;
        padding:0 14px;
    }

    .header-actions .btn{
        padding:8px 10px;
        font-size:10px;
    }

    .hero{
        padding:30px 16px 15px;
    }

    .hero h1{
        font-size:32px;
    }

    .hero-art{
        display:none;
    }

    .search-box{
        padding:0 16px 15px;
    }

    .search-row{
        grid-template-columns:1fr;
    }

    .section{
        padding:10px 16px 20px;
    }

    .job-grid{
        grid-template-columns:1fr;
    }

    .auth-page{
        padding:15px;
    }

    .auth-card{
        grid-template-columns:1fr;
    }

    .auth-side{
        display:none;
    }

    .auth-form{
        padding:25px 20px;
    }

    .form-grid,
    .form-row{
        grid-template-columns:1fr;
    }

    .stats{
        grid-template-columns:1fr;
    }

    .topbar{
        padding:0 14px;
    }

    .topbar .user-mini span{
        display:none;
    }

    .detail-grid,
    .profile-grid{
        grid-template-columns:1fr;
    }

    .page{
        padding:18px 14px 85px;
    }

}

</style>
</head>


<body>

<div id="app"></div>


<script>

const app = document.getElementById("app");

let me = null;

let jobsCache = [];


function esc(value){

    return String(value ?? "")
        .replace(/[&<>"']/g, function(c){

            return {
                "&":"&amp;",
                "<":"&lt;",
                ">":"&gt;",
                '"':"&quot;",
                "'":"&#39;"
            }[c];

        });

}


function initials(name){

    const parts =
        String(name || "User")
        .trim()
        .split(/\s+/);

    return (
        (parts[0]?.[0] || "U") +
        (parts[1]?.[0] || "")
    ).toUpperCase();

}


function fmtDate(value){

    if(!value) return "";

    const date = new Date(value);

    if(Number.isNaN(date.getTime()))
        return "";

    return date.toLocaleDateString(
        undefined,
        {
            day:"2-digit",
            month:"short",
            year:"numeric"
        }
    );

}


async function api(url, options={}){

    const opts = {
        ...options,
        headers:{
            ...(options.headers || {})
        }
    };

    if(
        opts.body &&
        typeof opts.body !== "string"
    ){

        opts.headers["Content-Type"] =
            "application/json";

        opts.body =
            JSON.stringify(opts.body);

    }

    const response =
        await fetch(url, opts);

    let data = {};

    try{
        data = await response.json();
    }catch(e){}

    if(!response.ok){

        throw new Error(
            data.detail ||
            "Something went wrong"
        );

    }

    return data;

}


/* =====================================================
   PUBLIC HEADER
===================================================== */

function publicHeader(){

    return `

    <header class="public-header">

        <div class="brand">
            <span class="brand-mark">JM</span>
            Job Mart
        </div>

        <nav class="public-nav">

            <a href="#"
               onclick="showHome();return false">
               Home
            </a>

            <a href="#"
               onclick="showJobs();return false">
               Jobs
            </a>

            <a href="#"
               onclick="showHome();return false">
               Employers
            </a>

            <a href="#"
               onclick="showHome();return false">
               About Us
            </a>

            <a href="#"
               onclick="showHome();return false">
               Contact
            </a>

        </nav>

        <div class="header-actions">

            <button
                class="btn btn-outline btn-small"
                onclick="showLogin()">
                Login
            </button>

            <button
                class="btn btn-primary btn-small"
                onclick="showRegister()">
                Register
            </button>

        </div>

    </header>

    `;

}


/* =====================================================
   HOME
===================================================== */

function showHome(){

    if(me){
        showDashboard();
        return;
    }

    renderPublicHome();

}


function renderPublicHome(){

    app.innerHTML = `

    ${publicHeader()}

    <main>

        <section class="hero">

            <div>

                <h1>
                    Find The Job<br>
                    That Fits Your Life
                </h1>

                <p>
                    Search jobs posted by verified
                    employers and build your career.
                </p>

            </div>

            <div class="hero-art">

                <div class="hero-person">
                    🧑‍💻
                </div>

            </div>

        </section>


        <section class="search-box">

            <div class="search-row">

                <input
                    id="homeQ"
                    class="field"
                    placeholder="Job title, keyword, or company"
                >

                <select
                    id="homeCountry"
                    class="select"
                >

                    <option value="">
                        All Countries
                    </option>

                    <option>India</option>
                    <option>USA</option>
                    <option>UAE</option>
                    <option>UK</option>
                    <option>Other</option>

                </select>


                <select
                    id="homeType"
                    class="select"
                >

                    <option value="">
                        All Job Types
                    </option>

                    <option>Full-time</option>
                    <option>Part-time</option>
                    <option>Contract</option>
                    <option>Freelance</option>

                </select>


                <button
                    class="btn btn-primary"
                    onclick="homeSearch()">
                    Search
                </button>

            </div>

        </section>


        <section class="section">

            <div class="section-title">

                <h2>
                    Popular Categories
                </h2>

                <a
                    class="link"
                    href="#"
                    onclick="showJobs();return false">
                    View all
                </a>

            </div>


            <div class="chips">

                ${
                    [
                        "IT & Software",
                        "Design",
                        "Marketing",
                        "Sales",
                        "Finance",
                        "HR",
                        "Customer Support",
                        "Engineering"
                    ].map(function(category){

                        return `
                        <button
                            class="chip"
                            onclick="categorySearch('${category}')">
                            ${esc(category)}
                        </button>
                        `;

                    }).join("")
                }

            </div>

        </section>


        <section class="section">

            <div class="section-title">

                <h2>
                    Latest Jobs
                </h2>

                <a
                    class="link"
                    href="#"
                    onclick="showJobs();return false">
                    View all
                </a>

            </div>

            <div
                id="publicJobs"
                class="job-grid">
            </div>

        </section>

    </main>

    `;

    loadPublicJobs();

}


function homeSearch(){

    const q =
        document.getElementById(
            "homeQ"
        ).value.trim();

    const country =
        document.getElementById(
            "homeCountry"
        ).value;

    const type =
        document.getElementById(
            "homeType"
        ).value;

    showJobs({
        q,
        country,
        job_type:type
    });

}


function categorySearch(category){

    showJobs({
        category
    });

}


async function loadPublicJobs(params={}){

    const box =
        document.getElementById(
            "publicJobs"
        );

    if(!box) return;

    box.innerHTML =
        `<div class="empty">Loading jobs...</div>`;

    try{

        const query =
            new URLSearchParams(params)
                .toString();

        const data =
            await api(
                "/api/jobs" +
                (query ? "?" + query : "")
            );

        jobsCache =
            data.jobs || [];

        box.innerHTML =
            jobsCache.length
            ?
            jobsCache
                .slice(0,6)
                .map(jobCard)
                .join("")
            :
            `
            <div
                class="empty"
                style="grid-column:1/-1">

                No jobs posted yet.

                <br>

                <small>
                    Jobs will appear here
                    after an employer posts them.
                </small>

            </div>
            `;

    }catch(error){

        box.innerHTML =
            `<div class="empty">
                ${esc(error.message)}
            </div>`;

    }

}


function jobCard(job){

    return `

    <article class="job-card">

        <div class="job-head">

            <div class="company-icon">
                ▣
            </div>

            <div style="min-width:0;flex:1">

                <h3 class="job-title">
                    ${esc(job.title)}
                </h3>

                <div class="company">
                    ${esc(job.company)}
                </div>

                <div class="tags">

                    <span class="tag">
                        ${esc(job.country)}
                    </span>

                    <span class="tag">
                        ${esc(job.job_type)}
                    </span>

                    <span class="tag">
                        ${esc(job.work_mode)}
                    </span>

                </div>

            </div>

        </div>


        <div
            class="muted"
            style="margin-top:10px">

            ${esc(
                job.location ||
                job.country
            )}

            ${
                job.salary
                ?
                " · " + esc(job.salary)
                :
                ""
            }

        </div>


        <div class="job-actions">

            <button
                class="btn btn-outline btn-small"
                onclick="showJob(${job.id})">

                View Job

            </button>

        </div>

    </article>

    `;

}


/* =====================================================
   LOGIN
===================================================== */

function showLogin(){

    app.innerHTML = `

    ${publicHeader()}

    <main class="auth-page">

        <div class="auth-card">

            <aside class="auth-side">

                <div class="big">
                    🔐
                </div>

                <h2>
                    Welcome Back!
                </h2>

                <p>
                    Login to your account
                    <br>
                    and explore thousands of jobs.
                </p>

            </aside>


            <section class="auth-form">

                <h1>
                    Welcome Back!
                </h1>

                <div class="sub">
                    Login to your account
                    and explore thousands of jobs.
                </div>


                <div class="form-group">

                    <label class="form-label">
                        Email
                    </label>

                    <input
                        id="loginEmail"
                        class="field"
                        type="email"
                        placeholder="you@example.com"
                    >

                </div>


                <div class="form-group">

                    <label class="form-label">
                        Password
                    </label>

                    <input
                        id="loginPassword"
                        class="field"
                        type="password"
                        placeholder="Your password"
                    >

                </div>


                <label class="check">

                    <input
                        id="remember"
                        type="checkbox"
                    >

                    Remember me

                </label>


                <div
                    id="loginMsg"
                    class="msg">
                </div>


                <button
                    class="btn btn-primary full"
                    onclick="doLogin()">

                    Login

                </button>


                <p
                    class="muted"
                    style="text-align:center">

                    Don't have an account?

                    <a
                        class="link"
                        href="#"
                        onclick="showRegister();return false">

                        Register

                    </a>

                </p>

            </section>

        </div>

    </main>

    `;

}


async function doLogin(){

    const msg =
        document.getElementById(
            "loginMsg"
        );

    msg.className = "msg";
    msg.textContent = "";

    try{

        const data =
            await api(
                "/api/login",
                {
                    method:"POST",
                    body:{
                        email:
                            document
                            .getElementById(
                                "loginEmail"
                            )
                            .value
                            .trim(),

                        password:
                            document
                            .getElementById(
                                "loginPassword"
                            )
                            .value
                    }
                }
            );

        me = data.user;

        showDashboard();

    }catch(error){

        msg.className =
            "msg error";

        msg.textContent =
            error.message;

    }

}


/* =====================================================
   REGISTER
===================================================== */

function showRegister(){

    app.innerHTML = `

    ${publicHeader()}

    <main class="auth-page">

        <div class="auth-card">

            <aside class="auth-side">

                <div class="big">
                    👩‍💼
                </div>

                <h2>
                    Join Job Mart
                </h2>

                <p>
                    Join thousands of job seekers
                    <br>
                    and employers today.
                </p>

            </aside>


            <section class="auth-form">

                <h1>
                    Create your Account
                </h1>

                <div class="sub">
                    Join thousands of job seekers
                    and employers today!
                </div>


                <div class="form-grid">

                    <div class="form-group">

                        <label class="form-label">
                            Full Name
                        </label>

                        <input
                            id="regName"
                            class="field"
                            placeholder="Your name"
                        >

                    </div>


                    <div class="form-group">

                        <label class="form-label">
                            Email
                        </label>

                        <input
                            id="regEmail"
                            class="field"
                            type="email"
                            placeholder="you@example.com"
                        >

                    </div>

                </div>


                <div class="form-grid">

                    <div class="form-group">

                        <label class="form-label">
                            Password
                        </label>

                        <input
                            id="regPassword"
                            class="field"
                            type="password"
                            placeholder="Minimum 6 characters"
                        >

                    </div>


                    <div class="form-group">

                        <label class="form-label">
                            Confirm Password
                        </label>

                        <input
                            id="regConfirm"
                            class="field"
                            type="password"
                            placeholder="Repeat password"
                        >

                    </div>

                </div>


                <div class="form-group">

                    <label class="form-label">
                        Account Type
                    </label>

                    <select
                        id="regRole"
                        class="select">

                        <option value="jobseeker">
                            Job Seeker
                        </option>

                        <option value="employer">
                            Employer / Recruiter
                        </option>

                    </select>

                </div>


                <div class="form-grid">

                    <div class="form-group">

                        <label class="form-label">
                            Phone
                        </label>

                        <input
                            id="regPhone"
                            class="field"
                            placeholder="Phone number"
                        >

                    </div>


                    <div class="form-group">

                        <label class="form-label">
                            Country
                        </label>

                        <input
                            id="regCountry"
                            class="field"
                            value="India"
                        >

                    </div>

                </div>


                <div class="form-group">

                    <label class="form-label">
                        City
                    </label>

                    <input
                        id="regCity"
                        class="field"
                        placeholder="City"
                    >

                </div>


                <label class="check">

                    <input
                        id="terms"
                        type="checkbox"
                    >

                    I agree to the Terms & Conditions

                </label>


                <div
                    id="regMsg"
                    class="msg">
                </div>


                <button
                    class="btn btn-primary full"
                    onclick="doRegister()">

                    Register

                </button>


                <p
                    class="muted"
                    style="text-align:center">

                    Already have an account?

                    <a
                        class="link"
                        href="#"
                        onclick="showLogin();return false">

                        Login

                    </a>

                </p>

            </section>

        </div>

    </main>

    `;

}


async function doRegister(){

    const msg =
        document.getElementById(
            "regMsg"
        );

    msg.className = "msg";
    msg.textContent = "";

    const password =
        document.getElementById(
            "regPassword"
        ).value;

    const confirm =
        document.getElementById(
            "regConfirm"
        ).value;

    if(password !== confirm){

        msg.className =
            "msg error";

        msg.textContent =
            "Passwords do not match";

        return;
    }

    if(password.length < 6){

        msg.className =
            "msg error";

        msg.textContent =
            "Password must be at least 6 characters";

        return;
    }

    if(
        !document.getElementById(
            "terms"
        ).checked
    ){

        msg.className =
            "msg error";

        msg.textContent =
            "Please accept the Terms & Conditions";

        return;
    }

    try{

        await api(
            "/api/register",
            {
                method:"POST",
                body:{
                    name:
                        document
                        .getElementById(
                            "regName"
                        )
                        .value
                        .trim(),

                    email:
                        document
                        .getElementById(
                            "regEmail"
                        )
                        .value
                        .trim(),

                    password,

                    role:
                        document
                        .getElementById(
                            "regRole"
                        )
                        .value,

                    phone:
                        document
                        .getElementById(
                            "regPhone"
                        )
                        .value
                        .trim(),

                    country:
                        document
                        .getElementById(
                            "regCountry"
                        )
                        .value
                        .trim(),

                    city:
                        document
                        .getElementById(
                            "regCity"
                        )
                        .value
                        .trim()
                }
            }
        );

        msg.className =
            "msg ok";

        msg.textContent =
            "Account created. Opening login...";

        setTimeout(
            showLogin,
            700
        );

    }catch(error){

        msg.className =
            "msg error";

        msg.textContent =
            error.message;

    }

}


/* =====================================================
   SIDEBAR
===================================================== */

function sidebar(){

    const employer =
        me &&
        (
            me.role === "employer" ||
            me.role === "admin"
        );

    return `

    <aside
        id="sidebar"
        class="sidebar">

        <div class="brand">

            <span class="brand-mark">
                JM
            </span>

            Job Mart

        </div>


        <div class="side-label">
            Menu
        </div>


        <button
            class="side-btn"
            data-page="dashboard"
            onclick="showDashboard()">

            ▦ Dashboard

        </button>


        <button
            class="side-btn"
            data-page="jobs"
            onclick="showJobs()">

            ▣ Jobs

        </button>


        ${
            employer
            ?
            `
            <button
                class="side-btn"
                data-page="post"
                onclick="showPostJob()">

                ＋ Post Job

            </button>
            `
            :
            ""
        }


        <button
            class="side-btn"
            data-page="saved"
            onclick="showSaved()">

            ♡ Saved Jobs

        </button>


        <button
            class="side-btn"
            data-page="applications"
            onclick="showApplications()">

            ▤ Applications

        </button>


        <button
            class="side-btn"
            data-page="notifications"
            onclick="showNotifications()">

            ♧ Notifications

        </button>


        <button
            class="side-btn"
            data-page="profile"
            onclick="showProfile()">

            ♙ Profile

        </button>


        <div class="side-spacer"></div>


        <button
            class="side-btn"
            onclick="doLogout()">

            ↪ Logout

        </button>

    </aside>

    `;

}


function shell(content,page){

    app.innerHTML = `

    <div class="shell">

        ${sidebar()}

        <div class="shell-main">

            <header class="topbar">

                <button
                    class="mobile-menu"
                    onclick="toggleSidebar()">

                    ☰

                </button>

                <div></div>

                <div class="user-mini">

                    <span>🔔</span>

                    <span>
                        ${esc(me.name)}
                    </span>

                    <div class="avatar">
                        ${esc(initials(me.name))}
                    </div>

                </div>

            </header>


            ${content}

        </div>

    </div>


    <nav class="mobile-bottom">

        <button
            data-page="dashboard"
            onclick="showDashboard()">

            ⌂
            <br>
            Home

        </button>


        <button
            data-page="jobs"
            onclick="showJobs()">

            ▣
            <br>
            Jobs

        </button>


        <button
            data-page="saved"
            onclick="showSaved()">

            ♡
            <br>
            Saved

        </button>


        <button
            data-page="applications"
            onclick="showApplications()">

            ▤
            <br>
            Applications

        </button>


        <button
            data-page="profile"
            onclick="showProfile()">

            ♙
            <br>
            Profile

        </button>

    </nav>

    `;

    setActive(page);

}


function setActive(page){

    document
        .querySelectorAll(
            ".side-btn,.mobile-bottom button"
        )
        .forEach(function(button){

            button.classList.toggle(
                "active",
                button.dataset.page === page
            );

        });

}


function toggleSidebar(){

    document
        .getElementById("sidebar")
        ?.classList.toggle("open");

}


function closeSidebar(){

    document
        .getElementById("sidebar")
        ?.classList.remove("open");

}


/* =====================================================
   DASHBOARD
===================================================== */

async function showDashboard(){

    if(!me){

        showLogin();
        return;

    }

    closeSidebar();

    let data;

    try{

        data =
            await api(
                "/api/dashboard"
            );

    }catch(error){

        showLogin();
        return;

    }

    const d =
        data.dashboard;

    const employer =
        me.role === "employer" ||
        me.role === "admin";


    const stats =
        employer
        ?
        `
        <div class="stats">

            <div class="stat">

                <div class="n">
                    ${d.applications}
                </div>

                <div class="l">
                    Applications
                </div>

            </div>


            <div class="stat">

                <div class="n">
                    ${d.active_jobs}
                </div>

                <div class="l">
                    Active Jobs
                </div>

            </div>


            <div class="stat">

                <div class="n">
                    ${d.notifications}
                </div>

                <div class="l">
                    Notifications
                </div>

            </div>

        </div>
        `
        :
        `
        <div class="stats">

            <div class="stat">

                <div class="n">
                    ${d.applications}
                </div>

                <div class="l">
                    Jobs you applied
                </div>

            </div>


            <div class="stat">

                <div class="n">
                    ${d.saved_jobs}
                </div>

                <div class="l">
                    Saved Jobs
                </div>

            </div>


            <div class="stat">

                <div class="n">
                    ${d.notifications}
                </div>

                <div class="l">
                    Notifications
                </div>

            </div>

        </div>
        `;


    shell(`

    <main class="page">

        <div class="page-title">

            <div>

                <h1>
                    Dashboard
                </h1>

                <p>
                    Welcome back,
                    ${esc(me.name)}
                </p>

            </div>


            ${
                employer
                ?
                `
                <button
                    class="btn btn-primary"
                    onclick="showPostJob()">

                    + Post New Job

                </button>
                `
                :
                `
                <button
                    class="btn btn-primary"
                    onclick="showJobs()">

                    Find Jobs

                </button>
                `
            }

        </div>


        ${stats}


        <div class="panel">

            <h3>
                ${
                    employer
                    ?
                    "Recent Applications"
                    :
                    "Recent Jobs"
                }
            </h3>

            <div id="dashboardList">

                <div class="empty">
                    Loading...
                </div>

            </div>

        </div>

    </main>

    `,"dashboard");


    if(employer){

        loadEmployerRecent();

    }else{

        loadSeekerRecent();

    }

}


async function loadSeekerRecent(){

    const box =
        document.getElementById(
            "dashboardList"
        );

    try{

        const data =
            await api(
                "/api/jobs"
            );

        const rows =
            (data.jobs || [])
            .slice(0,5);

        box.innerHTML =
            rows.length
            ?
            rows.map(jobCard).join("")
            :
            `
            <div class="empty">
                No jobs posted yet.
            </div>
            `;

    }catch(error){

        box.innerHTML =
            `<div class="empty">
                ${esc(error.message)}
            </div>`;

    }

}


async function loadEmployerRecent(){

    const box =
        document.getElementById(
            "dashboardList"
        );

    try{

        const data =
            await api(
                "/api/applications"
            );

        const rows =
            (data.applications || [])
            .slice(0,5);

        if(!rows.length){

            box.innerHTML =
                `
                <div class="empty">
                    No applications yet.
                </div>
                `;

            return;

        }

        box.innerHTML = `

        <div class="table-wrap">

            <table>

                <thead>

                    <tr>

                        <th>
                            Applicant
                        </th>

                        <th>
                            Job
                        </th>

                        <th>
                            Email
                        </th>

                        <th>
                            Status
                        </th>

                    </tr>

                </thead>


                <tbody>

                    ${
                        rows.map(function(a){

                            return `

                            <tr>

                                <td>
                                    <b>
                                        ${esc(a.applicant_name)}
                                    </b>
                                </td>

                                <td>
                                    ${esc(a.title)}
                                </td>

                                <td>
                                    ${esc(a.applicant_email)}
                                </td>

                                <td>
                                    <span class="status">
                                        ${esc(a.status)}
                                    </span>
                                </td>

                            </tr>

                            `;

                        }).join("")
                    }

                </tbody>

            </table>

        </div>

        `;

    }catch(error){

        box.innerHTML =
            `<div class="empty">
                ${esc(error.message)}
            </div>`;

    }

}


/* =====================================================
   JOBS
===================================================== */

async function showJobs(params={}){

    if(!me){

        showLogin();
        return;

    }

    closeSidebar();

    shell(`

    <main class="page">

        <div class="page-title">

            <div>

                <h1>
                    Jobs
                </h1>

                <p>
                    Find your next opportunity
                </p>

            </div>

        </div>


        <div class="panel">

            <div
                class="search-row"
                style="box-shadow:none">

                <input
                    id="jobsQ"
                    class="field"
                    placeholder="Search jobs..."
                    value="${esc(params.q || "")}"
                >


                <select
                    id="jobsCountry"
                    class="select">

                    <option value="">
                        All Countries
                    </option>

                    <option>India</option>
                    <option>USA</option>
                    <option>UAE</option>
                    <option>UK</option>
                    <option>Other</option>

                </select>


                <select
                    id="jobsType"
                    class="select">

                    <option value="">
                        All Types
                    </option>

                    <option>Full-time</option>
                    <option>Part-time</option>
                    <option>Contract</option>
                    <option>Freelance</option>

                </select>


                <button
                    class="btn btn-primary"
                    onclick="searchJobs()">

                    Search

                </button>

            </div>

        </div>


        <div
            id="jobsResults"
            class="job-grid">

        </div>

    </main>

    `,"jobs");


    if(params.country){

        document.getElementById(
            "jobsCountry"
        ).value = params.country;

    }

    if(params.job_type){

        document.getElementById(
            "jobsType"
        ).value = params.job_type;

    }

    await loadJobs(params);

}


async function searchJobs(){

    const params = {

        q:
            document
            .getElementById(
                "jobsQ"
            )
            .value
            .trim(),

        country:
            document
            .getElementById(
                "jobsCountry"
            )
            .value,

        job_type:
            document
            .getElementById(
                "jobsType"
            )
            .value

    };

    await loadJobs(params);

}


async function loadJobs(params={}){

    const box =
        document.getElementById(
            "jobsResults"
        );

    if(!box) return;

    box.innerHTML =
        `<div class="empty"
              style="grid-column:1/-1">
            Loading jobs...
        </div>`;

    try{

        const query =
            new URLSearchParams(params)
            .toString();

        const data =
            await api(
                "/api/jobs" +
                (
                    query
                    ?
                    "?" + query
                    :
                    ""
                )
            );

        jobsCache =
            data.jobs || [];

        box.innerHTML =
            jobsCache.length
            ?
            jobsCache
                .map(jobCard)
                .join("")
            :
            `
            <div
                class="empty"
                style="grid-column:1/-1">

                No jobs found.

            </div>
            `;

    }catch(error){

        box.innerHTML =
            `<div
                class="empty"
                style="grid-column:1/-1">

                ${esc(error.message)}

            </div>`;

    }

}


/* =====================================================
   JOB DETAILS
===================================================== */

async function showJob(id){

    if(!me){

        showLogin();
        return;

    }

    try{

        const data =
            await api(
                "/api/jobs/" + id
            );

        const job =
            data.job;

        shell(`

        <main class="page">

            <div style="margin-bottom:12px">

                <button
                    class="btn btn-outline btn-small"
                    onclick="showJobs()">

                    ← Back to Jobs

                </button>

            </div>


            <div class="detail-grid">

                <div class="detail-card">

                    <div class="job-head">

                        <div class="company-icon">
                            ▣
                        </div>

                        <div>

                            <h1>
                                ${esc(job.title)}
                            </h1>

                            <div class="company">
                                ${esc(job.company)}
                            </div>

                            <div class="tags">

                                <span class="tag">
                                    ${esc(job.country)}
                                </span>

                                <span class="tag">
                                    ${esc(job.job_type)}
                                </span>

                                <span class="tag">
                                    ${esc(job.work_mode)}
                                </span>

                            </div>

                        </div>

                    </div>


                    <h2>
                        Description
                    </h2>

                    <p>
                        ${esc(job.description)}
                    </p>


                    <h2>
                        Skills
                    </h2>

                    <p>
                        ${esc(job.skills || "Not specified")}
                    </p>


                    <h2>
                        Salary
                    </h2>

                    <p>
                        ${esc(job.salary || "Not specified")}
                    </p>


                    <h2>
                        Location
                    </h2>

                    <p>
                        ${esc(
                            job.location ||
                            job.country
                        )}
                    </p>

                </div>


                <div class="detail-card">

                    <h2 style="margin-top:0">
                        Actions
                    </h2>

                    <div class="action-stack">

                        ${
                            me.role === "jobseeker"
                            ?
                            `
                            <button
                                class="btn btn-primary"
                                onclick="applyJob(${job.id})"
                                ${
                                    job.applied
                                    ?
                                    "disabled"
                                    :
                                    ""
                                }>

                                ${
                                    job.applied
                                    ?
                                    "Already Applied"
                                    :
                                    "Apply Now"
                                }

                            </button>
                            `
                            :
                            ""
                        }


                        ${
                            me.role === "jobseeker"
                            ?
                            `
                            <button
                                class="btn btn-outline"
                                onclick="saveJob(${job.id})">

                                ${
                                    job.saved
                                    ?
                                    "♥ Remove Saved"
                                    :
                                    "♡ Save Job"
                                }

                            </button>
                            `
                            :
                            ""
                        }


                        ${
                            me.role === "employer" &&
                            job.employer_id === me.id
                            ?
                            `
                            <button
                                class="btn btn-danger"
                                onclick="closeJob(${job.id})">

                                Close Job

                            </button>
                            `
                            :
                            ""
                        }

                    </div>

                </div>

            </div>

        </main>

        `,"jobs");

    }catch(error){

        alert(error.message);
        showJobs();

    }

}


async function applyJob(id){

    const cover =
        prompt(
            "Optional cover letter:"
        );

    if(cover === null)
        return;

    try{

        await api(
            "/api/jobs/" + id + "/apply",
            {
                method:"POST",
                body:{
                    cover_letter:cover
                }
            }
        );

        alert(
            "Application submitted successfully!"
        );

        showJob(id);

    }catch(error){

        alert(error.message);

    }

}


async function saveJob(id){

    try{

        const data =
            await api(
                "/api/jobs/" +
                id +
                "/save",
                {
                    method:"POST"
                }
            );

        alert(data.message);

        showJob(id);

    }catch(error){

        alert(error.message);

    }

}


async function closeJob(id){

    if(
        !confirm(
            "Close this job?"
        )
    ){
        return;
    }

    try{

        await api(
            "/api/jobs/" + id,
            {
                method:"DELETE"
            }
        );

        alert(
            "Job closed successfully."
        );

        showJobs();

    }catch(error){

        alert(error.message);

    }

}


/* =====================================================
   SAVED JOBS
===================================================== */

async function showSaved(){

    if(!me){

        showLogin();
        return;

    }

    closeSidebar();

    shell(`

    <main class="page">

        <div class="page-title">

            <div>

                <h1>
                    Saved Jobs
                </h1>

                <p>
                    Jobs you saved
                </p>

            </div>

        </div>


        <div
            id="savedResults"
            class="job-grid">

        </div>

    </main>

    `,"saved");


    const box =
        document.getElementById(
            "savedResults"
        );

    try{

        const data =
            await api(
                "/api/saved-jobs"
            );

        const rows =
            data.jobs || [];

        box.innerHTML =
            rows.length
            ?
            rows.map(jobCard).join("")
            :
            `
            <div
                class="empty"
                style="grid-column:1/-1">

                No saved jobs yet.

            </div>
            `;

    }catch(error){

        box.innerHTML =
            `<div
                class="empty"
                style="grid-column:1/-1">

                ${esc(error.message)}

            </div>`;

    }

}


/* =====================================================
   APPLICATIONS
===================================================== */

async function showApplications(){

    if(!me){

        showLogin();
        return;

    }

    closeSidebar();

    const employer =
        me.role === "employer" ||
        me.role === "admin";

    shell(`

    <main class="page">

        <div class="page-title">

            <div>

                <h1>
                    Applications
                </h1>

                <p>
                    ${
                        employer
                        ?
                        "Applications received"
                        :
                        "Jobs you applied for"
                    }
                </p>

            </div>

        </div>


        <div
            id="applicationsResults">

        </div>

    </main>

    `,"applications");


    const box =
        document.getElementById(
            "applicationsResults"
        );

    try{

        const data =
            await api(
                "/api/applications"
            );

        const rows =
            data.applications || [];

        if(!rows.length){

            box.innerHTML =
                `
                <div class="empty">
                    No applications yet.
                </div>
                `;

            return;

        }


        if(!employer){

            box.innerHTML = `

            <div class="panel">

                <div class="table-wrap">

                    <table>

                        <thead>

                            <tr>

                                <th>
                                    Job
                                </th>

                                <th>
                                    Company
                                </th>

                                <th>
                                    Location
                                </th>

                                <th>
                                    Applied
                                </th>

                                <th>
                                    Status
                                </th>

                            </tr>

                        </thead>


                        <tbody>

                            ${
                                rows.map(function(a){

                                    return `

                                    <tr>

                                        <td>
                                            <b>
                                                ${esc(a.title)}
                                            </b>
                                        </td>

                                        <td>
                                            ${esc(a.company)}
                                        </td>

                                        <td>
                                            ${esc(
                                                a.location ||
                                                a.country
                                            )}
                                        </td>

                                        <td>
                                            ${fmtDate(
                                                a.created_at
                                            )}
                                        </td>

                                        <td>
                                            <span class="status">
                                                ${esc(a.status)}
                                            </span>
                                        </td>

                                    </tr>

                                    `;

                                }).join("")
                            }

                        </tbody>

                    </table>

                </div>

            </div>

            `;

        }else{

            box.innerHTML = `

            <div class="panel">

                <div class="table-wrap">

                    <table>

                        <thead>

                            <tr>

                                <th>
                                    Applicant
                                </th>

                                <th>
                                    Job
                                </th>

                                <th>
                                    Email
                                </th>

                                <th>
                                    Phone
                                </th>

                                <th>
                                    Date
                                </th>

                                <th>
                                    Status
                                </th>

                            </tr>

                        </thead>


                        <tbody>

                            ${
                                rows.map(function(a){

                                    return `

                                    <tr>

                                        <td>
                                            <b>
                                                ${esc(
                                                    a.applicant_name
                                                )}
                                            </b>
                                        </td>

                                        <td>
                                            ${esc(a.title)}
                                        </td>

                                        <td>
                                            ${esc(
                                                a.applicant_email
                                            )}
                                        </td>

                                        <td>
                                            ${esc(
                                                a.applicant_phone ||
                                                "-"
                                            )}
                                        </td>

                                        <td>
                                            ${fmtDate(
                                                a.created_at
                                            )}
                                        </td>

                                        <td>

                                            <select
                                                class="select"
                                                style="width:auto"
                                                onchange="
                                                changeStatus(
                                                    ${a.id},
                                                    this.value
                                                )">

                                                ${
                                                    [
                                                        "applied",
                                                        "viewed",
                                                        "shortlisted",
                                                        "rejected",
                                                        "selected"
                                                    ].map(function(s){

                                                        return `
                                                        <option
                                                            value="${s}"
                                                            ${
                                                                a.status === s
                                                                ?
                                                                "selected"
                                                                :
                                                                ""
                                                            }>

                                                            ${s}

                                                        </option>
                                                        `;

                                                    }).join("")
                                                }

                                            </select>

                                        </td>

                                    </tr>

                                    `;

                                }).join("")
                            }

                        </tbody>

                    </table>

                </div>

            </div>

            `;

        }

    }catch(error){

        box.innerHTML =
            `<div class="empty">
                ${esc(error.message)}
            </div>`;

    }

}


async function changeStatus(
    id,
    status
){

    try{

        await api(
            "/api/applications/" +
            id +
            "/status",
            {
                method:"PUT",
                body:{
                    status
                }
            }
        );

        alert(
            "Application status updated."
        );

        showApplications();

    }catch(error){

        alert(error.message);

    }

}


/* =====================================================
   NOTIFICATIONS
===================================================== */

async function showNotifications(){

    if(!me){

        showLogin();
        return;

    }

    closeSidebar();

    shell(`

    <main class="page">

        <div class="page-title">

            <div>

                <h1>
                    Notifications
                </h1>

                <p>
                    Your latest updates
                </p>

            </div>


            <button
                class="btn btn-outline btn-small"
                onclick="markNotificationsRead()">

                Mark all as read

            </button>

        </div>


        <div
            id="notificationResults">

        </div>

    </main>

    `,"notifications");


    const box =
        document.getElementById(
            "notificationResults"
        );

    try{

        const data =
            await api(
                "/api/notifications"
            );

        const rows =
            data.notifications || [];

        box.innerHTML =
            rows.length
            ?
            rows.map(function(n){

                return `

                <div
                    class="panel"
                    style="${
                        n.is_read
                        ?
                        ""
                        :
                        "border-left:3px solid var(--blue)"
                    }">

                    <div
                        style="
                        display:flex;
                        gap:12px">

                        <div class="company-icon">
                            ♧
                        </div>

                        <div>

                            <b>
                                ${esc(n.title)}
                            </b>

                            <div
                                class="muted"
                                style="margin-top:5px">

                                ${esc(n.message)}

                            </div>

                            <div
                                class="muted"
                                style="margin-top:7px">

                                ${fmtDate(
                                    n.created_at
                                )}

                            </div>

                        </div>

                    </div>

                </div>

                `;

            }).join("")
            :
            `
            <div class="empty">
                No notifications yet.
            </div>
            `;

    }catch(error){

        box.innerHTML =
            `<div class="empty">
                ${esc(error.message)}
            </div>`;

    }

}


async function markNotificationsRead(){

    try{

        await api(
            "/api/notifications/read",
            {
                method:"POST"
            }
        );

        showNotifications();

    }catch(error){

        alert(error.message);

    }

}


/* =====================================================
   POST JOB
===================================================== */

function showPostJob(){

    if(
        !me ||
        ![
            "employer",
            "admin"
        ].includes(me.role)
    ){

        showLogin();
        return;

    }

    closeSidebar();

    shell(`

    <main class="page">

        <div class="page-title">

            <div>

                <h1>
                    Post a New Job
                </h1>

                <p>
                    Reach candidates looking
                    for their next opportunity
                </p>

            </div>

        </div>


        <div class="panel form-panel">

            <div
                id="postMsg"
                class="msg">
            </div>


            <div class="form-row">

                <div class="form-field">

                    <label>
                        Job Title *
                    </label>

                    <input
                        id="jTitle"
                        class="field"
                        placeholder="Backend Developer"
                    >

                </div>


                <div class="form-field">

                    <label>
                        Company *
                    </label>

                    <input
                        id="jCompany"
                        class="field"
                        value="${esc(me.name)}"
                    >

                </div>

            </div>


            <div class="form-row">

                <div class="form-field">

                    <label>
                        Category *
                    </label>

                    <select
                        id="jCategory"
                        class="select">

                        <option>
                            IT & Software
                        </option>

                        <option>
                            Design
                        </option>

                        <option>
                            Marketing
                        </option>

                        <option>
                            Sales
                        </option>

                        <option>
                            Finance
                        </option>

                        <option>
                            HR
                        </option>

                        <option>
                            Engineering
                        </option>

                        <option>
                            Customer Support
                        </option>

                    </select>

                </div>


                <div class="form-field">

                    <label>
                        Country *
                    </label>

                    <select
                        id="jCountry"
                        class="select">

                        <option>
                            India
                        </option>

                        <option>
                            USA
                        </option>

                        <option>
                            UAE
                        </option>

                        <option>
                            UK
                        </option>

                        <option>
                            Other
                        </option>

                    </select>

                </div>

            </div>


            <div class="form-row">

                <div class="form-field">

                    <label>
                        Job Type *
                    </label>

                    <select
                        id="jType"
                        class="select">

                        <option>
                            Full-time
                        </option>

                        <option>
                            Part-time
                        </option>

                        <option>
                            Contract
                        </option>

                        <option>
                            Freelance
                        </option>

                    </select>

                </div>


                <div class="form-field">

                    <label>
                        Work Mode *
                    </label>

                    <select
                        id="jMode"
                        class="select">

                        <option>
                            Remote
                        </option>

                        <option>
                            Onsite
                        </option>

                        <option>
                            Hybrid
                        </option>

                    </select>

                </div>

            </div>


            <div class="form-row">

                <div class="form-field">

                    <label>
                        Location
                    </label>

                    <input
                        id="jLocation"
                        class="field"
                        placeholder="Hyderabad"
                    >

                </div>


                <div class="form-field">

                    <label>
                        Salary
                    </label>

                    <input
                        id="jSalary"
                        class="field"
                        placeholder="₹5,00,000 - ₹8,00,000 / year"
                    >

                </div>

            </div>


            <div class="form-field">

                <label>
                    Skills
                </label>

                <input
                    id="jSkills"
                    class="field"
                    placeholder="Python, FastAPI, SQL, PostgreSQL"
                >

            </div>


            <div class="form-field">

                <label>
                    Application Email
                </label>

                <input
                    id="jEmail"
                    class="field"
                    type="email"
                    placeholder="hr@company.com"
                >

            </div>


            <div class="form-field">

                <label>
                    Description *
                </label>

                <textarea
                    id="jDescription"
                    placeholder="
                    Describe the role,
                    responsibilities and requirements...
                    "></textarea>

            </div>


            <button
                class="btn btn-primary full"
                onclick="postJob()">

                Post Job

            </button>

        </div>

    </main>

    `,"post");

}


async function postJob(){

    const msg =
        document.getElementById(
            "postMsg"
        );

    msg.className = "msg";
    msg.textContent = "";

    try{

        await api(
            "/api/jobs",
            {
                method:"POST",
                body:{

                    title:
                        document
                        .getElementById(
                            "jTitle"
                        )
                        .value
                        .trim(),

                    company:
                        document
                        .getElementById(
                            "jCompany"
                        )
                        .value
                        .trim(),

                    category:
                        document
                        .getElementById(
                            "jCategory"
                        )
                        .value,

                    country:
                        document
                        .getElementById(
                            "jCountry"
                        )
                        .value,

                    location:
                        document
                        .getElementById(
                            "jLocation"
                        )
                        .value
                        .trim(),

                    job_type:
                        document
                        .getElementById(
                            "jType"
                        )
                        .value,

                    work_mode:
                        document
                        .getElementById(
                            "jMode"
                        )
                        .value,

                    salary:
                        document
                        .getElementById(
                            "jSalary"
                        )
                        .value
                        .trim(),

                    skills:
                        document
                        .getElementById(
                            "jSkills"
                        )
                        .value
                        .trim(),

                    application_email:
                        document
                        .getElementById(
                            "jEmail"
                        )
                        .value
                        .trim(),

                    description:
                        document
                        .getElementById(
                            "jDescription"
                        )
                        .value
                        .trim()

                }
            }
        );

        msg.className =
            "msg ok";

        msg.textContent =
            "Job posted successfully!";

        setTimeout(
            showJobs,
            700
        );

    }catch(error){

        msg.className =
            "msg error";

        msg.textContent =
            error.message;

    }

}


/* =====================================================
   PROFILE
===================================================== */

async function showProfile(){

    if(!me){

        showLogin();
        return;

    }

    closeSidebar();

    shell(`

    <main class="page">

        <div class="page-title">

            <div>

                <h1>
                    Profile
                </h1>

                <p>
                    Manage your Job Mart profile
                </p>

            </div>

        </div>


        <div class="profile-grid">

            <div class="panel profile-box">

                <div class="profile-avatar">

                    ${esc(initials(me.name))}

                </div>

                <h3>
                    ${esc(me.name)}
                </h3>

                <div class="muted">

                    ${
                        me.role === "employer"
                        ?
                        "Employer / Recruiter"
                        :
                        "Job Seeker"
                    }

                </div>

                <div
                    class="muted"
                    style="margin-top:8px">

                    ${esc(me.email)}

                </div>

            </div>


            <div class="panel">

                <div
                    id="profileMsg"
                    class="msg">
                </div>


                <div class="form-row">

                    <div class="form-field">

                        <label>
                            Full Name
                        </label>

                        <input
                            id="pName"
                            class="field"
                            value="${esc(me.name)}"
                        >

                    </div>


                    <div class="form-field">

                        <label>
                            Country
                        </label>

                        <input
                            id="pCountry"
                            class="field"
                            value="${esc(me.country)}"
                        >

                    </div>

                </div>


                <div class="form-row">

                    <div class="form-field">

                        <label>
                            Email
                        </label>

                        <input
                            class="field"
                            value="${esc(me.email)}"
                            disabled
                        >

                    </div>


                    <div class="form-field">

                        <label>
                            City
                        </label>

                        <input
                            id="pCity"
                            class="field"
                            value="${esc(me.city)}"
                        >

                    </div>

                </div>


                <div class="form-row">

                    <div class="form-field">

                        <label>
                            Phone
                        </label>

                        <input
                            id="pPhone"
                            class="field"
                            value="${esc(me.phone)}"
                        >

                    </div>


                    <div class="form-field">

                        <label>
                            Account Type
                        </label>

                        <input
                            class="field"
                            value="${esc(me.role)}"
                            disabled
                        >

                    </div>

                </div>


                <div class="form-field">

                    <label>
                        Bio
                    </label>

                    <textarea id="pBio">${esc(me.bio)}</textarea>

                </div>


                <button
                    class="btn btn-primary"
                    onclick="updateProfile()">

                    Update Profile

                </button>

            </div>

        </div>

    </main>

    `,"profile");

}


async function updateProfile(){

    const msg =
        document.getElementById(
            "profileMsg"
        );

    try{

        await api(
            "/api/profile",
            {
                method:"PUT",
                body:{

                    name:
                        document
                        .getElementById(
                            "pName"
                        )
                        .value
                        .trim(),

                    phone:
                        document
                        .getElementById(
                            "pPhone"
                        )
                        .value
                        .trim(),

                    country:
                        document
                        .getElementById(
                            "pCountry"
                        )
                        .value
                        .trim(),

                    city:
                        document
                        .getElementById(
                            "pCity"
                        )
                        .value
                        .trim(),

                    bio:
                        document
                        .getElementById(
                            "pBio"
                        )
                        .value
                        .trim()

                }
            }
        );

        await loadMe();

        msg.className =
            "msg ok";

        msg.textContent =
            "Profile updated successfully.";

        setTimeout(
            showProfile,
            500
        );

    }catch(error){

        msg.className =
            "msg error";

        msg.textContent =
            error.message;

    }

}


/* =====================================================
   LOGOUT
===================================================== */

async function doLogout(){

    try{

        await api(
            "/api/logout",
            {
                method:"POST"
            }
        );

    }catch(error){}

    me = null;

    renderPublicHome();

}


/* =====================================================
   LOAD USER
===================================================== */

async function loadMe(){

    try{

        const data =
            await api(
                "/api/me"
            );

        me =
            data.logged_in
            ?
            data.user
            :
            null;

    }catch(error){

        me = null;

    }

}


/* =====================================================
   START
===================================================== */

async function start(){

    await loadMe();

    if(me){

        showDashboard();

    }else{

        renderPublicHome();

    }

}


start();

</script>

</body>
</html>
"""


# =========================================================
# HTML ROUTES
# =========================================================

@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(HTML)


@app.get("/health")
def health():
    return {
        "ok": True,
        "service": "Job Mart",
        "version": "2.0"
    }
