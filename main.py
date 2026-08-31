from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from pathlib import Path
from typing import Optional
import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone

# =========================================================
# APP
# =========================================================

app = FastAPI(title="Job Mart")

DB_FILE = Path("job_mart.db")

# In-memory sessions
SESSIONS = {}


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
        is_read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,

        FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    );
    """)

    conn.commit()
    conn.close()


init_db()


# =========================================================
# PASSWORD
# =========================================================

def hash_password(password: str):
    salt = secrets.token_hex(16)

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000
    ).hex()

    return f"{salt}${key}"


def verify_password(password: str, stored: str):
    try:
        salt, key = stored.split("$", 1)

        check = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            120000
        ).hex()

        return secrets.compare_digest(check, key)

    except Exception:
        return False


# =========================================================
# AUTH
# =========================================================

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


class ApplicationStatusData(BaseModel):
    status: str


# =========================================================
# REGISTER
# =========================================================

@app.post("/api/register")
def register(data: RegisterData):

    role = data.role.lower().strip()

    if role not in ("jobseeker", "employer"):
        role = "jobseeker"

    email = data.email.strip().lower()

    if not email or "@" not in email:
        raise HTTPException(
            status_code=400,
            detail="Please enter a valid email"
        )

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
        (
            name,
            email,
            password,
            role,
            phone,
            country,
            city,
            created_at
        )
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


# =========================================================
# LOGIN
# =========================================================

@app.post("/api/login")
def login(data: LoginData):

    email = data.email.strip().lower()

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

    return response


# =========================================================
# LOGIN COOKIE FIX
# =========================================================

@app.post("/api/login-cookie")
def login_cookie(data: LoginData):

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

    from fastapi.responses import JSONResponse

    response = JSONResponse({
        "ok": True,
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    })

    response.set_cookie(
        key="jobmart_session",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 24 * 30,
        path="/"
    )

    return response


# =========================================================
# LOGOUT
# =========================================================

@app.post("/api/logout")
def logout(request: Request):

    token = request.cookies.get("jobmart_session")

    if token:
        SESSIONS.pop(token, None)

    from fastapi.responses import JSONResponse

    response = JSONResponse({
        "ok": True,
        "message": "Logged out"
    })

    response.delete_cookie(
        "jobmart_session",
        path="/"
    )

    return response


# =========================================================
# CURRENT USER
# =========================================================

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

    conn.execute(
        """
        UPDATE users
        SET
            name=?,
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
# CREATE JOB
# =========================================================

@app.post("/api/jobs")
def create_job(
    data: JobData,
    request: Request
):

    user = require_employer(request)

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
            data.application_email.strip(),
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


# =========================================================
# JOB LIST
# =========================================================

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
        JOIN users u
        ON u.id=j.employer_id
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

    user = current_user(request)

    if mine:

        if not user:
            conn.close()

            raise HTTPException(
                status_code=401,
                detail="Login required"
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


# =========================================================
# SINGLE JOB
# =========================================================

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


# =========================================================
# CLOSE JOB
# =========================================================

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
# APPLY
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

    already = conn.execute(
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

    if already:
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
            f"{user['name']} applied for {job['title']}",
            now()
        )
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Application submitted"
    }


# =========================================================
# APPLICATIONS
# =========================================================

@app.get("/api/applications")
def applications(request: Request):

    user = require_user(request)

    conn = db()

    if user["role"] in ("employer", "admin"):

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
                u.phone AS applicant_phone,
                u.city AS applicant_city
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
                j.job_type,
                j.work_mode
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


# =========================================================
# APPLICATION STATUS
# =========================================================

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

    status = data.status.strip().lower()

    if status not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Invalid application status"
        )

    conn = db()

    application = conn.execute(
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

    if not application:
        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Application not found"
        )

    if (
        application["employer_id"] != user["id"]
        and user["role"] != "admin"
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
            application["applicant_id"],
            "Application status updated",
            f"Your application for {application['title']} is now {status}.",
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
# SAVE / UNSAVE JOB
# =========================================================

@app.post("/api/jobs/{job_id}/save")
def save_job(
    job_id: int,
    request: Request
):

    user = require_user(request)

    conn = db()

    job = conn.execute(
        """
        SELECT id
        FROM jobs
        WHERE id=?
        """,
        (job_id,)
    ).fetchone()

    if not job:
        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Job not found"
        )

    saved = conn.execute(
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

    if saved:

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

        message = "Job saved"

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": message
    }


# =========================================================
# SAVED JOBS
# =========================================================

@app.get("/api/saved-jobs")
def saved_jobs(request: Request):

    user = require_user(request)

    conn = db()

    rows = conn.execute(
        """
        SELECT
            j.*,
            s.created_at AS saved_at
        FROM saved_jobs s
        JOIN jobs j
        ON j.id=s.job_id
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
def notifications(request: Request):

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
def notifications_read(request: Request):

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
def dashboard(request: Request):

    user = require_user(request)

    conn = db()

    if user["role"] in ("employer", "admin"):

        jobs_count = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM jobs
            WHERE employer_id=?
            """,
            (user["id"],)
        ).fetchone()["c"]

        active_jobs = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM jobs
            WHERE employer_id=?
            AND status='active'
            """,
            (user["id"],)
        ).fetchone()["c"]

        applications_count = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM applications a
            JOIN jobs j
            ON j.id=a.job_id
            WHERE j.employer_id=?
            """,
            (user["id"],)
        ).fetchone()["c"]

        hired_count = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM applications a
            JOIN jobs j
            ON j.id=a.job_id
            WHERE j.employer_id=?
            AND a.status='hired'
            """,
            (user["id"],)
        ).fetchone()["c"]

        result = {
            "role": "employer",
            "jobs_posted": jobs_count,
            "active_jobs": active_jobs,
            "applications": applications_count,
            "hired": hired_count
        }

    else:

        applied = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM applications
            WHERE applicant_id=?
            """,
            (user["id"],)
        ).fetchone()["c"]

        saved = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM saved_jobs
            WHERE user_id=?
            """,
            (user["id"],)
        ).fetchone()["c"]

        hired = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM applications
            WHERE applicant_id=?
            AND status='hired'
            """,
            (user["id"],)
        ).fetchone()["c"]

        result = {
            "role": "jobseeker",
            "applications": applied,
            "saved_jobs": saved,
            "hired": hired
        }

    conn.close()

    return {
        "ok": True,
        "dashboard": result
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
    content="width=device-width, initial-scale=1.0"
>

<title>Job Mart</title>

<style>

*{
    box-sizing:border-box;
}

:root{
    --blue:#1264e8;
    --blue-dark:#073b88;
    --blue-light:#eef5ff;
    --navy:#092c5c;
    --text:#172033;
    --muted:#667085;
    --border:#dfe5ec;
    --bg:#f5f8fc;
    --white:#ffffff;
    --green:#16a34a;
    --red:#dc2626;
}

body{
    margin:0;
    font-family:
        Arial,
        Helvetica,
        sans-serif;
    background:var(--bg);
    color:var(--text);
}

button,
input,
select,
textarea{
    font-family:inherit;
}

button{
    cursor:pointer;
}

.hidden{
    display:none !important;
}

/* HEADER */

.header{
    position:sticky;
    top:0;
    z-index:1000;
    background:var(--white);
    border-bottom:1px solid var(--border);
}

.header-inner{
    max-width:1200px;
    margin:auto;
    min-height:70px;
    padding:0 20px;

    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:20px;
}

.brand{
    display:flex;
    align-items:center;
    gap:10px;
    font-size:23px;
    font-weight:800;
    color:var(--blue-dark);
}

.brand-icon{
    width:42px;
    height:42px;
    border-radius:12px;
    background:var(--blue);
    color:white;

    display:flex;
    align-items:center;
    justify-content:center;

    font-size:22px;
}

.header-right{
    display:flex;
    align-items:center;
    gap:10px;
}

.user-pill{
    display:flex;
    align-items:center;
    gap:8px;

    background:var(--blue-light);
    color:var(--blue-dark);

    border-radius:30px;
    padding:7px 12px;

    font-size:14px;
    font-weight:700;
}

.avatar{
    width:32px;
    height:32px;
    border-radius:50%;
    background:var(--blue);
    color:white;

    display:flex;
    align-items:center;
    justify-content:center;

    font-weight:bold;
}

/* NAV */

.nav{
    background:var(--navy);
}

.nav-inner{
    max-width:1200px;
    margin:auto;
    padding:8px 20px;

    display:flex;
    gap:6px;

    overflow-x:auto;
}

.nav button{
    border:0;
    background:transparent;
    color:#dce9ff;

    padding:10px 13px;
    border-radius:8px;

    white-space:nowrap;
    font-size:14px;
    font-weight:600;
}

.nav button:hover{
    background:#124a91;
    color:white;
}

.nav button.active{
    background:var(--blue);
    color:white;
}

/* CONTAINER */

.container{
    max-width:1200px;
    margin:auto;
    padding:24px 20px 50px;
}

.page{
    animation:fade .15s ease;
}

@keyframes fade{
    from{
        opacity:.3;
        transform:translateY(4px);
    }

    to{
        opacity:1;
        transform:translateY(0);
    }
}

/* HOME */

.hero{
    background:
        linear-gradient(
            120deg,
            #073b88,
            #1264e8
        );

    color:white;

    border-radius:22px;
    padding:40px;

    margin-bottom:22px;

    position:relative;
    overflow:hidden;
}

.hero:after{
    content:"";
    position:absolute;
    width:280px;
    height:280px;
    border-radius:50%;
    background:rgba(255,255,255,.08);
    right:-80px;
    top:-80px;
}

.hero h1{
    margin:0 0 10px;
    font-size:38px;
    max-width:650px;
}

.hero p{
    margin:0 0 25px;
    color:#dbeaff;
    font-size:17px;
}

.search-box{
    background:white;
    border-radius:14px;
    padding:10px;

    display:grid;
    grid-template-columns:
        2fr
        1fr
        1fr
        auto;

    gap:9px;

    position:relative;
    z-index:2;
}

.search-box input,
.search-box select{
    border:1px solid var(--border);
}

/* BUTTONS */

.btn{
    border:0;
    border-radius:9px;
    padding:11px 16px;
    font-size:14px;
    font-weight:700;
}

.btn-primary{
    background:var(--blue);
    color:white;
}

.btn-primary:hover{
    background:#0955cc;
}

.btn-light{
    background:white;
    color:var(--blue);
    border:1px solid #bdd2f3;
}

.btn-danger{
    background:#fff0f0;
    color:var(--red);
}

.btn-success{
    background:var(--green);
    color:white;
}

.btn-block{
    width:100%;
}

/* INPUTS */

input,
select,
textarea{
    width:100%;
    padding:12px 13px;

    border:1px solid #cfd7e2;
    border-radius:9px;

    background:white;
    color:var(--text);

    outline:none;
}

input:focus,
select:focus,
textarea:focus{
    border-color:var(--blue);
    box-shadow:0 0 0 3px rgba(18,100,232,.1);
}

textarea{
    min-height:120px;
    resize:vertical;
}

/* SECTION */

.section-title{
    display:flex;
    justify-content:space-between;
    align-items:center;

    margin:24px 0 13px;
}

.section-title h2{
    margin:0;
    font-size:22px;
}

/* CATEGORY */

.categories{
    display:flex;
    gap:10px;
    overflow-x:auto;
    padding-bottom:4px;
}

.category{
    min-width:110px;
    background:white;
    border:1px solid var(--border);
    border-radius:12px;

    padding:15px;

    text-align:center;
    font-weight:700;
    color:var(--navy);
}

.category:hover{
    border-color:var(--blue);
    color:var(--blue);
}

/* CARDS */

.grid{
    display:grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(280px,1fr)
        );

    gap:16px;
}

.card{
    background:white;
    border:1px solid var(--border);
    border-radius:15px;
    padding:18px;

    box-shadow:
        0 3px 12px rgba(15,45,80,.05);
}

.job-card{
    transition:.15s;
}

.job-card:hover{
    transform:translateY(-2px);
    box-shadow:
        0 8px 25px rgba(15,45,80,.1);
}

.job-title{
    margin:0;
    color:var(--blue-dark);
    font-size:18px;
}

.company{
    color:#334155;
    margin-top:6px;
    font-weight:600;
}

.meta{
    color:var(--muted);
    font-size:14px;
    line-height:1.8;
}

.badges{
    display:flex;
    flex-wrap:wrap;
    gap:6px;
    margin:10px 0;
}

.badge{
    background:var(--blue-light);
    color:var(--blue-dark);

    padding:5px 8px;
    border-radius:20px;

    font-size:12px;
    font-weight:700;
}

.job-actions{
    display:flex;
    gap:8px;
    margin-top:15px;
}

.job-actions .btn{
    flex:1;
}

/* FORMS */

.form-card{
    max-width:760px;
    margin:auto;

    background:white;
    border:1px solid var(--border);
    border-radius:18px;
    padding:25px;
}

.form-card h2{
    margin-top:0;
}

.form-grid{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:14px;
}

.form-group{
    margin-bottom:14px;
}

.form-group label{
    display:block;
    font-weight:700;
    font-size:14px;
    margin-bottom:6px;
}

.full{
    grid-column:1 / -1;
}

/* AUTH */

.auth-layout{
    max-width:950px;
    margin:20px auto;

    display:grid;
    grid-template-columns:1fr 1fr;

    background:white;
    border-radius:20px;
    overflow:hidden;

    border:1px solid var(--border);
}

.auth-side{
    background:
        linear-gradient(
            145deg,
            #073b88,
            #1264e8
        );

    color:white;
    padding:40px;

    display:flex;
    flex-direction:column;
    justify-content:center;
}

.auth-side h2{
    font-size:32px;
    margin-top:0;
}

.auth-side p{
    color:#d9e9ff;
    line-height:1.7;
}

.auth-form{
    padding:35px;
}

.auth-form h2{
    margin-top:0;
}

/* DASHBOARD */

.dashboard-grid{
    display:grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(190px,1fr)
        );

    gap:15px;
}

.stat{
    background:white;
    border:1px solid var(--border);
    border-radius:15px;
    padding:20px;
}

.stat-label{
    color:var(--muted);
    font-size:14px;
}

.stat-number{
    font-size:30px;
    font-weight:800;
    color:var(--blue);
    margin-top:8px;
}

/* DETAILS */

.detail-layout{
    display:grid;
    grid-template-columns:2fr 1fr;
    gap:18px;
}

.detail-card{
    background:white;
    border:1px solid var(--border);
    border-radius:18px;
    padding:25px;
}

.detail-card h1{
    margin-top:0;
    color:var(--blue-dark);
}

.action-card{
    height:max-content;
    position:sticky;
    top:145px;
}

/* TABLE */

.table-wrap{
    overflow-x:auto;
}

table{
    width:100%;
    border-collapse:collapse;
    background:white;
}

th,
td{
    text-align:left;
    padding:12px;
    border-bottom:1px solid var(--border);
    font-size:14px;
}

th{
    background:#f5f8fc;
    color:var(--navy);
}

/* STATUS */

.status{
    display:inline-block;
    border-radius:20px;
    padding:5px 9px;
    font-size:12px;
    font-weight:700;
}

.status-applied{
    background:#eaf2ff;
    color:#1264e8;
}

.status-reviewing{
    background:#fff7df;
    color:#a16207;
}

.status-shortlisted{
    background:#e9f8ee;
    color:#15803d;
}

.status-rejected{
    background:#fff0f0;
    color:#dc2626;
}

.status-hired{
    background:#dcfce7;
    color:#166534;
}

/* NOTIFICATION */

.notification{
    background:white;
    border:1px solid var(--border);
    border-radius:14px;
    padding:16px;
    margin-bottom:10px;
}

.notification.unread{
    border-left:4px solid var(--blue);
    background:#f7fbff;
}

/* EMPTY */

.empty{
    background:white;
    border:1px dashed #cbd5e1;
    border-radius:15px;
    padding:40px;
    text-align:center;
    color:var(--muted);
}

/* TOAST */

.toast{
    position:fixed;
    right:20px;
    bottom:20px;

    background:#12233f;
    color:white;

    padding:13px 18px;
    border-radius:10px;

    z-index:9999;

    display:none;
    max-width:320px;
}

.toast.show{
    display:block;
}

/* MOBILE */

@media(max-width:800px){

    .hero{
        padding:25px;
    }

    .hero h1{
        font-size:29px;
    }

    .search-box{
        grid-template-columns:1fr;
    }

    .auth-layout{
        grid-template-columns:1fr;
    }

    .auth-side{
        display:none;
    }

    .form-grid{
        grid-template-columns:1fr;
    }

    .full{
        grid-column:auto;
    }

    .detail-layout{
        grid-template-columns:1fr;
    }

    .action-card{
        position:static;
    }

    .header-inner{
        padding:10px 15px;
    }

    .container{
        padding:18px 14px 40px;
    }

    .brand{
        font-size:20px;
    }

    .brand-icon{
        width:36px;
        height:36px;
    }

}

</style>

</head>

<body>

<!-- HEADER -->

<header class="header">

<div class="header-inner">

<div
    class="brand"
    onclick="showPage('home')"
    style="cursor:pointer"
>
    <div class="brand-icon">💼</div>
    <span>Job Mart</span>
</div>

<div class="header-right">

<div
    id="headerUser"
    class="user-pill hidden"
>
    <div
        id="headerAvatar"
        class="avatar"
    >
        U
    </div>

    <span id="headerName">
        User
    </span>
</div>

<button
    id="headerLogin"
    class="btn btn-primary"
    onclick="showPage('login')"
>
    Login
</button>

</div>

</div>

</header>


<!-- NAV -->

<div
    id="mainNav"
    class="nav hidden"
>

<div class="nav-inner">

<button
    id="navHome"
    onclick="showPage('home')"
>
    🏠 Home
</button>

<button
    id="navJobs"
    onclick="showPage('jobs')"
>
    💼 Jobs
</button>

<button
    id="navSaved"
    onclick="showPage('saved')"
>
    ♡ Saved
</button>

<button
    id="navApplications"
    onclick="showPage('applications')"
>
    📄 Applications
</button>

<button
    id="navNotifications"
    onclick="showPage('notifications')"
>
    🔔 Notifications
</button>

<button
    id="navProfile"
    onclick="showPage('profile')"
>
    👤 Profile
</button>

<button
    id="navDashboard"
    onclick="showPage('dashboard')"
>
    📊 Dashboard
</button>

<button
    id="navPost"
    onclick="showPage('post')"
    class="hidden"
>
    ➕ Post Job
</button>

<button
    onclick="logout()"
>
    🚪 Logout
</button>

</div>

</div>


<!-- MAIN -->

<main class="container">


<!-- HOME -->

<section
    id="home"
    class="page"
>

<div class="hero">

<h1>
Find The Job That Fits Your Life
</h1>

<p>
Search jobs posted by employers and build your career with Job Mart.
</p>

<div class="search-box">

<input
    id="homeSearch"
    placeholder="Job title, keyword or company"
/>

<select id="homeCountry">

<option value="">
All Countries
</option>

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
Other
</option>

</select>

<select id="homeType">

<option value="">
All Job Types
</option>

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

<button
    class="btn btn-primary"
    onclick="searchHome()"
>
Search Jobs
</button>

</div>

</div>


<div class="section-title">

<h2>
Popular Categories
</h2>

</div>

<div class="categories">

<div
    class="category"
    onclick="categorySearch('IT & Software')"
>
💻 IT & Software
</div>

<div
    class="category"
    onclick="categorySearch('Design')"
>
🎨 Design
</div>

<div
    class="category"
    onclick="categorySearch('Marketing')"
>
📣 Marketing
</div>

<div
    class="category"
    onclick="categorySearch('Sales')"
>
📈 Sales
</div>

<div
    class="category"
    onclick="categorySearch('Finance')"
>
💰 Finance
</div>

<div
    class="category"
    onclick="categorySearch('HR')"
>
👥 HR
</div>

</div>


<div class="section-title">

<h2>
Latest Jobs
</h2>

<button
    class="btn btn-light"
    onclick="showPage('jobs')"
>
View All
</button>

</div>

<div id="homeJobs">
</div>

</section>


<!-- JOBS -->

<section
    id="jobs"
    class="page hidden"
>

<div class="card">

<div class="section-title">

<h2>
Browse Jobs
</h2>

</div>

<div class="search-box">

<input
    id="jobSearch"
    placeholder="Search jobs..."
/>

<select id="jobCountry">

<option value="">
All Countries
</option>

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
Other
</option>

</select>

<select id="jobType">

<option value="">
All Types
</option>

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

<button
    class="btn btn-primary"
    onclick="loadJobs()"
>
Search
</button>

</div>

</div>

<br>

<div id="jobsList">
</div>

</section>


<!-- LOGIN -->

<section
    id="login"
    class="page hidden"
>

<div class="auth-layout">

<div class="auth-side">

<h2>
Welcome Back!
</h2>

<p>
Login to your Job Mart account and explore thousands of opportunities.
</p>

<p>
Find jobs. Apply. Build your career.
</p>

</div>

<div class="auth-form">

<h2>
Login
</h2>

<div class="form-group">

<label>
Email
</label>

<input
    id="loginEmail"
    type="email"
    placeholder="you@example.com"
/>

</div>

<div class="form-group">

<label>
Password
</label>

<input
    id="loginPassword"
    type="password"
    placeholder="Enter password"
/>

</div>

<button
    class="btn btn-primary btn-block"
    onclick="login()"
>
Login
</button>

<br>

<button
    class="btn btn-light btn-block"
    onclick="showPage('register')"
>
Create New Account
</button>

<p
    id="loginMsg"
    class="meta"
></p>

</div>

</div>

</section>


<!-- REGISTER -->

<section
    id="register"
    class="page hidden"
>

<div class="auth-layout">

<div class="auth-side">

<h2>
Join Job Mart
</h2>

<p>
Create your account and start your journey toward your next opportunity.
</p>

<p>
Job Seeker or Employer — choose your account type.
</p>

</div>

<div class="auth-form">

<h2>
Create Account
</h2>

<div class="form-group">

<label>
Full Name
</label>

<input
    id="regName"
    placeholder="Your full name"
/>

</div>

<div class="form-group">

<label>
Email
</label>

<input
    id="regEmail"
    type="email"
    placeholder="you@example.com"
/>

</div>

<div class="form-group">

<label>
Password
</label>

<input
    id="regPassword"
    type="password"
    placeholder="Minimum 6 characters"
/>

</div>

<div class="form-group">

<label>
Account Type
</label>

<select id="regRole">

<option value="jobseeker">
Job Seeker
</option>

<option value="employer">
Employer
</option>

</select>

</div>

<div class="form-group">

<label>
Phone
</label>

<input
    id="regPhone"
    placeholder="Phone number"
/>

</div>

<div class="form-grid">

<div class="form-group">

<label>
Country
</label>

<input
    id="regCountry"
    placeholder="India"
/>

</div>

<div class="form-group">

<label>
City
</label>

<input
    id="regCity"
    placeholder="Hyderabad"
/>

</div>

</div>

<button
    class="btn btn-primary btn-block"
    onclick="registerUser()"
>
Create Account
</button>

<br>

<button
    class="btn btn-light btn-block"
    onclick="showPage('login')"
>
Already have an account? Login
</button>

<p
    id="registerMsg"
    class="meta"
></p>

</div>

</div>

</section>


<!-- DASHBOARD -->

<section
    id="dashboard"
    class="page hidden"
>

<div class="section-title">

<h2>
Dashboard
</h2>

</div>

<div
    id="dashboardWelcome"
    class="card"
>
</div>

<br>

<div
    id="dashboardStats"
    class="dashboard-grid"
>
</div>

<br>

<div
    id="dashboardExtra"
>
</div>

</section>


<!-- JOB DETAILS -->

<section
    id="jobDetails"
    class="page hidden"
>

<div id="jobDetailsContent">
</div>

</section>


<!-- POST JOB -->

<section
    id="post"
    class="page hidden"
>

<div class="form-card">

<h2>
Post a New Job
</h2>

<p class="meta">
Reach qualified candidates through Job Mart.
</p>

<div class="form-grid">

<div class="form-group">

<label>
Job Title
</label>

<input
    id="postTitle"
    placeholder="Backend Developer"
/>

</div>

<div class="form-group">

<label>
Company
</label>

<input
    id="postCompany"
    placeholder="Your company"
/>

</div>

<div class="form-group">

<label>
Category
</label>

<select id="postCategory">

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
Other
</option>

</select>

</div>

<div class="form-group">

<label>
Country
</label>

<select id="postCountry">

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
Other
</option>

</select>

</div>

<div class="form-group">

<label>
Location
</label>

<input
    id="postLocation"
    placeholder="Hyderabad"
/>

</div>

<div class="form-group">

<label>
Job Type
</label>

<select id="postType">

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

<div class="form-group">

<label>
Work Mode
</label>

<select id="postMode">

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

<div class="form-group">

<label>
Salary
</label>

<input
    id="postSalary"
    placeholder="₹6,00,000 - ₹10,00,000 / year"
/>

</div>

<div class="form-group full">

<label>
Skills
</label>

<input
    id="postSkills"
    placeholder="Python, FastAPI, SQL"
/>

</div>

<div class="form-group full">

<label>
Application Email
</label>

<input
    id="postEmail"
    type="email"
    placeholder="jobs@company.com"
/>

</div>

<div class="form-group full">

<label>
Job Description
</label>

<textarea
    id="postDescription"
    placeholder="Describe the job..."
></textarea>

</div>

</div>

<button
    class="btn btn-primary btn-block"
    onclick="postJob()"
>
Post Job
</button>

</div>

</section>


<!-- APPLICATIONS -->

<section
    id="applications"
    class="page hidden"
>

<div class="section-title">

<h2 id="applicationsTitle">
Applications
</h2>

</div>

<div id="applicationsList">
</div>

</section>


<!-- SAVED -->

<section
    id="saved"
    class="page hidden"
>

<div class="section-title">

<h2>
Saved Jobs
</h2>

</div>

<div id="savedList">
</div>

</section>


<!-- NOTIFICATIONS -->

<section
    id="notifications"
    class="page hidden"
>

<div class="section-title">

<h2>
Notifications
</h2>

<button
    class="btn btn-light"
    onclick="markNotificationsRead()"
>
Mark All Read
</button>

</div>

<div id="notificationsList">
</div>

</section>


<!-- PROFILE -->

<section
    id="profile"
    class="page hidden"
>

<div class="form-card">

<h2>
My Profile
</h2>

<div class="form-grid">

<div class="form-group">

<label>
Name
</label>

<input
    id="profileName"
/>

</div>

<div class="form-group">

<label>
Email
</label>

<input
    id="profileEmail"
    disabled
/>

</div>

<div class="form-group">

<label>
Phone
</label>

<input
    id="profilePhone"
/>

</div>

<div class="form-group">

<label>
Country
</label>

<input
    id="profileCountry"
/>

</div>

<div class="form-group">

<label>
City
</label>

<input
    id="profileCity"
/>

</div>

<div class="form-group full">

<label>
Bio
</label>

<textarea
    id="profileBio"
></textarea>

</div>

</div>

<button
    class="btn btn-primary btn-block"
    onclick="updateProfile()"
>
Update Profile
</button>

</div>

</section>


</main>


<div
    id="toast"
    class="toast"
>
</div>


<script>

/* ======================================================
   GLOBAL
====================================================== */

let currentUser = null;

const pages = [
    "home",
    "jobs",
    "login",
    "register",
    "dashboard",
    "jobDetails",
    "post",
    "applications",
    "saved",
    "notifications",
    "profile"
];


/* ======================================================
   API
====================================================== */

async function api(
    url,
    options = {}
){

    options.headers = {
        "Content-Type":"application/json",
        ...(options.headers || {})
    };

    const response = await fetch(
        url,
        {
            ...options,
            credentials:"include"
        }
    );

    let data;

    try{
        data = await response.json();
    }
    catch{
        data = {
            detail:"Server error"
        };
    }

    if(!response.ok){

        throw new Error(
            data.detail || "Something went wrong"
        );

    }

    return data;
}


/* ======================================================
   TOAST
====================================================== */

let toastTimer;

function toast(message){

    const el =
        document.getElementById("toast");

    el.textContent = message;
    el.classList.add("show");

    clearTimeout(toastTimer);

    toastTimer = setTimeout(
        ()=>{
            el.classList.remove("show");
        },
        2500
    );
}


/* ======================================================
   ESCAPE HTML
====================================================== */

function esc(value){

    if(value === null || value === undefined){
        return "";
    }

    return String(value)
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");
}


/* ======================================================
   PAGE NAVIGATION
====================================================== */

function showPage(page){

    pages.forEach(
        id=>{
            const el =
                document.getElementById(id);

            if(el){
                el.classList.add("hidden");
            }
        }
    );

    const selected =
        document.getElementById(page);

    if(selected){
        selected.classList.remove("hidden");
    }

    updateNav(page);

    window.scrollTo({
        top:0,
        behavior:"smooth"
    });

    if(page === "home"){
        loadHomeJobs();
    }

    if(page === "jobs"){
        loadJobs();
    }

    if(page === "dashboard"){
        loadDashboard();
    }

    if(page === "applications"){
        loadApplications();
    }

    if(page === "saved"){
        loadSaved();
    }

    if(page === "notifications"){
        loadNotifications();
    }

    if(page === "profile"){
        loadProfile();
    }
}


function updateNav(page){

    const ids = [
        "navHome",
        "navJobs",
        "navSaved",
        "navApplications",
        "navNotifications",
        "navProfile",
        "navDashboard"
    ];

    ids.forEach(
        id=>{
            const el =
                document.getElementById(id);

            if(el){
                el.classList.remove("active");
            }
        }
    );

    const map = {
        home:"navHome",
        jobs:"navJobs",
        saved:"navSaved",
        applications:"navApplications",
        notifications:"navNotifications",
        profile:"navProfile",
        dashboard:"navDashboard"
    };

    if(map[page]){
        document
            .getElementById(map[page])
            .classList.add("active");
    }
}


/* ======================================================
   AUTH UI
====================================================== */

function updateAuthUI(){

    const nav =
        document.getElementById("mainNav");

    const login =
        document.getElementById("headerLogin");

    const userPill =
        document.getElementById("headerUser");

    const postBtn =
        document.getElementById("navPost");

    if(currentUser){

        nav.classList.remove("hidden");

        login.classList.add("hidden");

        userPill.classList.remove("hidden");

        document.getElementById(
            "headerName"
        ).textContent =
            currentUser.name;

        document.getElementById(
            "headerAvatar"
        ).textContent =
            currentUser.name
                .charAt(0)
                .toUpperCase();

        if(
            currentUser.role === "employer"
            ||
            currentUser.role === "admin"
        ){
            postBtn.classList.remove("hidden");
        }
        else{
            postBtn.classList.add("hidden");
        }

    }
    else{

        nav.classList.add("hidden");

        login.classList.remove("hidden");

        userPill.classList.add("hidden");

        postBtn.classList.add("hidden");
    }
}


/* ======================================================
   CHECK LOGIN
====================================================== */

async function checkLogin(){

    try{

        const data =
            await api("/api/me");

        if(data.logged_in){

            currentUser =
                data.user;

            updateAuthUI();

        }
        else{

            currentUser = null;

            updateAuthUI();

        }

    }
    catch{

        currentUser = null;

        updateAuthUI();

    }
}


/* ======================================================
   REGISTER
====================================================== */

async function registerUser(){

    const payload = {

        name:
            document.getElementById(
                "regName"
            ).value.trim(),

        email:
            document.getElementById(
                "regEmail"
            ).value.trim(),

        password:
            document.getElementById(
                "regPassword"
            ).value,

        role:
            document.getElementById(
                "regRole"
            ).value,

        phone:
            document.getElementById(
                "regPhone"
            ).value.trim(),

        country:
            document.getElementById(
                "regCountry"
            ).value.trim(),

        city:
            document.getElementById(
                "regCity"
            ).value.trim()
    };

    if(
        !payload.name ||
        !payload.email ||
        !payload.password
    ){

        toast(
            "Please fill all required fields"
        );

        return;
    }

    try{

        await api(
            "/api/register",
            {
                method:"POST",
                body:JSON.stringify(payload)
            }
        );

        toast(
            "Registration successful"
        );

        document.getElementById(
            "loginEmail"
        ).value =
            payload.email;

        document.getElementById(
            "loginPassword"
        ).value =
            payload.password;

        showPage("login");

        setTimeout(
            ()=>{
                login();
            },
            400
        );

    }
    catch(error){

        toast(error.message);

    }
}


/* ======================================================
   LOGIN
====================================================== */

async function login(){

    const email =
        document.getElementById(
            "loginEmail"
        ).value.trim();

    const password =
        document.getElementById(
            "loginPassword"
        ).value;

    if(!email || !password){

        toast(
            "Enter email and password"
        );

        return;
    }

    try{

        const data =
            await api(
                "/api/login-cookie",
                {
                    method:"POST",
                    body:JSON.stringify({
                        email,
                        password
                    })
                }
            );

        currentUser =
            data.user;

        updateAuthUI();

        toast(
            "Login successful"
        );

        showPage("dashboard");

    }
    catch(error){

        document.getElementById(
            "loginMsg"
        ).textContent =
            error.message;

        toast(error.message);

    }
}


/* ======================================================
   LOGOUT
====================================================== */

async function logout(){

    try{
        await api(
            "/api/logout",
            {
                method:"POST"
            }
        );
    }
    catch{}

    currentUser = null;

    updateAuthUI();

    toast(
        "Logged out successfully"
    );

    showPage("home");
}


/* ======================================================
   HOME JOBS
====================================================== */

async function loadHomeJobs(){

    const box =
        document.getElementById(
            "homeJobs"
        );

    try{

        const data =
            await api(
                "/api/jobs"
            );

        const jobs =
            data.jobs.slice(0,6);

        if(!jobs.length){

            box.innerHTML =
                `<div class="empty">
                    No jobs posted yet.
                </div>`;

            return;
        }

        box.innerHTML =
            `<div class="grid">
                ${jobs.map(
                    jobCard
                ).join("")}
            </div>`;

    }
    catch(error){

        box.innerHTML =
            `<div class="empty">
                ${esc(error.message)}
            </div>`;

    }
}


/* ======================================================
   JOB CARD
====================================================== */

function jobCard(job){

    const skills =
        job.skills
            ? job.skills
                .split(",")
                .slice(0,4)
                .map(
                    s =>
                    `<span class="badge">
                        ${esc(s.trim())}
                    </span>`
                )
                .join("")
            : "";

    return `
    <div class="card job-card">

        <h3 class="job-title">
            ${esc(job.title)}
        </h3>

        <div class="company">
            ${esc(job.company)}
        </div>

        <div class="badges">

            <span class="badge">
                ${esc(job.country)}
            </span>

            <span class="badge">
                ${esc(job.job_type)}
            </span>

            <span class="badge">
                ${esc(job.work_mode)}
            </span>

        </div>

        <div class="meta">
            📍 ${esc(job.location || "Location not specified")}
        </div>

        <div class="meta">
            💰 ${esc(job.salary || "Salary not disclosed")}
        </div>

        <p class="meta">
            ${esc(
                (job.description || "")
                    .substring(0,130)
            )}${job.description &&
            job.description.length > 130
                ? "..."
                : ""}
        </p>

        <div class="badges">
            ${skills}
        </div>

        <div class="job-actions">

            <button
                class="btn btn-light"
                onclick="openJob(${job.id})"
            >
                View Details
            </button>

            ${
                currentUser &&
                currentUser.role === "jobseeker"
                ?
                `
                <button
                    class="btn btn-primary"
                    onclick="openJob(${job.id})"
                >
                    Apply
                </button>
                `
                :
                ""
            }

        </div>

    </div>
    `;
}


/* ======================================================
   SEARCH HOME
====================================================== */

function searchHome(){

    const q =
        document.getElementById(
            "homeSearch"
        ).value;

    const country =
        document.getElementById(
            "homeCountry"
        ).value;

    const type =
        document.getElementById(
            "homeType"
        ).value;

    document.getElementById(
        "jobSearch"
    ).value = q;

    document.getElementById(
        "jobCountry"
    ).value = country;

    document.getElementById(
        "jobType"
    ).value = type;

    showPage("jobs");
}


/* ======================================================
   CATEGORY
====================================================== */

function categorySearch(category){

    document.getElementById(
        "jobSearch"
    ).value = category;

    showPage("jobs");
}


/* ======================================================
   LOAD JOBS
====================================================== */

async function loadJobs(){

    const q =
        document.getElementById(
            "jobSearch"
        ).value.trim();

    const country =
        document.getElementById(
            "jobCountry"
        ).value;

    const type =
        document.getElementById(
            "jobType"
        ).value;

    const params =
        new URLSearchParams();

    if(q){
        params.set("q",q);
    }

    if(country){
        params.set("country",country);
    }

    if(type){
        params.set("job_type",type);
    }

    const box =
        document.getElementById(
            "jobsList"
        );

    box.innerHTML =
        `<div class="empty">
            Loading jobs...
        </div>`;

    try{

        const data =
            await api(
                "/api/jobs?" +
                params.toString()
            );

        if(!data.jobs.length){

            box.innerHTML =
                `<div class="empty">
                    <h3>No jobs found</h3>
                    <p>
                        Try another keyword or filter.
                    </p>
                </div>`;

            return;
        }

        box.innerHTML =
            `<div class="grid">
                ${data.jobs.map(
                    jobCard
                ).join("")}
            </div>`;

    }
    catch(error){

        box.innerHTML =
            `<div class="empty">
                ${esc(error.message)}
            </div>`;

    }
}


/* ======================================================
   OPEN JOB
====================================================== */

async function openJob(id){

    showPage("jobDetails");

    const box =
        document.getElementById(
            "jobDetailsContent"
        );

    box.innerHTML =
        `<div class="empty">
            Loading job...
        </div>`;

    try{

        const data =
            await api(
                `/api/jobs/${id}`
            );

        const job =
            data.job;

        box.innerHTML = `
        <div class="detail-layout">

            <div class="detail-card">

                <h1>
                    ${esc(job.title)}
                </h1>

                <h3>
                    ${esc(job.company)}
                </h3>

                <div class="badges">

                    <span class="badge">
                        ${esc(job.country)}
                    </span>

                    <span class="badge">
                        ${esc(job.job_type)}
                    </span>

                    <span class="badge">
                        ${esc(job.work_mode)}
                    </span>

                    <span class="badge">
                        ${esc(job.category)}
                    </span>

                </div>

                <p class="meta">
                    📍 ${esc(job.location || "Location not specified")}
                </p>

                <hr>

                <h3>
                    Description
                </h3>

                <p>
                    ${esc(job.description)}
                </p>

                <h3>
                    Skills
                </h3>

                <div class="badges">

                    ${
                        job.skills
                        ?
                        job.skills
                            .split(",")
                            .map(
                                s =>
                                `<span class="badge">
                                    ${esc(s.trim())}
                                </span>`
                            )
                            .join("")
                        :
                        "<span class='meta'>Not specified</span>"
                    }

                </div>

                <h3>
                    Salary
                </h3>

                <p>
                    ${esc(
                        job.salary ||
                        "Salary not disclosed"
                    )}
                </p>

                <h3>
                    Employer
                </h3>

                <p class="meta">
                    ${esc(job.employer_name)}
                </p>

            </div>

            <div class="detail-card action-card">

                <h3>
                    Actions
                </h3>

                ${
                    !currentUser
                    ?
                    `
                    <button
                        class="btn btn-primary btn-block"
                        onclick="showPage('login')"
                    >
                        Login to Apply
                    </button>
                    `
                    :
                    currentUser.role === "jobseeker"
                    ?
                    `
                    <button
                        class="btn ${
                            job.applied
                            ? "btn-success"
                            : "btn-primary"
                        } btn-block"
                        ${
                            job.applied
                            ? "disabled"
                            : `onclick="applyJob(${job.id})"`
                        }
                    >
                        ${
                            job.applied
                            ? "✓ Already Applied"
                            : "Apply Now"
                        }
                    </button>

                    <br>

                    <button
                        class="btn btn-light btn-block"
                        onclick="saveJob(${job.id})"
                    >
                        ${
                            job.saved
                            ? "♥ Remove Saved"
                            : "♡ Save Job"
                        }
                    </button>
                    `
                    :
                    ""
                }

            </div>

        </div>
        `;

    }
    catch(error){

        box.innerHTML =
            `<div class="empty">
                ${esc(error.message)}
            </div>`;

    }
}


/* ======================================================
   APPLY JOB
====================================================== */

async function applyJob(id){

    if(!currentUser){

        showPage("login");

        return;
    }

    if(currentUser.role !== "jobseeker"){

        toast(
            "Only Job Seekers can apply"
        );

        return;
    }

    const cover =
        prompt(
            "Optional: Enter your cover letter"
        );

    try{

        await api(
            `/api/jobs/${id}/apply`,
            {
                method:"POST",
                body:JSON.stringify({
                    cover_letter:
                        cover || ""
                })
            }
        );

        toast(
            "Application submitted"
        );

        openJob(id);

    }
    catch(error){

        toast(error.message);

    }
}


/* ======================================================
   SAVE JOB
====================================================== */

async function saveJob(id){

    if(!currentUser){

        showPage("login");

        return;
    }

    try{

        const data =
            await api(
                `/api/jobs/${id}/save`,
                {
                    method:"POST"
                }
            );

        toast(data.message);

        openJob(id);

    }
    catch(error){

        toast(error.message);

    }
}


/* ======================================================
   DASHBOARD
====================================================== */

async function loadDashboard(){

    if(!currentUser){

        showPage("login");

        return;
    }

    try{

        const data =
            await api(
                "/api/dashboard"
            );

        const d =
            data.dashboard;

        document.getElementById(
            "dashboardWelcome"
        ).innerHTML = `
            <h2>
                Welcome back,
                ${esc(currentUser.name)} 👋
            </h2>

            <p class="meta">
                ${
                    d.role === "employer"
                    ?
                    "Manage your jobs and applicants."
                    :
                    "Find jobs, track applications and build your career."
                }
            </p>
        `;

        if(d.role === "employer"){

            document.getElementById(
                "dashboardStats"
            ).innerHTML = `

            <div class="stat">

                <div class="stat-label">
                    Jobs Posted
                </div>

                <div class="stat-number">
                    ${d.jobs_posted}
                </div>

            </div>

            <div class="stat">

                <div class="stat-label">
                    Active Jobs
                </div>

                <div class="stat-number">
                    ${d.active_jobs}
                </div>

            </div>

            <div class="stat">

                <div class="stat-label">
                    Applications
                </div>

                <div class="stat-number">
                    ${d.applications}
                </div>

            </div>

            <div class="stat">

                <div class="stat-label">
                    Hired
                </div>

                <div class="stat-number">
                    ${d.hired}
                </div>

            </div>
            `;

            document.getElementById(
                "dashboardExtra"
            ).innerHTML = `
                <div class="card">

                    <h3>
                        Employer Quick Actions
                    </h3>

                    <div class="job-actions">

                        <button
                            class="btn btn-primary"
                            onclick="showPage('post')"
                        >
                            ➕ Post New Job
                        </button>

                        <button
                            class="btn btn-light"
                            onclick="showPage('applications')"
                        >
                            📄 View Applications
                        </button>

                    </div>

                </div>
            `;

        }
        else{

            document.getElementById(
                "dashboardStats"
            ).innerHTML = `

            <div class="stat">

                <div class="stat-label">
                    Applications
                </div>

                <div class="stat-number">
                    ${d.applications}
                </div>

            </div>

            <div class="stat">

                <div class="stat-label">
                    Saved Jobs
                </div>

                <div class="stat-number">
                    ${d.saved_jobs}
                </div>

            </div>

            <div class="stat">

                <div class="stat-label">
                    Hired
                </div>

                <div class="stat-number">
                    ${d.hired}
                </div>

            </div>

            `;

            document.getElementById(
                "dashboardExtra"
            ).innerHTML = `
                <div class="card">

                    <h3>
                        Quick Links
                    </h3>

                    <div class="job-actions">

                        <button
                            class="btn btn-primary"
                            onclick="showPage('jobs')"
                        >
                            🔎 Find Jobs
                        </button>

                        <button
                            class="btn btn-light"
                            onclick="showPage('applications')"
                        >
                            📄 My Applications
                        </button>

                        <button
                            class="btn btn-light"
                            onclick="showPage('saved')"
                        >
                            ♡ Saved Jobs
                        </button>

                    </div>

                </div>
            `;
        }

    }
    catch(error){

        toast(error.message);

    }
}


/* ======================================================
   POST JOB
====================================================== */

async function postJob(){

    if(!currentUser){

        showPage("login");

        return;
    }

    if(
        currentUser.role !== "employer"
        &&
        currentUser.role !== "admin"
    ){

        toast(
            "Employer account required"
        );

        return;
    }

    const payload = {

        title:
            document.getElementById(
                "postTitle"
            ).value.trim(),

        company:
            document.getElementById(
                "postCompany"
            ).value.trim(),

        category:
            document.getElementById(
                "postCategory"
            ).value,

        country:
            document.getElementById(
                "postCountry"
            ).value,

        location:
            document.getElementById(
                "postLocation"
            ).value.trim(),

        job_type:
            document.getElementById(
                "postType"
            ).value,

        work_mode:
            document.getElementById(
                "postMode"
            ).value,

        salary:
            document.getElementById(
                "postSalary"
            ).value.trim(),

        skills:
            document.getElementById(
                "postSkills"
            ).value.trim(),

        application_email:
            document.getElementById(
                "postEmail"
            ).value.trim(),

        description:
            document.getElementById(
                "postDescription"
            ).value.trim()
    };

    if(
        !payload.title ||
        !payload.company ||
        !payload.description
    ){

        toast(
            "Please fill Job Title, Company and Description"
        );

        return;
    }

    try{

        await api(
            "/api/jobs",
            {
                method:"POST",
                body:JSON.stringify(payload)
            }
        );

        toast(
            "Job posted successfully"
        );

        document.getElementById(
            "postTitle"
        ).value = "";

        document.getElementById(
            "postLocation"
        ).value = "";

        document.getElementById(
            "postSalary"
        ).value = "";

        document.getElementById(
            "postSkills"
        ).value = "";

        document.getElementById(
            "postEmail"
        ).value = "";

        document.getElementById(
            "postDescription"
        ).value = "";

        showPage("jobs");

    }
    catch(error){

        toast(error.message);

    }
}


/* ======================================================
   APPLICATIONS
====================================================== */

async function loadApplications(){

    if(!currentUser){

        showPage("login");

        return;
    }

    const box =
        document.getElementById(
            "applicationsList"
        );

    box.innerHTML =
        `<div class="empty">
            Loading applications...
        </div>`;

    try{

        const data =
            await api(
                "/api/applications"
            );

        const apps =
            data.applications;

        if(
            currentUser.role === "employer"
            ||
            currentUser.role === "admin"
        ){

            document.getElementById(
                "applicationsTitle"
            ).textContent =
                "Applications Received";

            if(!apps.length){

                box.innerHTML =
                    `<div class="empty">
                        No applications received yet.
                    </div>`;

                return;
            }

            box.innerHTML = `
                <div class="card table-wrap">

                <table>

                <thead>

                <tr>
                    <th>Applicant</th>
                    <th>Job</th>
                    <th>Email</th>
                    <th>Phone</th>
                    <th>Status</th>
                    <th>Update</th>
                </tr>

                </thead>

                <tbody>

                ${apps.map(
                    app =>
                    `
                    <tr>

                        <td>
                            <strong>
                                ${esc(app.applicant_name)}
                            </strong>
                        </td>

                        <td>
                            ${esc(app.title)}
                        </td>

                        <td>
                            ${esc(app.applicant_email)}
                        </td>

                        <td>
                            ${esc(app.applicant_phone || "-")}
                        </td>

                        <td>
                            ${statusBadge(app.status)}
                        </td>

                        <td>

                            <select
                                onchange="
                                    updateApplicationStatus(
                                        ${app.id},
                                        this.value
                                    )
                                "
                            >

                                ${[
                                    "applied",
                                    "reviewing",
                                    "shortlisted",
                                    "rejected",
                                    "hired"
                                ].map(
                                    status =>
                                    `
                                    <option
                                        value="${status}"
                                        ${
                                            app.status === status
                                            ? "selected"
                                            : ""
                                        }
                                    >
                                        ${status}
                                    </option>
                                    `
                                ).join("")}

                            </select>

                        </td>

                    </tr>
                    `
                ).join("")}

                </tbody>

                </table>

                </div>
            `;

        }
        else{

            document.getElementById(
                "applicationsTitle"
            ).textContent =
                "My Applications";

            if(!apps.length){

                box.innerHTML =
                    `<div class="empty">
                        <h3>No applications yet</h3>
                        <p>
                            Start applying for jobs.
                        </p>

                        <button
                            class="btn btn-primary"
                            onclick="showPage('jobs')"
                        >
                            Find Jobs
                        </button>
                    </div>`;

                return;
            }

            box.innerHTML =
                `<div class="grid">
                    ${apps.map(
                        app =>
                        `
                        <div class="card">

                            <h3 class="job-title">
                                ${esc(app.title)}
                            </h3>

                            <div class="company">
                                ${esc(app.company)}
                            </div>

                            <p class="meta">
                                📍
                                ${esc(app.location || app.country || "-")}
                            </p>

                            <p class="meta">
                                Applied:
                                ${formatDate(app.created_at)}
                            </p>

                            <div>
                                ${statusBadge(app.status)}
                            </div>

                        </div>
                        `
                    ).join("")}
                </div>`;

        }

    }
    catch(error){

        box.innerHTML =
            `<div class="empty">
                ${esc(error.message)}
            </div>`;

    }
}


/* ======================================================
   STATUS BADGE
====================================================== */

function statusBadge(status){

    const s =
        String(status || "applied")
            .toLowerCase();

    return `
        <span class="status status-${esc(s)}">
            ${esc(
                s.charAt(0).toUpperCase() +
                s.slice(1)
            )}
        </span>
    `;
}


/* ======================================================
   UPDATE APPLICATION
====================================================== */

async function updateApplicationStatus(
    id,
    status
){

    try{

        await api(
            `/api/applications/${id}/status`,
            {
                method:"PUT",
                body:JSON.stringify({
                    status
                })
            }
        );

        toast(
            "Application status updated"
        );

        loadApplications();

    }
    catch(error){

        toast(error.message);

    }
}


/* ======================================================
   SAVED JOBS
====================================================== */

async function loadSaved(){

    if(!currentUser){

        showPage("login");

        return;
    }

    const box =
        document.getElementById(
            "savedList"
        );

    try{

        const data =
            await api(
                "/api/saved-jobs"
            );

        if(!data.jobs.length){

            box.innerHTML =
                `<div class="empty">

                    <h3>
                        No saved jobs
                    </h3>

                    <p>
                        Save jobs you want to check later.
                    </p>

                    <button
                        class="btn btn-primary"
                        onclick="showPage('jobs')"
                    >
                        Browse Jobs
                    </button>

                </div>`;

            return;
        }

        box.innerHTML =
            `<div class="grid">
                ${data.jobs.map(
                    jobCard
                ).join("")}
            </div>`;

    }
    catch(error){

        box.innerHTML =
            `<div class="empty">
                ${esc(error.message)}
            </div>`;

    }
}


/* ======================================================
   NOTIFICATIONS
====================================================== */

async function loadNotifications(){

    if(!currentUser){

        showPage("login");

        return;
    }

    const box =
        document.getElementById(
            "notificationsList"
        );

    try{

        const data =
            await api(
                "/api/notifications"
            );

        if(!data.notifications.length){

            box.innerHTML =
                `<div class="empty">
                    No notifications yet.
                </div>`;

            return;
        }

        box.innerHTML =
            data.notifications.map(
                n =>
                `
                <div
                    class="
                        notification
                        ${
                            n.is_read
                            ? ""
                            : "unread"
                        }
                    "
                >

                    <div
                        style="
                            display:flex;
                            justify-content:space-between;
                            gap:10px;
                        "
                    >

                        <strong>
                            ${esc(n.title)}
                        </strong>

                        <span class="meta">
                            ${formatDate(n.created_at)}
                        </span>

                    </div>

                    <p class="meta">
                        ${esc(n.message)}
                    </p>

                </div>
                `
            ).join("");

    }
    catch(error){

        box.innerHTML =
            `<div class="empty">
                ${esc(error.message)}
            </div>`;

    }
}


/* ======================================================
   READ NOTIFICATIONS
====================================================== */

async function markNotificationsRead(){

    try{

        await api(
            "/api/notifications/read",
            {
                method:"POST"
            }
        );

        toast(
            "Notifications marked as read"
        );

        loadNotifications();

    }
    catch(error){

        toast(error.message);

    }
}


/* ======================================================
   PROFILE
====================================================== */

async function loadProfile(){

    if(!currentUser){

        showPage("login");

        return;
    }

    try{

        const data =
            await api(
                "/api/me"
            );

        if(!data.logged_in){
            showPage("login");
            return;
        }

        const user =
            data.user;

        document.getElementById(
            "profileName"
        ).value =
            user.name || "";

        document.getElementById(
            "profileEmail"
        ).value =
            user.email || "";

        document.getElementById(
            "profilePhone"
        ).value =
            user.phone || "";

        document.getElementById(
            "profileCountry"
        ).value =
            user.country || "";

        document.getElementById(
            "profileCity"
        ).value =
            user.city || "";

        document.getElementById(
            "profileBio"
        ).value =
            user.bio || "";

    }
    catch(error){

        toast(error.message);

    }
}


/* ======================================================
   UPDATE PROFILE
====================================================== */

async function updateProfile(){

    const payload = {

        name:
            document.getElementById(
                "profileName"
            ).value.trim(),

        phone:
            document.getElementById(
                "profilePhone"
            ).value.trim(),

        country:
            document.getElementById(
                "profileCountry"
            ).value.trim(),

        city:
            document.getElementById(
                "profileCity"
            ).value.trim(),

        bio:
            document.getElementById(
                "profileBio"
            ).value.trim()
    };

    if(!payload.name){

        toast(
            "Name is required"
        );

        return;
    }

    try{

        await api(
            "/api/profile",
            {
                method:"PUT",
                body:JSON.stringify(payload)
            }
        );

        currentUser.name =
            payload.name;

        updateAuthUI();

        toast(
            "Profile updated"
        );

    }
    catch(error){

        toast(error.message);

    }
}


/* ======================================================
   DATE
====================================================== */

function formatDate(value){

    if(!value){
        return "-";
    }

    try{

        return new Date(
            value
        ).toLocaleDateString(
            "en-IN",
            {
                day:"2-digit",
                month:"short",
                year:"numeric"
            }
        );

    }
    catch{

        return value;

    }
}


/* ======================================================
   START APP
====================================================== */

async function startApp(){

    await checkLogin();

    showPage("home");

}

startApp();

</script>

</body>

</html>
"""


# =========================================================
# HTML ROUTE
# =========================================================

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": "Job Mart"
    }
