from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
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
    category: str = Field(min_length=2)
    country: str = Field(min_length=2)
    location: str = ""
    job_type: str = Field(min_length=2)
    work_mode: str = Field(min_length=2)
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

    name = data.name.strip()
    email = data.email.strip().lower()

    if len(name) < 2:
        raise HTTPException(
            status_code=400,
            detail="Please enter a valid name"
        )

    if "@" not in email:
        raise HTTPException(
            status_code=400,
            detail="Please enter a valid email"
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
        "message": "Account created successfully",
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
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    })

    # IMPORTANT:
    # Browser session cookie is now properly created.
    response.set_cookie(
        key="jobmart_session",
        value=token,
        httponly=True,
        samesite="lax",
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
        "message": "Profile updated successfully"
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
# LIST JOBS
# =========================================================

@app.get("/api/jobs")
def list_jobs(
    request: Request,
    q: str = "",
    category: str = "",
    country: str = "",
    job_type: str = "",
    work_mode: str = "",
    mine: bool = False
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
                OR LOWER(j.location) LIKE ?
            )
        """

        value = f"%{q.strip().lower()}%"

        params.extend([
            value,
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

    rows = conn.execute(
        sql,
        params
    ).fetchall()

    jobs = [dict(row) for row in rows]

    conn.close()

    return {
        "ok": True,
        "jobs": jobs,
        "count": len(jobs)
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
                (job_id, user["id"])
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
                (job_id, user["id"])
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
        (job_id, user["id"])
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
        "message": "Application submitted successfully"
    }


# =========================================================
# APPLICATIONS
# =========================================================

@app.get("/api/applications")
def applications(request: Request):

    user = require_user(request)

    conn = db()

    if user["role"] in ("employer", "admin"):

        if user["role"] == "admin":

            rows = conn.execute(
                """
                SELECT
                    a.*,
                    j.title,
                    j.company,
                    j.location,
                    j.country,
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
                    j.location,
                    j.country,
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
                j.job_type,
                j.work_mode,
                j.salary
            FROM applications a
            JOIN jobs j
                ON j.id=a.job_id
            WHERE a.applicant_id=?
            ORDER BY a.id DESC
            """,
            (user["id"],)
        ).fetchall()

    result = [dict(row) for row in rows]

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

    allowed = (
        "applied",
        "reviewing",
        "shortlisted",
        "rejected",
        "selected"
    )

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
            j.employer_id,
            j.title,
            j.company,
            u.name AS applicant_name
        FROM applications a
        JOIN jobs j
            ON j.id=a.job_id
        JOIN users u
            ON u.id=a.applicant_id
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
            "Application update",
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
# SAVE JOB
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
            (job_id,user_id,created_at)
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

    rows = conn.execute(
        """
        SELECT *
        FROM notifications
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (user["id"],)
    ).fetchall()

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

        if user["role"] == "admin":

            jobs_count = conn.execute(
                "SELECT COUNT(*) AS c FROM jobs"
            ).fetchone()["c"]

            applications_count = conn.execute(
                "SELECT COUNT(*) AS c FROM applications"
            ).fetchone()["c"]

            active_jobs = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM jobs
                WHERE status='active'
                """
            ).fetchone()["c"]

        else:

            jobs_count = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM jobs
                WHERE employer_id=?
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

            active_jobs = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM jobs
                WHERE employer_id=?
                AND status='active'
                """,
                (user["id"],)
            ).fetchone()["c"]

        result = {
            "role": user["role"],
            "jobs_posted": jobs_count,
            "active_jobs": active_jobs,
            "applications": applications_count
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

        result = {
            "role": "jobseeker",
            "applications": applied,
            "saved_jobs": saved
        }

    conn.close()

    return {
        "ok": True,
        "dashboard": result
    }


# =========================================================
# HTML
# =========================================================

HTML = r"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"
>

<title>Job Mart</title>

<style>

*{
    box-sizing:border-box;
    -webkit-tap-highlight-color:transparent;
}

:root{
    --blue:#0878e8;
    --blue2:#0059c9;
    --light:#f4f7fb;
    --card:#ffffff;
    --text:#17202a;
    --muted:#687386;
    --border:#e2e7ef;
    --green:#16a34a;
    --orange:#f59e0b;
    --red:#dc2626;
}

html,body{
    margin:0;
    padding:0;
    font-family:Arial,Helvetica,sans-serif;
    background:var(--light);
    color:var(--text);
}

body{
    min-height:100vh;
    padding-bottom:82px;
}

button,
input,
select,
textarea{
    font-family:inherit;
}

button{
    border:0;
    cursor:pointer;
}

.hidden{
    display:none!important;
}

/* =====================================================
HEADER
===================================================== */

.header{
    position:sticky;
    top:0;
    z-index:100;
    background:linear-gradient(
        135deg,
        var(--blue),
        var(--blue2)
    );
    color:white;
    box-shadow:0 3px 15px rgba(0,0,0,.15);
}

.header-inner{
    max-width:1200px;
    margin:auto;
    padding:12px 16px;
    display:flex;
    align-items:center;
    gap:12px;
}

.menu-btn{
    width:44px;
    height:44px;
    border-radius:12px;
    background:rgba(255,255,255,.15);
    color:white;
    font-size:23px;
}

.logo{
    font-size:23px;
    font-weight:800;
    letter-spacing:-.5px;
    flex:1;
}

.header-actions{
    display:flex;
    gap:7px;
}

.icon-btn{
    width:42px;
    height:42px;
    border-radius:12px;
    background:rgba(255,255,255,.15);
    color:white;
    font-size:19px;
}

/* =====================================================
SIDE MENU
===================================================== */

.drawer-bg{
    position:fixed;
    inset:0;
    background:rgba(0,0,0,.45);
    z-index:200;
}

.drawer{
    position:absolute;
    left:0;
    top:0;
    bottom:0;
    width:min(320px,88vw);
    background:white;
    box-shadow:8px 0 30px rgba(0,0,0,.2);
    overflow-y:auto;
}

.drawer-head{
    padding:22px 18px;
    color:white;
    background:linear-gradient(
        135deg,
        var(--blue),
        var(--blue2)
    );
}

.drawer-logo{
    font-size:25px;
    font-weight:800;
}

.drawer-user{
    margin-top:10px;
    opacity:.92;
}

.drawer-item{
    width:100%;
    padding:15px 18px;
    background:white;
    text-align:left;
    font-size:16px;
    border-bottom:1px solid #f0f1f3;
}

.drawer-item:hover{
    background:#f4f8ff;
}

.drawer-item span{
    display:inline-block;
    width:28px;
}

/* =====================================================
CONTAINER
===================================================== */

.container{
    max-width:1200px;
    margin:auto;
    padding:14px;
}

/* =====================================================
HOME HERO
===================================================== */

.hero{
    background:linear-gradient(
        135deg,
        #0878e8,
        #004db4
    );
    color:white;
    border-radius:24px;
    padding:25px 20px;
    margin-bottom:16px;
    box-shadow:0 10px 30px rgba(0,94,200,.18);
}

.hero h1{
    margin:0 0 8px;
    font-size:31px;
    line-height:1.12;
}

.hero p{
    margin:0 0 20px;
    opacity:.92;
    line-height:1.5;
}

.search-box{
    background:white;
    border-radius:17px;
    padding:8px;
    display:flex;
    gap:7px;
    box-shadow:0 6px 20px rgba(0,0,0,.15);
}

.search-box input{
    flex:1;
    min-width:0;
    border:0;
    outline:0;
    padding:12px;
    font-size:15px;
}

.search-button{
    background:var(--blue);
    color:white;
    border-radius:12px;
    padding:0 17px;
    font-size:15px;
    font-weight:700;
}

/* =====================================================
CATEGORY ROW
===================================================== */

.section-title{
    display:flex;
    align-items:center;
    justify-content:space-between;
    margin:20px 2px 11px;
}

.section-title h2{
    margin:0;
    font-size:20px;
}

.see-all{
    color:var(--blue);
    background:none;
    font-weight:700;
}

.categories{
    display:flex;
    gap:10px;
    overflow-x:auto;
    padding-bottom:5px;
}

.category{
    min-width:94px;
    background:white;
    border-radius:16px;
    padding:13px 8px;
    text-align:center;
    box-shadow:0 2px 8px rgba(0,0,0,.05);
    border:1px solid var(--border);
}

.category-icon{
    width:44px;
    height:44px;
    border-radius:50%;
    background:#e9f3ff;
    display:flex;
    align-items:center;
    justify-content:center;
    margin:auto auto 8px;
    font-size:22px;
}

.category-name{
    font-size:12px;
    font-weight:700;
}

/* =====================================================
CARDS
===================================================== */

.card{
    background:white;
    border-radius:18px;
    padding:17px;
    border:1px solid var(--border);
    box-shadow:0 3px 12px rgba(0,0,0,.045);
    margin-bottom:12px;
}

.job-card{
    position:relative;
}

.job-top{
    display:flex;
    gap:12px;
}

.company-logo{
    width:52px;
    height:52px;
    flex:none;
    border-radius:14px;
    background:linear-gradient(
        135deg,
        #e8f2ff,
        #cfe4ff
    );
    color:var(--blue);
    display:flex;
    align-items:center;
    justify-content:center;
    font-weight:800;
    font-size:20px;
}

.job-title{
    font-size:17px;
    font-weight:800;
    margin:1px 0 5px;
}

.company{
    font-size:14px;
    color:#465263;
}

.meta{
    color:var(--muted);
    font-size:13px;
    line-height:1.7;
}

.badges{
    display:flex;
    flex-wrap:wrap;
    gap:6px;
    margin-top:12px;
}

.badge{
    padding:6px 9px;
    border-radius:20px;
    background:#edf5ff;
    color:var(--blue);
    font-size:11px;
    font-weight:700;
}

.badge.green{
    background:#eaf8ef;
    color:var(--green);
}

.badge.orange{
    background:#fff5df;
    color:#b76a00;
}

.job-bottom{
    display:flex;
    gap:8px;
    margin-top:15px;
}

.btn{
    border-radius:11px;
    padding:11px 14px;
    font-size:14px;
    font-weight:700;
}

.btn-primary{
    background:var(--blue);
    color:white;
}

.btn-outline{
    background:white;
    border:1px solid #cfd7e2;
    color:var(--text);
}

.btn-danger{
    background:#fff0f0;
    color:var(--red);
}

/* =====================================================
FORMS
===================================================== */

.form-card{
    max-width:700px;
    margin:15px auto;
    background:white;
    border-radius:22px;
    padding:21px;
    border:1px solid var(--border);
}

.form-card h2{
    margin:0 0 5px;
}

.form-sub{
    color:var(--muted);
    font-size:14px;
    margin-bottom:18px;
}

label{
    display:block;
    font-size:14px;
    font-weight:700;
    margin:14px 0 7px;
}

input,
select,
textarea{
    width:100%;
    border:1px solid #cfd7e2;
    background:white;
    border-radius:12px;
    padding:13px;
    font-size:15px;
    outline:none;
}

input:focus,
select:focus,
textarea:focus{
    border-color:var(--blue);
    box-shadow:0 0 0 3px rgba(8,120,232,.1);
}

textarea{
    min-height:120px;
    resize:vertical;
}

.form-button{
    width:100%;
    margin-top:18px;
    padding:14px;
    border-radius:13px;
    background:var(--blue);
    color:white;
    font-size:16px;
    font-weight:800;
}

/* =====================================================
PAGE HEADER
===================================================== */

.page-header{
    background:white;
    padding:17px;
    border-radius:18px;
    margin-bottom:14px;
    border:1px solid var(--border);
}

.page-header h2{
    margin:0 0 12px;
}

.filters{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:8px;
}

/* =====================================================
AUTH
===================================================== */

.auth-wrap{
    min-height:70vh;
    display:flex;
    align-items:center;
    justify-content:center;
}

.auth-card{
    width:100%;
    max-width:470px;
    background:white;
    border-radius:24px;
    padding:24px;
    box-shadow:0 8px 30px rgba(0,0,0,.08);
}

.auth-logo{
    text-align:center;
    color:var(--blue);
    font-size:28px;
    font-weight:900;
    margin-bottom:4px;
}

.auth-desc{
    text-align:center;
    color:var(--muted);
    margin-bottom:20px;
}

.auth-switch{
    text-align:center;
    margin-top:16px;
    color:var(--muted);
}

.link-btn{
    background:none;
    color:var(--blue);
    font-weight:800;
}

/* =====================================================
BOTTOM NAV
===================================================== */

.bottom-nav{
    position:fixed;
    left:0;
    right:0;
    bottom:0;
    height:70px;
    background:white;
    border-top:1px solid var(--border);
    z-index:90;
    display:flex;
    justify-content:space-around;
    box-shadow:0 -5px 20px rgba(0,0,0,.07);
}

.bottom-item{
    flex:1;
    background:white;
    color:#7a8493;
    font-size:11px;
    display:flex;
    flex-direction:column;
    align-items:center;
    justify-content:center;
    gap:4px;
}

.bottom-item .ico{
    font-size:20px;
}

.bottom-item.active{
    color:var(--blue);
    font-weight:800;
}

/* =====================================================
NOTIFICATIONS
===================================================== */

.notification{
    display:flex;
    gap:12px;
    align-items:flex-start;
}

.notification-icon{
    width:42px;
    height:42px;
    border-radius:12px;
    background:#eaf3ff;
    color:var(--blue);
    display:flex;
    align-items:center;
    justify-content:center;
}

.notification.unread{
    border-left:4px solid var(--blue);
}

/* =====================================================
PROFILE
===================================================== */

.profile-head{
    text-align:center;
    background:linear-gradient(
        135deg,
        var(--blue),
        var(--blue2)
    );
    color:white;
    border-radius:20px;
    padding:25px 15px;
    margin-bottom:14px;
}

.avatar{
    width:74px;
    height:74px;
    border-radius:50%;
    background:white;
    color:var(--blue);
    margin:auto;
    display:flex;
    align-items:center;
    justify-content:center;
    font-size:30px;
    font-weight:900;
}

.profile-head h2{
    margin:10px 0 3px;
}

.profile-head p{
    margin:0;
    opacity:.9;
}

/* =====================================================
DASHBOARD
===================================================== */

.stats{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:10px;
}

.stat{
    background:white;
    border:1px solid var(--border);
    border-radius:16px;
    padding:15px 10px;
    text-align:center;
}

.stat-number{
    font-size:25px;
    font-weight:900;
    color:var(--blue);
}

.stat-label{
    color:var(--muted);
    font-size:11px;
    margin-top:4px;
}

/* =====================================================
EMPTY
===================================================== */

.empty{
    background:white;
    border-radius:18px;
    padding:38px 20px;
    text-align:center;
    color:var(--muted);
    border:1px solid var(--border);
}

.empty-icon{
    font-size:45px;
    margin-bottom:10px;
}

/* =====================================================
TOAST
===================================================== */

#toast{
    position:fixed;
    left:50%;
    bottom:82px;
    transform:translateX(-50%);
    background:#17202a;
    color:white;
    padding:12px 17px;
    border-radius:12px;
    z-index:500;
    max-width:90%;
    text-align:center;
    box-shadow:0 5px 25px rgba(0,0,0,.25);
}

#toast.success{
    background:#15803d;
}

#toast.error{
    background:#b91c1c;
}

/* =====================================================
DESKTOP
===================================================== */

@media(min-width:800px){

    .container{
        padding:22px;
    }

    .hero{
        padding:35px;
    }

    .hero h1{
        font-size:42px;
    }

    .jobs-grid{
        display:grid;
        grid-template-columns:repeat(2,1fr);
        gap:14px;
    }

    .jobs-grid .job-card{
        margin:0;
    }

    .bottom-nav{
        display:none;
    }

    body{
        padding-bottom:20px;
    }

    .filters{
        grid-template-columns:repeat(4,1fr);
    }
}

</style>

</head>

<body>

<!-- ===================================================
HEADER
=================================================== -->

<header class="header">

    <div class="header-inner">

        <button
            class="menu-btn"
            onclick="openMenu()"
        >
            ☰
        </button>

        <div class="logo">
            Job Mart
        </div>

        <div class="header-actions">

            <button
                class="icon-btn"
                onclick="showPage('notifications')"
            >
                🔔
            </button>

            <button
                class="icon-btn"
                onclick="showPage('profile')"
            >
                👤
            </button>

        </div>

    </div>

</header>


<!-- ===================================================
DRAWER
=================================================== -->

<div
    id="drawerBg"
    class="drawer-bg hidden"
    onclick="closeMenu()"
>

    <div
        class="drawer"
        onclick="event.stopPropagation()"
    >

        <div class="drawer-head">

            <div class="drawer-logo">
                Job Mart
            </div>

            <div
                id="drawerUser"
                class="drawer-user"
            >
                Find your next opportunity
            </div>

        </div>

        <button
            class="drawer-item"
            onclick="drawerPage('home')"
        >
            <span>🏠</span> Home
        </button>

        <button
            class="drawer-item"
            onclick="drawerPage('jobs')"
        >
            <span>💼</span> Find Jobs
        </button>

        <button
            class="drawer-item"
            onclick="drawerPage('saved')"
        >
            <span>🔖</span> Saved Jobs
        </button>

        <button
            class="drawer-item"
            onclick="drawerPage('applications')"
        >
            <span>📄</span> Applications
        </button>

        <button
            class="drawer-item"
            onclick="drawerPage('notifications')"
        >
            <span>🔔</span> Notifications
        </button>

        <button
            id="drawerPost"
            class="drawer-item hidden"
            onclick="drawerPage('post')"
        >
            <span>➕</span> Post a Job
        </button>

        <button
            class="drawer-item"
            onclick="drawerPage('profile')"
        >
            <span>👤</span> My Profile
        </button>

        <button
            id="drawerLogin"
            class="drawer-item"
            onclick="drawerPage('login')"
        >
            <span>🔐</span> Login
        </button>

        <button
            id="drawerLogout"
            class="drawer-item hidden"
            onclick="logout()"
        >
            <span>🚪</span> Logout
        </button>

    </div>

</div>


<!-- ===================================================
MAIN
=================================================== -->

<main class="container">


<!-- HOME -->

<section id="home" class="page">

    <div class="hero">

        <h1>
            Find your next opportunity
        </h1>

        <p>
            Discover jobs from employers and build your career with Job Mart.
        </p>

        <div class="search-box">

            <input
                id="homeSearch"
                placeholder="Job title, company or skills"
                onkeydown="if(event.key==='Enter') searchHome()"
            >

            <button
                class="search-button"
                onclick="searchHome()"
            >
                Search
            </button>

        </div>

    </div>


    <div class="section-title">

        <h2>
            Popular Categories
        </h2>

        <button
            class="see-all"
            onclick="showPage('jobs')"
        >
            See all
        </button>

    </div>


    <div class="categories">

        <button
            class="category"
            onclick="categorySearch('IT & Software')"
        >
            <div class="category-icon">💻</div>
            <div class="category-name">IT & Software</div>
        </button>

        <button
            class="category"
            onclick="categorySearch('Sales')"
        >
            <div class="category-icon">📈</div>
            <div class="category-name">Sales</div>
        </button>

        <button
            class="category"
            onclick="categorySearch('Marketing')"
        >
            <div class="category-icon">📢</div>
            <div class="category-name">Marketing</div>
        </button>

        <button
            class="category"
            onclick="categorySearch('Finance')"
        >
            <div class="category-icon">💰</div>
            <div class="category-name">Finance</div>
        </button>

        <button
            class="category"
            onclick="categorySearch('Healthcare')"
        >
            <div class="category-icon">🏥</div>
            <div class="category-name">Healthcare</div>
        </button>

        <button
            class="category"
            onclick="categorySearch('Education')"
        >
            <div class="category-icon">🎓</div>
            <div class="category-name">Education</div>
        </button>

    </div>


    <div class="section-title">

        <h2>
            Latest Jobs
        </h2>

        <button
            class="see-all"
            onclick="showPage('jobs')"
        >
            View all
        </button>

    </div>


    <div id="homeJobs"></div>

</section>


<!-- JOBS -->

<section
    id="jobs"
    class="page hidden"
>

    <div class="page-header">

        <h2>
            Find Jobs
        </h2>

        <div class="filters">

            <input
                id="jobSearch"
                placeholder="Search jobs"
            >

            <select id="jobCategory">

                <option value="">
                    All categories
                </option>

                <option>IT & Software</option>
                <option>Sales</option>
                <option>Marketing</option>
                <option>Finance</option>
                <option>Healthcare</option>
                <option>Education</option>
                <option>Engineering</option>
                <option>Customer Service</option>
                <option>Other</option>

            </select>

            <select id="jobCountry">

                <option value="">
                    All countries
                </option>

                <option>India</option>
                <option>USA</option>
                <option>UAE</option>
                <option>UK</option>
                <option>Other</option>

            </select>

            <select id="jobType">

                <option value="">
                    All job types
                </option>

                <option>Full-time</option>
                <option>Part-time</option>
                <option>Contract</option>
                <option>Freelance</option>
                <option>Internship</option>

            </select>

        </div>

        <button
            class="btn btn-primary"
            style="margin-top:10px;width:100%"
            onclick="loadJobs()"
        >
            🔎 Search Jobs
        </button>

    </div>


    <div id="jobsList"></div>

</section>


<!-- LOGIN -->

<section
    id="login"
    class="page hidden"
>

    <div class="auth-wrap">

        <div class="auth-card">

            <div class="auth-logo">
                Job Mart
            </div>

            <div class="auth-desc">
                Login to continue
            </div>

            <label>Email</label>

            <input
                id="loginEmail"
                type="email"
                autocomplete="email"
                placeholder="Enter email"
            >

            <label>Password</label>

            <input
                id="loginPassword"
                type="password"
                autocomplete="current-password"
                placeholder="Enter password"
            >

            <button
                class="form-button"
                onclick="login()"
            >
                Login
            </button>

            <div
                id="loginMsg"
                class="meta"
                style="margin-top:12px;text-align:center"
            ></div>

            <div class="auth-switch">

                Don't have an account?

                <button
                    class="link-btn"
                    onclick="showPage('register')"
                >
                    Create Account
                </button>

            </div>

        </div>

    </div>

</section>


<!-- REGISTER -->

<section
    id="register"
    class="page hidden"
>

    <div class="auth-wrap">

        <div class="auth-card">

            <div class="auth-logo">
                Job Mart
            </div>

            <div class="auth-desc">
                Create your free account
            </div>

            <label>Full Name</label>

            <input
                id="regName"
                placeholder="Your name"
            >

            <label>Email</label>

            <input
                id="regEmail"
                type="email"
                placeholder="Your email"
            >

            <label>Password</label>

            <input
                id="regPassword"
                type="password"
                placeholder="Minimum 6 characters"
            >

            <label>Account Type</label>

            <select id="regRole">

                <option value="jobseeker">
                    Job Seeker
                </option>

                <option value="employer">
                    Employer / Recruiter
                </option>

            </select>

            <label>Phone</label>

            <input
                id="regPhone"
                inputmode="tel"
                placeholder="Phone number"
            >

            <label>Country</label>

            <select id="regCountry">

                <option value="">
                    Select country
                </option>

                <option>India</option>
                <option>USA</option>
                <option>UAE</option>
                <option>UK</option>
                <option>Other</option>

            </select>

            <label>City</label>

            <input
                id="regCity"
                placeholder="City"
            >

            <button
                class="form-button"
                onclick="registerUser()"
            >
                Create Account
            </button>

            <div
                id="registerMsg"
                class="meta"
                style="margin-top:12px;text-align:center"
            ></div>

            <div class="auth-switch">

                Already have an account?

                <button
                    class="link-btn"
                    onclick="showPage('login')"
                >
                    Login
                </button>

            </div>

        </div>

    </div>

</section>


<!-- SAVED -->

<section
    id="saved"
    class="page hidden"
>

    <div class="page-header">

        <h2>
            🔖 Saved Jobs
        </h2>

        <p class="meta">
            Jobs you saved for later.
        </p>

    </div>

    <div id="savedList"></div>

</section>


<!-- APPLICATIONS -->

<section
    id="applications"
    class="page hidden"
>

    <div class="page-header">

        <h2>
            📄 Applications
        </h2>

        <p
            id="applicationsSub"
            class="meta"
        >
            Track your job applications.
        </p>

    </div>

    <div id="applicationsList"></div>

</section>


<!-- NOTIFICATIONS -->

<section
    id="notifications"
    class="page hidden"
>

    <div class="page-header">

        <h2>
            🔔 Notifications
        </h2>

        <button
            class="btn btn-outline"
            onclick="markNotificationsRead()"
        >
            Mark all as read
        </button>

    </div>

    <div id="notificationsList"></div>

</section>


<!-- PROFILE -->

<section
    id="profile"
    class="page hidden"
>

    <div
        id="profileHead"
        class="profile-head"
    ></div>

    <div class="form-card">

        <h2>
            My Profile
        </h2>

        <div class="form-sub">
            Update your personal information.
        </div>

        <label>Name</label>

        <input id="profileName">

        <label>Phone</label>

        <input id="profilePhone">

        <label>Country</label>

        <input id="profileCountry">

        <label>City</label>

        <input id="profileCity">

        <label>About</label>

        <textarea
            id="profileBio"
            placeholder="Tell employers about yourself..."
        ></textarea>

        <button
            class="form-button"
            onclick="updateProfile()"
        >
            Save Profile
        </button>

    </div>

</section>


<!-- POST JOB -->

<section
    id="post"
    class="page hidden"
>

    <div class="form-card">

        <h2>
            ➕ Post a Job
        </h2>

        <div class="form-sub">
            Reach job seekers on Job Mart.
        </div>

        <label>Job Title</label>

        <input
            id="jobTitle"
            placeholder="e.g. Software Developer"
        >

        <label>Company</label>

        <input
            id="jobCompany"
            placeholder="Company name"
        >

        <label>Category</label>

        <select id="jobPostCategory">

            <option>IT & Software</option>
            <option>Sales</option>
            <option>Marketing</option>
            <option>Finance</option>
            <option>Healthcare</option>
            <option>Education</option>
            <option>Engineering</option>
            <option>Customer Service</option>
            <option>Other</option>

        </select>

        <label>Country</label>

        <select id="jobPostCountry">

            <option>India</option>
            <option>USA</option>
            <option>UAE</option>
            <option>UK</option>
            <option>Other</option>

        </select>

        <label>Location / City</label>

        <input
            id="jobLocation"
            placeholder="e.g. Hyderabad"
        >

        <label>Job Type</label>

        <select id="jobPostType">

            <option>Full-time</option>
            <option>Part-time</option>
            <option>Contract</option>
            <option>Freelance</option>
            <option>Internship</option>

        </select>

        <label>Work Mode</label>

        <select id="jobWorkMode">

            <option>On-site</option>
            <option>Remote</option>
            <option>Hybrid</option>

        </select>

        <label>Salary</label>

        <input
            id="jobSalary"
            placeholder="e.g. ₹25,000 - ₹50,000"
        >

        <label>Skills</label>

        <input
            id="jobSkills"
            placeholder="Python, FastAPI, SQL..."
        >

        <label>Application Email</label>

        <input
            id="jobApplicationEmail"
            type="email"
            placeholder="hr@company.com"
        >

        <label>Job Description</label>

        <textarea
            id="jobDescription"
            placeholder="Describe the job..."
        ></textarea>

        <button
            class="form-button"
            onclick="postJob()"
        >
            Publish Job
        </button>

    </div>

</section>


<!-- JOB DETAILS -->

<section
    id="details"
    class="page hidden"
>

    <div id="jobDetails"></div>

</section>


</main>


<!-- ===================================================
BOTTOM NAV
=================================================== -->

<nav class="bottom-nav">

    <button
        class="bottom-item active"
        data-page="home"
        onclick="showPage('home')"
    >
        <span class="ico">🏠</span>
        Home
    </button>

    <button
        class="bottom-item"
        data-page="jobs"
        onclick="showPage('jobs')"
    >
        <span class="ico">💼</span>
        Jobs
    </button>

    <button
        class="bottom-item"
        data-page="saved"
        onclick="showPage('saved')"
    >
        <span class="ico">🔖</span>
        Saved
    </button>

    <button
        class="bottom-item"
        data-page="applications"
        onclick="showPage('applications')"
    >
        <span class="ico">📄</span>
        Applications
    </button>

    <button
        class="bottom-item"
        data-page="profile"
        onclick="showPage('profile')"
    >
        <span class="ico">👤</span>
        Profile
    </button>

</nav>


<div
    id="toast"
    class="hidden"
></div>


<script>

/* =====================================================
GLOBAL
===================================================== */

let ME = null;

let currentPage = "home";


/* =====================================================
API HELPER
===================================================== */

async function api(
    url,
    options = {}
){

    try{

        const response = await fetch(
            url,
            {
                credentials:"same-origin",
                ...options,
                headers:{
                    "Content-Type":"application/json",
                    ...(options.headers || {})
                }
            }
        );

        const data = await response.json()
            .catch(() => ({
                detail:"Server returned an invalid response"
            }));

        if(!response.ok){

            throw new Error(
                data.detail ||
                "Something went wrong"
            );
        }

        return data;

    }catch(error){

        throw error;
    }
}


/* =====================================================
TOAST
===================================================== */

function toast(
    message,
    type="success"
){

    const box = document.getElementById("toast");

    box.textContent = message;

    box.className = "";

    box.classList.add(type);

    setTimeout(
        () => {
            box.className = "hidden";
        },
        2800
    );
}


/* =====================================================
MENU
===================================================== */

function openMenu(){

    document
        .getElementById("drawerBg")
        .classList.remove("hidden");
}


function closeMenu(){

    document
        .getElementById("drawerBg")
        .classList.add("hidden");
}


function drawerPage(page){

    closeMenu();

    showPage(page);
}


/* =====================================================
PAGE NAVIGATION
===================================================== */

function showPage(page){

    if(
        (
            page === "saved" ||
            page === "applications" ||
            page === "notifications" ||
            page === "profile"
        )
        &&
        !ME
    ){

        toast(
            "Please login first",
            "error"
        );

        page = "login";
    }

    if(
        page === "post"
        &&
        (
            !ME ||
            !["employer","admin"].includes(ME.role)
        )
    ){

        toast(
            "Employer account required",
            "error"
        );

        page = ME ? "home" : "login";
    }

    document
        .querySelectorAll(".page")
        .forEach(
            element => {
                element.classList.add("hidden");
            }
        );

    const target =
        document.getElementById(page);

    if(target){
        target.classList.remove("hidden");
    }

    currentPage = page;

    document
        .querySelectorAll(".bottom-item")
        .forEach(
            button => {

                button.classList.toggle(
                    "active",
                    button.dataset.page === page
                );

            }
        );

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

    if(page === "saved"){
        loadSaved();
    }

    if(page === "applications"){
        loadApplications();
    }

    if(page === "notifications"){
        loadNotifications();
    }

    if(page === "profile"){
        loadProfile();
    }
}


/* =====================================================
REGISTER
===================================================== */

async function registerUser(){

    const name =
        document.getElementById("regName").value.trim();

    const email =
        document.getElementById("regEmail").value.trim();

    const password =
        document.getElementById("regPassword").value;

    const role =
        document.getElementById("regRole").value;

    const phone =
        document.getElementById("regPhone").value.trim();

    const country =
        document.getElementById("regCountry").value;

    const city =
        document.getElementById("regCity").value.trim();

    const msg =
        document.getElementById("registerMsg");


    if(!name || !email || !password){

        msg.textContent =
            "Please fill all required fields.";

        return;
    }

    if(password.length < 6){

        msg.textContent =
            "Password must be at least 6 characters.";

        return;
    }


    msg.textContent =
        "Creating account...";


    try{

        const data = await api(
            "/api/register",
            {
                method:"POST",
                body:JSON.stringify({
                    name,
                    email,
                    password,
                    role,
                    phone,
                    country,
                    city
                })
            }
        );

        toast(
            "Account created successfully"
        );

        msg.textContent =
            data.message;

        document.getElementById(
            "loginEmail"
        ).value = email;

        document.getElementById(
            "loginPassword"
        ).value = "";

        showPage("login");

    }catch(error){

        msg.textContent =
            error.message;

        toast(
            error.message,
            "error"
        );
    }
}


/* =====================================================
LOGIN
===================================================== */

async function login(){

    const email =
        document.getElementById("loginEmail").value.trim();

    const password =
        document.getElementById("loginPassword").value;

    const msg =
        document.getElementById("loginMsg");


    if(!email || !password){

        msg.textContent =
            "Enter email and password.";

        return;
    }


    msg.textContent =
        "Logging in...";


    try{

        const data = await api(
            "/api/login",
            {
                method:"POST",
                body:JSON.stringify({
                    email,
                    password
                })
            }
        );

        ME = data.user;

        msg.textContent =
            "Login successful.";

        toast(
            "Welcome, " + ME.name
        );

        updateHeader();

        showPage("home");

    }catch(error){

        msg.textContent =
            error.message;

        toast(
            error.message,
            "error"
        );
    }
}


/* =====================================================
LOGOUT
===================================================== */

async function logout(){

    try{

        await api(
            "/api/logout",
            {
                method:"POST"
            }
        );

    }catch(error){
        console.log(error);
    }

    ME = null;

    updateHeader();

    closeMenu();

    toast(
        "Logged out successfully"
    );

    showPage("home");
}


/* =====================================================
HEADER UPDATE
===================================================== */

function updateHeader(){

    const drawerUser =
        document.getElementById("drawerUser");

    const drawerLogin =
        document.getElementById("drawerLogin");

    const drawerLogout =
        document.getElementById("drawerLogout");

    const drawerPost =
        document.getElementById("drawerPost");


    if(ME){

        drawerUser.textContent =
            "Hi, " + ME.name;

        drawerLogin.classList.add(
            "hidden"
        );

        drawerLogout.classList.remove(
            "hidden"
        );

        if(
            ME.role === "employer" ||
            ME.role === "admin"
        ){

            drawerPost.classList.remove(
                "hidden"
            );

        }else{

            drawerPost.classList.add(
                "hidden"
            );
        }

    }else{

        drawerUser.textContent =
            "Find your next opportunity";

        drawerLogin.classList.remove(
            "hidden"
        );

        drawerLogout.classList.add(
            "hidden"
        );

        drawerPost.classList.add(
            "hidden"
        );
    }
}


/* =====================================================
HOME SEARCH
===================================================== */

function searchHome(){

    const q =
        document.getElementById(
            "homeSearch"
        ).value.trim();

    document.getElementById(
        "jobSearch"
    ).value = q;

    showPage("jobs");
}


/* =====================================================
CATEGORY SEARCH
===================================================== */

function categorySearch(category){

    document.getElementById(
        "jobCategory"
    ).value = category;

    showPage("jobs");
}


/* =====================================================
LOAD HOME JOBS
===================================================== */

async function loadHomeJobs(){

    const box =
        document.getElementById("homeJobs");

    box.innerHTML =
        `<div class="empty">
            Loading latest jobs...
        </div>`;


    try{

        const data =
            await api("/api/jobs");


        if(!data.jobs.length){

            box.innerHTML =
                `<div class="empty">
                    <div class="empty-icon">💼</div>
                    <b>No jobs posted yet</b>
                    <p>
                        Jobs will appear here after employers post them.
                    </p>
                </div>`;

            return;
        }


        const latest =
            data.jobs.slice(0,6);


        box.innerHTML =
            `<div class="jobs-grid">
                ${latest.map(jobCard).join("")}
            </div>`;

    }catch(error){

        box.innerHTML =
            `<div class="empty">
                Unable to load jobs.
            </div>`;
    }
}


/* =====================================================
JOB CARD
===================================================== */

function jobCard(job){

    const letter =
        (job.company || "J")
        .charAt(0)
        .toUpperCase();

    const salary =
        job.salary
        ? `<span class="badge green">💰 ${escapeHtml(job.salary)}</span>`
        : "";

    const savedButton =
        ME
        ? `
            <button
                class="btn btn-outline"
                onclick="saveJob(${job.id})"
            >
                🔖 Save
            </button>
        `
        : "";


    return `
        <div class="card job-card">

            <div class="job-top">

                <div class="company-logo">
                    ${escapeHtml(letter)}
                </div>

                <div style="flex:1">

                    <div class="job-title">
                        ${escapeHtml(job.title)}
                    </div>

                    <div class="company">
                        ${escapeHtml(job.company)}
                    </div>

                </div>

            </div>

            <div class="meta" style="margin-top:9px">

                📍 ${escapeHtml(job.location || job.country)}
                <br>

                💼 ${escapeHtml(job.job_type)}
                ·
                ${escapeHtml(job.work_mode)}

            </div>

            <div class="badges">

                <span class="badge">
                    ${escapeHtml(job.category)}
                </span>

                ${salary}

            </div>

            <div class="job-bottom">

                <button
                    class="btn btn-primary"
                    onclick="viewJob(${job.id})"
                    style="flex:1"
                >
                    View Job
                </button>

                ${savedButton}

            </div>

        </div>
    `;
}


/* =====================================================
LOAD JOBS
===================================================== */

async function loadJobs(){

    const box =
        document.getElementById("jobsList");

    box.innerHTML =
        `<div class="empty">
            Searching jobs...
        </div>`;


    const q =
        document.getElementById(
            "jobSearch"
        ).value.trim();

    const category =
        document.getElementById(
            "jobCategory"
        ).value;

    const country =
        document.getElementById(
            "jobCountry"
        ).value;

    const jobType =
        document.getElementById(
            "jobType"
        ).value;


    const params =
        new URLSearchParams();

    if(q) params.set("q",q);

    if(category) params.set(
        "category",
        category
    );

    if(country) params.set(
        "country",
        country
    );

    if(jobType) params.set(
        "job_type",
        jobType
    );


    try{

        const data =
            await api(
                "/api/jobs?" +
                params.toString()
            );


        if(!data.jobs.length){

            box.innerHTML =
                `<div class="empty">

                    <div class="empty-icon">
                        🔎
                    </div>

                    <b>No matching jobs</b>

                    <p>
                        Try another keyword or filter.
                    </p>

                </div>`;

            return;
        }


        box.innerHTML =
            `<div class="jobs-grid">
                ${data.jobs.map(jobCard).join("")}
            </div>`;

    }catch(error){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(error.message)}
            </div>`;
    }
}


/* =====================================================
VIEW JOB
===================================================== */

async function viewJob(jobId){

    showPage("details");

    const box =
        document.getElementById("jobDetails");

    box.innerHTML =
        `<div class="empty">
            Loading job...
        </div>`;


    try{

        const data =
            await api(
                `/api/jobs/${jobId}`
            );

        const job = data.job;

        box.innerHTML = `

            <div class="card">

                <button
                    class="btn btn-outline"
                    onclick="showPage('jobs')"
                >
                    ← Back to Jobs
                </button>

            </div>


            <div class="card">

                <div class="job-top">

                    <div class="company-logo">
                        ${escapeHtml(
                            (job.company || "J")
                            .charAt(0)
                            .toUpperCase()
                        )}
                    </div>

                    <div>

                        <div class="job-title"
                             style="font-size:22px">

                            ${escapeHtml(job.title)}

                        </div>

                        <div class="company">

                            ${escapeHtml(job.company)}

                        </div>

                    </div>

                </div>


                <div class="badges">

                    <span class="badge">
                        ${escapeHtml(job.category)}
                    </span>

                    <span class="badge">
                        ${escapeHtml(job.job_type)}
                    </span>

                    <span class="badge">
                        ${escapeHtml(job.work_mode)}
                    </span>

                    ${
                        job.salary
                        ? `
                        <span class="badge green">
                            💰 ${escapeHtml(job.salary)}
                        </span>
                        `
                        : ""
                    }

                </div>


                <hr style="
                    border:0;
                    border-top:1px solid var(--border);
                    margin:18px 0;
                ">


                <h3>Job Details</h3>

                <div class="meta">

                    📍
                    ${escapeHtml(
                        job.location ||
                        job.country
                    )}

                    <br>

                    👤 Posted by:
                    ${escapeHtml(
                        job.employer_name
                    )}

                </div>


                <h3 style="margin-top:22px">
                    Description
                </h3>

                <div style="
                    line-height:1.7;
                    white-space:pre-wrap;
                ">
                    ${escapeHtml(
                        job.description
                    )}
                </div>


                ${
                    job.skills
                    ? `
                    <h3 style="margin-top:22px">
                        Skills
                    </h3>

                    <div>
                        ${escapeHtml(job.skills)}
                    </div>
                    `
                    : ""
                }


                <div
                    style="
                        display:flex;
                        gap:8px;
                        margin-top:22px;
                        flex-wrap:wrap;
                    "
                >

                    ${
                        ME &&
                        ME.role === "jobseeker"
                        ? `
                            <button
                                class="btn btn-primary"
                                onclick="applyJob(${job.id})"
                            >
                                ${
                                    job.applied
                                    ? "✓ Applied"
                                    : "Apply Now"
                                }
                            </button>
                        `
                        : ""
                    }


                    ${
                        ME
                        ? `
                            <button
                                class="btn btn-outline"
                                onclick="saveJob(${job.id})"
                            >
                                🔖
                                ${
                                    job.saved
                                    ? "Saved"
                                    : "Save Job"
                                }
                            </button>
                        `
                        : `
                            <button
                                class="btn btn-primary"
                                onclick="showPage('login')"
                            >
                                Login to Apply
                            </button>
                        `
                    }

                </div>

            </div>

        `;

    }catch(error){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(error.message)}
            </div>`;
    }
}


/* =====================================================
APPLY JOB
===================================================== */

async function applyJob(jobId){

    if(!ME){

        showPage("login");

        return;
    }


    if(ME.role !== "jobseeker"){

        toast(
            "Only job seekers can apply.",
            "error"
        );

        return;
    }


    const cover =
        prompt(
            "Enter a short cover letter (optional):"
        );


    if(cover === null){
        return;
    }


    try{

        const data =
            await api(
                `/api/jobs/${jobId}/apply`,
                {
                    method:"POST",
                    body:JSON.stringify({
                        cover_letter:cover
                    })
                }
            );

        toast(
            data.message
        );

        viewJob(jobId);

    }catch(error){

        toast(
            error.message,
            "error"
        );
    }
}


/* =====================================================
SAVE JOB
===================================================== */

async function saveJob(jobId){

    if(!ME){

        toast(
            "Please login first",
            "error"
        );

        showPage("login");

        return;
    }


    try{

        const data =
            await api(
                `/api/jobs/${jobId}/save`,
                {
                    method:"POST"
                }
            );

        toast(
            data.message
        );

        if(currentPage === "saved"){
            loadSaved();
        }

    }catch(error){

        toast(
            error.message,
            "error"
        );
    }
}


/* =====================================================
SAVED
===================================================== */

async function loadSaved(){

    const box =
        document.getElementById(
            "savedList"
        );

    box.innerHTML =
        `<div class="empty">
            Loading saved jobs...
        </div>`;


    try{

        const data =
            await api(
                "/api/saved-jobs"
            );


        if(!data.jobs.length){

            box.innerHTML =
                `<div class="empty">

                    <div class="empty-icon">
                        🔖
                    </div>

                    <b>No saved jobs</b>

                    <p>
                        Save interesting jobs here.
                    </p>

                </div>`;

            return;
        }


        box.innerHTML =
            `<div class="jobs-grid">
                ${data.jobs.map(jobCard).join("")}
            </div>`;

    }catch(error){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(error.message)}
            </div>`;
    }
}


/* =====================================================
APPLICATIONS
===================================================== */

async function loadApplications(){

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


        if(!data.applications.length){

            box.innerHTML =
                `<div class="empty">

                    <div class="empty-icon">
                        📄
                    </div>

                    <b>No applications yet</b>

                </div>`;

            return;
        }


        if(
            ME.role === "employer" ||
            ME.role === "admin"
        ){

            box.innerHTML =
                data.applications.map(
                    employerApplicationCard
                ).join("");

        }else{

            box.innerHTML =
                data.applications.map(
                    applicantApplicationCard
                ).join("");
        }

    }catch(error){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(error.message)}
            </div>`;
    }
}


/* =====================================================
APPLICANT APPLICATION CARD
===================================================== */

function applicantApplicationCard(app){

    return `

        <div class="card">

            <div class="job-title">
                ${escapeHtml(app.title)}
            </div>

            <div class="company">
                ${escapeHtml(app.company)}
            </div>

            <div class="meta"
                 style="margin-top:8px">

                📍
                ${escapeHtml(
                    app.location ||
                    app.country ||
                    ""
                )}

                <br>

                💼
                ${escapeHtml(
                    app.job_type || ""
                )}

            </div>

            <div class="badges">

                <span class="badge ${
                    app.status === "selected"
                    ? "green"
                    : app.status === "rejected"
                    ? ""
                    : "orange"
                }">

                    ${escapeHtml(app.status)}

                </span>

            </div>

        </div>

    `;
}


/* =====================================================
EMPLOYER APPLICATION CARD
===================================================== */

function employerApplicationCard(app){

    const statuses = [
        "applied",
        "reviewing",
        "shortlisted",
        "rejected",
        "selected"
    ];


    return `

        <div class="card">

            <div class="job-title">

                ${escapeHtml(
                    app.applicant_name
                )}

            </div>

            <div class="company">

                Applied for:
                ${escapeHtml(app.title)}

            </div>

            <div class="meta"
                 style="margin-top:8px">

                📧
                ${escapeHtml(
                    app.applicant_email
                )}

                <br>

                📱
                ${escapeHtml(
                    app.applicant_phone || "Not provided"
                )}

            </div>


            ${
                app.cover_letter
                ? `
                    <div style="
                        margin-top:12px;
                        padding:12px;
                        background:#f7f9fc;
                        border-radius:10px;
                        white-space:pre-wrap;
                    ">
                        ${escapeHtml(
                            app.cover_letter
                        )}
                    </div>
                `
                : ""
            }


            <div style="
                margin-top:13px;
            ">

                <label>
                    Application Status
                </label>

                <select
                    onchange="
                        updateApplicationStatus(
                            ${app.id},
                            this.value
                        )
                    "
                >

                    ${statuses.map(
                        status => `
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

            </div>

        </div>

    `;
}


/* =====================================================
UPDATE APPLICATION STATUS
===================================================== */

async function updateApplicationStatus(
    id,
    status
){

    try{

        const data =
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
            data.message
        );

        loadApplications();

    }catch(error){

        toast(
            error.message,
            "error"
        );
    }
}


/* =====================================================
NOTIFICATIONS
===================================================== */

async function loadNotifications(){

    const box =
        document.getElementById(
            "notificationsList"
        );

    box.innerHTML =
        `<div class="empty">
            Loading notifications...
        </div>`;


    try{

        const data =
            await api(
                "/api/notifications"
            );


        if(!data.notifications.length){

            box.innerHTML =
                `<div class="empty">

                    <div class="empty-icon">
                        🔔
                    </div>

                    <b>No notifications</b>

                </div>`;

            return;
        }


        box.innerHTML =
            data.notifications.map(
                n => `

                    <div class="card notification ${
                        n.is_read
                        ? ""
                        : "unread"
                    }">

                        <div class="notification-icon">
                            🔔
                        </div>

                        <div>

                            <b>
                                ${escapeHtml(n.title)}
                            </b>

                            <div
                                class="meta"
                                style="margin-top:4px"
                            >
                                ${escapeHtml(n.message)}
                            </div>

                        </div>

                    </div>

                `
            ).join("");

    }catch(error){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(error.message)}
            </div>`;
    }
}


/* =====================================================
MARK NOTIFICATIONS
===================================================== */

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

    }catch(error){

        toast(
            error.message,
            "error"
        );
    }
}


/* =====================================================
PROFILE
===================================================== */

async function loadProfile(){

    if(!ME){
        showPage("login");
        return;
    }


    try{

        const data =
            await api("/api/me");

        if(!data.logged_in){

            ME = null;

            showPage("login");

            return;
        }


        ME = data.user;


        const letter =
            ME.name
            .charAt(0)
            .toUpperCase();


        document.getElementById(
            "profileHead"
        ).innerHTML = `

            <div class="avatar">
                ${escapeHtml(letter)}
            </div>

            <h2>
                ${escapeHtml(ME.name)}
            </h2>

            <p>
                ${escapeHtml(ME.email)}
            </p>

            <p style="margin-top:7px">
                ${ME.role === "employer"
                    ? "Employer / Recruiter"
                    : "Job Seeker"
                }
            </p>

        `;


        document.getElementById(
            "profileName"
        ).value = ME.name || "";

        document.getElementById(
            "profilePhone"
        ).value = ME.phone || "";

        document.getElementById(
            "profileCountry"
        ).value = ME.country || "";

        document.getElementById(
            "profileCity"
        ).value = ME.city || "";

        document.getElementById(
            "profileBio"
        ).value = ME.bio || "";


    }catch(error){

        toast(
            error.message,
            "error"
        );
    }
}


/* =====================================================
UPDATE PROFILE
===================================================== */

async function updateProfile(){

    try{

        const data =
            await api(
                "/api/profile",
                {
                    method:"PUT",
                    body:JSON.stringify({

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

                    })
                }
            );

        toast(
            data.message
        );

        const me =
            await api("/api/me");

        if(me.logged_in){

            ME = me.user;

            updateHeader();
        }

        loadProfile();

    }catch(error){

        toast(
            error.message,
            "error"
        );
    }
}


/* =====================================================
POST JOB
===================================================== */

async function postJob(){

    const title =
        document.getElementById(
            "jobTitle"
        ).value.trim();

    const company =
        document.getElementById(
            "jobCompany"
        ).value.trim();

    const category =
        document.getElementById(
            "jobPostCategory"
        ).value;

    const country =
        document.getElementById(
            "jobPostCountry"
        ).value;

    const location =
        document.getElementById(
            "jobLocation"
        ).value.trim();

    const jobType =
        document.getElementById(
            "jobPostType"
        ).value;

    const workMode =
        document.getElementById(
            "jobWorkMode"
        ).value;

    const salary =
        document.getElementById(
            "jobSalary"
        ).value.trim();

    const skills =
        document.getElementById(
            "jobSkills"
        ).value.trim();

    const applicationEmail =
        document.getElementById(
            "jobApplicationEmail"
        ).value.trim();

    const description =
        document.getElementById(
            "jobDescription"
        ).value.trim();


    if(
        !title ||
        !company ||
        !location ||
        !description
    ){

        toast(
            "Please fill all required job fields.",
            "error"
        );

        return;
    }


    try{

        const data =
            await api(
                "/api/jobs",
                {
                    method:"POST",
                    body:JSON.stringify({

                        title,
                        company,
                        category,
                        country,
                        location,
                        job_type:jobType,
                        work_mode:workMode,
                        salary,
                        description,
                        skills,
                        application_email:applicationEmail

                    })
                }
            );

        toast(
            data.message
        );


        [
            "jobTitle",
            "jobCompany",
            "jobLocation",
            "jobSalary",
            "jobSkills",
            "jobApplicationEmail",
            "jobDescription"
        ].forEach(
            id => {
                document.getElementById(
                    id
                ).value = "";
            }
        );


        showPage("jobs");

    }catch(error){

        toast(
            error.message,
            "error"
        );
    }
}


/* =====================================================
ESCAPE HTML
===================================================== */

function escapeHtml(value){

    if(value === null || value === undefined){
        return "";
    }

    return String(value)
        .replace(/&/g,"&amp;")
        .replace(/</g,"&lt;")
        .replace(/>/g,"&gt;")
        .replace(/"/g,"&quot;")
        .replace(/'/g,"&#039;");
}


/* =====================================================
INITIAL LOAD
===================================================== */

async function init(){

    try{

        const data =
            await api("/api/me");

        if(data.logged_in){

            ME = data.user;

        }else{

            ME = null;

        }

    }catch(error){

        ME = null;

    }


    updateHeader();

    showPage("home");

}


/* START */

init();

</script>

</body>

</html>
"""


# =========================================================
# HOME ROUTE
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
        "ok": True,
        "app": "Job Mart"
    }
