from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from pathlib import Path
import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone

# =========================================================
# JOB MART
# =========================================================

app = FastAPI(title="Job Mart")

DB_FILE = Path("job_mart.db")

# Temporary server sessions
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
# PASSWORD SECURITY
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


# =========================================================
# REGISTER
# =========================================================

@app.post("/api/register")
def register(data: RegisterData):

    role = data.role.lower().strip()

    if role not in ("jobseeker", "employer"):
        role = "jobseeker"

    email = data.email.strip().lower()

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
def login(data: LoginData, response: Response):

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

    response.set_cookie(
        key="jobmart_session",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 24 * 30
    )

    return {
        "ok": True,
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }


# =========================================================
# LOGOUT
# =========================================================

@app.post("/api/logout")
def logout(request: Request, response: Response):

    token = request.cookies.get("jobmart_session")

    if token:
        SESSIONS.pop(token, None)

    response.delete_cookie("jobmart_session")

    return {
        "ok": True,
        "message": "Logged out"
    }


# =========================================================
# ME
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
# JOB DETAILS
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
        "message": "Application submitted"
    }


# =========================================================
# APPLICATIONS
# =========================================================

@app.get("/api/applications")
def applications(request: Request):

    user = require_user(request)

    conn = db()

    if user["role"] == "employer":

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
                j.location
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

    existing = conn.execute(
        """
        SELECT id
        FROM saved_jobs
        WHERE job_id=?
        AND user_id=?
        """,
        (job_id, user["id"])
    ).fetchone()

    if existing:

        conn.execute(
            """
            DELETE FROM saved_jobs
            WHERE job_id=?
            AND user_id=?
            """,
            (job_id, user["id"])
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

    if user["role"] == "employer":

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

        result = {
            "role": "employer",
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
# FRONTEND
# =========================================================

HTML = r"""
<!doctype html>

<html lang="en">

<head>

<meta charset="utf-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>Job Mart</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    font-family:Arial,Helvetica,sans-serif;
    background:#f1f3f6;
    color:#17202a;
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

.header{
    background:#2874f0;
    color:white;
    position:sticky;
    top:0;
    z-index:100;
    box-shadow:0 2px 8px rgba(0,0,0,.18);
}

.header-row{
    max-width:1250px;
    margin:auto;
    min-height:62px;
    display:flex;
    align-items:center;
    gap:15px;
    padding:8px 15px;
}

.menu-btn{
    background:transparent;
    color:white;
    font-size:25px;
    padding:5px 8px;
}

.logo{
    font-size:24px;
    font-weight:bold;
    white-space:nowrap;
}

.logo small{
    display:block;
    font-size:10px;
    color:#ffe500;
    text-align:center;
}

.header-search{
    flex:1;
    display:flex;
    max-width:650px;
}

.header-search input{
    flex:1;
    border:0;
    outline:0;
    padding:12px 15px;
    border-radius:3px 0 0 3px;
    font-size:15px;
}

.header-search button{
    width:55px;
    background:white;
    color:#2874f0;
    font-size:19px;
    border-radius:0 3px 3px 0;
}

.header-login{
    background:white;
    color:#2874f0;
    font-weight:bold;
    padding:10px 25px;
    border-radius:3px;
    white-space:nowrap;
}

.header-user{
    display:none;
    align-items:center;
    gap:8px;
    font-weight:bold;
}

.container{
    max-width:1250px;
    margin:auto;
    padding:16px;
}

.page{
    display:block;
}

.hidden{
    display:none!important;
}

.hero{
    background:white;
    padding:28px;
    border-radius:4px;
    margin-bottom:16px;
    box-shadow:0 1px 3px rgba(0,0,0,.12);
}

.hero h1{
    margin:0 0 8px;
    font-size:30px;
}

.hero p{
    color:#666;
}

.hero-search{
    display:grid;
    grid-template-columns:2fr 1fr 1fr auto;
    gap:10px;
    margin-top:20px;
}

input,
select,
textarea{
    width:100%;
    border:1px solid #d5d9df;
    background:white;
    border-radius:3px;
    padding:12px;
    font-size:14px;
    outline:none;
}

input:focus,
select:focus,
textarea:focus{
    border-color:#2874f0;
}

.primary{
    background:#2874f0;
    color:white;
    padding:12px 20px;
    border-radius:3px;
    font-weight:bold;
}

.secondary{
    background:white;
    color:#2874f0;
    border:1px solid #2874f0;
    padding:10px 16px;
    border-radius:3px;
}

.danger{
    background:#e53935;
    color:white;
    padding:10px 15px;
    border-radius:3px;
}

.category-row{
    display:flex;
    gap:12px;
    overflow:auto;
    background:white;
    padding:16px;
    margin-bottom:16px;
    box-shadow:0 1px 3px rgba(0,0,0,.12);
}

.category{
    min-width:110px;
    text-align:center;
    cursor:pointer;
    padding:10px;
    border-radius:5px;
}

.category:hover{
    background:#f1f5ff;
}

.category-icon{
    font-size:30px;
    margin-bottom:5px;
}

.category-name{
    font-weight:bold;
    font-size:13px;
}

.section-title{
    background:white;
    padding:18px;
    margin-bottom:1px;
    border-bottom:1px solid #eee;
}

.grid{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:12px;
}

.card{
    background:white;
    padding:17px;
    border-radius:3px;
    box-shadow:0 1px 3px rgba(0,0,0,.12);
}

.card h3{
    margin:0 0 7px;
    font-size:17px;
}

.card p{
    margin:6px 0;
}

.meta{
    color:#666;
    font-size:13px;
    line-height:1.8;
}

.salary{
    font-weight:bold;
    margin:10px 0;
}

.badge{
    display:inline-block;
    background:#f0f5ff;
    color:#2874f0;
    padding:5px 8px;
    margin:3px 2px;
    border-radius:3px;
    font-size:11px;
}

.card-actions{
    display:flex;
    gap:8px;
    margin-top:14px;
}

.card-actions button{
    flex:1;
}

.form-card{
    max-width:720px;
    margin:20px auto;
    background:white;
    padding:25px;
    border-radius:5px;
    box-shadow:0 1px 4px rgba(0,0,0,.15);
}

.form-card h2{
    margin-top:0;
}

.form-group{
    margin-bottom:14px;
}

.form-group label{
    display:block;
    font-weight:bold;
    margin-bottom:6px;
    font-size:14px;
}

.detail{
    background:white;
    padding:25px;
    border-radius:4px;
    box-shadow:0 1px 3px rgba(0,0,0,.12);
}

.detail h1{
    margin-top:0;
}

.detail-section{
    margin-top:22px;
}

.detail-section h3{
    border-bottom:1px solid #eee;
    padding-bottom:8px;
}

.side-menu{
    position:fixed;
    left:-320px;
    top:0;
    bottom:0;
    width:300px;
    background:white;
    z-index:200;
    box-shadow:4px 0 15px rgba(0,0,0,.2);
    transition:.25s;
    overflow:auto;
}

.side-menu.open{
    left:0;
}

.side-head{
    background:#2874f0;
    color:white;
    padding:25px 20px;
}

.side-head h2{
    margin:0;
}

.side-item{
    padding:16px 20px;
    border-bottom:1px solid #eee;
    cursor:pointer;
    font-size:15px;
}

.side-item:hover{
    background:#f1f5ff;
    color:#2874f0;
}

.overlay{
    display:none;
    position:fixed;
    inset:0;
    background:rgba(0,0,0,.4);
    z-index:150;
}

.overlay.show{
    display:block;
}

.dashboard{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:15px;
}

.stat{
    background:white;
    padding:22px;
    border-radius:5px;
    box-shadow:0 1px 3px rgba(0,0,0,.12);
}

.stat-number{
    font-size:32px;
    font-weight:bold;
    color:#2874f0;
}

.table-wrap{
    overflow:auto;
    background:white;
    box-shadow:0 1px 3px rgba(0,0,0,.12);
}

table{
    width:100%;
    border-collapse:collapse;
}

th,
td{
    padding:13px;
    border-bottom:1px solid #eee;
    text-align:left;
    font-size:14px;
}

th{
    background:#fafafa;
}

.empty{
    background:white;
    padding:45px;
    text-align:center;
    color:#777;
}

.message{
    margin-top:12px;
    font-weight:bold;
}

.success{
    color:#16833a;
}

.error{
    color:#d32f2f;
}

@media(max-width:900px){

    .grid{
        grid-template-columns:repeat(2,1fr);
    }

    .hero-search{
        grid-template-columns:1fr 1fr;
    }

}

@media(max-width:600px){

    .header-row{
        gap:8px;
    }

    .logo{
        font-size:19px;
    }

    .header-search{
        order:5;
        flex-basis:100%;
        max-width:none;
    }

    .header-row{
        flex-wrap:wrap;
    }

    .header-login{
        padding:9px 13px;
    }

    .hero{
        padding:20px;
    }

    .hero h1{
        font-size:24px;
    }

    .hero-search{
        grid-template-columns:1fr;
    }

    .grid{
        grid-template-columns:1fr;
    }

    .dashboard{
        grid-template-columns:1fr;
    }

}

</style>

</head>

<body>


<!-- SIDE MENU -->

<div id="overlay" class="overlay" onclick="closeMenu()"></div>

<aside id="sideMenu" class="side-menu">

    <div class="side-head">

        <h2>Job Mart</h2>

        <div id="menuUser">
            Welcome 👋
        </div>

    </div>

    <div class="side-item" onclick="menuPage('home')">
        🏠 Home
    </div>

    <div class="side-item" onclick="menuPage('jobs')">
        💼 All Jobs
    </div>

    <div class="side-item" onclick="menuPage('categories')">
        📂 Categories
    </div>

    <div class="side-item" onclick="menuPage('saved')">
        ❤️ Saved Jobs
    </div>

    <div class="side-item" onclick="menuPage('applications')">
        📋 My Applications
    </div>

    <div class="side-item" onclick="menuPage('notifications')">
        🔔 Notifications
    </div>

    <div class="side-item" onclick="menuPage('profile')">
        👤 My Profile
    </div>

    <div id="employerMenu">

        <div class="side-item" onclick="menuPage('post')">
            ➕ Post a Job
        </div>

        <div class="side-item" onclick="menuPage('myjobs')">
            💼 My Jobs
        </div>

        <div class="side-item" onclick="menuPage('applications')">
            👥 Applicants
        </div>

    </div>

    <div class="side-item" onclick="logout()">
        🚪 Logout
    </div>

</aside>


<!-- HEADER -->

<header class="header">

<div class="header-row">

    <button
        class="menu-btn"
        onclick="toggleMenu()"
    >
        ☰
    </button>

    <div class="logo">
        Job Mart
        <small>Find • Apply • Grow</small>
    </div>

    <div class="header-search">

        <input
            id="globalSearch"
            placeholder="Search jobs, companies, skills..."
            onkeydown="if(event.key==='Enter') globalSearch()"
        >

        <button onclick="globalSearch()">
            🔍
        </button>

    </div>

    <button
        id="loginButton"
        class="header-login"
        onclick="showPage('login')"
    >
        Login
    </button>

    <div
        id="headerUser"
        class="header-user"
    >
        👤 <span id="headerName"></span>
    </div>

</div>

</header>


<!-- MAIN -->

<div class="container">


<!-- HOME -->

<section id="home" class="page">

    <div class="hero">

        <h1>
            Find your next opportunity
        </h1>

        <p>
            Search jobs posted by trusted employers.
        </p>

        <div class="hero-search">

            <input
                id="homeSearch"
                placeholder="Job title, company, skills"
            >

            <select id="homeCountry">
                <option value="">All Countries</option>
                <option>India</option>
                <option>USA</option>
                <option>UAE</option>
                <option>Other</option>
            </select>

            <select id="homeType">
                <option value="">All Job Types</option>
                <option>Full-time</option>
                <option>Part-time</option>
                <option>Contract</option>
                <option>Freelance</option>
            </select>

            <button
                class="primary"
                onclick="searchHome()"
            >
                Search
            </button>

        </div>

    </div>


    <div class="category-row">

        <div class="category" onclick="categorySearch('IT')">
            <div class="category-icon">💻</div>
            <div class="category-name">IT Jobs</div>
        </div>

        <div class="category" onclick="categorySearch('Sales')">
            <div class="category-icon">📈</div>
            <div class="category-name">Sales</div>
        </div>

        <div class="category" onclick="categorySearch('Marketing')">
            <div class="category-icon">📣</div>
            <div class="category-name">Marketing</div>
        </div>

        <div class="category" onclick="categorySearch('Finance')">
            <div class="category-icon">💰</div>
            <div class="category-name">Finance</div>
        </div>

        <div class="category" onclick="categorySearch('Teaching')">
            <div class="category-icon">📚</div>
            <div class="category-name">Teaching</div>
        </div>

        <div class="category" onclick="categorySearch('Healthcare')">
            <div class="category-icon">🏥</div>
            <div class="category-name">Healthcare</div>
        </div>

        <div class="category" onclick="categorySearch('Driver')">
            <div class="category-icon">🚗</div>
            <div class="category-name">Driver</div>
        </div>

    </div>


    <div class="section-title">
        <h2>Latest Jobs</h2>
    </div>

    <div id="homeJobs"></div>

</section>


<!-- JOBS -->

<section id="jobs" class="page hidden">

    <div class="hero">

        <h2>All Jobs</h2>

        <div class="hero-search">

            <input
                id="jobSearch"
                placeholder="Search jobs"
            >

            <select id="jobCountry">
                <option value="">All Countries</option>
                <option>India</option>
                <option>USA</option>
                <option>UAE</option>
                <option>Other</option>
            </select>

            <select id="jobType">
                <option value="">All Types</option>
                <option>Full-time</option>
                <option>Part-time</option>
                <option>Contract</option>
                <option>Freelance</option>
            </select>

            <button
                class="primary"
                onclick="loadJobs()"
            >
                Search
            </button>

        </div>

    </div>

    <div id="jobsList"></div>

</section>


<!-- LOGIN -->

<section id="login" class="page hidden">

    <div class="form-card">

        <h2>Welcome Back 👋</h2>

        <div class="form-group">
            <label>Email</label>
            <input
                id="loginEmail"
                type="email"
                placeholder="Enter email"
            >
        </div>

        <div class="form-group">
            <label>Password</label>
            <input
                id="loginPassword"
                type="password"
                placeholder="Enter password"
            >
        </div>

        <button
            class="primary"
            onclick="login()"
        >
            Login
        </button>

        <button
            class="secondary"
            onclick="showPage('register')"
        >
            Create Account
        </button>

        <div id="loginMsg" class="message"></div>

    </div>

</section>


<!-- REGISTER -->

<section id="register" class="page hidden">

    <div class="form-card">

        <h2>Create Account</h2>

        <div class="form-group">
            <label>Name</label>
            <input id="regName">
        </div>

        <div class="form-group">
            <label>Email</label>
            <input id="regEmail" type="email">
        </div>

        <div class="form-group">
            <label>Password</label>
            <input id="regPassword" type="password">
        </div>

        <div class="form-group">
            <label>Account Type</label>

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
            <label>Phone</label>
            <input id="regPhone">
        </div>

        <div class="form-group">
            <label>Country</label>
            <input id="regCountry" placeholder="India">
        </div>

        <div class="form-group">
            <label>City</label>
            <input id="regCity">
        </div>

        <button
            class="primary"
            onclick="register()"
        >
            Register
        </button>

        <button
            class="secondary"
            onclick="showPage('login')"
        >
            Login
        </button>

        <div id="regMsg" class="message"></div>

    </div>

</section>


<!-- JOB DETAIL -->

<section id="jobdetail" class="page hidden">

    <div id="jobDetailBox"></div>

</section>


<!-- SAVED -->

<section id="saved" class="page hidden">

    <div class="hero">
        <h2>❤️ Saved Jobs</h2>
    </div>

    <div id="savedList"></div>

</section>


<!-- APPLICATIONS -->

<section id="applications" class="page hidden">

    <div class="hero">
        <h2>📋 Applications</h2>
    </div>

    <div id="applicationsList"></div>

</section>


<!-- NOTIFICATIONS -->

<section id="notifications" class="page hidden">

    <div class="hero">

        <h2>🔔 Notifications</h2>

        <button
            class="secondary"
            onclick="markNotificationsRead()"
        >
            Mark All Read
        </button>

    </div>

    <div id="notificationsList"></div>

</section>


<!-- PROFILE -->

<section id="profile" class="page hidden">

    <div class="form-card">

        <h2>👤 My Profile</h2>

        <div class="form-group">
            <label>Name</label>
            <input id="profileName">
        </div>

        <div class="form-group">
            <label>Phone</label>
            <input id="profilePhone">
        </div>

        <div class="form-group">
            <label>Country</label>
            <input id="profileCountry">
        </div>

        <div class="form-group">
            <label>City</label>
            <input id="profileCity">
        </div>

        <div class="form-group">
            <label>Bio</label>
            <textarea id="profileBio"></textarea>
        </div>

        <button
            class="primary"
            onclick="updateProfile()"
        >
            Save Profile
        </button>

        <div id="profileMsg" class="message"></div>

    </div>

</section>


<!-- POST JOB -->

<section id="post" class="page hidden">

    <div class="form-card">

        <h2>➕ Post a New Job</h2>

        <div class="form-group">
            <label>Job Title</label>
            <input id="jobTitle">
        </div>

        <div class="form-group">
            <label>Company</label>
            <input id="jobCompany">
        </div>

        <div class="form-group">
            <label>Category</label>
            <input id="jobCategory" placeholder="IT">
        </div>

        <div class="form-group">
            <label>Country</label>
            <input id="jobPostCountry" placeholder="India">
        </div>

        <div class="form-group">
            <label>Location</label>
            <input id="jobLocation" placeholder="Hyderabad">
        </div>

        <div class="form-group">
            <label>Job Type</label>

            <select id="jobPostType">

                <option>Full-time</option>
                <option>Part-time</option>
                <option>Contract</option>
                <option>Freelance</option>

            </select>

        </div>

        <div class="form-group">
            <label>Work Mode</label>

            <select id="jobWorkMode">

                <option>Remote</option>
                <option>Hybrid</option>
                <option>Office</option>

            </select>

        </div>

        <div class="form-group">
            <label>Salary</label>
            <input id="jobSalary" placeholder="₹6-10 LPA">
        </div>

        <div class="form-group">
            <label>Skills</label>
            <input id="jobSkills" placeholder="Python, FastAPI, SQL">
        </div>

        <div class="form-group">
            <label>Application Email</label>
            <input id="jobEmail" type="email">
        </div>

        <div class="form-group">
            <label>Description</label>
            <textarea id="jobDescription"></textarea>
        </div>

        <button
            class="primary"
            onclick="postJob()"
        >
            Post Job
        </button>

        <div id="postMsg" class="message"></div>

    </div>

</section>


<!-- MY JOBS -->

<section id="myjobs" class="page hidden">

    <div class="hero">
        <h2>💼 My Jobs</h2>
    </div>

    <div id="myJobsList"></div>

</section>


<!-- DASHBOARD -->

<section id="dashboard" class="page hidden">

    <div class="hero">
        <h2>📊 Dashboard</h2>
    </div>

    <div id="dashboardBox"></div>

</section>


<!-- CATEGORIES -->

<section id="categories" class="page hidden">

    <div class="hero">

        <h2>📂 Job Categories</h2>

        <div class="grid">

            <div class="card" onclick="categorySearch('IT')">
                💻 IT & Software
            </div>

            <div class="card" onclick="categorySearch('Sales')">
                📈 Sales
            </div>

            <div class="card" onclick="categorySearch('Marketing')">
                📣 Marketing
            </div>

            <div class="card" onclick="categorySearch('Finance')">
                💰 Finance
            </div>

            <div class="card" onclick="categorySearch('Teaching')">
                📚 Teaching
            </div>

            <div class="card" onclick="categorySearch('Healthcare')">
                🏥 Healthcare
            </div>

            <div class="card" onclick="categorySearch('Driver')">
                🚗 Driver
            </div>

            <div class="card" onclick="categorySearch('Other')">
                📦 Other Jobs
            </div>

        </div>

    </div>

</section>


</div>


<script>

let ME = null;


// =========================================================
// API
// =========================================================

async function api(url, options={}){

    const response = await fetch(url,{
        credentials:"same-origin",
        ...options,
        headers:{
            "Content-Type":"application/json",
            ...(options.headers || {})
        }
    });

    let data = {};

    try{
        data = await response.json();
    }catch(e){}

    if(!response.ok){

        throw new Error(
            data.detail || "Something went wrong"
        );

    }

    return data;
}


// =========================================================
// MENU
// =========================================================

function toggleMenu(){

    document
        .getElementById("sideMenu")
        .classList.toggle("open");

    document
        .getElementById("overlay")
        .classList.toggle("show");

}


function closeMenu(){

    document
        .getElementById("sideMenu")
        .classList.remove("open");

    document
        .getElementById("overlay")
        .classList.remove("show");

}


function menuPage(page){

    closeMenu();

    if(
        page !== "home" &&
        page !== "jobs" &&
        page !== "categories" &&
        !ME
    ){
        showPage("login");
        return;
    }

    showPage(page);

}


// =========================================================
// PAGE
// =========================================================

function showPage(page){

    document
        .querySelectorAll(".page")
        .forEach(x => x.classList.add("hidden"));

    const element =
        document.getElementById(page);

    if(element){
        element.classList.remove("hidden");
    }

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

    if(page === "myjobs"){
        loadMyJobs();
    }

    if(page === "dashboard"){
        loadDashboard();
    }

}


// =========================================================
// AUTH UI
// =========================================================

function updateAuthUI(){

    const loginButton =
        document.getElementById("loginButton");

    const headerUser =
        document.getElementById("headerUser");

    const headerName =
        document.getElementById("headerName");

    const employerMenu =
        document.getElementById("employerMenu");

    const menuUser =
        document.getElementById("menuUser");


    if(ME){

        loginButton.style.display="none";

        headerUser.style.display="flex";

        headerName.textContent =
            ME.name;

        menuUser.textContent =
            "Hello, " + ME.name;

        if(ME.role === "employer"){

            employerMenu.style.display="block";

        }else{

            employerMenu.style.display="none";

        }

    }else{

        loginButton.style.display="block";

        headerUser.style.display="none";

        employerMenu.style.display="none";

        menuUser.textContent =
            "Please Login";

    }

}


// =========================================================
// CHECK LOGIN
// =========================================================

async function checkMe(){

    try{

        const data =
            await api("/api/me");

        if(data.logged_in){

            ME = data.user;

        }else{

            ME = null;

        }

        updateAuthUI();

    }catch(e){

        ME = null;

        updateAuthUI();

    }

}


// =========================================================
// REGISTER
// =========================================================

async function register(){

    const msg =
        document.getElementById("regMsg");

    msg.textContent="Creating account...";
    msg.className="message";


    try{

        await api(
            "/api/register",
            {
                method:"POST",
                body:JSON.stringify({

                    name:
                        document.getElementById("regName").value,

                    email:
                        document.getElementById("regEmail").value,

                    password:
                        document.getElementById("regPassword").value,

                    role:
                        document.getElementById("regRole").value,

                    phone:
                        document.getElementById("regPhone").value,

                    country:
                        document.getElementById("regCountry").value,

                    city:
                        document.getElementById("regCity").value

                })
            }
        );


        msg.textContent =
            "Registration successful. Please login.";

        msg.className =
            "message success";


        setTimeout(
            () => showPage("login"),
            900
        );


    }catch(e){

        msg.textContent =
            e.message;

        msg.className =
            "message error";

    }

}


// =========================================================
// LOGIN
// =========================================================

async function login(){

    const msg =
        document.getElementById("loginMsg");

    msg.textContent="Logging in...";
    msg.className="message";


    try{

        const data =
            await api(
                "/api/login",
                {
                    method:"POST",
                    body:JSON.stringify({

                        email:
                            document.getElementById("loginEmail").value,

                        password:
                            document.getElementById("loginPassword").value

                    })
                }
            );


        ME = data.user;

        updateAuthUI();

        msg.textContent =
            "Login successful";

        msg.className =
            "message success";


        setTimeout(
            () => showPage("home"),
            500
        );


    }catch(e){

        msg.textContent =
            e.message;

        msg.className =
            "message error";

    }

}


// =========================================================
// LOGOUT
// =========================================================

async function logout(){

    try{

        await api(
            "/api/logout",
            {
                method:"POST"
            }
        );

    }catch(e){}


    ME = null;

    updateAuthUI();

    closeMenu();

    showPage("home");

}


// =========================================================
// JOB CARD
// =========================================================

function jobCard(job){

    return `

    <div class="card">

        <h3>
            ${escapeHtml(job.title)}
        </h3>

        <p>
            <b>
                ${escapeHtml(job.company)}
            </b>
        </p>

        <div class="meta">

            📍 ${escapeHtml(job.location || job.country)}

            <br>

            💼 ${escapeHtml(job.job_type)}

            <br>

            🏠 ${escapeHtml(job.work_mode)}

        </div>

        <div class="salary">
            ${escapeHtml(job.salary || "Salary not disclosed")}
        </div>

        <div>

            <span class="badge">
                ${escapeHtml(job.category)}
            </span>

            <span class="badge">
                ${escapeHtml(job.country)}
            </span>

        </div>

        <div class="card-actions">

            <button
                class="primary"
                onclick="viewJob(${job.id})"
            >
                View Job
            </button>

            ${
                ME
                ?
                `<button
                    class="secondary"
                    onclick="saveJob(${job.id})"
                >
                    ❤️
                </button>`
                :
                ""
            }

        </div>

    </div>

    `;

}


// =========================================================
// HOME JOBS
// =========================================================

async function loadHomeJobs(){

    const box =
        document.getElementById("homeJobs");

    try{

        const data =
            await api("/api/jobs");

        const jobs =
            data.jobs.slice(0,8);

        if(!jobs.length){

            box.innerHTML =
                `<div class="empty">
                    No jobs available yet.
                </div>`;

            return;

        }

        box.innerHTML =
            `<div class="grid">
                ${jobs.map(jobCard).join("")}
            </div>`;

    }catch(e){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(e.message)}
            </div>`;

    }

}


// =========================================================
// SEARCH
// =========================================================

function searchHome(){

    const q =
        document.getElementById("homeSearch").value;

    const country =
        document.getElementById("homeCountry").value;

    const type =
        document.getElementById("homeType").value;


    document.getElementById("jobSearch").value=q;
    document.getElementById("jobCountry").value=country;
    document.getElementById("jobType").value=type;

    showPage("jobs");

    loadJobs();

}


function globalSearch(){

    const q =
        document.getElementById("globalSearch").value;

    document.getElementById("jobSearch").value=q;

    showPage("jobs");

    loadJobs();

}


function categorySearch(category){

    document.getElementById("jobSearch").value="";
    document.getElementById("jobCountry").value="";
    document.getElementById("jobType").value="";

    showPage("jobs");

    loadJobs(category);

}


// =========================================================
// JOBS
// =========================================================

async function loadJobs(category=""){

    const box =
        document.getElementById("jobsList");

    const q =
        document.getElementById("jobSearch").value;

    const country =
        document.getElementById("jobCountry").value;

    const type =
        document.getElementById("jobType").value;


    let url =
        "/api/jobs?q="
        + encodeURIComponent(q)
        + "&country="
        + encodeURIComponent(country)
        + "&job_type="
        + encodeURIComponent(type);


    if(category){

        url +=
            "&category="
            + encodeURIComponent(category);

    }


    box.innerHTML =
        `<div class="empty">
            Loading jobs...
        </div>`;


    try{

        const data =
            await api(url);

        if(!data.jobs.length){

            box.innerHTML =
                `<div class="empty">
                    No jobs found.
                </div>`;

            return;

        }

        box.innerHTML =
            `<div class="grid">
                ${data.jobs.map(jobCard).join("")}
            </div>`;

    }catch(e){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(e.message)}
            </div>`;

    }

}


// =========================================================
// VIEW JOB
// =========================================================

async function viewJob(id){

    showPage("jobdetail");

    const box =
        document.getElementById("jobDetailBox");

    box.innerHTML =
        `<div class="empty">
            Loading...
        </div>`;


    try{

        const data =
            await api("/api/jobs/" + id);

        const job =
            data.job;


        box.innerHTML = `

        <div class="detail">

            <h1>
                ${escapeHtml(job.title)}
            </h1>

            <h3>
                ${escapeHtml(job.company)}
            </h3>

            <div class="meta">

                📍 ${escapeHtml(job.location || job.country)}
                <br>
                💼 ${escapeHtml(job.job_type)}
                <br>
                🏠 ${escapeHtml(job.work_mode)}
                <br>
                💰 ${escapeHtml(job.salary || "Not disclosed")}
                <br>
                👤 Posted by ${escapeHtml(job.employer_name)}

            </div>


            <div class="detail-section">

                <h3>Job Description</h3>

                <p>
                    ${escapeHtml(job.description)}
                </p>

            </div>


            <div class="detail-section">

                <h3>Skills</h3>

                <p>
                    ${escapeHtml(job.skills || "Not specified")}
                </p>

            </div>


            <div class="card-actions">

                ${
                    ME && ME.role === "jobseeker"
                    ?
                    `
                    <button
                        class="primary"
                        onclick="applyJob(${job.id})"
                        ${job.applied ? "disabled" : ""}
                    >
                        ${job.applied ? "Already Applied" : "Apply Now"}
                    </button>
                    `
                    :
                    ""
                }


                ${
                    ME
                    ?
                    `
                    <button
                        class="secondary"
                        onclick="saveJob(${job.id})"
                    >
                        ❤️ ${job.saved ? "Saved" : "Save Job"}
                    </button>
                    `
                    :
                    `
                    <button
                        class="primary"
                        onclick="showPage('login')"
                    >
                        Login to Apply
                    </button>
                    `
                }

            </div>

        </div>

        `;

    }catch(e){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(e.message)}
            </div>`;

    }

}


// =========================================================
// APPLY
// =========================================================

async function applyJob(id){

    if(!ME){

        showPage("login");
        return;

    }


    const cover =
        prompt(
            "Write your cover letter:",
            "I am interested in this position."
        );


    if(cover === null){
        return;
    }


    try{

        const data =
            await api(
                "/api/jobs/" + id + "/apply",
                {
                    method:"POST",
                    body:JSON.stringify({
                        cover_letter:cover
                    })
                }
            );


        alert(data.message);

        viewJob(id);

    }catch(e){

        alert(e.message);

    }

}


// =========================================================
// SAVE
// =========================================================

async function saveJob(id){

    if(!ME){

        showPage("login");
        return;

    }


    try{

        const data =
            await api(
                "/api/jobs/" + id + "/save",
                {
                    method:"POST"
                }
            );


        alert(data.message);

        if(
            !document
                .getElementById("jobdetail")
                .classList.contains("hidden")
        ){
            viewJob(id);
        }

    }catch(e){

        alert(e.message);

    }

}


// =========================================================
// SAVED
// =========================================================

async function loadSaved(){

    const box =
        document.getElementById("savedList");

    try{

        const data =
            await api("/api/saved-jobs");

        if(!data.jobs.length){

            box.innerHTML =
                `<div class="empty">
                    No saved jobs.
                </div>`;

            return;

        }

        box.innerHTML =
            `<div class="grid">
                ${data.jobs.map(jobCard).join("")}
            </div>`;

    }catch(e){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(e.message)}
            </div>`;

    }

}


// =========================================================
// APPLICATIONS
// =========================================================

async function loadApplications(){

    const box =
        document.getElementById("applicationsList");

    try{

        const data =
            await api("/api/applications");

        const list =
            data.applications;


        if(!list.length){

            box.innerHTML =
                `<div class="empty">
                    No applications yet.
                </div>`;

            return;

        }


        if(ME.role === "employer"){

            box.innerHTML = `

            <div class="table-wrap">

                <table>

                    <tr>
                        <th>Job</th>
                        <th>Applicant</th>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>Status</th>
                    </tr>

                    ${list.map(a => `

                    <tr>

                        <td>
                            ${escapeHtml(a.title)}
                        </td>

                        <td>
                            ${escapeHtml(a.applicant_name)}
                        </td>

                        <td>
                            ${escapeHtml(a.applicant_email)}
                        </td>

                        <td>
                            ${escapeHtml(a.applicant_phone || "-")}
                        </td>

                        <td>
                            ${escapeHtml(a.status)}
                        </td>

                    </tr>

                    `).join("")}

                </table>

            </div>

            `;

        }else{

            box.innerHTML = `

            <div class="table-wrap">

                <table>

                    <tr>
                        <th>Job</th>
                        <th>Company</th>
                        <th>Location</th>
                        <th>Status</th>
                    </tr>

                    ${list.map(a => `

                    <tr>

                        <td>
                            ${escapeHtml(a.title)}
                        </td>

                        <td>
                            ${escapeHtml(a.company)}
                        </td>

                        <td>
                            ${escapeHtml(a.location || a.country)}
                        </td>

                        <td>
                            ${escapeHtml(a.status)}
                        </td>

                    </tr>

                    `).join("")}

                </table>

            </div>

            `;

        }

    }catch(e){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(e.message)}
            </div>`;

    }

}


// =========================================================
// NOTIFICATIONS
// =========================================================

async function loadNotifications(){

    const box =
        document.getElementById("notificationsList");

    try{

        const data =
            await api("/api/notifications");

        if(!data.notifications.length){

            box.innerHTML =
                `<div class="empty">
                    No notifications.
                </div>`;

            return;

        }


        box.innerHTML =
            `<div class="grid">
                ${data.notifications.map(n => `

                    <div class="card">

                        <h3>
                            ${escapeHtml(n.title)}
                        </h3>

                        <p>
                            ${escapeHtml(n.message)}
                        </p>

                        <div class="meta">
                            ${escapeHtml(n.created_at)}
                        </div>

                    </div>

                `).join("")}
            </div>`;

    }catch(e){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(e.message)}
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

        loadNotifications();

    }catch(e){

        alert(e.message);

    }

}


// =========================================================
// PROFILE
// =========================================================

async function loadProfile(){

    if(!ME){
        showPage("login");
        return;
    }


    document.getElementById("profileName").value =
        ME.name || "";

    document.getElementById("profilePhone").value =
        ME.phone || "";

    document.getElementById("profileCountry").value =
        ME.country || "";

    document.getElementById("profileCity").value =
        ME.city || "";

    document.getElementById("profileBio").value =
        ME.bio || "";

}


async function updateProfile(){

    try{

        await api(
            "/api/profile",
            {
                method:"PUT",
                body:JSON.stringify({

                    name:
                        document.getElementById("profileName").value,

                    phone:
                        document.getElementById("profilePhone").value,

                    country:
                        document.getElementById("profileCountry").value,

                    city:
                        document.getElementById("profileCity").value,

                    bio:
                        document.getElementById("profileBio").value

                })
            }
        );


        await checkMe();

        document.getElementById("profileMsg").textContent =
            "Profile updated successfully";

        document.getElementById("profileMsg").className =
            "message success";

    }catch(e){

        document.getElementById("profileMsg").textContent =
            e.message;

        document.getElementById("profileMsg").className =
            "message error";

    }

}


// =========================================================
// POST JOB
// =========================================================

async function postJob(){

    const msg =
        document.getElementById("postMsg");

    try{

        const data =
            await api(
                "/api/jobs",
                {
                    method:"POST",
                    body:JSON.stringify({

                        title:
                            document.getElementById("jobTitle").value,

                        company:
                            document.getElementById("jobCompany").value,

                        category:
                            document.getElementById("jobCategory").value,

                        country:
                            document.getElementById("jobPostCountry").value,

                        location:
                            document.getElementById("jobLocation").value,

                        job_type:
                            document.getElementById("jobPostType").value,

                        work_mode:
                            document.getElementById("jobWorkMode").value,

                        salary:
                            document.getElementById("jobSalary").value,

                        skills:
                            document.getElementById("jobSkills").value,

                        application_email:
                            document.getElementById("jobEmail").value,

                        description:
                            document.getElementById("jobDescription").value

                    })
                }
            );


        msg.textContent =
            data.message;

        msg.className =
            "message success";


        document
            .querySelectorAll("#post input, #post textarea")
            .forEach(x => x.value="");


        setTimeout(
            () => showPage("myjobs"),
            700
        );

    }catch(e){

        msg.textContent =
            e.message;

        msg.className =
            "message error";

    }

}


// =========================================================
// MY JOBS
// =========================================================

async function loadMyJobs(){

    const box =
        document.getElementById("myJobsList");

    try{

        const data =
            await api("/api/jobs?mine=true");


        if(!data.jobs.length){

            box.innerHTML =
                `<div class="empty">
                    You have not posted any jobs.
                </div>`;

            return;

        }


        box.innerHTML =
            `<div class="grid">
                ${data.jobs.map(job => `

                    <div class="card">

                        <h3>
                            ${escapeHtml(job.title)}
                        </h3>

                        <p>
                            ${escapeHtml(job.company)}
                        </p>

                        <div class="meta">
                            ${escapeHtml(job.location)}
                            <br>
                            ${escapeHtml(job.job_type)}
                            <br>
                            Status:
                            ${escapeHtml(job.status)}
                        </div>

                        <div class="card-actions">

                            <button
                                class="primary"
                                onclick="viewJob(${job.id})"
                            >
                                View
                            </button>

                            ${
                                job.status === "active"
                                ?
                                `
                                <button
                                    class="danger"
                                    onclick="closeJob(${job.id})"
                                >
                                    Close
                                </button>
                                `
                                :
                                ""
                            }

                        </div>

                    </div>

                `).join("")}
            </div>`;

    }catch(e){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(e.message)}
            </div>`;

    }

}


// =========================================================
// CLOSE JOB
// =========================================================

async function closeJob(id){

    if(!confirm("Close this job?")){
        return;
    }


    try{

        const data =
            await api(
                "/api/jobs/" + id,
                {
                    method:"DELETE"
                }
            );


        alert(data.message);

        loadMyJobs();

    }catch(e){

        alert(e.message);

    }

}


// =========================================================
// DASHBOARD
// =========================================================

async function loadDashboard(){

    const box =
        document.getElementById("dashboardBox");

    try{

        const data =
            await api("/api/dashboard");

        const d =
            data.dashboard;


        if(d.role === "employer"){

            box.innerHTML = `

                <div class="dashboard">

                    <div class="stat">
                        <div>Total Jobs</div>
                        <div class="stat-number">
                            ${d.jobs_posted}
                        </div>
                    </div>

                    <div class="stat">
                        <div>Active Jobs</div>
                        <div class="stat-number">
                            ${d.active_jobs}
                        </div>
                    </div>

                    <div class="stat">
                        <div>Applications</div>
                        <div class="stat-number">
                            ${d.applications}
                        </div>
                    </div>

                </div>

            `;

        }else{

            box.innerHTML = `

                <div class="dashboard">

                    <div class="stat">
                        <div>Applications</div>
                        <div class="stat-number">
                            ${d.applications}
                        </div>
                    </div>

                    <div class="stat">
                        <div>Saved Jobs</div>
                        <div class="stat-number">
                            ${d.saved_jobs}
                        </div>
                    </div>

                </div>

            `;

        }

    }catch(e){

        box.innerHTML =
            `<div class="empty">
                ${escapeHtml(e.message)}
            </div>`;

    }

}


// =========================================================
// ESCAPE HTML
// =========================================================

function escapeHtml(value){

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


// =========================================================
// START
// =========================================================

async function startApp(){

    await checkMe();

    showPage("home");

}

startApp();

</script>

</body>

</html>
"""


# =========================================================
# FRONTEND ROUTE
# =========================================================

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML


# =========================================================
# RUN
# =========================================================

# Start with:
# uvicorn main:app --host 0.0.0.0 --port 8000
