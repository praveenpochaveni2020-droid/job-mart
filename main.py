from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from pathlib import Path
import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone

# =========================================================
# APP
# =========================================================

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
# SESSION
# =========================================================

SESSIONS = {}


def current_user(request: Request):

    token = request.cookies.get("jobmart_session")

    if not token:
        return None

    if token not in SESSIONS:
        return None

    conn = db()

    user = conn.execute(
        "SELECT * FROM users WHERE id=?",
        (SESSIONS[token],)
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

    name: str = Field(
        min_length=2,
        max_length=100
    )

    email: str

    password: str = Field(
        min_length=6
    )

    role: str = "jobseeker"

    phone: str = ""

    country: str = ""

    city: str = ""


class LoginData(BaseModel):

    email: str
    password: str


class ProfileData(BaseModel):

    name: str = Field(
        min_length=2,
        max_length=100
    )

    phone: str = ""

    country: str = ""

    city: str = ""

    bio: str = ""


class JobData(BaseModel):

    title: str = Field(
        min_length=2,
        max_length=150
    )

    company: str = Field(
        min_length=2,
        max_length=150
    )

    category: str

    country: str

    location: str = ""

    job_type: str

    work_mode: str

    salary: str = ""

    description: str = Field(
        min_length=5
    )

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

    return {
        "ok": True,
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        },
        "_session_token": token
    }


@app.post("/api/logout")
def logout(request: Request):

    token = request.cookies.get(
        "jobmart_session"
    )

    if token:
        SESSIONS.pop(token, None)

    response = {
        "ok": True,
        "message": "Logged out"
    }

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
# JOBS
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

        val = f"%{q.strip().lower()}%"

        params.extend([
            val,
            val,
            val,
            val
        ])

    if category.strip():

        sql += """
        AND LOWER(j.category)=LOWER(?)
        """

        params.append(
            category.strip()
        )

    if country.strip():

        sql += """
        AND LOWER(j.country)=LOWER(?)
        """

        params.append(
            country.strip()
        )

    if job_type.strip():

        sql += """
        AND LOWER(j.job_type)=LOWER(?)
        """

        params.append(
            job_type.strip()
        )

    if work_mode.strip():

        sql += """
        AND LOWER(j.work_mode)=LOWER(?)
        """

        params.append(
            work_mode.strip()
        )

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

        params.append(
            user["id"]
        )

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

    if user["role"] == "employer":

        rows = conn.execute(
            """
            SELECT
                a.*,
                j.title,
                j.company,
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
    background:#f4f6f8;
    color:#17202a;
}

header{
    background:#0878e8;
    color:white;
    padding:12px 16px;
    position:sticky;
    top:0;
    z-index:100;
    box-shadow:0 2px 10px rgba(0,0,0,.12);
}

.top{
    max-width:1150px;
    margin:auto;
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:10px;
}

.logo{
    font-size:24px;
    font-weight:800;
    letter-spacing:.3px;
}

.logo span{
    color:#ffe600;
}

.top-right{
    display:flex;
    align-items:center;
    gap:8px;
}

.container{
    max-width:1150px;
    margin:auto;
    padding:18px;
}

nav{
    display:flex;
    gap:7px;
    overflow-x:auto;
    padding:8px 0 14px;
}

nav button{
    background:white;
    color:#17202a;
    white-space:nowrap;
    border:1px solid #e0e5ea;
}

button{
    border:0;
    border-radius:9px;
    padding:11px 15px;
    font-size:15px;
    cursor:pointer;
}

button:active{
    transform:scale(.98);
}

.primary{
    background:#0878e8;
    color:white;
}

.white{
    background:white;
    color:#0878e8;
}

.danger{
    background:#dc3545;
    color:white;
}

.secondary{
    background:#eef2f6;
    color:#17202a;
}

.hero{
    background:white;
    border-radius:17px;
    padding:25px;
    margin-bottom:18px;
    box-shadow:0 2px 10px rgba(0,0,0,.05);
}

.hero h1{
    margin:0 0 8px;
    font-size:31px;
}

.hero p{
    color:#667085;
}

.search{
    display:grid;
    grid-template-columns:2fr 1fr 1fr auto;
    gap:9px;
    margin-top:18px;
}

input,
select,
textarea{
    width:100%;
    padding:12px;
    border:1px solid #ccd3da;
    border-radius:9px;
    font-size:15px;
    background:white;
    outline:none;
}

input:focus,
select:focus,
textarea:focus{
    border-color:#0878e8;
    box-shadow:0 0 0 2px rgba(8,120,232,.08);
}

textarea{
    min-height:130px;
    resize:vertical;
}

.grid{
    display:grid;
    grid-template-columns:repeat(
        auto-fit,
        minmax(270px,1fr)
    );
    gap:15px;
}

.card{
    background:white;
    border-radius:15px;
    padding:18px;
    box-shadow:0 2px 9px rgba(0,0,0,.06);
}

.card h3{
    margin:0 0 8px;
}

.meta{
    color:#667085;
    font-size:14px;
    line-height:1.75;
}

.badge{
    display:inline-block;
    padding:5px 9px;
    border-radius:20px;
    background:#e8f2ff;
    color:#0878e8;
    font-size:12px;
    margin:3px 3px 3px 0;
}

.actions{
    display:flex;
    flex-wrap:wrap;
    gap:8px;
    margin-top:13px;
}

.form{
    background:white;
    padding:22px;
    border-radius:15px;
    max-width:750px;
    margin:auto;
    box-shadow:0 2px 10px rgba(0,0,0,.05);
}

.form label{
    display:block;
    font-weight:bold;
    margin:13px 0 6px;
}

.empty{
    background:white;
    padding:40px 20px;
    text-align:center;
    border-radius:15px;
    color:#667085;
}

.hidden{
    display:none!important;
}

.page{
    animation:fade .15s ease;
}

@keyframes fade{
    from{
        opacity:.5;
        transform:translateY(3px);
    }
    to{
        opacity:1;
        transform:none;
    }
}

.stat-grid{
    display:grid;
    grid-template-columns:repeat(
        auto-fit,
        minmax(160px,1fr)
    );
    gap:12px;
}

.stat{
    background:white;
    border-radius:14px;
    padding:20px;
    box-shadow:0 2px 8px rgba(0,0,0,.05);
}

.stat strong{
    display:block;
    font-size:28px;
    color:#0878e8;
    margin-top:7px;
}

.job-title{
    color:#0878e8;
    cursor:pointer;
}

.detail{
    line-height:1.7;
}

.notification{
    border-left:4px solid #0878e8;
}

.unread{
    background:#eef7ff;
}

.small{
    font-size:13px;
    color:#667085;
}

hr{
    border:0;
    border-top:1px solid #e8ebee;
    margin:17px 0;
}

@media(max-width:700px){

    .container{
        padding:12px;
    }

    .hero{
        padding:18px;
    }

    .hero h1{
        font-size:25px;
    }

    .search{
        grid-template-columns:1fr;
    }

    .top{
        align-items:center;
    }

    .logo{
        font-size:21px;
    }

    .grid{
        grid-template-columns:1fr;
    }

    nav{
        margin-left:-4px;
        margin-right:-4px;
    }

}

</style>

</head>

<body>

<header>

<div class="top">

<div class="logo">
Job <span>Mart</span>
</div>

<div
class="top-right"
id="authButtons"
>
<button
class="white"
onclick="showPage('login')"
>
Login
</button>

</div>

</div>

</header>

<div class="container">

<nav id="nav" class="hidden">

<button onclick="showPage('home')">
Home
</button>

<button onclick="showPage('jobs')">
Jobs
</button>

<button onclick="showPage('saved')">
Saved
</button>

<button onclick="showPage('applications')">
Applications
</button>

<button onclick="showPage('notifications')">
Notifications
</button>

<button onclick="showPage('profile')">
Profile
</button>

<button
id="postBtn"
class="hidden"
onclick="showPage('post')"
>
Post Job
</button>

<button onclick="logout()">
Logout
</button>

</nav>


<!-- HOME -->

<section
id="home"
class="page"
>

<div class="hero">

<h1>
Find your next opportunity
</h1>

<p>
Search jobs posted by employers.
</p>

<div class="search">

<input
id="homeSearch"
placeholder="Job title, company, skills"
/>

<select id="homeCountry">

<option value="">
All countries
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
All job types
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
class="primary"
onclick="searchHome()"
>
Search
</button>

</div>

</div>

<div id="homeJobs"></div>

</section>


<!-- JOBS -->

<section
id="jobs"
class="page hidden"
>

<div class="hero">

<h2>
Jobs
</h2>

<div class="search">

<input
id="jobSearch"
placeholder="Search jobs"
/>

<select id="jobCountry">

<option value="">
All countries
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
All types
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

<section
id="login"
class="page hidden"
>

<div class="form">

<h2>
Login
</h2>

<label>
Email
</label>

<input
id="loginEmail"
type="email"
placeholder="Enter email"
/>

<label>
Password
</label>

<input
id="loginPassword"
type="password"
placeholder="Enter password"
/>

<br><br>

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
Create account
</button>

<p id="loginMsg"></p>

</div>

</section>


<!-- REGISTER -->

<section
id="register"
class="page hidden"
>

<div class="form">

<h2>
Create Job Mart Account
</h2>

<label>
Full Name
</label>

<input
id="regName"
placeholder="Your name"
/>

<label>
Email
</label>

<input
id="regEmail"
type="email"
placeholder="you@example.com"
/>

<label>
Password
</label>

<input
id="regPassword"
type="password"
placeholder="Minimum 6 characters"
/>

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

<label>
Phone
</label>

<input
id="regPhone"
placeholder="Phone number"
/>

<label>
Country
</label>

<select id="regCountry">

<option value="">
Select country
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

<label>
City
</label>

<input
id="regCity"
placeholder="City"
/>

<br><br>

<button
class="primary"
onclick="registerUser()"
>
Create Account
</button>

<button
class="secondary"
onclick="showPage('login')"
>
Already have account
</button>

<p id="registerMsg"></p>

</div>

</section>


<!-- JOB DETAIL -->

<section
id="jobDetail"
class="page hidden"
>

<div id="jobDetailBox"></div>

</section>


<!-- SAVED -->

<section
id="saved"
class="page hidden"
>

<div class="hero">

<h2>
Saved Jobs
</h2>

<p>
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

<div class="hero">

<h2>
Applications
</h2>

<p id="applicationIntro"></p>

</div>

<div id="applicationsList"></div>

</section>


<!-- NOTIFICATIONS -->

<section
id="notifications"
class="page hidden"
>

<div class="hero">

<h2>
Notifications
</h2>

<button
class="secondary"
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

<div class="form">

<h2>
My Profile
</h2>

<label>
Name
</label>

<input id="profileName">

<label>
Phone
</label>

<input id="profilePhone">

<label>
Country
</label>

<input id="profileCountry">

<label>
City
</label>

<input id="profileCity">

<label>
Bio
</label>

<textarea
id="profileBio"
placeholder="Tell employers about yourself"
></textarea>

<br>

<button
class="primary"
onclick="updateProfile()"
>
Save Profile
</button>

<p id="profileMsg"></p>

</div>

</section>


<!-- POST JOB -->

<section
id="post"
class="page hidden"
>

<div class="form">

<h2>
Post a Job
</h2>

<label>
Job Title
</label>

<input
id="postTitle"
placeholder="Software Developer"
/>

<label>
Company
</label>

<input
id="postCompany"
placeholder="Company name"
/>

<label>
Category
</label>

<select id="postCategory">

<option>
IT & Software
</option>

<option>
Sales
</option>

<option>
Marketing
</option>

<option>
Finance
</option>

<option>
Education
</option>

<option>
Healthcare
</option>

<option>
Engineering
</option>

<option>
Other
</option>

</select>

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

<label>
Location
</label>

<input
id="postLocation"
placeholder="Hyderabad"
/>

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

<label>
Work Mode
</label>

<select id="postMode">

<option>
On-site
</option>

<option>
Remote
</option>

<option>
Hybrid
</option>

</select>

<label>
Salary
</label>

<input
id="postSalary"
placeholder="₹3,00,000 - ₹6,00,000"
/>

<label>
Skills
</label>

<input
id="postSkills"
placeholder="Python, FastAPI, SQL"
/>

<label>
Application Email
</label>

<input
id="postEmail"
type="email"
placeholder="jobs@company.com"
/>

<label>
Job Description
</label>

<textarea
id="postDescription"
placeholder="Describe the job..."
></textarea>

<br>

<button
class="primary"
onclick="postJob()"
>
Publish Job
</button>

<p id="postMsg"></p>

</div>

</section>


<!-- DASHBOARD -->

<section
id="dashboard"
class="page hidden"
>

<div class="hero">

<h2>
Dashboard
</h2>

<div
id="dashboardStats"
class="stat-grid"
></div>

</div>

</section>

</div>


<script>

let currentUser = null;


/* ========================================================
   API HELPER
======================================================== */

async function api(
    url,
    options = {}
){

    options.headers = {
        "Content-Type":"application/json",
        ...(options.headers || {})
    };

    const response =
        await fetch(url, options);

    let data = {};

    try{
        data = await response.json();
    }
    catch(e){
        data = {};
    }

    if(!response.ok){

        throw new Error(
            data.detail ||
            "Something went wrong"
        );
    }

    return data;
}


/* ========================================================
   PAGE
======================================================== */

function showPage(page){

    document
        .querySelectorAll(".page")
        .forEach(
            p => p.classList.add("hidden")
        );

    const target =
        document.getElementById(page);

    if(target){
        target.classList.remove("hidden");
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

    if(page === "dashboard"){
        loadDashboard();
    }
}


/* ========================================================
   REGISTER
======================================================== */

async function registerUser(){

    const msg =
        document.getElementById("registerMsg");

    msg.textContent = "Creating account...";

    try{

        const data =
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
            data.message +
            ". You can now login.";

        document.getElementById(
            "loginEmail"
        ).value =
            document.getElementById(
                "regEmail"
            ).value;

        showPage("login");

    }
    catch(error){

        msg.textContent =
            error.message;

    }
}


/* ========================================================
   LOGIN
======================================================== */

async function login(){

    const msg =
        document.getElementById("loginMsg");

    msg.textContent =
        "Logging in...";

    try{

        const data =
            await api(
                "/api/login",
                {
                    method:"POST",
                    body:JSON.stringify({

                        email:
                            document.getElementById(
                                "loginEmail"
                            ).value,

                        password:
                            document.getElementById(
                                "loginPassword"
                            ).value

                    })
                }
            );

        const token =
            data._session_token;

        document.cookie =
            "jobmart_session=" +
            encodeURIComponent(token) +
            "; path=/; SameSite=Lax";

        currentUser =
            data.user;

        updateUI();

        showPage("home");

    }
    catch(error){

        msg.textContent =
            error.message;

    }
}


/* ========================================================
   LOGOUT
======================================================== */

async function logout(){

    try{

        await api(
            "/api/logout",
            {
                method:"POST"
            }
        );

    }
    catch(e){}

    document.cookie =
        "jobmart_session=; Max-Age=0; path=/";

    currentUser = null;

    updateUI();

    showPage("home");
}


/* ========================================================
   UI
======================================================== */

function updateUI(){

    const nav =
        document.getElementById("nav");

    const auth =
        document.getElementById(
            "authButtons"
        );

    const postBtn =
        document.getElementById(
            "postBtn"
        );

    if(currentUser){

        nav.classList.remove(
            "hidden"
        );

        auth.innerHTML = `
            <span>
                Hi, ${escapeHtml(
                    currentUser.name
                )}
            </span>
        `;

        if(
            currentUser.role ===
            "employer"
        ){

            postBtn.classList.remove(
                "hidden"
            );

        }
        else{

            postBtn.classList.add(
                "hidden"
            );

        }

    }
    else{

        nav.classList.add(
            "hidden"
        );

        auth.innerHTML = `
            <button
                class="white"
                onclick="showPage('login')"
            >
                Login
            </button>
        `;

        postBtn.classList.add(
            "hidden"
        );
    }
}


/* ========================================================
   CHECK LOGIN
======================================================== */

async function checkLogin(){

    try{

        const data =
            await api("/api/me");

        if(data.logged_in){

            currentUser =
                data.user;

        }
        else{

            currentUser =
                null;

        }

        updateUI();

    }
    catch(e){

        currentUser = null;

        updateUI();

    }
}


/* ========================================================
   HOME JOBS
======================================================== */

async function loadHomeJobs(){

    try{

        const data =
            await api(
                "/api/jobs"
            );

        renderJobs(
            data.jobs.slice(0,6),
            "homeJobs"
        );

    }
    catch(error){

        document.getElementById(
            "homeJobs"
        ).innerHTML =
            `<div class="empty">
                ${escapeHtml(
                    error.message
                )}
            </div>`;

    }
}


function searchHome(){

    document.getElementById(
        "jobSearch"
    ).value =
        document.getElementById(
            "homeSearch"
        ).value;

    document.getElementById(
        "jobCountry"
    ).value =
        document.getElementById(
            "homeCountry"
        ).value;

    document.getElementById(
        "jobType"
    ).value =
        document.getElementById(
            "homeType"
        ).value;

    showPage("jobs");
}


/* ========================================================
   LOAD JOBS
======================================================== */

async function loadJobs(){

    const q =
        document.getElementById(
            "jobSearch"
        ).value;

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

    if(q)
        params.set("q", q);

    if(country)
        params.set(
            "country",
            country
        );

    if(type)
        params.set(
            "job_type",
            type
        );

    try{

        const data =
            await api(
                "/api/jobs?" +
                params.toString()
            );

        renderJobs(
            data.jobs,
            "jobsList"
        );

    }
    catch(error){

        document.getElementById(
            "jobsList"
        ).innerHTML =
            `<div class="empty">
                ${escapeHtml(
                    error.message
                )}
            </div>`;

    }
}


/* ========================================================
   RENDER JOBS
======================================================== */

function renderJobs(
    jobs,
    elementId
){

    const box =
        document.getElementById(
            elementId
        );

    if(!jobs.length){

        box.innerHTML =
            `<div class="empty">
                <h3>No jobs found</h3>
                <p>Try another search.</p>
            </div>`;

        return;
    }

    box.innerHTML =
        `<div class="grid">
            ${
                jobs.map(
                    jobCard
                ).join("")
            }
        </div>`;
}


function jobCard(job){

    return `
    <div class="card">

        <h3
            class="job-title"
            onclick="openJob(${job.id})"
        >
            ${escapeHtml(job.title)}
        </h3>

        <strong>
            ${escapeHtml(job.company)}
        </strong>

        <div class="meta">

            📍 ${escapeHtml(
                job.location ||
                job.country
            )}

            <br>

            💼 ${escapeHtml(
                job.job_type
            )}

            <br>

            🏠 ${escapeHtml(
                job.work_mode
            )}

            <br>

            💰 ${escapeHtml(
                job.salary ||
                "Salary not specified"
            )}

        </div>

        <div>
            <span class="badge">
                ${escapeHtml(
                    job.category
                )}
            </span>

            <span class="badge">
                ${escapeHtml(
                    job.country
                )}
            </span>
        </div>

        <div class="actions">

            <button
                class="primary"
                onclick="openJob(${job.id})"
            >
                View Job
            </button>

            ${
                currentUser
                ?
                `
                <button
                    class="secondary"
                    onclick="saveJob(${job.id})"
                >
                    Save
                </button>
                `
                :
                ""
            }

        </div>

    </div>
    `;
}


/* ========================================================
   OPEN JOB
======================================================== */

async function openJob(id){

    try{

        const data =
            await api(
                "/api/jobs/" + id
            );

        const job =
            data.job;

        let action = "";

        if(!currentUser){

            action = `
                <button
                    class="primary"
                    onclick="showPage('login')"
                >
                    Login to Apply
                </button>
            `;

        }
        else if(
            currentUser.role ===
            "jobseeker"
        ){

            action =
                job.applied
                ?
                `
                <button
                    class="secondary"
                    disabled
                >
                    Already Applied
                </button>
                `
                :
                `
                <button
                    class="primary"
                    onclick="applyForJob(${job.id})"
                >
                    Apply Now
                </button>
                `;

        }

        document.getElementById(
            "jobDetailBox"
        ).innerHTML = `

        <div class="card detail">

            <button
                class="secondary"
                onclick="showPage('jobs')"
            >
                ← Back
            </button>

            <hr>

            <h1>
                ${escapeHtml(job.title)}
            </h1>

            <h3>
                ${escapeHtml(job.company)}
            </h3>

            <p class="meta">
                📍 ${escapeHtml(
                    job.location ||
                    job.country
                )}
                <br>
                💼 ${escapeHtml(
                    job.job_type
                )}
                <br>
                🏠 ${escapeHtml(
                    job.work_mode
                )}
                <br>
                💰 ${escapeHtml(
                    job.salary ||
                    "Not specified"
                )}
            </p>

            <div>

                <span class="badge">
                    ${escapeHtml(
                        job.category
                    )}
                </span>

                <span class="badge">
                    ${escapeHtml(
                        job.country
                    )}
                </span>

            </div>

            <hr>

            <h3>
                Job Description
            </h3>

            <p>
                ${escapeHtml(
                    job.description
                )}
            </p>

            <h3>
                Skills
            </h3>

            <p>
                ${escapeHtml(
                    job.skills ||
                    "Not specified"
                )}
            </p>

            <h3>
                Employer
            </h3>

            <p>
                ${escapeHtml(
                    job.employer_name
                )}
            </p>

            <div class="actions">

                ${action}

                ${
                    currentUser
                    ?
                    `
                    <button
                        class="secondary"
                        onclick="saveJob(${job.id})"
                    >
                        ${job.saved
                            ? "★ Saved"
                            : "☆ Save Job"
                        }
                    </button>
                    `
                    :
                    ""
                }

            </div>

        </div>
        `;

        showPage("jobDetail");

    }
    catch(error){

        alert(
            error.message
        );

    }
}


/* ========================================================
   APPLY
======================================================== */

async function applyForJob(
    jobId
){

    const cover =
        prompt(
            "Enter your cover letter:"
        );

    if(cover === null){
        return;
    }

    try{

        const data =
            await api(
                "/api/jobs/" +
                jobId +
                "/apply",
                {
                    method:"POST",
                    body:JSON.stringify({
                        cover_letter:
                            cover
                    })
                }
            );

        alert(
            data.message
        );

        openJob(jobId);

    }
    catch(error){

        alert(
            error.message
        );

    }
}


/* ========================================================
   SAVE
======================================================== */

async function saveJob(
    jobId
){

    if(!currentUser){

        showPage("login");

        return;
    }

    try{

        const data =
            await api(
                "/api/jobs/" +
                jobId +
                "/save",
                {
                    method:"POST"
                }
            );

        alert(
            data.message
        );

        if(
            document.getElementById(
                "saved"
            ).classList.contains(
                "hidden"
            ) === false
        ){
            loadSaved();
        }

    }
    catch(error){

        alert(
            error.message
        );

    }
}


/* ========================================================
   SAVED
======================================================== */

async function loadSaved(){

    if(!currentUser){

        showPage("login");

        return;
    }

    try{

        const data =
            await api(
                "/api/saved-jobs"
            );

        renderJobs(
            data.jobs,
            "savedList"
        );

    }
    catch(error){

        document.getElementById(
            "savedList"
        ).innerHTML =
            `<div class="empty">
                ${escapeHtml(
                    error.message
                )}
            </div>`;

    }
}


/* ========================================================
   APPLICATIONS
======================================================== */

async function loadApplications(){

    if(!currentUser){

        showPage("login");

        return;
    }

    try{

        const data =
            await api(
                "/api/applications"
            );

        const list =
            data.applications;

        document.getElementById(
            "applicationIntro"
        ).textContent =
            currentUser.role ===
            "employer"
            ?
            "Applications received for your jobs."
            :
            "Jobs you have applied for.";

        const box =
            document.getElementById(
                "applicationsList"
            );

        if(!list.length){

            box.innerHTML =
                `<div class="empty">
                    No applications yet.
                </div>`;

            return;
        }

        box.innerHTML =
            `<div class="grid">
                ${
                    list.map(
                        a => {

                            if(
                                currentUser.role ===
                                "employer"
                            ){

                                return `
                                <div class="card">

                                    <h3>
                                        ${escapeHtml(
                                            a.title
                                        )}
                                    </h3>

                                    <strong>
                                        Applicant:
                                        ${escapeHtml(
                                            a.applicant_name
                                        )}
                                    </strong>

                                    <p class="meta">

                                        Email:
                                        ${escapeHtml(
                                            a.applicant_email
                                        )}

                                        <br>

                                        Phone:
                                        ${escapeHtml(
                                            a.applicant_phone ||
                                            "Not provided"
                                        )}

                                        <br>

                                        Status:
                                        ${escapeHtml(
                                            a.status
                                        )}

                                    </p>

                                    <hr>

                                    <p>
                                        ${escapeHtml(
                                            a.cover_letter ||
                                            "No cover letter"
                                        )}
                                    </p>

                                </div>
                                `;

                            }

                            return `
                            <div class="card">

                                <h3>
                                    ${escapeHtml(
                                        a.title
                                    )}
                                </h3>

                                <strong>
                                    ${escapeHtml(
                                        a.company
                                    )}
                                </strong>

                                <p class="meta">

                                    📍
                                    ${escapeHtml(
                                        a.location ||
                                        a.country
                                    )}

                                    <br>

                                    Status:
                                    ${escapeHtml(
                                        a.status
                                    )}

                                </p>

                                <p>
                                    Applied successfully.
                                </p>

                            </div>
                            `;

                        }
                    ).join("")
                }
            </div>`;

    }
    catch(error){

        document.getElementById(
            "applicationsList"
        ).innerHTML =
            `<div class="empty">
                ${escapeHtml(
                    error.message
                )}
            </div>`;

    }
}


/* ========================================================
   NOTIFICATIONS
======================================================== */

async function loadNotifications(){

    if(!currentUser){

        showPage("login");

        return;
    }

    try{

        const data =
            await api(
                "/api/notifications"
            );

        const box =
            document.getElementById(
                "notificationsList"
            );

        if(!data.notifications.length){

            box.innerHTML =
                `<div class="empty">
                    No notifications.
                </div>`;

            return;
        }

        box.innerHTML =
            `<div class="grid">
                ${
                    data.notifications.map(
                        n => `
                        <div
                            class="card notification
                            ${
                                n.is_read
                                ? ""
                                : "unread"
                            }"
                        >

                            <h3>
                                ${escapeHtml(
                                    n.title
                                )}
                            </h3>

                            <p>
                                ${escapeHtml(
                                    n.message
                                )}
                            </p>

                            <span class="small">
                                ${escapeHtml(
                                    n.created_at
                                )}
                            </span>

                        </div>
                        `
                    ).join("")
                }
            </div>`;

    }
    catch(error){

        document.getElementById(
            "notificationsList"
        ).innerHTML =
            `<div class="empty">
                ${escapeHtml(
                    error.message
                )}
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

    }
    catch(error){

        alert(
            error.message
        );

    }
}


/* ========================================================
   PROFILE
======================================================== */

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

        const user =
            data.user;

        document.getElementById(
            "profileName"
        ).value =
            user.name || "";

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

        alert(
            error.message
        );

    }
}


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
                            ).value,

                        phone:
                            document.getElementById(
                                "profilePhone"
                            ).value,

                        country:
                            document.getElementById(
                                "profileCountry"
                            ).value,

                        city:
                            document.getElementById(
                                "profileCity"
                            ).value,

                        bio:
                            document.getElementById(
                                "profileBio"
                            ).value

                    })
                }
            );

        document.getElementById(
            "profileMsg"
        ).textContent =
            data.message;

        await checkLogin();

    }
    catch(error){

        document.getElementById(
            "profileMsg"
        ).textContent =
            error.message;

    }
}


/* ========================================================
   POST JOB
======================================================== */

async function postJob(){

    const msg =
        document.getElementById(
            "postMsg"
        );

    msg.textContent =
        "Publishing job...";

    try{

        const data =
            await api(
                "/api/jobs",
                {
                    method:"POST",
                    body:JSON.stringify({

                        title:
                            document.getElementById(
                                "postTitle"
                            ).value,

                        company:
                            document.getElementById(
                                "postCompany"
                            ).value,

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
                            ).value,

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
                            ).value,

                        skills:
                            document.getElementById(
                                "postSkills"
                            ).value,

                        application_email:
                            document.getElementById(
                                "postEmail"
                            ).value,

                        description:
                            document.getElementById(
                                "postDescription"
                            ).value

                    })
                }
            );

        msg.textContent =
            data.message;

        document
            .getElementById(
                "postTitle"
            ).value = "";

        document
            .getElementById(
                "postCompany"
            ).value = "";

        document
            .getElementById(
                "postLocation"
            ).value = "";

        document
            .getElementById(
                "postSalary"
            ).value = "";

        document
            .getElementById(
                "postSkills"
            ).value = "";

        document
            .getElementById(
                "postEmail"
            ).value = "";

        document
            .getElementById(
                "postDescription"
            ).value = "";

    }
    catch(error){

        msg.textContent =
            error.message;

    }
}


/* ========================================================
   DASHBOARD
======================================================== */

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

        const box =
            document.getElementById(
                "dashboardStats"
            );

        if(
            d.role ===
            "employer"
        ){

            box.innerHTML = `

                <div class="stat">
                    Jobs Posted
                    <strong>
                        ${d.jobs_posted}
                    </strong>
                </div>

                <div class="stat">
                    Active Jobs
                    <strong>
                        ${d.active_jobs}
                    </strong>
                </div>

                <div class="stat">
                    Applications
                    <strong>
                        ${d.applications}
                    </strong>
                </div>

            `;

        }
        else{

            box.innerHTML = `

                <div class="stat">
                    Applications
                    <strong>
                        ${d.applications}
                    </strong>
                </div>

                <div class="stat">
                    Saved Jobs
                    <strong>
                        ${d.saved_jobs}
                    </strong>
                </div>

            `;

        }

    }
    catch(error){

        alert(
            error.message
        );

    }
}


/* ========================================================
   ESCAPE HTML
======================================================== */

function escapeHtml(value){

    if(value === null ||
       value === undefined){

        return "";

    }

    return String(value)
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");
}


/* ========================================================
   START
======================================================== */

checkLogin();

loadHomeJobs();

</script>

</body>

</html>
"""


# =========================================================
# HOME
# =========================================================

@app.get("/", response_class=HTMLResponse)
def home():

    return HTMLResponse(
        HTML
    )
