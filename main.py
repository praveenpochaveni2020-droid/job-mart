from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from pathlib import Path
from datetime import datetime, timezone, timedelta
import sqlite3
import hashlib
import secrets
import re

# =========================================================
# JOB MART
# =========================================================

app = FastAPI(title="Job Mart", version="2.0")

DB_FILE = Path("job_mart.db")

SESSIONS = {}
OTPS = {}

COUNTRIES = [
    "India",
    "United States",
    "United Kingdom",
    "Canada",
    "Australia",
    "Germany",
    "UAE",
    "Singapore",
    "Other",
]

JOB_TYPES = [
    "Full-time",
    "Part-time",
    "Contract",
    "Internship",
    "Freelance",
]

WORK_MODES = [
    "On-site",
    "Hybrid",
    "Remote",
]


# =========================================================
# DATABASE
# =========================================================

def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = db()

    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'jobseeker',
        phone TEXT DEFAULT '',
        location TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        skills TEXT DEFAULT '',
        experience TEXT DEFAULT '',
        education TEXT DEFAULT '',
        resume TEXT DEFAULT '',
        company_name TEXT DEFAULT '',
        company_description TEXT DEFAULT '',
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employer_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        company TEXT NOT NULL,
        description TEXT NOT NULL,
        skills TEXT DEFAULT '',
        country TEXT DEFAULT 'India',
        location TEXT DEFAULT '',
        job_type TEXT DEFAULT 'Full-time',
        work_mode TEXT DEFAULT 'On-site',
        salary_min INTEGER DEFAULT 0,
        salary_max INTEGER DEFAULT 0,
        experience TEXT DEFAULT '',
        education TEXT DEFAULT '',
        openings INTEGER DEFAULT 1,
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL,
        FOREIGN KEY(employer_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS saved_jobs (
        user_id INTEGER NOT NULL,
        job_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(user_id, job_id),
        FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE,
        FOREIGN KEY(job_id)
            REFERENCES jobs(id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        cover_letter TEXT DEFAULT '',
        resume TEXT DEFAULT '',
        status TEXT DEFAULT 'Applied',
        created_at TEXT NOT NULL,

        UNIQUE(job_id, user_id),

        FOREIGN KEY(job_id)
            REFERENCES jobs(id)
            ON DELETE CASCADE,

        FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    );
    """)

    conn.commit()
    conn.close()


init_db()


# =========================================================
# HELPERS
# =========================================================

def now():
    return datetime.now(timezone.utc).isoformat()


def clean_email(email):
    return email.strip().lower()


def valid_email(email):
    return bool(
        re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email
        )
    )


def hash_password(password):
    salt = secrets.token_hex(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        180000
    ).hex()

    return salt + "$" + digest


def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)

        check = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            180000
        ).hex()

        return secrets.compare_digest(
            check,
            digest
        )

    except Exception:
        return False


def get_user_by_email(email):
    conn = db()

    row = conn.execute(
        "SELECT * FROM users WHERE email=?",
        (clean_email(email),)
    ).fetchone()

    conn.close()

    return row


def get_user_by_id(user_id):
    conn = db()

    row = conn.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,)
    ).fetchone()

    conn.close()

    return row


def public_user(row):
    if not row:
        return None

    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "role": row["role"],
        "phone": row["phone"],
        "location": row["location"],
        "bio": row["bio"],
        "skills": row["skills"],
        "experience": row["experience"],
        "education": row["education"],
        "resume": row["resume"],
        "company_name": row["company_name"],
        "company_description": row["company_description"],
        "created_at": row["created_at"],
    }


def create_session(user_id):
    token = secrets.token_urlsafe(32)

    SESSIONS[token] = {
        "user_id": user_id,
        "created_at": now()
    }

    return token


def current_user(request: Request):

    token = (
        request.headers.get("X-Session-Token")
        or request.cookies.get("jobmart_session")
    )

    if not token:
        return None

    session = SESSIONS.get(token)

    if not session:
        return None

    return get_user_by_id(
        session["user_id"]
    )


def require_user(request):
    user = current_user(request)

    if not user:
        raise HTTPException(
            401,
            "Please login first"
        )

    return user


def job_json(row, saved=False, applied=False):

    return {
        "id": row["id"],
        "employer_id": row["employer_id"],
        "title": row["title"],
        "company": row["company"],
        "description": row["description"],
        "skills": row["skills"],
        "country": row["country"],
        "location": row["location"],
        "job_type": row["job_type"],
        "work_mode": row["work_mode"],
        "salary_min": row["salary_min"],
        "salary_max": row["salary_max"],
        "experience": row["experience"],
        "education": row["education"],
        "openings": row["openings"],
        "status": row["status"],
        "created_at": row["created_at"],
        "saved": bool(saved),
        "applied": bool(applied),
    }


# =========================================================
# MODELS
# =========================================================

class RegisterIn(BaseModel):

    name: str = Field(
        min_length=2,
        max_length=100
    )

    email: str

    password: str = Field(
        min_length=6,
        max_length=100
    )

    role: str = "jobseeker"

    phone: str = ""

    location: str = ""


class LoginIn(BaseModel):

    email: str
    password: str


class OTPRequest(BaseModel):

    email: str


class OTPLogin(BaseModel):

    email: str
    otp: str


class ResetPasswordIn(BaseModel):

    email: str
    otp: str

    new_password: str = Field(
        min_length=6,
        max_length=100
    )


class ProfileIn(BaseModel):

    name: str = Field(
        min_length=2,
        max_length=100
    )

    phone: str = ""
    location: str = ""
    bio: str = ""
    skills: str = ""
    experience: str = ""
    education: str = ""
    resume: str = ""

    company_name: str = ""
    company_description: str = ""


class JobIn(BaseModel):

    title: str = Field(
        min_length=2,
        max_length=150
    )

    company: str = Field(
        min_length=2,
        max_length=150
    )

    description: str = Field(
        min_length=10,
        max_length=10000
    )

    skills: str = ""

    country: str = "India"

    location: str = ""

    job_type: str = "Full-time"

    work_mode: str = "On-site"

    salary_min: int = 0

    salary_max: int = 0

    experience: str = ""

    education: str = ""

    openings: int = 1


class ApplyIn(BaseModel):

    cover_letter: str = ""

    resume: str = ""


class StatusIn(BaseModel):

    status: str


# =========================================================
# REGISTER
# =========================================================

@app.post("/api/register")
def register(data: RegisterIn):

    email = clean_email(data.email)

    if not valid_email(email):
        raise HTTPException(
            400,
            "Enter a valid email"
        )

    if data.role not in [
        "jobseeker",
        "employer"
    ]:
        raise HTTPException(
            400,
            "Invalid account type"
        )

    if get_user_by_email(email):
        raise HTTPException(
            409,
            "An account already exists with this email"
        )

    conn = db()

    cur = conn.execute("""
        INSERT INTO users
        (
            name,
            email,
            password_hash,
            role,
            phone,
            location,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        data.name.strip(),
        email,
        hash_password(data.password),
        data.role,
        data.phone.strip(),
        data.location.strip(),
        now()
    ))

    conn.commit()

    user_id = cur.lastrowid

    conn.close()

    user = get_user_by_id(user_id)

    token = create_session(user_id)

    return {
        "ok": True,
        "message": "Account created successfully",
        "token": token,
        "user": public_user(user)
    }


# =========================================================
# LOGIN
# =========================================================

@app.post("/api/login")
def login(data: LoginIn):

    user = get_user_by_email(
        data.email
    )

    if not user:
        raise HTTPException(
            401,
            "Invalid email or password"
        )

    if not verify_password(
        data.password,
        user["password_hash"]
    ):
        raise HTTPException(
            401,
            "Invalid email or password"
        )

    token = create_session(
        user["id"]
    )

    return {
        "ok": True,
        "token": token,
        "user": public_user(user)
    }


# =========================================================
# OTP LOGIN
# =========================================================

@app.post("/api/send-otp")
def send_otp(data: OTPRequest):

    email = clean_email(
        data.email
    )

    user = get_user_by_email(
        email
    )

    if not user:
        raise HTTPException(
            404,
            "No account found with this email. Create an account first."
        )

    otp = f"{secrets.randbelow(1000000):06d}"

    OTPS[email] = {
        "otp": otp,
        "expires": (
            datetime.now(timezone.utc)
            + timedelta(minutes=5)
        )
    }

    return {
        "ok": True,
        "message": "OTP generated",
        "demo_otp": otp
    }


@app.post("/api/login-otp")
def login_otp(data: OTPLogin):

    email = clean_email(
        data.email
    )

    item = OTPS.get(email)

    if not item:
        raise HTTPException(
            400,
            "Please request OTP first"
        )

    if datetime.now(timezone.utc) > item["expires"]:

        OTPS.pop(email, None)

        raise HTTPException(
            400,
            "OTP expired"
        )

    if not secrets.compare_digest(
        data.otp.strip(),
        item["otp"]
    ):
        raise HTTPException(
            401,
            "Invalid OTP"
        )

    user = get_user_by_email(
        email
    )

    if not user:
        raise HTTPException(
            404,
            "Account not found"
        )

    OTPS.pop(email, None)

    token = create_session(
        user["id"]
    )

    return {
        "ok": True,
        "token": token,
        "user": public_user(user)
    }


# =========================================================
# FORGOT PASSWORD
# =========================================================

@app.post("/api/forgot-password")
def forgot_password(data: OTPRequest):

    email = clean_email(
        data.email
    )

    user = get_user_by_email(
        email
    )

    if not user:
        raise HTTPException(
            404,
            "No account found with this email"
        )

    otp = f"{secrets.randbelow(1000000):06d}"

    OTPS["reset:" + email] = {
        "otp": otp,
        "expires": (
            datetime.now(timezone.utc)
            + timedelta(minutes=5)
        )
    }

    return {
        "ok": True,
        "demo_otp": otp
    }


@app.post("/api/reset-password")
def reset_password(
    data: ResetPasswordIn
):

    email = clean_email(
        data.email
    )

    key = "reset:" + email

    item = OTPS.get(key)

    if not item:
        raise HTTPException(
            400,
            "Request reset OTP first"
        )

    if datetime.now(timezone.utc) > item["expires"]:

        OTPS.pop(key, None)

        raise HTTPException(
            400,
            "Reset OTP expired"
        )

    if not secrets.compare_digest(
        data.otp.strip(),
        item["otp"]
    ):
        raise HTTPException(
            401,
            "Invalid OTP"
        )

    conn = db()

    conn.execute(
        """
        UPDATE users
        SET password_hash=?
        WHERE email=?
        """,
        (
            hash_password(data.new_password),
            email
        )
    )

    conn.commit()
    conn.close()

    OTPS.pop(key, None)

    return {
        "ok": True,
        "message": "Password changed successfully"
    }


# =========================================================
# LOGOUT
# =========================================================

@app.post("/api/logout")
def logout(request: Request):

    token = (
        request.headers.get("X-Session-Token")
        or request.cookies.get("jobmart_session")
    )

    if token:
        SESSIONS.pop(token, None)

    return {
        "ok": True,
        "message": "Logged out"
    }


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
        "user": public_user(user)
    }


# =========================================================
# PROFILE
# =========================================================

@app.get("/api/profile")
def get_profile(request: Request):

    user = require_user(request)

    return {
        "user": public_user(user)
    }


@app.put("/api/profile")
def update_profile(
    data: ProfileIn,
    request: Request
):

    user = require_user(request)

    conn = db()

    conn.execute("""
        UPDATE users
        SET
            name=?,
            phone=?,
            location=?,
            bio=?,
            skills=?,
            experience=?,
            education=?,
            resume=?,
            company_name=?,
            company_description=?
        WHERE id=?
    """, (
        data.name.strip(),
        data.phone.strip(),
        data.location.strip(),
        data.bio.strip(),
        data.skills.strip(),
        data.experience.strip(),
        data.education.strip(),
        data.resume.strip(),
        data.company_name.strip(),
        data.company_description.strip(),
        user["id"]
    ))

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "message": "Profile saved successfully",
        "user": public_user(
            get_user_by_id(user["id"])
        )
    }


# =========================================================
# CREATE JOB
# =========================================================

@app.post("/api/jobs")
def create_job(
    data: JobIn,
    request: Request
):

    user = require_user(request)

    if user["role"] != "employer":

        raise HTTPException(
            403,
            "Only employers can post jobs"
        )

    if data.job_type not in JOB_TYPES:

        raise HTTPException(
            400,
            "Invalid job type"
        )

    if data.work_mode not in WORK_MODES:

        raise HTTPException(
            400,
            "Invalid work mode"
        )

    if data.salary_min < 0:
        raise HTTPException(
            400,
            "Invalid minimum salary"
        )

    if data.salary_max < 0:
        raise HTTPException(
            400,
            "Invalid maximum salary"
        )

    if (
        data.salary_max
        and data.salary_min > data.salary_max
    ):
        raise HTTPException(
            400,
            "Minimum salary cannot exceed maximum salary"
        )

    conn = db()

    cur = conn.execute("""
        INSERT INTO jobs
        (
            employer_id,
            title,
            company,
            description,
            skills,
            country,
            location,
            job_type,
            work_mode,
            salary_min,
            salary_max,
            experience,
            education,
            openings,
            status,
            created_at
        )
        VALUES (
            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
        )
    """, (
        user["id"],
        data.title.strip(),
        data.company.strip(),
        data.description.strip(),
        data.skills.strip(),
        data.country,
        data.location.strip(),
        data.job_type,
        data.work_mode,
        data.salary_min,
        data.salary_max,
        data.experience.strip(),
        data.education.strip(),
        max(1, data.openings),
        "active",
        now()
    ))

    conn.commit()

    job_id = cur.lastrowid

    conn.close()

    return {
        "ok": True,
        "message": "Job posted successfully",
        "job_id": job_id
    }


# =========================================================
# SEARCH JOBS
# =========================================================

@app.get("/api/jobs")
def jobs(
    request: Request,
    q: str = "",
    country: str = "",
    job_type: str = "",
    work_mode: str = "",
    location: str = "",
    page: int = 1,
    limit: int = 30
):

    page = max(1, page)

    limit = min(
        50,
        max(1, limit)
    )

    offset = (
        page - 1
    ) * limit

    clauses = [
        "j.status='active'"
    ]

    params = []

    if q.strip():

        like = "%" + q.strip() + "%"

        clauses.append("""
        (
            j.title LIKE ?
            OR j.company LIKE ?
            OR j.skills LIKE ?
            OR j.description LIKE ?
            OR j.location LIKE ?
        )
        """)

        params += [
            like,
            like,
            like,
            like,
            like
        ]

    if (
        country
        and country != "All countries"
    ):

        clauses.append(
            "j.country=?"
        )

        params.append(country)

    if (
        job_type
        and job_type != "All job types"
    ):

        clauses.append(
            "j.job_type=?"
        )

        params.append(job_type)

    if (
        work_mode
        and work_mode != "All work modes"
    ):

        clauses.append(
            "j.work_mode=?"
        )

        params.append(work_mode)

    if location.strip():

        clauses.append(
            "j.location LIKE ?"
        )

        params.append(
            "%" + location.strip() + "%"
        )

    where = " AND ".join(
        clauses
    )

    conn = db()

    rows = conn.execute(
        f"""
        SELECT j.*
        FROM jobs j
        WHERE {where}
        ORDER BY j.id DESC
        LIMIT ? OFFSET ?
        """,
        params + [
            limit,
            offset
        ]
    ).fetchall()

    user = current_user(request)

    uid = (
        user["id"]
        if user
        else -1
    )

    result = []

    for row in rows:

        saved = conn.execute(
            """
            SELECT 1
            FROM saved_jobs
            WHERE user_id=? AND job_id=?
            """,
            (
                uid,
                row["id"]
            )
        ).fetchone()

        applied = conn.execute(
            """
            SELECT 1
            FROM applications
            WHERE user_id=? AND job_id=?
            """,
            (
                uid,
                row["id"]
            )
        ).fetchone()

        result.append(
            job_json(
                row,
                saved,
                applied
            )
        )

    total = conn.execute(
        f"""
        SELECT COUNT(*) c
        FROM jobs j
        WHERE {where}
        """,
        params
    ).fetchone()["c"]

    conn.close()

    return {
        "jobs": result,
        "page": page,
        "limit": limit,
        "total": total,
        "pages": (
            total + limit - 1
        ) // limit
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

    row = conn.execute(
        "SELECT * FROM jobs WHERE id=?",
        (job_id,)
    ).fetchone()

    if not row:

        conn.close()

        raise HTTPException(
            404,
            "Job not found"
        )

    user = current_user(request)

    uid = (
        user["id"]
        if user
        else -1
    )

    saved = conn.execute(
        """
        SELECT 1
        FROM saved_jobs
        WHERE user_id=? AND job_id=?
        """,
        (
            uid,
            job_id
        )
    ).fetchone()

    applied = conn.execute(
        """
        SELECT 1
        FROM applications
        WHERE user_id=? AND job_id=?
        """,
        (
            uid,
            job_id
        )
    ).fetchone()

    conn.close()

    return {
        "job": job_json(
            row,
            saved,
            applied
        )
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
        "SELECT id FROM jobs WHERE id=?",
        (job_id,)
    ).fetchone()

    if not job:

        conn.close()

        raise HTTPException(
            404,
            "Job not found"
        )

    exists = conn.execute(
        """
        SELECT 1
        FROM saved_jobs
        WHERE user_id=? AND job_id=?
        """,
        (
            user["id"],
            job_id
        )
    ).fetchone()

    if exists:

        conn.execute(
            """
            DELETE FROM saved_jobs
            WHERE user_id=? AND job_id=?
            """,
            (
                user["id"],
                job_id
            )
        )

        saved = False

        message = "Removed from saved jobs"

    else:

        conn.execute(
            """
            INSERT INTO saved_jobs
            (
                user_id,
                job_id,
                created_at
            )
            VALUES (?, ?, ?)
            """,
            (
                user["id"],
                job_id,
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


# =========================================================
# SAVED JOBS
# =========================================================

@app.get("/api/saved")
def saved_jobs(request: Request):

    user = require_user(request)

    conn = db()

    rows = conn.execute("""
        SELECT j.*
        FROM jobs j
        JOIN saved_jobs s
            ON s.job_id=j.id
        WHERE s.user_id=?
        ORDER BY s.created_at DESC
    """, (
        user["id"],
    )).fetchall()

    result = [
        job_json(
            row,
            True
        )
        for row in rows
    ]

    conn.close()

    return {
        "jobs": result
    }


# =========================================================
# APPLY
# =========================================================

@app.post("/api/jobs/{job_id}/apply")
def apply_job(
    job_id: int,
    data: ApplyIn,
    request: Request
):

    user = require_user(request)

    if user["role"] != "jobseeker":

        raise HTTPException(
            403,
            "Only job seekers can apply"
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
            404,
            "Active job not found"
        )

    existing = conn.execute(
        """
        SELECT id
        FROM applications
        WHERE job_id=?
        AND user_id=?
        """,
        (
            job_id,
            user["id"]
        )
    ).fetchone()

    if existing:

        conn.close()

        raise HTTPException(
            409,
            "You already applied for this job"
        )

    resume = (
        data.resume.strip()
        or user["resume"]
        or ""
    )

    conn.execute("""
        INSERT INTO applications
        (
            job_id,
            user_id,
            cover_letter,
            resume,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        job_id,
        user["id"],
        data.cover_letter.strip(),
        resume,
        "Applied",
        now()
    ))

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

    if user["role"] == "jobseeker":

        rows = conn.execute("""
            SELECT
                a.*,
                j.title,
                j.company,
                j.location,
                j.job_type
            FROM applications a
            JOIN jobs j
                ON j.id=a.job_id
            WHERE a.user_id=?
            ORDER BY a.id DESC
        """, (
            user["id"],
        )).fetchall()

    else:

        rows = conn.execute("""
            SELECT
                a.*,
                j.title,
                j.company,
                j.location,
                j.job_type,
                u.name applicant_name,
                u.email applicant_email,
                u.phone applicant_phone
            FROM applications a
            JOIN jobs j
                ON j.id=a.job_id
            JOIN users u
                ON u.id=a.user_id
            WHERE j.employer_id=?
            ORDER BY a.id DESC
        """, (
            user["id"],
        )).fetchall()

    result = [
        dict(row)
        for row in rows
    ]

    conn.close()

    return {
        "applications": result
    }


# =========================================================
# UPDATE APPLICATION STATUS
# =========================================================

@app.patch("/api/applications/{application_id}")
def update_application(
    application_id: int,
    data: StatusIn,
    request: Request
):

    user = require_user(request)

    allowed = {
        "Applied",
        "Under Review",
        "Shortlisted",
        "Interview",
        "Selected",
        "Rejected"
    }

    if data.status not in allowed:

        raise HTTPException(
            400,
            "Invalid application status"
        )

    conn = db()

    row = conn.execute("""
        SELECT
            a.*,
            j.employer_id
        FROM applications a
        JOIN jobs j
            ON j.id=a.job_id
        WHERE a.id=?
    """, (
        application_id,
    )).fetchone()

    if not row:

        conn.close()

        raise HTTPException(
            404,
            "Application not found"
        )

    if row["employer_id"] != user["id"]:

        conn.close()

        raise HTTPException(
            403,
            "Only the employer can update status"
        )

    conn.execute(
        """
        UPDATE applications
        SET status=?
        WHERE id=?
        """,
        (
            data.status,
            application_id
        )
    )

    conn.commit()

    conn.close()

    return {
        "ok": True,
        "message": "Application status updated"
    }


# =========================================================
# EMPLOYER JOBS
# =========================================================

@app.get("/api/my-jobs")
def my_jobs(request: Request):

    user = require_user(request)

    if user["role"] != "employer":

        raise HTTPException(
            403,
            "Employer account required"
        )

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM jobs
        WHERE employer_id=?
        ORDER BY id DESC
        """,
        (
            user["id"],
        )
    ).fetchall()

    result = [
        job_json(row)
        for row in rows
    ]

    conn.close()

    return {
        "jobs": result
    }


# =========================================================
# CLOSE JOB
# =========================================================

@app.delete("/api/jobs/{job_id}")
def close_job(
    job_id: int,
    request: Request
):

    user = require_user(request)

    conn = db()

    row = conn.execute(
        "SELECT * FROM jobs WHERE id=?",
        (job_id,)
    ).fetchone()

    if not row:

        conn.close()

        raise HTTPException(
            404,
            "Job not found"
        )

    if row["employer_id"] != user["id"]:

        conn.close()

        raise HTTPException(
            403,
            "You can close only your own job"
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
# DASHBOARD
# =========================================================

@app.get("/api/dashboard")
def dashboard(request: Request):

    user = require_user(request)

    conn = db()

    if user["role"] == "employer":

        jobs = conn.execute(
            """
            SELECT COUNT(*) c
            FROM jobs
            WHERE employer_id=?
            """,
            (user["id"],)
        ).fetchone()["c"]

        active = conn.execute(
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

        selected = conn.execute(
            """
            SELECT COUNT(*) c
            FROM applications a
            JOIN jobs j
                ON j.id=a.job_id
            WHERE j.employer_id=?
            AND a.status='Selected'
            """,
            (user["id"],)
        ).fetchone()["c"]

        result = {
            "role": "employer",
            "jobs": jobs,
            "active_jobs": active,
            "applications": applications,
            "selected": selected
        }

    else:

        applications = conn.execute(
            """
            SELECT COUNT(*) c
            FROM applications
            WHERE user_id=?
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

        selected = conn.execute(
            """
            SELECT COUNT(*) c
            FROM applications
            WHERE user_id=?
            AND status='Selected'
            """,
            (user["id"],)
        ).fetchone()["c"]

        result = {
            "role": "jobseeker",
            "applications": applications,
            "saved": saved,
            "selected": selected
        }

    conn.close()

    return result


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():

    return {
        "ok": True,
        "service": "Job Mart",
        "version": "2.0"
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
content="width=device-width,initial-scale=1"
>

<title>Job Mart</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    background:#f3f6fa;
    color:#172033;
    font-family:Arial,Helvetica,sans-serif;
}

.top{
    background:#147bea;
    color:white;
    position:sticky;
    top:0;
    z-index:50;
    box-shadow:0 3px 15px #0002;
}

.nav{
    max-width:1200px;
    margin:auto;
    padding:12px 18px;
    display:flex;
    align-items:center;
    gap:15px;
}

.logo{
    font-size:30px;
    font-weight:800;
}

.tag{
    flex:1;
    font-size:14px;
}

.nav button{
    border:0;
    background:white;
    color:#147bea;
    border-radius:9px;
    padding:12px 20px;
    font-weight:bold;
}

.searchbar{
    max-width:1200px;
    margin:auto;
    padding:0 18px 14px;
    display:flex;
    gap:8px;
}

.searchbar input{
    flex:1;
    border:0;
    border-radius:10px;
    padding:15px;
    outline:none;
}

.searchbar button{
    width:60px;
    border:0;
    border-radius:10px;
    background:white;
    font-size:23px;
}

.wrap{
    max-width:1200px;
    margin:25px auto;
    padding:0 18px;
}

.tabs{
    display:flex;
    gap:8px;
    overflow:auto;
    margin-bottom:18px;
}

.tabs button{
    border:1px solid #dce3ed;
    background:white;
    border-radius:10px;
    padding:12px 17px;
    white-space:nowrap;
}

.card{
    background:white;
    border:1px solid #dce3ed;
    border-radius:16px;
    padding:24px;
    margin-bottom:18px;
    box-shadow:0 5px 18px #17203312;
}

.hero{
    padding:45px 35px;
}

.hero h1{
    font-size:50px;
    margin:0 0 15px;
}

.hero p{
    color:#687386;
    font-size:19px;
}

.grid{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:16px;
}

.formgrid{
    display:grid;
    grid-template-columns:repeat(2,1fr);
    gap:14px;
}

label{
    display:block;
    font-weight:bold;
    margin:8px 0;
}

input,
select,
textarea{
    width:100%;
    padding:13px;
    border:1px solid #cbd4e1;
    border-radius:9px;
    background:white;
}

textarea{
    min-height:120px;
    resize:vertical;
}

.primary,
.secondary,
.danger,
.success{
    border:0;
    border-radius:9px;
    padding:12px 18px;
    margin:4px;
}

.primary{
    background:#147bea;
    color:white;
}

.secondary{
    background:#eef3fa;
    color:#17304d;
}

.danger{
    background:#ffeaea;
    color:#b52f2f;
}

.success{
    background:#e7f8ef;
    color:#11713e;
}

.job h3{
    margin-bottom:7px;
}

.company{
    color:#147bea;
    font-weight:bold;
}

.meta{
    display:flex;
    flex-wrap:wrap;
    gap:7px;
    margin:12px 0;
}

.badge{
    background:#eef4ff;
    border-radius:20px;
    padding:6px 10px;
    font-size:13px;
}

.stat{
    font-size:34px;
    font-weight:bold;
    color:#147bea;
}

.muted{
    color:#687386;
}

.msg{
    padding:12px;
    border-radius:9px;
    margin:10px 0;
}

.error{
    background:#fff0f0;
    color:#c33;
}

.ok{
    background:#ecfff4;
    color:#168047;
}

.empty{
    text-align:center;
    color:#687386;
    padding:40px;
}

.hide{
    display:none!important;
}

.modal{
    position:fixed;
    inset:0;
    background:#0008;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:18px;
    z-index:100;
}

.modalbox{
    background:white;
    width:100%;
    max-width:650px;
    max-height:90vh;
    overflow:auto;
    border-radius:16px;
    padding:25px;
}

.close{
    float:right;
    border:0;
    border-radius:50%;
    width:35px;
    height:35px;
    font-size:20px;
}

footer{
    text-align:center;
    padding:30px;
    color:#687386;
}

@media(max-width:750px){

    .logo{
        font-size:26px;
    }

    .tag{
        display:none;
    }

    .wrap{
        padding:0 10px;
    }

    .card{
        padding:18px;
    }

    .hero{
        padding:28px 20px;
    }

    .hero h1{
        font-size:40px;
    }

    .grid,
    .formgrid{
        grid-template-columns:1fr;
    }

}

</style>

</head>

<body>

<header class="top">

<div class="nav">

<div class="logo">
Job Mart
</div>

<div class="tag">
Find • Apply • Grow
</div>

<button id="authBtn"
onclick="showPage('login')">
Login
</button>

</div>

<div class="searchbar">

<input
id="globalSearch"
placeholder="Search jobs, companies, skills..."
onkeydown="if(event.key==='Enter')doSearch()"
>

<button onclick="doSearch()">
🔍
</button>

</div>

</header>

<main class="wrap">

<div
id="tabs"
class="tabs">
</div>

<section id="app">
</section>

</main>

<footer>
Job Mart • Find jobs • Apply online • Build your career
</footer>

<div
id="modal"
class="modal hide"
onclick="if(event.target.id==='modal')closeModal()"
>

<div class="modalbox">

<button
class="close"
onclick="closeModal()">
×
</button>

<div id="modalContent">
</div>

</div>

</div>


<script>

let token =
localStorage.getItem("jobmart_token") || "";

let me = null;


async function api(url,options={}){

    options.headers =
        Object.assign(
            {"Content-Type":"application/json"},
            options.headers || {}
        );

    if(token){

        options.headers["X-Session-Token"]
            = token;

    }

    const response =
        await fetch(url,options);

    let data={};

    try{
        data=await response.json();
    }
    catch(e){}

    if(!response.ok){

        throw new Error(
            data.detail ||
            "Something went wrong"
        );

    }

    return data;
}


function esc(value){

    return String(value ?? "")
        .replace(/[&<>"']/g,function(c){

            return {
                "&":"&amp;",
                "<":"&lt;",
                ">":"&gt;",
                '"':"&quot;",
                "'":"&#039;"
            }[c];

        });

}


function message(text,type="msg"){

    return `
    <div class="msg ${type}">
        ${esc(text)}
    </div>
    `;

}


function closeModal(){

    document
        .getElementById("modal")
        .classList.add("hide");

}


function openModal(html){

    document
        .getElementById("modalContent")
        .innerHTML=html;

    document
        .getElementById("modal")
        .classList.remove("hide");

}


async function refreshMe(){

    try{

        const d =
            await api("/api/me");

        me=d.user;

    }
    catch(e){

        me=null;

    }

    renderTabs();

    document
        .getElementById("authBtn")
        .textContent =
        me
        ? "Hi, "+me.name.split(" ")[0]
        : "Login";

}


function renderTabs(){

    const t =
        document.getElementById("tabs");

    if(!me){

        t.innerHTML="";

        return;

    }

    let items;

    if(me.role==="employer"){

        items=[
            ["home","Home"],
            ["jobs","Jobs"],
            ["post","Post Job"],
            ["applications","Applications"],
            ["dashboard","Dashboard"],
            ["profile","Profile"]
        ];

    }
    else{

        items=[
            ["home","Home"],
            ["jobs","Jobs"],
            ["saved","Saved"],
            ["applications","Applications"],
            ["dashboard","Dashboard"],
            ["profile","Profile"]
        ];

    }

    t.innerHTML =
        items.map(
            x=>`
            <button
            onclick="showPage('${x[0]}')">
            ${x[1]}
            </button>
            `
        ).join("")
        +
        `
        <button onclick="logout()">
        Logout
        </button>
        `;

}


async function logout(){

    await api(
        "/api/logout",
        {
            method:"POST"
        }
    ).catch(()=>{});

    token="";

    localStorage.removeItem(
        "jobmart_token"
    );

    me=null;

    renderTabs();

    showPage("home");

}


function showPage(page){

    if(page==="home")
        renderHome();

    else if(page==="login")
        renderLogin();

    else if(page==="register")
        renderRegister();

    else if(page==="jobs")
        renderJobs();

    else if(page==="saved")
        renderSaved();

    else if(page==="applications")
        renderApplications();

    else if(page==="profile")
        renderProfile();

    else if(page==="post")
        renderPost();

    else if(page==="dashboard")
        renderDashboard();

}


async function init(){

    await refreshMe();

    showPage("home");

}


function renderHome(){

    renderTabs();

    document
    .getElementById("app")
    .innerHTML=`

    <div class="card hero">

        <h1>
        Find your next opportunity 🚀
        </h1>

        <p>
        Search jobs, discover companies,
        save opportunities and apply online.
        </p>

        <div class="formgrid">

            <input
            id="homeQuery"
            placeholder="Job title, company, skills"
            >

            <select id="homeCountry">

                <option>
                All countries
                </option>

                ${[
                    "India",
                    "United States",
                    "United Kingdom",
                    "Canada",
                    "Australia",
                    "Germany",
                    "UAE",
                    "Singapore",
                    "Other"
                ].map(
                    x=>`<option>${x}</option>`
                ).join("")}

            </select>

        </div>

        <button
        class="primary"
        onclick="homeSearch()">
        Search Jobs
        </button>

    </div>


    <div class="grid">

        <div class="card">

            <div class="stat">
            🔎
            </div>

            <h3>
            Smart Search
            </h3>

            <p class="muted">
            Search by title, company,
            skills and location.
            </p>

        </div>


        <div class="card">

            <div class="stat">
            💾
            </div>

            <h3>
            Save Jobs
            </h3>

            <p class="muted">
            Save interesting jobs.
            </p>

        </div>


        <div class="card">

            <div class="stat">
            📄
            </div>

            <h3>
            Apply Online
            </h3>

            <p class="muted">
            Apply and track status.
            </p>

        </div>

    </div>


    <div class="card">

        <h2>
        Latest Jobs
        </h2>

        <div id="latestJobs">
        Loading...
        </div>

    </div>
    `;

    loadLatestJobs();

}


function homeSearch(){

    const q =
        document.getElementById(
            "homeQuery"
        ).value;

    document.getElementById(
        "globalSearch"
    ).value=q;

    showPage("jobs");

}


async function loadLatestJobs(){

    try{

        const d =
            await api(
                "/api/jobs?limit=6"
            );

        document.getElementById(
            "latestJobs"
        ).innerHTML =
            d.jobs.length
            ? d.jobs.map(jobCard).join("")
            : `
            <div class="empty">
            No jobs posted yet.
            </div>
            `;

    }
    catch(e){

        document.getElementById(
            "latestJobs"
        ).innerHTML =
            message(e.message,"error");

    }

}


function doSearch(){

    showPage("jobs");

}


function renderJobs(){

    renderTabs();

    document
    .getElementById("app")
    .innerHTML=`

    <div class="card">

        <h2>
        Find Jobs
        </h2>

        <div class="formgrid">

            <input
            id="jobQuery"
            value="${esc(
                document.getElementById(
                    "globalSearch"
                ).value
            )}"
            placeholder="Title, company, skills"
            >

            <input
            id="jobLocation"
            placeholder="Location"
            >

            <select id="jobCountry">

                <option>
                All countries
                </option>

                ${[
                    "India",
                    "United States",
                    "United Kingdom",
                    "Canada",
                    "Australia",
                    "Germany",
                    "UAE",
                    "Singapore",
                    "Other"
                ].map(
                    x=>`<option>${x}</option>`
                ).join("")}

            </select>

            <select id="jobType">

                <option>
                All job types
                </option>

                ${[
                    "Full-time",
                    "Part-time",
                    "Contract",
                    "Internship",
                    "Freelance"
                ].map(
                    x=>`<option>${x}</option>`
                ).join("")}

            </select>

            <select id="workMode">

                <option>
                All work modes
                </option>

                ${[
                    "On-site",
                    "Hybrid",
                    "Remote"
                ].map(
                    x=>`<option>${x}</option>`
                ).join("")}

            </select>

        </div>

        <button
        class="primary"
        onclick="loadJobs()">
        Search
        </button>

    </div>

    <div id="jobResults">
    </div>

    `;

    loadJobs();

}


async function loadJobs(){

    const q =
        document.getElementById(
            "jobQuery"
        )?.value || "";

    const location =
        document.getElementById(
            "jobLocation"
        )?.value || "";

    const country =
        document.getElementById(
            "jobCountry"
        )?.value || "";

    const type =
        document.getElementById(
            "jobType"
        )?.value || "";

    const mode =
        document.getElementById(
            "workMode"
        )?.value || "";

    const params =
        new URLSearchParams({
            q,
            location,
            country,
            job_type:type,
            work_mode:mode,
            limit:"30"
        });

    try{

        const d =
            await api(
                "/api/jobs?"+params
            );

        document.getElementById(
            "jobResults"
        ).innerHTML =
            d.jobs.length
            ? d.jobs.map(jobCard).join("")
            : `
            <div class="card empty">
            <h2>No matching jobs</h2>
            <p>
            Try another title, company,
            skill or location.
            </p>
            </div>
            `;

    }
    catch(e){

        document.getElementById(
            "jobResults"
        ).innerHTML =
            message(e.message,"error");

    }

}


function jobCard(j){

    let salary="Salary not specified";

    if(j.salary_min || j.salary_max){

        salary =
            "₹"
            +Number(
                j.salary_min || 0
            ).toLocaleString()
            +" - ₹"
            +Number(
                j.salary_max || 0
            ).toLocaleString();

    }

    return `

    <div class="card">

        <h3>
        ${esc(j.title)}
        </h3>

        <div class="company">
        ${esc(j.company)}
        </div>

        <div class="meta">

            <span class="badge">
            📍 ${esc(
                j.location ||
                j.country
            )}
            </span>

            <span class="badge">
            ${esc(j.job_type)}
            </span>

            <span class="badge">
            ${esc(j.work_mode)}
            </span>

            <span class="badge">
            💰 ${salary}
            </span>

        </div>

        <p>
        ${esc(
            j.description.slice(
                0,
                300
            )
        )}
        </p>

        <button
        class="primary"
        onclick="viewJob(${j.id})">
        View Job
        </button>

        ${
            me
            ?
            `
            <button
            class="secondary"
            onclick="saveJob(${j.id})">
            ${j.saved ? "★ Saved" : "☆ Save"}
            </button>
            `
            :
            ""
        }

        ${
            me &&
            me.role==="jobseeker"
            ?
            `
            <button
            class="success"
            onclick="applyJob(${j.id})">
            ${j.applied ? "Applied" : "Apply Now"}
            </button>
            `
            :
            ""
        }

    </div>

    `;

}


async function viewJob(id){

    try{

        const d =
            await api(
                "/api/jobs/"+id
            );

        const j=d.job;

        openModal(`

        <h2>
        ${esc(j.title)}
        </h2>

        <h3 class="company">
        ${esc(j.company)}
        </h3>

        <div class="meta">

        <span class="badge">
        📍 ${esc(
            j.location ||
            j.country
        )}
        </span>

        <span class="badge">
        ${esc(j.job_type)}
        </span>

        <span class="badge">
        ${esc(j.work_mode)}
        </span>

        </div>

        <h3>
        Description
        </h3>

        <p>
        ${esc(
            j.description
        ).replace(
            /\n/g,
            "<br>"
        )}
        </p>

        <h3>
        Skills
        </h3>

        <p>
        ${esc(
            j.skills ||
            "Not specified"
        )}
        </p>

        <h3>
        Experience
        </h3>

        <p>
        ${esc(
            j.experience ||
            "Not specified"
        )}
        </p>

        <h3>
        Education
        </h3>

        <p>
        ${esc(
            j.education ||
            "Not specified"
        )}
        </p>

        ${
            me &&
            me.role==="jobseeker"
            ?
            `
            <button
            class="primary"
            onclick="
                closeModal();
                applyJob(${j.id})
            ">
            Apply Now
            </button>
            `
            :
            ""
        }

        <button
        class="secondary"
        onclick="closeModal()">
        Close
        </button>

        `);

    }
    catch(e){

        alert(e.message);

    }

}


async function saveJob(id){

    if(!me){

        alert(
            "Please login first"
        );

        showPage("login");

        return;
    }

    try{

        const d =
            await api(
                "/api/jobs/"+id+"/save",
                {
                    method:"POST"
                }
            );

        alert(d.message);

        showPage("jobs");

    }
    catch(e){

        alert(e.message);

    }

}


async function applyJob(id){

    if(!me){

        alert(
            "Please login first"
        );

        showPage("login");

        return;
    }

    if(me.role!=="jobseeker"){

        alert(
            "Only job seekers can apply"
        );

        return;
    }

    openModal(`

    <h2>
    Apply for Job
    </h2>

    <label>
    Cover Letter
    </label>

    <textarea
    id="coverLetter"
    placeholder="Tell the employer why you are suitable...">
    </textarea>

    <label>
    Resume / CV
    </label>

    <textarea
    id="resumeText"
    placeholder="Paste resume text or resume link..."
    >${esc(
        me.resume || ""
    )}</textarea>

    <button
    class="primary"
    onclick="submitApplication(${id})">
    Submit Application
    </button>

    `);

}


async function submitApplication(id){

    try{

        const d =
            await api(
                "/api/jobs/"+id+"/apply",
                {
                    method:"POST",
                    body:JSON.stringify({

                        cover_letter:
                            document.getElementById(
                                "coverLetter"
                            ).value,

                        resume:
                            document.getElementById(
                                "resumeText"
                            ).value

                    })
                }
            );

        closeModal();

        alert(d.message);

        showPage(
            "applications"
        );

    }
    catch(e){

        alert(e.message);

    }

}


function renderLogin(){

    renderTabs();

    document.getElementById(
        "app"
    ).innerHTML=`

    <div
    class="card"
    style="max-width:650px;margin:auto">

        <h1>
        Welcome Back 👋
        </h1>

        <div class="tabs">

            <button
            id="passwordTab"
            onclick="loginMode('password')">
            Password
            </button>

            <button
            id="otpTab"
            onclick="loginMode('otp')">
            OTP Login
            </button>

        </div>

        <div id="loginBox">
        </div>

        <div id="loginMessage">
        </div>

    </div>

    `;

    loginMode("password");

}


function loginMode(mode){

    document.getElementById(
        "passwordTab"
    ).style.background =
        mode==="password"
        ? "#147bea"
        : "";

    document.getElementById(
        "passwordTab"
    ).style.color =
        mode==="password"
        ? "white"
        : "";

    document.getElementById(
        "otpTab"
    ).style.background =
        mode==="otp"
        ? "#147bea"
        : "";

    document.getElementById(
        "otpTab"
    ).style.color =
        mode==="otp"
        ? "white"
        : "";


    if(mode==="password"){

        document.getElementById(
            "loginBox"
        ).innerHTML=`

        <label>
        Email
        </label>

        <input
        id="loginEmail"
        type="email"
        placeholder="you@example.com"
        >

        <label>
        Password
        </label>

        <input
        id="loginPassword"
        type="password"
        placeholder="Password"
        >

        <button
        class="primary"
        onclick="doLogin()">
        Login
        </button>

        <button
        class="secondary"
        onclick="forgotPassword()">
        Forgot Password?
        </button>

        <button
        class="secondary"
        onclick="showPage('register')">
        Create Account
        </button>

        `;

    }
    else{

        document.getElementById(
            "loginBox"
        ).innerHTML=`

        <label>
        Email
        </label>

        <input
        id="otpEmail"
        type="email"
        placeholder="you@example.com"
        >

        <button
        class="secondary"
        onclick="sendOTP()">
        Send OTP
        </button>

        <label>
        6-digit OTP
        </label>

        <input
        id="otpCode"
        maxlength="6"
        inputmode="numeric"
        placeholder="123456"
        >

        <button
        class="primary"
        onclick="doOTPLogin()">
        Login with OTP
        </button>

        <button
        class="secondary"
        onclick="showPage('register')">
        Create Account
        </button>

        `;

    }

}


async function doLogin(){

    try{

        const d =
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

        token=d.token;

        localStorage.setItem(
            "jobmart_token",
            token
        );

        me=d.user;

        renderTabs();

        showPage("home");

    }
    catch(e){

        document.getElementById(
            "loginMessage"
        ).innerHTML =
            message(
                e.message,
                "error"
            );

    }

}


async function sendOTP(){

    try{

        const d =
            await api(
                "/api/send-otp",
                {
                    method:"POST",

                    body:JSON.stringify({

                        email:
                            document.getElementById(
                                "otpEmail"
                            ).value

                    })
                }
            );

        document.getElementById(
            "loginMessage"
        ).innerHTML =
            message(
                "Your demo OTP is: "
                + d.demo_otp,
                "ok"
            );

    }
    catch(e){

        document.getElementById(
            "loginMessage"
        ).innerHTML =
            message(
                e.message,
                "error"
            );

    }

}


async function doOTPLogin(){

    try{

        const d =
            await api(
                "/api/login-otp",
                {
                    method:"POST",

                    body:JSON.stringify({

                        email:
                            document.getElementById(
                                "otpEmail"
                            ).value,

                        otp:
                            document.getElementById(
                                "otpCode"
                            ).value

                    })
                }
            );

        token=d.token;

        localStorage.setItem(
            "jobmart_token",
            token
        );

        me=d.user;

        renderTabs();

        showPage("home");

    }
    catch(e){

        document.getElementById(
            "loginMessage"
        ).innerHTML =
            message(
                e.message,
                "error"
            );

    }

}


function renderRegister(){

    document.getElementById(
        "app"
    ).innerHTML=`

    <div
    class="card"
    style="max-width:700px;margin:auto">

        <h1>
        Create Job Mart Account
        </h1>

        <div class="formgrid">

            <div>

                <label>
                Full Name
                </label>

                <input
                id="regName"
                placeholder="Your name"
                >

            </div>

            <div>

                <label>
                Email
                </label>

                <input
                id="regEmail"
                type="email"
                placeholder="you@example.com"
                >

            </div>

            <div>

                <label>
                Password
                </label>

                <input
                id="regPassword"
                type="password"
                placeholder="Minimum 6 characters"
                >

            </div>

            <div>

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

            <div>

                <label>
                Phone
                </label>

                <input
                id="regPhone"
                placeholder="Phone number"
                >

            </div>

            <div>

                <label>
                Location
                </label>

                <input
                id="regLocation"
                placeholder="City, Country"
                >

            </div>

        </div>

        <div id="registerMessage">
        </div>

        <button
        class="primary"
        onclick="registerUser()">
        Create Account
        </button>

        <button
        class="secondary"
        onclick="showPage('login')">
        Back to Login
        </button>

    </div>

    `;

}


async function registerUser(){

    try{

        const d =
            await api(
                "/api/register",
                {
                    method:"POST",

                    body:JSON.stringify({

                        name:
                            document.getElementById(
                                "regName"
                            ).value,

                        email:
                            document.getElementById(
                                "regEmail"
                            ).value,

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
                            ).value,

                        location:
                            document.getElementById(
                                "regLocation"
                            ).value

                    })
                }
            );

        token=d.token;

        localStorage.setItem(
            "jobmart_token",
            token
        );

        me=d.user;

        renderTabs();

        showPage("home");

    }
    catch(e){

        document.getElementById(
            "registerMessage"
        ).innerHTML =
            message(
                e.message,
                "error"
            );

    }

}


function forgotPassword(){

    openModal(`

    <h2>
    Forgot Password
    </h2>

    <label>
    Email
    </label>

    <input
    id="forgotEmail"
    type="email"
    placeholder="you@example.com"
    >

    <button
    class="secondary"
    onclick="sendResetOTP()">
    Send Reset OTP
    </button>

    <div id="forgotMessage">
    </div>

    `);

}


async function sendResetOTP(){

    try{

        const d =
            await api(
                "/api/forgot-password",
                {
                    method:"POST",

                    body:JSON.stringify({

                        email:
                            document.getElementById(
                                "forgotEmail"
                            ).value

                    })
                }
            );

        document.getElementById(
            "forgotMessage"
        ).innerHTML=`

        ${message(
            "Reset OTP: "
            +d.demo_otp,
            "ok"
        )}

        <label>
        OTP
        </label>

        <input id="resetOTP">

        <label>
        New Password
        </label>

        <input
        id="newPassword"
        type="password"
        >

        <button
        class="primary"
        onclick="resetPassword()">
        Change Password
        </button>

        `;

    }
    catch(e){

        document.getElementById(
            "forgotMessage"
        ).innerHTML =
            message(
                e.message,
                "error"
            );

    }

}


async function resetPassword(){

    try{

        const d =
            await api(
                "/api/reset-password",
                {
                    method:"POST",

                    body:JSON.stringify({

                        email:
                            document.getElementById(
                                "forgotEmail"
                            ).value,

                        otp:
                            document.getElementById(
                                "resetOTP"
                            ).value,

                        new_password:
                            document.getElementById(
                                "newPassword"
                            ).value

                    })
                }
            );

        alert(d.message);

        closeModal();

    }
    catch(e){

        alert(e.message);

    }

}


async function renderProfile(){

    if(!me){

        showPage("login");

        return;

    }

    document.getElementById(
        "app"
    ).innerHTML=`

    <div class="card">

        <h1>
        My Profile
        </h1>

        <div class="formgrid">

            <div>

                <label>Name</label>

                <input
                id="profileName"
                value="${esc(me.name)}"
                >

            </div>

            <div>

                <label>Phone</label>

                <input
                id="profilePhone"
                value="${esc(me.phone)}"
                >

            </div>

            <div>

                <label>Location</label>

                <input
                id="profileLocation"
                value="${esc(me.location)}"
                >

            </div>

            <div>

                <label>Skills</label>

                <input
                id="profileSkills"
                value="${esc(me.skills)}"
                placeholder="Python, SQL, JavaScript"
                >

            </div>

            <div>

                <label>Experience</label>

                <input
                id="profileExperience"
                value="${esc(me.experience)}"
                >

            </div>

            <div>

                <label>Education</label>

                <input
                id="profileEducation"
                value="${esc(me.education)}"
                >

            </div>

        </div>

        <label>
        Bio
        </label>

        <textarea
        id="profileBio"
        >${esc(me.bio)}</textarea>

        <label>
        Resume / CV
        </label>

        <textarea
        id="profileResume"
        >${esc(me.resume)}</textarea>

        ${
            me.role==="employer"
            ?
            `

            <h2>
            Company Details
            </h2>

            <label>
            Company Name
            </label>

            <input
            id="companyName"
            value="${esc(
                me.company_name
            )}"
            >

            <label>
            Company Description
            </label>

            <textarea
            id="companyDescription"
            >${esc(
                me.company_description
            )}</textarea>

            `
            :
            ""
        }

        <div id="profileMessage">
        </div>

        <button
        class="primary"
        onclick="saveProfile()">
        Save Profile
        </button>

    </div>

    `;

}


async function saveProfile(){

    try{

        const d =
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

                        location:
                            document.getElementById(
                                "profileLocation"
                            ).value,

                        skills:
                            document.getElementById(
                                "profileSkills"
                            ).value,

                        experience:
                            document.getElementById(
                                "profileExperience"
                            ).value,

                        education:
                            document.getElementById(
                                "profileEducation"
                            ).value,

                        bio:
                            document.getElementById(
                                "profileBio"
                            ).value,

                        resume:
                            document.getElementById(
                                "profileResume"
                            ).value,

                        company_name:
                            document.getElementById(
                                "companyName"
                            )?.value || "",

                        company_description:
                            document.getElementById(
                                "companyDescription"
                            )?.value || ""

                    })
                }
            );

        me=d.user;

        document.getElementById(
            "profileMessage"
        ).innerHTML =
            message(
                d.message,
                "ok"
            );

        renderTabs();

    }
    catch(e){

        document.getElementById(
            "profileMessage"
        ).innerHTML =
            message(
                e.message,
                "error"
            );

    }

}


function renderPost(){

    if(
        !me ||
        me.role!=="employer"
    ){

        document.getElementById(
            "app"
        ).innerHTML =
            message(
                "Employer account required",
                "error"
            );

        return;

    }

    document.getElementById(
        "app"
    ).innerHTML=`

    <div class="card">

        <h1>
        Post a Job
        </h1>

        <div class="formgrid">

            <div>

                <label>
                Job Title
                </label>

                <input
                id="postTitle"
                placeholder="Software Developer"
                >

            </div>

            <div>

                <label>
                Company
                </label>

                <input
                id="postCompany"
                value="${esc(
                    me.company_name || ""
                )}"
                >

            </div>

            <div>

                <label>
                Country
                </label>

                <select id="postCountry">

                    ${[
                        "India",
                        "United States",
                        "United Kingdom",
                        "Canada",
                        "Australia",
                        "Germany",
                        "UAE",
                        "Singapore",
                        "Other"
                    ].map(
                        x=>`<option>${x}</option>`
                    ).join("")}

                </select>

            </div>

            <div>

                <label>
                Location
                </label>

                <input
                id="postLocation"
                placeholder="Hyderabad, Telangana"
                >

            </div>

            <div>

                <label>
                Job Type
                </label>

                <select id="postType">

                    ${[
                        "Full-time",
                        "Part-time",
                        "Contract",
                        "Internship",
                        "Freelance"
                    ].map(
                        x=>`<option>${x}</option>`
                    ).join("")}

                </select>

            </div>

            <div>

                <label>
                Work Mode
                </label>

                <select id="postMode">

                    ${[
                        "On-site",
                        "Hybrid",
                        "Remote"
                    ].map(
                        x=>`<option>${x}</option>`
                    ).join("")}

                </select>

            </div>

            <div>

                <label>
                Minimum Salary
                </label>

                <input
                id="salaryMin"
                type="number"
                value="0"
                >

            </div>

            <div>

                <label>
                Maximum Salary
                </label>

                <input
                id="salaryMax"
                type="number"
                value="0"
                >

            </div>

            <div>

                <label>
                Experience
                </label>

                <input
                id="postExperience"
                placeholder="0-2 years"
                >

            </div>

            <div>

                <label>
                Education
                </label>

                <input
                id="postEducation"
                placeholder="Degree / Any"
                >

            </div>

            <div>

                <label>
                Openings
                </label>

                <input
                id="openings"
                type="number"
                value="1"
                min="1"
                >

            </div>

            <div>

                <label>
                Skills
                </label>

                <input
                id="postSkills"
                placeholder="Python, SQL, FastAPI"
                >

            </div>

        </div>

        <label>
        Job Description
        </label>

        <textarea
        id="postDescription"
        placeholder="Responsibilities, requirements, benefits..."
        ></textarea>

        <div id="postMessage">
        </div>

        <button
        class="primary"
        onclick="createJob()">
        Publish Job
        </button>

    </div>

    `;

}


async function createJob(){

    try{

        const d =
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

                        description:
                            document.getElementById(
                                "postDescription"
                            ).value,

                        skills:
                            document.getElementById(
                                "postSkills"
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

                        salary_min:
                            Number(
                                document.getElementById(
                                    "salaryMin"
                                ).value || 0
                            ),

                        salary_max:
                            Number(
                                document.getElementById(
                                    "salaryMax"
                                ).value || 0
                            ),

                        experience:
                            document.getElementById(
                                "postExperience"
                            ).value,

                        education:
                            document.getElementById(
                                "postEducation"
                            ).value,

                        openings:
                            Number(
                                document.getElementById(
                                    "openings"
                                ).value || 1
                            )

                    })
                }
            );

        document.getElementById(
            "postMessage"
        ).innerHTML =
            message(
                d.message,
                "ok"
            );

        setTimeout(
            ()=>{
                showPage("dashboard");
            },
            700
        );

    }
    catch(e){

        document.getElementById(
            "postMessage"
        ).innerHTML =
            message(
                e.message,
                "error"
            );

    }

}


async function renderSaved(){

    if(!me){

        showPage("login");

        return;

    }

    try{

        const d =
            await api(
                "/api/saved"
            );

        document.getElementById(
            "app"
        ).innerHTML=`

        <h1>
        Saved Jobs
        </h1>

        ${
            d.jobs.length
            ?
            d.jobs.map(
                jobCard
            ).join("")
            :
            `
            <div class="card empty">
            No saved jobs yet.
            </div>
            `
        }

        `;

    }
    catch(e){

        document.getElementById(
            "app"
        ).innerHTML =
            message(
                e.message,
                "error"
            );

    }

}


async function renderApplications(){

    if(!me){

        showPage("login");

        return;

    }

    try{

        const d =
            await api(
                "/api/applications"
            );

        if(!d.applications.length){

            document.getElementById(
                "app"
            ).innerHTML=`

            <div class="card empty">

                <h2>
                No applications yet
                </h2>

                <p>
                Apply for a job and
                track it here.
                </p>

            </div>

            `;

            return;

        }

        document.getElementById(
            "app"
        ).innerHTML=`

        <h1>
        Applications
        </h1>

        ${
            d.applications.map(
                a=>`

                <div class="card">

                    <h3>
                    ${esc(a.title)}
                    </h3>

                    <b>
                    ${esc(a.company)}
                    </b>

                    <div class="meta">

                        <span class="badge">
                        ${esc(
                            a.location || ""
                        )}
                        </span>

                        <span class="badge">
                        ${esc(
                            a.job_type || ""
                        )}
                        </span>

                        <span class="badge">
                        ${esc(a.status)}
                        </span>

                    </div>

                    ${
                        me.role==="employer"

                        ?

                        `
                        <p>
                        <b>
                        Applicant:
                        </b>

                        ${esc(
                            a.applicant_name
                        )}

                        <br>

                        ${esc(
                            a.applicant_email
                        )}

                        <br>

                        ${esc(
                            a.applicant_phone || ""
                        )}

                        </p>

                        <p>
                        ${esc(
                            a.cover_letter || ""
                        )}
                        </p>

                        <select
                        onchange="
                        changeStatus(
                            ${a.id},
                            this.value
                        )">

                        ${[
                            "Applied",
                            "Under Review",
                            "Shortlisted",
                            "Interview",
                            "Selected",
                            "Rejected"
                        ].map(
                            s=>`
                            <option
                            ${
                                a.status===s
                                ?"selected"
                                :""
                            }>
                            ${s}
                            </option>
                            `
                        ).join("")}

                        </select>

                        `

                        :

                        `

                        <p>
                        ${esc(
                            a.cover_letter || ""
                        )}
                        </p>

                        <p class="muted">
                        Applied:
                        ${esc(
                            a.created_at
                        )}
                        </p>

                        `

                    }

                </div>

                `
            ).join("")
        }

        `;

    }
    catch(e){

        document.getElementById(
            "app"
        ).innerHTML =
            message(
                e.message,
                "error"
            );

    }

}


async function changeStatus(
    id,
    status
){

    try{

        await api(
            "/api/applications/"+id,
            {
                method:"PATCH",

                body:JSON.stringify({
                    status
                })
            }
        );

        alert(
            "Status updated"
        );

    }
    catch(e){

        alert(e.message);

    }

}


async function renderDashboard(){

    if(!me){

        showPage("login");

        return;

    }

    try{

        const d =
            await api(
                "/api/dashboard"
            );

        let html=`

        <h1>
        Dashboard
        </h1>

        <div class="grid">

        `;

        Object.entries(d)
        .filter(
            x=>x[0]!=="role"
        )
        .forEach(
            x=>{

                html += `

                <div class="card">

                    <div class="stat">
                    ${esc(x[1])}
                    </div>

                    <h3>
                    ${esc(
                        x[0]
                        .replace(
                            "_",
                            " "
                        )
                    )}
                    </h3>

                </div>

                `;

            }
        );

        html += `
        </div>
        `;

        if(me.role==="employer"){

            const jobs =
                await api(
                    "/api/my-jobs"
                );

            html += `

            <div class="card">

                <h2>
                My Job Posts
                </h2>

                ${
                    jobs.jobs.length
                    ?

                    jobs.jobs.map(
                        j=>`

                        <div class="card">

                            <h3>
                            ${esc(
                                j.title
                            )}
                            </h3>

                            <p>
                            ${esc(
                                j.location
                            )}
                            •
                            ${esc(
                                j.job_type
                            )}
                            •
                            ${esc(
                                j.status
                            )}
                            </p>

                            ${
                                j.status==="active"
                                ?
                                `
                                <button
                                class="danger"
                                onclick="
                                closeJob(
                                    ${j.id}
                                )">
                                Close Job
                                </button>
                                `
                                :
                                ""
                            }

                        </div>

                        `
                    ).join("")

                    :

                    `
                    <div class="empty">
                    No jobs posted yet.
                    </div>
                    `
                }

            </div>

            `;

        }

        document.getElementById(
            "app"
        ).innerHTML=html;

    }
    catch(e){

        document.getElementById(
            "app"
        ).innerHTML =
            message(
                e.message,
                "error"
            );

    }

}


async function closeJob(id){

    try{

        await api(
            "/api/jobs/"+id,
            {
                method:"DELETE"
            }
        );

        renderDashboard();

    }
    catch(e){

        alert(e.message);

    }

}


init();

</script>

</body>
</html>
"""


# =========================================================
# HOME
# =========================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
def home():

    return HTMLResponse(
        HTML
    )
