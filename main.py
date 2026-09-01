from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone
import sqlite3
import hashlib
import secrets
import html
import re

# =========================================================
# JOB MART - COMPLETE SINGLE FILE APPLICATION
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
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        otp TEXT NOT NULL,
        purpose TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
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
        job_type TEXT DEFAULT 'Full Time',
        salary TEXT DEFAULT '',
        experience TEXT DEFAULT '',
        education TEXT DEFAULT '',
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL,
        FOREIGN KEY(employer_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        cover_letter TEXT DEFAULT '',
        status TEXT DEFAULT 'Applied',
        created_at TEXT NOT NULL,
        UNIQUE(job_id, user_id),
        FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    conn.commit()
    conn.close()


init_db()

# =========================================================
# HELPERS
# =========================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200_000
    )
    return salt.hex() + ":" + hashed.hex()


def password_verify(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)

        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            200_000
        )

        return secrets.compare_digest(
            hashed.hex(),
            hash_hex
        )
    except Exception:
        return False


def clean(value: str) -> str:
    return html.escape((value or "").strip())


def valid_email(email: str) -> bool:
    return re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ) is not None


def get_user(request: Request):
    token = request.cookies.get("jobmart_session")

    if not token:
        return None

    conn = db()

    row = conn.execute("""
        SELECT users.*
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ?
    """, (token,)).fetchone()

    conn.close()

    return row


def create_session(user_id: int):
    token = secrets.token_urlsafe(48)

    conn = db()

    conn.execute(
        "INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)",
        (token, user_id, now_iso())
    )

    conn.commit()
    conn.close()

    return token


def logout_session(request: Request):
    token = request.cookies.get("jobmart_session")

    if token:
        conn = db()
        conn.execute(
            "DELETE FROM sessions WHERE token=?",
            (token,)
        )
        conn.commit()
        conn.close()


def create_otp(email: str, purpose: str):
    otp = str(secrets.randbelow(900000) + 100000)

    expires = int(datetime.now(timezone.utc).timestamp()) + 600

    conn = db()

    conn.execute(
        """
        UPDATE otps
        SET used=1
        WHERE email=? AND purpose=? AND used=0
        """,
        (email, purpose)
    )

    conn.execute(
        """
        INSERT INTO otps(email,otp,purpose,expires_at)
        VALUES(?,?,?,?)
        """,
        (email, otp, purpose, expires)
    )

    conn.commit()
    conn.close()

    return otp


def verify_otp(email: str, otp: str, purpose: str):
    timestamp = int(datetime.now(timezone.utc).timestamp())

    conn = db()

    row = conn.execute(
        """
        SELECT *
        FROM otps
        WHERE email=?
        AND otp=?
        AND purpose=?
        AND used=0
        AND expires_at>?
        ORDER BY id DESC
        LIMIT 1
        """,
        (email, otp, purpose, timestamp)
    ).fetchone()

    if row:
        conn.execute(
            "UPDATE otps SET used=1 WHERE id=?",
            (row["id"],)
        )
        conn.commit()

    conn.close()

    return row is not None


def redirect_login(message: str = ""):
    url = "/login"

    if message:
        url += "?msg=" + message

    return RedirectResponse(
        url=url,
        status_code=303
    )


# =========================================================
# HTML / UI
# =========================================================

CSS = """
<style>
*{
    box-sizing:border-box;
}

body{
    margin:0;
    font-family:Arial,Helvetica,sans-serif;
    background:#f3f6fb;
    color:#182033;
}

a{
    color:inherit;
    text-decoration:none;
}

.topbar{
    background:#1976ed;
    color:white;
    position:sticky;
    top:0;
    z-index:20;
    box-shadow:0 3px 12px rgba(0,0,0,.16);
}

.nav{
    max-width:1150px;
    margin:auto;
    padding:12px 18px;
    display:flex;
    align-items:center;
    gap:15px;
}

.logo{
    font-size:30px;
    font-weight:800;
    white-space:nowrap;
}

.tagline{
    font-size:14px;
    opacity:.9;
}

.spacer{
    flex:1;
}

.navbtn{
    background:white;
    color:#1769d5;
    border:0;
    padding:12px 20px;
    border-radius:8px;
    font-size:17px;
    cursor:pointer;
    font-weight:600;
}

.navlink{
    padding:10px 12px;
    border-radius:7px;
}

.navlink:hover{
    background:rgba(255,255,255,.15);
}

.searchbar{
    background:#1976ed;
    padding:0 18px 15px;
}

.search-inner{
    max-width:1150px;
    margin:auto;
    display:flex;
    gap:10px;
}

.search-inner input{
    flex:1;
}

.search-button{
    width:80px;
    font-size:25px;
}

.container{
    max-width:1150px;
    margin:35px auto;
    padding:0 18px;
}

.card{
    background:white;
    border-radius:18px;
    padding:30px;
    box-shadow:0 2px 10px rgba(0,0,0,.08);
    margin-bottom:25px;
}

.hero{
    padding:45px;
}

.hero h1{
    font-size:52px;
    line-height:1.1;
    margin:0 0 20px;
}

.hero p{
    font-size:20px;
    color:#59657a;
}

h1,h2,h3{
    margin-top:0;
}

input,
select,
textarea{
    width:100%;
    padding:15px;
    border:1px solid #cbd2dc;
    border-radius:9px;
    font-size:17px;
    outline:none;
    background:white;
}

input:focus,
select:focus,
textarea:focus{
    border-color:#1976ed;
    box-shadow:0 0 0 3px rgba(25,118,237,.1);
}

textarea{
    min-height:130px;
    resize:vertical;
}

label{
    display:block;
    font-weight:600;
    margin:16px 0 7px;
}

.btn{
    display:inline-block;
    border:0;
    border-radius:8px;
    padding:13px 20px;
    background:#1976ed;
    color:white;
    font-size:17px;
    cursor:pointer;
    font-weight:600;
}

.btn:hover{
    background:#1264ca;
}

.btn.secondary{
    background:#eef3fb;
    color:#2467bc;
}

.btn.danger{
    background:#d9363e;
}

.btn.success{
    background:#168a55;
}

.grid{
    display:grid;
    grid-template-columns:repeat(2,1fr);
    gap:20px;
}

.job-grid{
    display:grid;
    grid-template-columns:repeat(2,1fr);
    gap:20px;
}

.job{
    background:white;
    border-radius:15px;
    padding:24px;
    box-shadow:0 2px 9px rgba(0,0,0,.08);
}

.job h3{
    color:#155db7;
    font-size:24px;
    margin-bottom:8px;
}

.company{
    font-weight:700;
    font-size:17px;
}

.meta{
    color:#687386;
    margin:8px 0;
}

.badge{
    display:inline-block;
    padding:6px 10px;
    background:#eaf2ff;
    color:#1769d5;
    border-radius:20px;
    margin:3px;
    font-size:14px;
}

.alert{
    padding:15px;
    border-radius:10px;
    margin-bottom:18px;
    background:#fff0f0;
    color:#bd3030;
}

.success-alert{
    background:#edfff5;
    color:#137846;
}

.empty{
    text-align:center;
    padding:55px 20px;
    color:#687386;
}

footer{
    text-align:center;
    color:#687386;
    padding:40px 15px;
}

.auth-card{
    max-width:650px;
    margin:35px auto;
}

.tabs{
    display:flex;
    gap:10px;
    margin-bottom:25px;
}

.tab{
    flex:1;
    padding:15px;
    border:1px solid #ccd3df;
    background:white;
    border-radius:8px;
    text-align:center;
    font-size:18px;
}

.tab.active{
    background:#1976ed;
    color:white;
}

.profile{
    display:flex;
    gap:25px;
    align-items:center;
}

.avatar{
    width:75px;
    height:75px;
    border-radius:50%;
    background:#1976ed;
    color:white;
    display:flex;
    justify-content:center;
    align-items:center;
    font-size:30px;
    font-weight:bold;
}

.stat-grid{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:15px;
}

.stat{
    background:#f5f8fd;
    border-radius:12px;
    padding:20px;
}

.stat strong{
    display:block;
    font-size:30px;
    color:#1976ed;
}

@media(max-width:700px){
    .nav{
        flex-wrap:wrap;
    }

    .logo{
        font-size:27px;
    }

    .tagline{
        display:none;
    }

    .navlink{
        display:none;
    }

    .hero{
        padding:28px;
    }

    .hero h1{
        font-size:40px;
    }

    .card{
        padding:22px;
    }

    .grid,
    .job-grid{
        grid-template-columns:1fr;
    }

    .search-inner{
        flex-direction:row;
    }

    .search-button{
        width:70px;
    }

    .stat-grid{
        grid-template-columns:1fr;
    }
}
</style>
"""


def layout(
    title: str,
    body: str,
    user=None,
    search_value: str = ""
):
    if user:
        nav = f"""
        <a class="navlink" href="/dashboard">Dashboard</a>
        <a class="navlink" href="/jobs">Jobs</a>
        <a class="navlink" href="/applications">Applications</a>
        <a class="navlink" href="/post-job">Post Job</a>
        <form method="post" action="/logout" style="margin:0">
            <button class="navbtn">Logout</button>
        </form>
        """
    else:
        nav = """
        <a class="navlink" href="/jobs">Jobs</a>
        <a class="navlink" href="/login">Login</a>
        <a class="navbtn" href="/register">Create Account</a>
        """

    return f"""
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport"
              content="width=device-width,initial-scale=1">
        <title>{html.escape(title)} - Job Mart</title>
        {CSS}
    </head>

    <body>

    <header class="topbar">

        <div class="nav">

            <a href="/" class="logo">Job Mart</a>

            <span class="tagline">
                Find • Apply • Grow
            </span>

            <div class="spacer"></div>

            {nav}

        </div>

        <div class="searchbar">

            <form
                method="get"
                action="/jobs"
                class="search-inner"
            >

                <input
                    name="q"
                    value="{html.escape(search_value)}"
                    placeholder="Search jobs, companies, skills..."
                >

                <button
                    class="btn search-button"
                    type="submit"
                >
                    🔍
                </button>

            </form>

        </div>

    </header>

    <main class="container">

        {body}

    </main>

    <footer>
        Job Mart • Find jobs • Apply online • Build your career
    </footer>

    </body>
    </html>
    """


# =========================================================
# HOME
# =========================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = get_user(request)

    conn = db()

    jobs = conn.execute("""
        SELECT *
        FROM jobs
        WHERE status='active'
        ORDER BY id DESC
        LIMIT 6
    """).fetchall()

    conn.close()

    job_html = ""

    for job in jobs:
        job_html += job_card(job)

    if not job_html:
        job_html = """
        <div class="empty">
            <h2>No jobs posted yet</h2>
            <p>
                Jobs will appear here after an employer posts them.
            </p>
        </div>
        """

    body = f"""
    <section class="card hero">

        <h1>Find your next opportunity 👋</h1>

        <p>
            Search jobs posted by employers and apply online.
        </p>

        <form method="get" action="/jobs">

            <input
                name="q"
                placeholder="Job title, company, skills..."
            >

            <br><br>

            <div class="grid">

                <select name="country">
                    <option value="">All countries</option>
                    <option>India</option>
                    <option>United States</option>
                    <option>United Kingdom</option>
                    <option>Canada</option>
                    <option>Australia</option>
                </select>

                <select name="job_type">
                    <option value="">All job types</option>
                    <option>Full Time</option>
                    <option>Part Time</option>
                    <option>Remote</option>
                    <option>Contract</option>
                    <option>Internship</option>
                </select>

            </div>

            <br>

            <button class="btn" style="width:100%">
                Search Jobs
            </button>

        </form>

    </section>

    <section>

        <div style="
            display:flex;
            justify-content:space-between;
            align-items:center;
            margin-bottom:15px;
        ">
            <h2>Latest Jobs</h2>
            <a class="btn secondary" href="/jobs">
                View All
            </a>
        </div>

        <div class="job-grid">
            {job_html}
        </div>

    </section>
    """

    return layout(
        "Home",
        body,
        user
    )


# =========================================================
# JOB CARD
# =========================================================

def job_card(job):
    skills = ""

    for skill in (job["skills"] or "").split(","):
        skill = skill.strip()

        if skill:
            skills += (
                f'<span class="badge">'
                f'{html.escape(skill)}'
                f'</span>'
            )

    return f"""
    <article class="job">

        <h3>
            <a href="/job/{job['id']}">
                {html.escape(job['title'])}
            </a>
        </h3>

        <div class="company">
            {html.escape(job['company'])}
        </div>

        <div class="meta">
            📍 {html.escape(job['location'] or 'India')}
        </div>

        <div class="meta">
            💼 {html.escape(job['job_type'])}
        </div>

        <div class="meta">
            💰 {html.escape(job['salary'] or 'Salary not specified')}
        </div>

        <div>
            {skills}
        </div>

        <br>

        <a
            class="btn"
            href="/job/{job['id']}"
        >
            View Job
        </a>

    </article>
    """


# =========================================================
# JOB SEARCH
# =========================================================

@app.get("/jobs", response_class=HTMLResponse)
def jobs(
    request: Request,
    q: str = "",
    country: str = "",
    job_type: str = ""
):
    user = get_user(request)

    query = """
        SELECT jobs.*, users.name AS employer_name
        FROM jobs
        JOIN users ON users.id = jobs.employer_id
        WHERE jobs.status='active'
    """

    params = []

    if q.strip():
        query += """
        AND (
            jobs.title LIKE ?
            OR jobs.company LIKE ?
            OR jobs.skills LIKE ?
            OR jobs.description LIKE ?
            OR jobs.location LIKE ?
        )
        """

        value = "%" + q.strip() + "%"

        params.extend([
            value,
            value,
            value,
            value,
            value
        ])

    if country.strip():
        query += " AND jobs.country=?"
        params.append(country.strip())

    if job_type.strip():
        query += " AND jobs.job_type=?"
        params.append(job_type.strip())

    query += " ORDER BY jobs.id DESC"

    conn = db()

    rows = conn.execute(
        query,
        params
    ).fetchall()

    conn.close()

    cards = ""

    for job in rows:
        cards += job_card(job)

    if not cards:
        cards = """
        <div class="card empty">

            <h2>No jobs found</h2>

            <p>
                Try another job title, company or skill.
            </p>

        </div>
        """

    body = f"""
    <div class="card">

        <h1>Find Jobs</h1>

        <form method="get" action="/jobs">

            <input
                name="q"
                value="{html.escape(q)}"
                placeholder="Search jobs, companies, skills..."
            >

            <br>

            <div class="grid">

                <select name="country">

                    <option value="">
                        All countries
                    </option>

                    <option
                        {"selected" if country=="India" else ""}
                    >
                        India
                    </option>

                    <option
                        {"selected" if country=="United States" else ""}
                    >
                        United States
                    </option>

                    <option
                        {"selected" if country=="United Kingdom" else ""}
                    >
                        United Kingdom
                    </option>

                    <option
                        {"selected" if country=="Canada" else ""}
                    >
                        Canada
                    </option>

                </select>

                <select name="job_type">

                    <option value="">
                        All job types
                    </option>

                    <option
                        {"selected" if job_type=="Full Time" else ""}
                    >
                        Full Time
                    </option>

                    <option
                        {"selected" if job_type=="Part Time" else ""}
                    >
                        Part Time
                    </option>

                    <option
                        {"selected" if job_type=="Remote" else ""}
                    >
                        Remote
                    </option>

                    <option
                        {"selected" if job_type=="Contract" else ""}
                    >
                        Contract
                    </option>

                    <option
                        {"selected" if job_type=="Internship" else ""}
                    >
                        Internship
                    </option>

                </select>

            </div>

            <br>

            <button class="btn">
                Search
            </button>

        </form>

    </div>

    <div class="job-grid">
        {cards}
    </div>
    """

    return layout(
        "Jobs",
        body,
        user,
        q
    )


# =========================================================
# JOB DETAILS
# =========================================================

@app.get("/job/{job_id}", response_class=HTMLResponse)
def job_detail(
    request: Request,
    job_id: int
):
    user = get_user(request)

    conn = db()

    job = conn.execute("""
        SELECT jobs.*, users.name AS employer_name
        FROM jobs
        JOIN users ON users.id=jobs.employer_id
        WHERE jobs.id=?
    """, (job_id,)).fetchone()

    conn.close()

    if not job:
        return HTMLResponse(
            layout(
                "Job Not Found",
                """
                <div class="card empty">
                    <h1>Job not found</h1>
                    <a class="btn" href="/jobs">
                        Back to Jobs
                    </a>
                </div>
                """,
                user
            ),
            status_code=404
        )

    skills = ""

    for skill in (job["skills"] or "").split(","):
        if skill.strip():
            skills += (
                f'<span class="badge">'
                f'{html.escape(skill.strip())}'
                f'</span>'
            )

    apply_section = ""

    if user:
        if user["role"] == "employer":
            apply_section = """
            <div class="alert">
                Employers cannot apply to jobs.
            </div>
            """

        else:
            conn = db()

            existing = conn.execute("""
                SELECT id
                FROM applications
                WHERE job_id=? AND user_id=?
            """, (job_id, user["id"])).fetchone()

            conn.close()

            if existing:
                apply_section = """
                <div class="alert success-alert">
                    You already applied for this job.
                </div>
                """

            else:
                apply_section = f"""
                <div class="card">

                    <h2>Apply for this job</h2>

                    <form
                        method="post"
                        action="/apply/{job_id}"
                    >

                        <label>
                            Cover Letter
                        </label>

                        <textarea
                            name="cover_letter"
                            placeholder="Tell the employer why you are suitable..."
                        ></textarea>

                        <br><br>

                        <button class="btn success">
                            Apply Now
                        </button>

                    </form>

                </div>
                """

    else:
        apply_section = """
        <div class="card">

            <h2>Interested in this job?</h2>

            <p>
                Create an account or login to apply.
            </p>

            <a class="btn" href="/login">
                Login to Apply
            </a>

            <a class="btn secondary" href="/register">
                Create Account
            </a>

        </div>
        """

    body = f"""
    <div class="card">

        <a href="/jobs" style="color:#1769d5">
            ← Back to Jobs
        </a>

        <br><br>

        <h1>
            {html.escape(job["title"])}
        </h1>

        <h2>
            {html.escape(job["company"])}
        </h2>

        <div class="meta">
            📍 {html.escape(job["location"] or "India")}
        </div>

        <div class="meta">
            🌎 {html.escape(job["country"])}
        </div>

        <div class="meta">
            💼 {html.escape(job["job_type"])}
        </div>

        <div class="meta">
            💰 {html.escape(job["salary"] or "Not specified")}
        </div>

        <div class="meta">
            🎓 {html.escape(job["education"] or "Not specified")}
        </div>

        <div class="meta">
            👨‍💼 Employer:
            {html.escape(job["employer_name"])}
        </div>

        <hr>

        <h2>Job Description</h2>

        <p style="white-space:pre-wrap">
            {html.escape(job["description"])}
        </p>

        <h2>Skills</h2>

        <div>
            {skills or "Not specified"}
        </div>

        <h2>Experience</h2>

        <p>
            {html.escape(job["experience"] or "Not specified")}
        </p>

    </div>

    {apply_section}
    """

    return layout(
        job["title"],
        body,
        user
    )


# =========================================================
# REGISTER
# =========================================================

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    user = get_user(request)

    if user:
        return RedirectResponse(
            "/dashboard",
            status_code=303
        )

    body = """
    <div class="card auth-card">

        <h1>Create Account</h1>

        <p>
            Join Job Mart and start your career.
        </p>

        <form method="post" action="/register">

            <label>Full Name</label>

            <input
                name="name"
                required
                placeholder="Your name"
            >

            <label>Email</label>

            <input
                type="email"
                name="email"
                required
                placeholder="you@example.com"
            >

            <label>Phone</label>

            <input
                name="phone"
                placeholder="10 digit mobile number"
            >

            <label>Location</label>

            <input
                name="location"
                placeholder="City, State"
            >

            <label>Account Type</label>

            <select name="role">

                <option value="jobseeker">
                    Job Seeker
                </option>

                <option value="employer">
                    Employer
                </option>

            </select>

            <label>Password</label>

            <input
                type="password"
                name="password"
                required
                minlength="6"
                placeholder="Minimum 6 characters"
            >

            <label>Confirm Password</label>

            <input
                type="password"
                name="confirm_password"
                required
                minlength="6"
            >

            <br><br>

            <button class="btn" style="width:100%">
                Create Account
            </button>

        </form>

        <br>

        <p>
            Already have an account?
            <a
                href="/login"
                style="color:#1769d5"
            >
                Login
            </a>
        </p>

    </div>
    """

    return layout(
        "Create Account",
        body,
        user
    )


@app.post("/register")
def register(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(""),
    location: str = Form(""),
    role: str = Form("jobseeker"),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    name = name.strip()
    email = email.strip().lower()

    if not name:
        return HTMLResponse(
            layout(
                "Registration Error",
                """
                <div class="card alert">
                    Name is required.
                </div>
                """,
                None
            ),
            status_code=400
        )

    if not valid_email(email):
        return HTMLResponse(
            layout(
                "Registration Error",
                """
                <div class="card alert">
                    Please enter a valid email address.
                </div>
                """,
                None
            ),
            status_code=400
        )

    if len(password) < 6:
        return HTMLResponse(
            layout(
                "Registration Error",
                """
                <div class="card alert">
                    Password must contain at least 6 characters.
                </div>
                """,
                None
            ),
            status_code=400
        )

    if password != confirm_password:
        return HTMLResponse(
            layout(
                "Registration Error",
                """
                <div class="card alert">
                    Passwords do not match.
                </div>
                """,
                None
            ),
            status_code=400
        )

    if role not in ("jobseeker", "employer"):
        role = "jobseeker"

    conn = db()

    existing = conn.execute(
        "SELECT id FROM users WHERE email=?",
        (email,)
    ).fetchone()

    if existing:
        conn.close()

        return HTMLResponse(
            layout(
                "Account Exists",
                f"""
                <div class="card">

                    <div class="alert">
                        An account already exists with
                        <strong>{html.escape(email)}</strong>.
                    </div>

                    <a class="btn" href="/login">
                        Login
                    </a>

                </div>
                """,
                None
            ),
            status_code=400
        )

    cursor = conn.execute(
        """
        INSERT INTO users
        (name,email,password_hash,role,phone,location,created_at)
        VALUES(?,?,?,?,?,?,?)
        """,
        (
            name,
            email,
            password_hash(password),
            role,
            phone.strip(),
            location.strip(),
            now_iso()
        )
    )

    user_id = cursor.lastrowid

    conn.commit()
    conn.close()

    token = create_session(user_id)

    response = RedirectResponse(
        "/dashboard",
        status_code=303
    )

    response.set_cookie(
        "jobmart_session",
        token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 24 * 30
    )

    return response


# =========================================================
# LOGIN
# =========================================================

@app.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    msg: str = ""
):
    user = get_user(request)

    if user:
        return RedirectResponse(
            "/dashboard",
            status_code=303
        )

    message_html = ""

    if msg:
        message_html = f"""
        <div class="alert">
            {html.escape(msg)}
        </div>
        """

    body = f"""
    <div class="card auth-card">

        <h1>Welcome Back 👋</h1>

        {message_html}

        <div class="tabs">

            <a
                href="/login"
                class="tab active"
            >
                Password
            </a>

            <a
                href="/otp-login"
                class="tab"
            >
                OTP Login
            </a>

        </div>

        <form method="post" action="/login">

            <label>Email</label>

            <input
                type="email"
                name="email"
                required
                placeholder="you@example.com"
            >

            <label>Password</label>

            <input
                type="password"
                name="password"
                required
                placeholder="Password"
            >

            <br><br>

            <button class="btn">
                Login
            </button>

            <a
                class="btn secondary"
                href="/forgot-password"
            >
                Forgot Password?
            </a>

        </form>

        <br>

        <a
            class="btn secondary"
            href="/register"
        >
            Create Account
        </a>

    </div>
    """

    return layout(
        "Login",
        body,
        None
    )


@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...)
):
    email = email.strip().lower()

    conn = db()

    user = conn.execute(
        "SELECT * FROM users WHERE email=?",
        (email,)
    ).fetchone()

    conn.close()

    if not user or not password_verify(
        password,
        user["password_hash"]
    ):
        return HTMLResponse(
            layout(
                "Login Failed",
                f"""
                <div class="card auth-card">

                    <div class="alert">
                        Invalid email or password.
                    </div>

                    <a class="btn" href="/login">
                        Try Again
                    </a>

                    <a
                        class="btn secondary"
                        href="/register"
                    >
                        Create Account
                    </a>

                </div>
                """,
                None
            ),
            status_code=401
        )

    token = create_session(user["id"])

    response = RedirectResponse(
        "/dashboard",
        status_code=303
    )

    response.set_cookie(
        "jobmart_session",
        token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 24 * 30
    )

    return response


# =========================================================
# OTP LOGIN
# =========================================================

@app.get("/otp-login", response_class=HTMLResponse)
def otp_login_page(
    request: Request,
    email: str = "",
    sent: str = "",
    error: str = ""
):
    user = get_user(request)

    if user:
        return RedirectResponse(
            "/dashboard",
            status_code=303
        )

    alert = ""

    if error:
        alert = f"""
        <div class="alert">
            {html.escape(error)}
        </div>
        """

    body = f"""
    <div class="card auth-card">

        <h1>Welcome Back 👋</h1>

        {alert}

        <div class="tabs">

            <a
                href="/login"
                class="tab"
            >
                Password
            </a>

            <a
                href="/otp-login"
                class="tab active"
            >
                OTP Login
            </a>

        </div>

        <form method="post" action="/send-login-otp">

            <label>Email</label>

            <input
                type="email"
                name="email"
                value="{html.escape(email)}"
                required
                placeholder="you@example.com"
            >

            <br><br>

            <button class="btn secondary">
                Send OTP
            </button>

        </form>

        <br>

        <form method="post" action="/verify-login-otp">

            <input
                type="hidden"
                name="email"
                value="{html.escape(email)}"
            >

            <label>6-digit OTP</label>

            <input
                name="otp"
                inputmode="numeric"
                maxlength="6"
                pattern="[0-9]{{6}}"
                placeholder="Enter OTP"
            >

            <br><br>

            <button class="btn">
                Login with OTP
            </button>

        </form>

        <br>

        <a
            class="btn secondary"
            href="/register"
        >
            Create Account
        </a>

        {"<div class='alert success-alert'>OTP sent. For this demo the OTP is shown on screen after sending.</div>" if sent else ""}

    </div>
    """

    return layout(
        "OTP Login",
        body,
        None
    )


@app.post("/send-login-otp")
def send_login_otp(
    email: str = Form(...)
):
    email = email.strip().lower()

    conn = db()

    user = conn.execute(
        "SELECT id FROM users WHERE email=?",
        (email,)
    ).fetchone()

    conn.close()

    if not user:
        return RedirectResponse(
            "/otp-login?email=" +
            email +
            "&error=No account found with this email. Create an account first.",
            status_code=303
        )

    otp = create_otp(
        email,
        "login"
    )

    # DEMO ONLY:
    # Real email/SMS service can be connected later.

    body = f"""
    <div class="card auth-card">

        <div class="alert success-alert">

            OTP generated successfully.

            <br><br>

            <strong style="font-size:30px">
                {otp}
            </strong>

            <br><br>

            This demo displays the OTP on screen.
            In production, send it through email/SMS.

        </div>

        <a
            class="btn"
            href="/otp-login?email={email}&sent=1"
        >
            Enter OTP
        </a>

    </div>
    """

    return HTMLResponse(
        layout(
            "OTP Generated",
            body,
            None
        )
    )


@app.post("/verify-login-otp")
def verify_login_otp(
    request: Request,
    email: str = Form(...),
    otp: str = Form(...)
):
    email = email.strip().lower()
    otp = otp.strip()

    if not verify_otp(
        email,
        otp,
        "login"
    ):
        return RedirectResponse(
            "/otp-login?email=" +
            email +
            "&error=Invalid or expired OTP.",
            status_code=303
        )

    conn = db()

    user = conn.execute(
        "SELECT * FROM users WHERE email=?",
        (email,)
    ).fetchone()

    conn.close()

    if not user:
        return RedirectResponse(
            "/otp-login?error=Account not found.",
            status_code=303
        )

    token = create_session(user["id"])

    response = RedirectResponse(
        "/dashboard",
        status_code=303
    )

    response.set_cookie(
        "jobmart_session",
        token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 24 * 30
    )

    return response


# =========================================================
# FORGOT PASSWORD
# =========================================================

@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_page(
    request: Request,
    email: str = "",
    error: str = ""
):
    user = get_user(request)

    if user:
        return RedirectResponse(
            "/dashboard",
            status_code=303
        )

    error_html = ""

    if error:
        error_html = f"""
        <div class="alert">
            {html.escape(error)}
        </div>
        """

    body = f"""
    <div class="card auth-card">

        <h1>Forgot Password</h1>

        {error_html}

        <form method="post" action="/send-reset-otp">

            <label>Email</label>

            <input
                type="email"
                name="email"
                value="{html.escape(email)}"
                required
                placeholder="you@example.com"
            >

            <br><br>

            <button class="btn">
                Send Reset OTP
            </button>

        </form>

        <br>

        <a
            class="btn secondary"
            href="/login"
        >
            Back to Login
        </a>

    </div>
    """

    return layout(
        "Forgot Password",
        body,
        None
    )


@app.post("/send-reset-otp")
def send_reset_otp(
    email: str = Form(...)
):
    email = email.strip().lower()

    conn = db()

    user = conn.execute(
        "SELECT id FROM users WHERE email=?",
        (email,)
    ).fetchone()

    conn.close()

    if not user:
        return RedirectResponse(
            "/forgot-password?email=" +
            email +
            "&error=No account found with this email. Create an account first.",
            status_code=303
        )

    otp = create_otp(
        email,
        "reset"
    )

    body = f"""
    <div class="card auth-card">

        <div class="alert success-alert">

            Password reset OTP generated.

            <br><br>

            <strong style="font-size:30px">
                {otp}
            </strong>

            <br><br>

            Demo mode: OTP is displayed here.
            Production version can send it by email/SMS.

        </div>

        <a
            class="btn"
            href="/reset-password?email={email}"
        >
            Continue
        </a>

    </div>
    """

    return HTMLResponse(
        layout(
            "Reset OTP",
            body,
            None
        )
    )


@app.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(
    request: Request,
    email: str = "",
    error: str = ""
):
    error_html = ""

    if error:
        error_html = f"""
        <div class="alert">
            {html.escape(error)}
        </div>
        """

    body = f"""
    <div class="card auth-card">

        <h1>Reset Password</h1>

        {error_html}

        <form method="post" action="/reset-password">

            <input
                type="hidden"
                name="email"
                value="{html.escape(email)}"
            >

            <label>6-digit OTP</label>

            <input
                name="otp"
                required
                maxlength="6"
                pattern="[0-9]{{6}}"
                inputmode="numeric"
            >

            <label>New Password</label>

            <input
                type="password"
                name="password"
                required
                minlength="6"
            >

            <label>Confirm Password</label>

            <input
                type="password"
                name="confirm_password"
                required
                minlength="6"
            >

            <br><br>

            <button class="btn">
                Reset Password
            </button>

        </form>

    </div>
    """

    return layout(
        "Reset Password",
        body,
        None
    )


@app.post("/reset-password")
def reset_password(
    email: str = Form(...),
    otp: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    email = email.strip().lower()

    if password != confirm_password:
        return RedirectResponse(
            "/reset-password?email=" +
            email +
            "&error=Passwords do not match.",
            status_code=303
        )

    if len(password) < 6:
        return RedirectResponse(
            "/reset-password?email=" +
            email +
            "&error=Password must contain at least 6 characters.",
            status_code=303
        )

    if not verify_otp(
        email,
        otp.strip(),
        "reset"
    ):
        return RedirectResponse(
            "/reset-password?email=" +
            email +
            "&error=Invalid or expired OTP.",
            status_code=303
        )

    conn = db()

    user = conn.execute(
        "SELECT id FROM users WHERE email=?",
        (email,)
    ).fetchone()

    if not user:
        conn.close()

        return RedirectResponse(
            "/login?msg=Account not found.",
            status_code=303
        )

    conn.execute(
        """
        UPDATE users
        SET password_hash=?
        WHERE id=?
        """,
        (
            password_hash(password),
            user["id"]
        )
    )

    conn.commit()
    conn.close()

    return RedirectResponse(
        "/login?msg=Password reset successful. Please login.",
        status_code=303
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = get_user(request)

    if not user:
        return redirect_login(
            "Please login first."
        )

    conn = db()

    applications_count = conn.execute(
        """
        SELECT COUNT(*)
        FROM applications
        WHERE user_id=?
        """,
        (user["id"],)
    ).fetchone()[0]

    jobs_count = conn.execute(
        """
        SELECT COUNT(*)
        FROM jobs
        WHERE employer_id=?
        """,
        (user["id"],)
    ).fetchone()[0]

    conn.close()

    initial = (
        user["name"][0].upper()
        if user["name"]
        else "U"
    )

    body = f"""
    <div class="card">

        <div class="profile">

            <div class="avatar">
                {html.escape(initial)}
            </div>

            <div>

                <h1>
                    Welcome, {html.escape(user["name"])} 👋
                </h1>

                <p>
                    {html.escape(user["email"])}
                </p>

                <span class="badge">
                    {html.escape(user["role"].title())}
                </span>

            </div>

        </div>

    </div>

    <div class="stat-grid">

        <div class="stat">
            <strong>{applications_count}</strong>
            Applications
        </div>

        <div class="stat">
            <strong>{jobs_count}</strong>
            Jobs Posted
        </div>

        <div class="stat">
            <strong>✓</strong>
            Account Active
        </div>

    </div>

    <br>

    <div class="card">

        <h2>Quick Actions</h2>

        <a class="btn" href="/jobs">
            Find Jobs
        </a>

        <a
            class="btn secondary"
            href="/applications"
        >
            My Applications
        </a>

        {"<a class='btn success' href='/post-job'>Post a Job</a>" if user["role"]=="employer" else ""}

    </div>
    """

    return layout(
        "Dashboard",
        body,
        user
    )


# =========================================================
# POST JOB
# =========================================================

@app.get("/post-job", response_class=HTMLResponse)
def post_job_page(request: Request):
    user = get_user(request)

    if not user:
        return redirect_login(
            "Login to post a job."
        )

    if user["role"] != "employer":
        return HTMLResponse(
            layout(
                "Access Denied",
                """
                <div class="card alert">
                    Only employer accounts can post jobs.
                </div>
                """,
                user
            ),
            status_code=403
        )

    body = """
    <div class="card">

        <h1>Post a New Job</h1>

        <form method="post" action="/post-job">

            <div class="grid">

                <div>
                    <label>Job Title</label>

                    <input
                        name="title"
                        required
                        placeholder="Software Developer"
                    >
                </div>

                <div>
                    <label>Company</label>

                    <input
                        name="company"
                        required
                        placeholder="Company name"
                    >
                </div>

                <div>
                    <label>Location</label>

                    <input
                        name="location"
                        placeholder="Hyderabad"
                    >
                </div>

                <div>
                    <label>Country</label>

                    <select name="country">

                        <option>India</option>
                        <option>United States</option>
                        <option>United Kingdom</option>
                        <option>Canada</option>
                        <option>Australia</option>

                    </select>
                </div>

                <div>
                    <label>Job Type</label>

                    <select name="job_type">

                        <option>Full Time</option>
                        <option>Part Time</option>
                        <option>Remote</option>
                        <option>Contract</option>
                        <option>Internship</option>

                    </select>
                </div>

                <div>
                    <label>Salary</label>

                    <input
                        name="salary"
                        placeholder="₹5 LPA - ₹10 LPA"
                    >
                </div>

                <div>
                    <label>Experience</label>

                    <input
                        name="experience"
                        placeholder="0-2 years"
                    >
                </div>

                <div>
                    <label>Education</label>

                    <input
                        name="education"
                        placeholder="Any Degree"
                    >
                </div>

            </div>

            <label>Skills</label>

            <input
                name="skills"
                placeholder="Python, FastAPI, SQL"
            >

            <label>Job Description</label>

            <textarea
                name="description"
                required
                placeholder="Describe the job..."
            ></textarea>

            <br><br>

            <button class="btn success">
                Publish Job
            </button>

        </form>

    </div>
    """

    return layout(
        "Post Job",
        body,
        user
    )


@app.post("/post-job")
def post_job(
    request: Request,
    title: str = Form(...),
    company: str = Form(...),
    description: str = Form(...),
    skills: str = Form(""),
    country: str = Form("India"),
    location: str = Form(""),
    job_type: str = Form("Full Time"),
    salary: str = Form(""),
    experience: str = Form(""),
    education: str = Form("")
):
    user = get_user(request)

    if not user:
        return redirect_login(
            "Login to post a job."
        )

    if user["role"] != "employer":
        return HTMLResponse(
            layout(
                "Access Denied",
                """
                <div class="card alert">
                    Only employers can post jobs.
                </div>
                """,
                user
            ),
            status_code=403
        )

    conn = db()

    conn.execute(
        """
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
            salary,
            experience,
            education,
            status,
            created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            user["id"],
            title.strip(),
            company.strip(),
            description.strip(),
            skills.strip(),
            country.strip(),
            location.strip(),
            job_type.strip(),
            salary.strip(),
            experience.strip(),
            education.strip(),
            "active",
            now_iso()
        )
    )

    conn.commit()
    conn.close()

    return RedirectResponse(
        "/jobs",
        status_code=303
    )


# =========================================================
# APPLY
# =========================================================

@app.post("/apply/{job_id}")
def apply_job(
    request: Request,
    job_id: int,
    cover_letter: str = Form("")
):
    user = get_user(request)

    if not user:
        return redirect_login(
            "Login to apply for a job."
        )

    if user["role"] == "employer":
        return HTMLResponse(
            layout(
                "Cannot Apply",
                """
                <div class="card alert">
                    Employer accounts cannot apply to jobs.
                    Create a Job Seeker account to apply.
                </div>
                """,
                user
            ),
            status_code=403
        )

    conn = db()

    job = conn.execute(
        "SELECT id FROM jobs WHERE id=? AND status='active'",
        (job_id,)
    ).fetchone()

    if not job:
        conn.close()

        return HTMLResponse(
            layout(
                "Job Not Found",
                """
                <div class="card alert">
                    Job not found or no longer active.
                </div>
                """,
                user
            ),
            status_code=404
        )

    try:
        conn.execute(
            """
            INSERT INTO applications
            (job_id,user_id,cover_letter,status,created_at)
            VALUES(?,?,?,?,?)
            """,
            (
                job_id,
                user["id"],
                cover_letter.strip(),
                "Applied",
                now_iso()
            )
        )

        conn.commit()

    except sqlite3.IntegrityError:
        conn.close()

        return RedirectResponse(
            "/applications",
            status_code=303
        )

    conn.close()

    return RedirectResponse(
        "/applications",
        status_code=303
    )


# =========================================================
# MY APPLICATIONS
# =========================================================

@app.get("/applications", response_class=HTMLResponse)
def applications(request: Request):
    user = get_user(request)

    if not user:
        return redirect_login(
            "Please login first."
        )

    conn = db()

    rows = conn.execute("""
        SELECT
            applications.*,
            jobs.title,
            jobs.company,
            jobs.location
        FROM applications
        JOIN jobs ON jobs.id=applications.job_id
        WHERE applications.user_id=?
        ORDER BY applications.id DESC
    """, (user["id"],)).fetchall()

    conn.close()

    content = ""

    for row in rows:
        content += f"""
        <div class="job">

            <h3>
                {html.escape(row["title"])}
            </h3>

            <div class="company">
                {html.escape(row["company"])}
            </div>

            <div class="meta">
                📍 {html.escape(row["location"] or "India")}
            </div>

            <span class="badge">
                {html.escape(row["status"])}
            </span>

            <p>
                Applied on:
                {html.escape(row["created_at"][:10])}
            </p>

        </div>
        """

    if not content:
        content = """
        <div class="card empty">

            <h2>No applications yet</h2>

            <p>
                Find a job and click Apply Now.
            </p>

            <a class="btn" href="/jobs">
                Find Jobs
            </a>

        </div>
        """

    body = f"""
    <div class="card">

        <h1>My Applications</h1>

        <p>
            Track the jobs you have applied for.
        </p>

    </div>

    <div class="job-grid">
        {content}
    </div>
    """

    return layout(
        "My Applications",
        body,
        user
    )


# =========================================================
# MY JOBS
# =========================================================

@app.get("/my-jobs", response_class=HTMLResponse)
def my_jobs(request: Request):
    user = get_user(request)

    if not user:
        return redirect_login()

    if user["role"] != "employer":
        return HTMLResponse(
            layout(
                "Access Denied",
                """
                <div class="card alert">
                    Employer account required.
                </div>
                """,
                user
            ),
            status_code=403
        )

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM jobs
        WHERE employer_id=?
        ORDER BY id DESC
        """,
        (user["id"],)
    ).fetchall()

    conn.close()

    content = ""

    for row in rows:
        content += f"""
        <div class="job">

            <h3>
                {html.escape(row["title"])}
            </h3>

            <div class="company">
                {html.escape(row["company"])}
            </div>

            <div class="meta">
                📍 {html.escape(row["location"])}
            </div>

            <span class="badge">
                {html.escape(row["status"])}
            </span>

            <br><br>

            <a
                class="btn"
                href="/job/{row['id']}"
            >
                View Job
            </a>

            <a
                class="btn secondary"
                href="/job-applications/{row['id']}"
            >
                View Applicants
            </a>

        </div>
        """

    if not content:
        content = """
        <div class="card empty">

            <h2>No jobs posted</h2>

            <a class="btn" href="/post-job">
                Post Your First Job
            </a>

        </div>
        """

    body = f"""
    <div class="card">

        <h1>My Jobs</h1>

    </div>

    <div class="job-grid">
        {content}
    </div>
    """

    return layout(
        "My Jobs",
        body,
        user
    )


# =========================================================
# JOB APPLICANTS
# =========================================================

@app.get(
    "/job-applications/{job_id}",
    response_class=HTMLResponse
)
def job_applications(
    request: Request,
    job_id: int
):
    user = get_user(request)

    if not user:
        return redirect_login()

    if user["role"] != "employer":
        return HTMLResponse(
            layout(
                "Access Denied",
                """
                <div class="card alert">
                    Employer account required.
                </div>
                """,
                user
            ),
            status_code=403
        )

    conn = db()

    job = conn.execute(
        """
        SELECT *
        FROM jobs
        WHERE id=? AND employer_id=?
        """,
        (job_id, user["id"])
    ).fetchone()

    if not job:
        conn.close()

        return HTMLResponse(
            layout(
                "Job Not Found",
                """
                <div class="card alert">
                    Job not found.
                </div>
                """,
                user
            ),
            status_code=404
        )

    rows = conn.execute(
        """
        SELECT
            applications.*,
            users.name,
            users.email,
            users.phone,
            users.location
        FROM applications
        JOIN users
        ON users.id=applications.user_id
        WHERE applications.job_id=?
        ORDER BY applications.id DESC
        """,
        (job_id,)
    ).fetchall()

    conn.close()

    content = ""

    for row in rows:
        content += f"""
        <div class="card">

            <h2>
                {html.escape(row["name"])}
            </h2>

            <p>
                📧 {html.escape(row["email"])}
            </p>

            <p>
                📱 {html.escape(row["phone"] or "Not provided")}
            </p>

            <p>
                📍 {html.escape(row["location"] or "Not provided")}
            </p>

            <span class="badge">
                {html.escape(row["status"])}
            </span>

            <h3>Cover Letter</h3>

            <p style="white-space:pre-wrap">
                {html.escape(
                    row["cover_letter"]
                    or "No cover letter provided."
                )}
            </p>

        </div>
        """

    if not content:
        content = """
        <div class="card empty">

            <h2>No applications yet</h2>

            <p>
                Applicants will appear here.
            </p>

        </div>
        """

    body = f"""
    <div class="card">

        <h1>
            Applicants
        </h1>

        <p>
            Job:
            <strong>
                {html.escape(job["title"])}
            </strong>
        </p>

    </div>

    {content}
    """

    return layout(
        "Applicants",
        body,
        user
    )


# =========================================================
# LOGOUT
# =========================================================

@app.post("/logout")
def logout(request: Request):
    logout_session(request)

    response = RedirectResponse(
        "/",
        status_code=303
    )

    response.delete_cookie(
        "jobmart_session"
    )

    return response


# =========================================================
# API - CURRENT USER
# =========================================================

@app.get("/api/me")
def api_me(request: Request):
    user = get_user(request)

    if not user:
        return JSONResponse({
            "logged_in": False
        })

    return {
        "logged_in": True,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "phone": user["phone"],
            "location": user["location"]
        }
    }


# =========================================================
# API - JOBS
# =========================================================

@app.get("/api/jobs")
def api_jobs(
    q: str = "",
    country: str = "",
    job_type: str = ""
):
    query = """
        SELECT *
        FROM jobs
        WHERE status='active'
    """

    params = []

    if q.strip():
        value = "%" + q.strip() + "%"

        query += """
        AND (
            title LIKE ?
            OR company LIKE ?
            OR skills LIKE ?
            OR description LIKE ?
            OR location LIKE ?
        )
        """

        params.extend([
            value,
            value,
            value,
            value,
            value
        ])

    if country.strip():
        query += " AND country=?"
        params.append(country.strip())

    if job_type.strip():
        query += " AND job_type=?"
        params.append(job_type.strip())

    query += " ORDER BY id DESC"

    conn = db()

    rows = conn.execute(
        query,
        params
    ).fetchall()

    conn.close()

    return {
        "count": len(rows),
        "jobs": [dict(row) for row in rows]
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": "Job Mart",
        "database": "connected"
    }


# =========================================================
# RUN
# =========================================================

# Local:
# uvicorn main:app --reload
#
# Render:
# uvicorn main:app --host 0.0.0.0 --port $PORT
#
# If you run:
# python main.py
# it will also start the server.

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
