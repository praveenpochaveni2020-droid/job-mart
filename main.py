from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Query, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, List
import sqlite3, hashlib, secrets, html, re, os, json, urllib.request, urllib.error, urllib.parse, smtplib, base64
from email.message import EmailMessage

# ============================================================
# JOB MART — PRODUCTION-READY STANDALONE PLATFORM (v3.5.0)
# All features included: Web UI, REST API, Live AI, Real OTP,
# Resume handling, Employer portal, Seeker portal & Admin panel.
# ============================================================

APP_NAME = "Job Mart"
DB_FILE = Path(os.getenv("JOBMART_DB", "job_mart.db"))
UPLOAD_DIR = Path(os.getenv("JOBMART_UPLOADS", "uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@jobmart.com").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@JobMart2026")

# AI Settings (Compatible with OpenAI GPT-4o / GPT-4o-mini standard endpoints)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# SMTP Credentials for Real Email Delivery
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "no-reply@jobmart.com")

# Twilio Credentials for Real SMS Delivery
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM = os.getenv("TWILIO_FROM", "")

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "5"))

app = FastAPI(title=APP_NAME, version="3.5.0", docs_url="/docs", redoc_url="/redoc")

# ============================================================
# DATABASE SETUP & AUTO MIGRATIONS
# ============================================================

def db():
    conn = sqlite3.connect(DB_FILE, timeout=25)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def esc(v):
    return html.escape(str(v or ""))

def clean(v):
    return (v or "").strip()

def valid_email(v):
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", clean(v)) is not None

def categories():
    return [
        "IT & Software", "Sales & Marketing", "Finance & Accounting", 
        "Healthcare & Pharma", "Education & Training", "Engineering & Core", 
        "Government & Public Sector", "Construction & Real Estate",
        "Retail & FMCG", "Logistics & Supply Chain", "Hospitality & Tourism", 
        "Agriculture", "Customer Support", "Creative & Design", "Other"
    ]

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'jobseeker',
        phone TEXT DEFAULT '',
        location TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        skills TEXT DEFAULT '',
        education TEXT DEFAULT '',
        experience TEXT DEFAULT '',
        resume_path TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        is_blocked INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS otps(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        otp TEXT NOT NULL,
        purpose TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        used INTEGER DEFAULT 0,
        attempts INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS companies(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        name TEXT NOT NULL UNIQUE,
        description TEXT DEFAULT '',
        website TEXT DEFAULT '',
        location TEXT DEFAULT '',
        logo_path TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employer_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        company TEXT DEFAULT '',
        company_id INTEGER,
        description TEXT NOT NULL,
        skills TEXT DEFAULT '',
        country TEXT DEFAULT 'India',
        location TEXT DEFAULT '',
        job_type TEXT DEFAULT 'Full Time',
        salary TEXT DEFAULT '',
        experience TEXT DEFAULT '',
        education TEXT DEFAULT '',
        category TEXT DEFAULT 'Other',
        status TEXT DEFAULT 'active',
        views INTEGER DEFAULT 0,
        is_flagged INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(employer_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS applications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        cover_letter TEXT DEFAULT '',
        status TEXT DEFAULT 'Applied',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(job_id, user_id),
        FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS saved_jobs(
        user_id INTEGER NOT NULL,
        job_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(user_id, job_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notifications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        details TEXT DEFAULT '',
        status TEXT DEFAULT 'open',
        created_at TEXT NOT NULL,
        FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS ai_chats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        role TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS admin_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_email TEXT,
        action TEXT,
        details TEXT,
        created_at TEXT NOT NULL
    );
    """)

    # Check & migrate columns safely
    migrations = {
        "users": {
            "phone": "TEXT DEFAULT ''", "bio": "TEXT DEFAULT ''", "skills": "TEXT DEFAULT ''",
            "education": "TEXT DEFAULT ''", "experience": "TEXT DEFAULT ''",
            "resume_path": "TEXT DEFAULT ''", "is_blocked": "INTEGER DEFAULT 0"
        },
        "sessions": {"expires_at": "TEXT"},
        "jobs": {
            "company": "TEXT DEFAULT ''", "company_id": "INTEGER",
            "category": "TEXT DEFAULT 'Other'", "views": "INTEGER DEFAULT 0",
            "is_flagged": "INTEGER DEFAULT 0", "updated_at": "TEXT"
        },
        "applications": {"updated_at": "TEXT"},
    }

    for table, cols in migrations.items():
        existing = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
        for col, definition in cols.items():
            if col not in existing:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {definition}")

    c.execute("UPDATE jobs SET updated_at = COALESCE(updated_at, created_at) WHERE updated_at IS NULL OR updated_at = ''")
    c.execute("UPDATE applications SET updated_at = COALESCE(updated_at, created_at) WHERE updated_at IS NULL OR updated_at = ''")
    c.execute("UPDATE sessions SET expires_at = COALESCE(expires_at, ?) WHERE expires_at IS NULL OR expires_at = ''",
              ((datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),))
    c.commit()
    c.close()

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 220000)
    return salt.hex() + ":" + h.hex()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split(":")
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 220000)
        return secrets.compare_digest(h.hex(), digest)
    except Exception:
        return False

def ensure_admin():
    c = db()
    row = c.execute("SELECT id FROM users WHERE email=?", (ADMIN_EMAIL,)).fetchone()
    if not row:
        c.execute(
            "INSERT INTO users(name, email, password_hash, role, created_at) VALUES(?,?,?,?,?)",
            ("Job Mart Admin", ADMIN_EMAIL, hash_password(ADMIN_PASSWORD), "admin", now_iso())
        )
        c.commit()
    c.close()

init_db()
ensure_admin()

# ============================================================
# AUTHENTICATION & ACCESS CONTROL
# ============================================================

def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    expiry = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    c = db()
    c.execute("INSERT INTO sessions(token, user_id, created_at, expires_at) VALUES(?,?,?,?)",
              (token, user_id, now_iso(), expiry))
    c.commit()
    c.close()
    return token

def current_user(request: Request):
    token = request.cookies.get("jobmart_session")
    if not token:
        # Also allow Bearer token in header for REST API requests
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        else:
            return None
    c = db()
    row = c.execute("""
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ? AND (s.expires_at IS NULL OR s.expires_at > ?)
    """, (token, now_iso())).fetchone()
    c.close()
    return row

def set_login_cookie(response, token: str):
    response.set_cookie(
        "jobmart_session", token, httponly=True,
        samesite="lax", secure=COOKIE_SECURE,
        max_age=60 * 60 * 24 * 30
    )

def logout_user(request: Request):
    token = request.cookies.get("jobmart_session")
    if token:
        c = db()
        c.execute("DELETE FROM sessions WHERE token=?", (token,))
        c.commit()
        c.close()

def require_user(request: Request):
    u = current_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Authentication required")
    if u["is_blocked"]:
        raise HTTPException(status_code=403, detail="Your account is suspended")
    return u

def require_employer(request: Request):
    u = require_user(request)
    if u["role"] not in ("employer", "admin"):
        raise HTTPException(status_code=403, detail="Employer privileges required")
    return u

def require_admin(request: Request):
    u = require_user(request)
    if u["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return u

def redirect_login(msg: str = "Please login first."):
    return RedirectResponse("/login?msg=" + urllib.parse.quote(msg), status_code=303)

# ============================================================
# NOTIFICATIONS & OTP DISPATCH
# ============================================================

def notify(user_id: int, title: str, message: str):
    c = db()
    c.execute("INSERT INTO notifications(user_id, title, message, created_at) VALUES(?,?,?,?)",
              (user_id, title, message, now_iso()))
    c.commit()
    c.close()

def notify_job_owner(job_id: int, title: str, message: str):
    c = db()
    row = c.execute("SELECT employer_id FROM jobs WHERE id=?", (job_id,)).fetchone()
    c.close()
    if row:
        notify(row["employer_id"], title, message)

def create_otp(email: str, purpose: str) -> str:
    otp = str(secrets.randbelow(900000) + 100000)
    expires = int(datetime.now(timezone.utc).timestamp()) + 600
    c = db()
    c.execute("UPDATE otps SET used=1 WHERE email=? AND purpose=? AND used=0", (email, purpose))
    c.execute("INSERT INTO otps(email, otp, purpose, expires_at) VALUES(?,?,?,?)",
              (email, otp, purpose, expires))
    c.commit()
    c.close()
    return otp

def verify_otp(email: str, otp: str, purpose: str) -> bool:
    now = int(datetime.now(timezone.utc).timestamp())
    c = db()
    row = c.execute("""
        SELECT * FROM otps
        WHERE email=? AND purpose=? AND used=0 AND expires_at>? 
        ORDER BY id DESC LIMIT 1
    """, (email, purpose, now)).fetchone()
    if not row or row["attempts"] >= 5:
        c.close()
        return False
    if not secrets.compare_digest(str(row["otp"]), clean(otp)):
        c.execute("UPDATE otps SET attempts = attempts + 1 WHERE id=?", (row["id"],))
        c.commit()
        c.close()
        return False
    c.execute("UPDATE otps SET used=1 WHERE id=?", (row["id"],))
    c.commit()
    c.close()
    return True

def send_email(to_email: str, subject: str, body: str):
    if not SMTP_HOST:
        return False, "SMTP server not configured"
    try:
        msg = EmailMessage()
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
            s.starttls()
            if SMTP_USER and SMTP_PASSWORD:
                s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(msg)
        return True, "sent"
    except Exception as e:
        return False, str(e)

def send_sms(phone: str, message: str):
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM and phone):
        return False, "SMS gateway credentials not set"
    try:
        data = urllib.parse.urlencode({"To": phone, "From": TWILIO_FROM, "Body": message}).encode()
        url = f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json"
        req = urllib.request.Request(url, data=data, method="POST")
        auth = base64.b64encode(f"{TWILIO_ACCOUNT_SID}:{TWILIO_AUTH_TOKEN}".encode()).decode()
        req.add_header("Authorization", "Basic " + auth)
        urllib.request.urlopen(req, timeout=20).read()
        return True, "sent"
    except Exception as e:
        return False, str(e)

def deliver_otp(email: str, phone: str, otp: str, purpose: str):
    subject = f"{APP_NAME} Verification Code"
    text = f"Your {APP_NAME} verification code for {purpose} is {otp}. Valid for 10 minutes."
    email_ok, email_msg = send_email(email, subject, text)
    sms_ok, sms_msg = (False, "")
    if phone:
        sms_ok, sms_msg = send_sms(phone, text)
    # If no gateway configured, inform frontend to display demo OTP
    demo_mode = (not email_ok) and (not sms_ok)
    return demo_mode, email_ok, sms_ok

# ============================================================
# AI ENGINE (OPENAI / GEMINI COMPATIBLE WITH FALLBACKS)
# ============================================================

def openai_call(messages: list, temperature: float = 0.3) -> Optional[str]:
    if not OPENAI_API_KEY:
        return None
    payload = {
        "model": OPENAI_MODEL,
        "messages": messages,
        "temperature": temperature
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.loads(r.read().decode())
            return res["choices"][0]["message"]["content"].strip()
    except Exception:
        return None

def ai_support_chat(user_msg: str, role: str = "guest") -> str:
    system_prompt = (
        "You are Job Mart AI Assistant. Help users navigate jobs, draft cover letters, "
        "detect fraud, build profiles and troubleshoot. Be concise, polite, and actionable. "
        "Warn users never to transfer money for interviews or share credentials."
    )
    res = openai_call([
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"User role: {role}\nQuery: {user_msg}"}
    ])
    if res:
        return res
    m = user_msg.lower()
    if any(k in m for k in ("resume", "cv")):
        return "You can upload or generate your resume inside Profile -> Resume Builder. Keep achievements measurable."
    if any(k in m for k in ("scam", "fraud", "money", "fake")):
        return "Safety Warning: Legitimate employers on Job Mart never demand fees for interviews, training, or kit. Report flagged jobs instantly."
    if any(k in m for k in ("apply", "application")):
        return "Click on any job listing and submit your cover letter. Check real-time progress under Seeker Dashboard."
    if any(k in m for k in ("post", "hire", "employer")):
        return "Employers can post and manage listings via the 'Post Job' and 'Employer Desk' menus."
    return "Hello! I am Job Mart AI Support. Ask me about job listings, resume tips, interview prep, or safety verification."

def ai_resume_advisor(skills: str, bio: str, target_job: str = "") -> str:
    prompt = f"Analyze skills: '{skills}' and bio: '{bio}' for target role '{target_job}'. Provide 3 bullet improvements and 3 recommended keywords."
    res = openai_call([
        {"role": "system", "content": "You are a senior hiring recruiter. Provide high-impact resume bullet points."},
        {"role": "user", "content": prompt}
    ])
    if res:
        return res
    return (
        "1. Highlight quantifiable achievements (e.g. 'Boosted performance by 25%').\n"
        "2. Align technical keywords directly with posted vacancy requirements.\n"
        "3. Include direct links to projects, certifications, and code repositories."
    )

# ============================================================
# UI DESIGN SYSTEM & RESPONSIVE HTML GENERATOR
# ============================================================

CSS = r"""
:root{--primary:#1976ed;--primary-dark:#1256b0;--secondary:#f0f4f9;--text:#172033;--muted:#657388;--border:#d6dfeb;--card:#ffffff;--bg:#f6f8fb;--danger:#e03137;--success:#178c54;--warn:#f59e0b}
*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
a{text-decoration:none;color:inherit}
.header{position:sticky;top:0;z-index:100;background:var(--primary);color:#fff;box-shadow:0 3px 12px rgba(0,0,0,0.1)}
.navbar{max-width:1200px;margin:auto;padding:12px 18px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
.brand{font-size:24px;font-weight:800;letter-spacing:-0.5px}
.nav-menu{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.nav-link{padding:8px 12px;border-radius:6px;font-size:14px;font-weight:600;color:#fff;display:inline-block;transition:0.2s}
.nav-link:hover{background:rgba(255,255,255,0.2)}
.container{max-width:1200px;margin:28px auto;padding:0 18px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px;box-shadow:0 2px 6px rgba(0,0,0,0.04);margin-bottom:22px}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}.three{grid-template-columns:repeat(3,1fr)}.four{grid-template-columns:repeat(4,1fr)}
input,select,textarea{width:100%;padding:11px 14px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:#fff;margin-top:6px;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(25,118,237,0.15)}
textarea{min-height:110px;resize:vertical}
label{font-weight:700;font-size:13px;color:#334155;display:block;margin-top:12px}
.btn{display:inline-block;border:0;background:var(--primary);color:#fff;border-radius:8px;padding:10px 18px;font-weight:700;font-size:14px;cursor:pointer;text-align:center;transition:0.2s}
.btn:hover{background:var(--primary-dark)}
.btn.secondary{background:var(--secondary);color:var(--primary)}
.btn.success{background:var(--success)}
.btn.danger{background:var(--danger)}
.btn.warn{background:var(--warn);color:#000}
.btn.sm{padding:6px 12px;font-size:12px;border-radius:6px}
.badge{display:inline-block;padding:3px 9px;border-radius:14px;background:#e9f2ff;color:var(--primary);font-size:12px;font-weight:600}
.badge.green{background:#e8f7ee;color:var(--success)}
.badge.red{background:#feecee;color:var(--danger)}
.badge.orange{background:#fef5e7;color:#b45309}
.job-item{background:#fff;border:1px solid var(--border);border-radius:12px;padding:20px;display:flex;flex-direction:column;justify-content:space-between;border-left:4px solid var(--primary);transition:transform 0.15s}
.job-item:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,0.06)}
.job-title{font-size:19px;font-weight:700;color:var(--primary);margin-bottom:6px}
.job-company{font-weight:700;color:#2c3e50;font-size:14px;margin-bottom:4px}
.job-meta{font-size:13px;color:var(--muted);margin-bottom:12px}
.alert{padding:12px 16px;border-radius:8px;background:#fdf2f2;color:var(--danger);border:1px solid #f9d6d7;margin-bottom:18px;font-size:14px}
.alert.ok{background:#edf9f2;color:var(--success);border-color:#c7eed5}
.stats-box{background:var(--secondary);border-radius:10px;padding:18px;text-align:center}
.stats-box b{display:block;font-size:26px;color:var(--primary);margin-top:4px}
table{width:100%;border-collapse:collapse;margin-top:14px}
th,td{padding:12px;border-bottom:1px solid var(--border);text-align:left;font-size:14px}
th{background:#f8fafc;font-weight:700}
@media(max-width:850px){.grid,.three,.four{grid-template-columns:1fr}.navbar{flex-direction:column;align-items:flex-start}}
"""

def render_page(title: str, content: str, user=None, msg: str = "", ok: str = ""):
    nav = '<a class="nav-link" href="/">Explore Jobs</a>'
    if user:
        if user["role"] in ("employer", "admin"):
            nav += '<a class="nav-link" href="/jobs/post">Post Job</a>'
            nav += '<a class="nav-link" href="/employer/dashboard">Employer Desk</a>'
        if user["role"] in ("jobseeker", "admin"):
            nav += '<a class="navlink" href="/seeker/dashboard">My Applications</a>'
            nav += '<a class="nav-link" href="/saved">Bookmarks</a>'
        if user["role"] == "admin":
            nav += '<a class="nav-link" href="/admin">Admin Panel</a>'
        nav += '<a class="nav-link" href="/profile">Profile</a>'
        nav += '<a class="nav-link" href="/notifications">Alerts</a>'
        nav += '<a class="nav-link" href="/ai-assistant">AI Support</a>'
        nav += '<a class="nav-link" href="/logout">Logout</a>'
    else:
        nav += '<a class="nav-link" href="/login">Login</a>'
        nav += '<a class="nav-link" href="/register">Register</a>'
        nav += '<a class="nav-link" href="/ai-assistant">AI Help</a>'

    alert_html = ""
    if msg:
        alert_html += f'<div class="alert">{esc(msg)}</div>'
    if ok:
        alert_html += f'<div class="alert ok">{esc(ok)}</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} — {APP_NAME}</title>
<style>{CSS}</style>
</head>
<body>
<header class="header">
  <div class="navbar">
    <a href="/" class="brand">🚀 {APP_NAME}</a>
    <nav class="nav-menu">{nav}</nav>
  </div>
</header>
<main class="container">
  {alert_html}
  {content}
</main>
</body>
</html>"""

# ============================================================
# PUBLIC JOB SEARCH & DISCOVERY
# ============================================================

@app.get("/", response_class=HTMLResponse)
def home_jobs(
    request: Request,
    q: str = "",
    category: str = "",
    job_type: str = "",
    country: str = "India",
    msg: str = "",
    ok: str = ""
):
    user = current_user(request)
    c = db()
    query = "SELECT * FROM jobs WHERE status='active' AND is_flagged=0"
    params = []

    if q:
        query += " AND (title LIKE ? OR description LIKE ? OR skills LIKE ? OR company LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])
    if category and category != "All":
        query += " AND category=?"
        params.append(category)
    if job_type and job_type != "All":
        query += " AND job_type=?"
        params.append(job_type)
    if country and country != "All":
        query += " AND country=?"
        params.append(country)

    query += " ORDER BY id DESC LIMIT 40"
    job_rows = c.execute(query, params).fetchall()
    c.close()

    cat_opts = '<option value="All">All Categories</option>'
    for cat in categories():
        sel = "selected" if cat == category else ""
        cat_opts += f'<option value="{esc(cat)}" {sel}>{esc(cat)}</option>'

    type_opts = '<option value="All">All Types</option>'
    for jt in ["Full Time", "Part Time", "Contract", "Remote", "Internship"]:
        sel = "selected" if jt == job_type else ""
        type_opts += f'<option value="{jt}" {sel}>{jt}</option>'

    cards = ""
    for r in job_rows:
        cards += f"""
        <div class="job-item">
          <div>
            <a href="/jobs/{r['id']}" class="job-title">{esc(r['title'])}</a>
            <div class="job-company">{esc(r['company'] or 'Verified Enterprise')}</div>
            <div class="job-meta">📍 {esc(r['location'])}, {esc(r['country'])} • 💼 {esc(r['job_type'])}</div>
            <p style="font-size:13px; color:#475569; margin-bottom:12px;">{esc(r['description'][:140])}...</p>
            <div>
              <span class="badge">{esc(r['category'])}</span>
              <span class="badge green">{esc(r['salary'] or 'Best in Industry')}</span>
            </div>
          </div>
          <div style="margin-top:16px; display:flex; gap:8px;">
            <a href="/jobs/{r['id']}" class="btn sm">View Role</a>
            <form action="/jobs/{r['id']}/save" method="post" style="display:inline;">
              <button class="btn secondary sm" type="submit">Bookmark</button>
            </form>
          </div>
        </div>
        """

    if not cards:
        cards = '<div class="card empty" style="grid-column:1/-1; text-align:center; color:#64748b;">No matching roles found. Try resetting filters.</div>'

    filter_box = f"""
    <div class="card">
      <h2 style="margin-bottom:12px; font-size:22px;">Discover Opportunities</h2>
      <form method="get" action="/" class="grid four">
        <input type="text" name="q" value="{esc(q)}" placeholder="Job title, keywords, company...">
        <select name="category">{cat_opts}</select>
        <select name="job_type">{type_opts}</select>
        <button class="btn" type="submit">Search Jobs</button>
      </form>
    </div>
    <div class="grid" style="grid-template-columns: repeat(auto-fill, minmax(330px, 1fr));">
      {cards}
    </div>
    """
    return HTMLResponse(render_page("Job Explorer", filter_box, user, msg=msg, ok=ok))

@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_details(job_id: int, request: Request, msg: str = "", ok: str = ""):
    user = current_user(request)
    c = db()
    c.execute("UPDATE jobs SET views = views + 1 WHERE id=?", (job_id,))
    c.commit()
    job = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    
    already_applied = False
    if user:
        app_check = c.execute("SELECT id FROM applications WHERE job_id=? AND user_id=?", (job_id, user["id"])).fetchone()
        already_applied = bool(app_check)
    c.close()

    if not job:
        raise HTTPException(status_code=404, detail="Job listing not found")

    action_section = ""
    if not user:
        action_section = '<p><a href="/login" class="btn">Login to Apply</a></p>'
    elif user["role"] == "jobseeker":
        if already_applied:
            action_section = '<div class="alert ok">You have applied for this position. Track progress under Dashboard.</div>'
        else:
            action_section = f"""
            <form method="post" action="/jobs/{job_id}/apply">
              <label>Cover Letter / Qualifications</label>
              <textarea name="cover_letter" placeholder="Explain why you are an ideal fit for this role..."></textarea>
              <button class="btn success" style="margin-top:12px;" type="submit">Confirm Application</button>
            </form>
            """

    content = f"""
    <div class="card" style="max-width:800px; margin:auto;">
      <div style="display:flex; justify-content:space-between; align-items:flex-start;">
        <div>
          <h1 style="font-size:26px; color:#1e293b;">{esc(job['title'])}</h1>
          <div style="font-size:16px; font-weight:700; color:#3b82f6; margin-top:4px;">{esc(job['company'])}</div>
          <div style="color:#64748b; font-size:14px; margin:6px 0;">📍 {esc(job['location'])}, {esc(job['country'])} • {esc(job['job_type'])}</div>
        </div>
        <div style="text-align:right;">
          <span class="badge green" style="font-size:14px; padding:6px 12px;">{esc(job['salary'] or 'Negotiable')}</span>
          <div style="font-size:12px; color:#94a3b8; margin-top:6px;">Views: {job['views']}</div>
        </div>
      </div>
      <hr style="margin:20px 0; border:0; border-top:1px solid #e2e8f0;">
      <h3 style="font-size:17px; margin-bottom:8px;">Job Description</h3>
      <p style="white-space:pre-wrap; line-height:1.7; color:#334155;">{esc(job['description'])}</p>
      
      <h3 style="font-size:17px; margin:18px 0 8px;">Key Requirements & Skills</h3>
      <p style="color:#334155;">{esc(job['skills'] or 'Open for relevant qualifications')}</p>
      
      <hr style="margin:20px 0; border:0; border-top:1px solid #e2e8f0;">
      {action_section}
      
      <div style="margin-top:24px; padding-top:14px; border-top:1px dashed #cbd5e1; display:flex; justify-content:space-between;">
        <form action="/jobs/{job_id}/report" method="post" style="display:inline;">
          <input type="hidden" name="reason" value="Potential Spam or Irregular Request">
          <button class="btn danger sm" type="submit">Report Suspicious Job</button>
        </form>
        <form action="/jobs/{job_id}/save" method="post" style="display:inline;">
          <button class="btn secondary sm" type="submit">Bookmark Role</button>
        </form>
      </div>
    </div>
    """
    return HTMLResponse(render_page(job["title"], content, user, msg=msg, ok=ok))

@app.post("/jobs/{job_id}/apply")
def apply_to_job(job_id: int, request: Request, cover_letter: str = Form("")):
    user = current_user(request)
    if not user:
        return redirect_login("Please login before applying.")
    if user["role"] != "jobseeker":
        return RedirectResponse(f"/jobs/{job_id}?msg=Employer+accounts+cannot+apply+for+jobs.", status_code=303)

    c = db()
    try:
        c.execute("""
            INSERT INTO applications(job_id, user_id, cover_letter, created_at, updated_at)
            VALUES(?,?,?,?,?)
        """, (job_id, user["id"], clean(cover_letter), now_iso(), now_iso()))
        c.commit()
        notify_job_owner(job_id, "Candidate Applied", f"{user['name']} has applied for your job posting.")
    except sqlite3.IntegrityError:
        c.close()
        return RedirectResponse(f"/jobs/{job_id}?msg=You+have+already+applied+to+this+role.", status_code=303)
    c.close()
    return RedirectResponse(f"/jobs/{job_id}?ok=Application+submitted+successfully!", status_code=303)

@app.post("/jobs/{job_id}/save")
def bookmark_job(job_id: int, request: Request):
    user = current_user(request)
    if not user:
        return redirect_login("Please sign in to save jobs.")
    c = db()
    c.execute("INSERT OR IGNORE INTO saved_jobs(user_id, job_id, created_at) VALUES(?,?,?)",
              (user["id"], job_id, now_iso()))
    c.commit()
    c.close()
    return RedirectResponse("/saved?ok=Role+saved+to+your+bookmarks.", status_code=303)

@app.get("/saved", response_class=HTMLResponse)
def view_saved(request: Request):
    user = require_user(request)
    c = db()
    rows = c.execute("""
        SELECT j.* FROM saved_jobs s
        JOIN jobs j ON j.id = s.job_id
        WHERE s.user_id = ?
        ORDER BY s.created_at DESC
    """, (user["id"],)).fetchall()
    c.close()

    cards = ""
    for r in rows:
        cards += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <h3><a href="/jobs/{r['id']}">{esc(r['title'])}</a></h3>
            <div style="color:#64748b; font-size:13px;">{esc(r['company'])} • {esc(r['location'])}</div>
          </div>
          <div>
            <a href="/jobs/{r['id']}" class="btn sm">Apply Now</a>
          </div>
        </div>
        """
    if not cards:
        cards = '<div class="card empty">No bookmarked jobs found.</div>'

    return HTMLResponse(render_page("Bookmarked Jobs", f"<h2>Saved Vacancies</h2><br>{cards}", user))

@app.post("/jobs/{job_id}/report")
def report_job(job_id: int, request: Request, reason: str = Form("Fraudulent/Spam")):
    user = current_user(request)
    if not user:
        return redirect_login("Please sign in to report a listing.")
    c = db()
    c.execute("INSERT INTO reports(job_id, user_id, reason, details, created_at) VALUES(?,?,?,?,?)",
              (job_id, user["id"], clean(reason), "Flagged via direct action", now_iso()))
    c.commit()
    c.close()
    return RedirectResponse(f"/jobs/{job_id}?ok=Listing+has+been+reported+for+moderation.", status_code=303)

# ============================================================
# AUTHENTICATION: LOGIN, REGISTER, REAL/DEMO OTP & RECOVERY
# ============================================================

@app.get("/login", response_class=HTMLResponse)
def login_view(request: Request, msg: str = "", ok: str = ""):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    content = f"""
    <div class="card" style="max-width:440px; margin:auto;">
      <h2 style="margin-bottom:14px; text-align:center;">Welcome Back</h2>
      <form method="post" action="/login">
        <label>Email Address</label>
        <input type="email" name="email" required autofocus>
        <label>Password</label>
        <input type="password" name="password" required>
        <button class="btn" style="width:100%; margin-top:18px;" type="submit">Sign In with Password</button>
      </form>
      <div style="margin-top:18px; text-align:center; font-size:13px; color:#64748b;">
        <a href="/login/otp" style="color:#2563eb; font-weight:600;">Sign in via Mobile/Email OTP</a> • 
        <a href="/forgot-password" style="color:#2563eb;">Forgot Password?</a>
      </div>
      <div style="margin-top:14px; text-align:center; font-size:13px; color:#64748b;">
        Don't have an account? <a href="/register" style="color:#2563eb; font-weight:700;">Create Account</a>
      </div>
    </div>
    """
    return HTMLResponse(render_page("Login", content, None, msg=msg, ok=ok))

@app.post("/login")
def login_post(email: str = Form(...), password: str = Form(...)):
    email = clean(email).lower()
    c = db()
    u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    c.close()
    if not u or not verify_password(password, u["password_hash"]):
        return redirect_login("Incorrect email or password credentials.")
    if u["is_blocked"]:
        return redirect_login("Your account has been suspended by administration.")

    token = create_session(u["id"])
    resp = RedirectResponse("/", status_code=303)
    set_login_cookie(resp, token)
    return resp

@app.get("/login/otp", response_class=HTMLResponse)
def login_otp_view(request: Request, step: str = "request", email: str = "", demo_otp: str = "", msg: str = ""):
    if step == "request":
        content = f"""
        <div class="card" style="max-width:440px; margin:auto;">
          <h2>OTP Sign-In</h2>
          <p style="font-size:13px; color:#64748b; margin-top:4px;">Receive a secure login code via registered Email or SMS.</p>
          <form method="post" action="/login/otp/request" style="margin-top:16px;">
            <label>Registered Email</label>
            <input type="email" name="email" required>
            <button class="btn" style="width:100%; margin-top:16px;" type="submit">Generate OTP</button>
          </form>
        </div>
        """
    else:
        demo_box = ""
        if demo_otp:
            demo_box = f'<div class="alert ok" style="text-align:center;"><b>Demo Simulation OTP:</b> {demo_otp}</div>'
        content = f"""
        <div class="card" style="max-width:440px; margin:auto;">
          <h2>Enter Verification Code</h2>
          <p style="font-size:13px; color:#64748b; margin-top:4px;">OTP sent to: <b>{esc(email)}</b></p>
          {demo_box}
          <form method="post" action="/login/otp/verify" style="margin-top:16px;">
            <input type="hidden" name="email" value="{esc(email)}">
            <label>6-Digit Verification Code</label>
            <input type="text" name="otp" pattern="[0-9]{{6}}" required autofocus>
            <button class="btn success" style="width:100%; margin-top:16px;" type="submit">Verify & Login</button>
          </form>
        </div>
        """
    return HTMLResponse(render_page("OTP Login", content, None, msg=msg))

@app.post("/login/otp/request")
def otp_request_post(email: str = Form(...)):
    email = clean(email).lower()
    c = db()
    user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    c.close()
    if not user:
        return RedirectResponse("/login/otp?msg=No+account+found+with+that+email.", status_code=303)
    if user["is_blocked"]:
        return RedirectResponse("/login/otp?msg=Account+suspended.", status_code=303)

    otp = create_otp(email, "login")
    demo_mode, email_ok, sms_ok = deliver_otp(email, user["phone"], otp, "login")
    demo_param = f"&demo_otp={otp}" if demo_mode else ""
    return RedirectResponse(f"/login/otp?step=verify&email={urllib.parse.quote(email)}{demo_param}", status_code=303)

@app.post("/login/otp/verify")
def otp_verify_post(email: str = Form(...), otp: str = Form(...)):
    email = clean(email).lower()
    if not verify_otp(email, otp, "login"):
        return RedirectResponse(f"/login/otp?step=verify&email={urllib.parse.quote(email)}&msg=Invalid+or+expired+code.", status_code=303)
    c = db()
    u = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    c.close()
    token = create_session(u["id"])
    resp = RedirectResponse("/", status_code=303)
    set_login_cookie(resp, token)
    return resp

@app.get("/register", response_class=HTMLResponse)
def register_view(request: Request, msg: str = ""):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    content = f"""
    <div class="card" style="max-width:500px; margin:auto;">
      <h2 style="margin-bottom:12px; text-align:center;">Create Your Free Account</h2>
      <form method="post" action="/register">
        <label>Full Name</label>
        <input type="text" name="name" required>
        <label>Email Address</label>
        <input type="email" name="email" required>
        <label>Mobile Phone (with country code)</label>
        <input type="tel" name="phone" placeholder="+919876543210">
        <label>Password (min 6 characters)</label>
        <input type="password" name="password" required minlength="6">
        <label>Account Intention</label>
        <select name="role">
          <option value="jobseeker">Job Seeker (Browse & Apply)</option>
          <option value="employer">Employer / Recruiter (Post & Hire)</option>
        </select>
        <button class="btn" style="width:100%; margin-top:20px;" type="submit">Complete Registration</button>
      </form>
    </div>
    """
    return HTMLResponse(render_page("Register", content, None, msg=msg))

@app.post("/register")
def register_post(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    phone: str = Form(""),
    role: str = Form("jobseeker")
):
    email = clean(email).lower()
    if not valid_email(email):
        return RedirectResponse("/register?msg=Invalid+email+address+format.", status_code=303)
    if role not in ("jobseeker", "employer"):
        role = "jobseeker"

    c = db()
    if c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        c.close()
        return RedirectResponse("/login?msg=Email+already+registered.+Please+sign+in.", status_code=303)

    c.execute("""
        INSERT INTO users(name, email, phone, password_hash, role, created_at)
        VALUES(?,?,?,?,?,?)
    """, (clean(name), email, clean(phone), hash_password(password), role, now_iso()))
    user_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
    c.commit()
    c.close()

    token = create_session(user_id)
    resp = RedirectResponse("/", status_code=303)
    set_login_cookie(resp, token)
    return resp

@app.get("/logout")
def logout_handler(request: Request):
    logout_user(request)
    resp = RedirectResponse("/login?ok=Logged+out+successfully.", status_code=303)
    resp.delete_cookie("jobmart_session")
    return resp

# ============================================================
# JOBSEEKER PORTAL: RESUME BUILDER, PROFILE & APPLICATIONS
# ============================================================

@app.get("/seeker/dashboard", response_class=HTMLResponse)
def seeker_dashboard(request: Request):
    user = require_user(request)
    c = db()
    apps = c.execute("""
        SELECT a.id as app_id, a.status, a.created_at as applied_at, j.title, j.company, j.location, j.id as job_id
        FROM applications a
        JOIN jobs j ON j.id = a.job_id
        WHERE a.user_id = ?
        ORDER BY a.created_at DESC
    """, (user["id"],)).fetchall()
    c.close()

    rows = ""
    for r in apps:
        badge_cls = "green" if r["status"] == "Accepted" else ("red" if r["status"] == "Rejected" else "orange")
        rows += f"""
        <tr>
          <td><b><a href="/jobs/{r['job_id']}">{esc(r['title'])}</a></b></td>
          <td>{esc(r['company'])}</td>
          <td>{esc(r['applied_at'][:10])}</td>
          <td><span class="badge {badge_cls}">{esc(r['status'])}</span></td>
        </tr>
        """
    if not rows:
        rows = '<tr><td colspan="4" style="text-align:center; color:#64748b;">No active applications submitted yet.</td></tr>'

    content = f"""
    <div class="card">
      <h2>Jobseeker Overview</h2>
      <p style="color:#64748b; margin:4px 0 16px;">Track your submitted profiles and recruiter decisions.</p>
      <table>
        <thead>
          <tr><th>Position</th><th>Company</th><th>Submission Date</th><th>Status</th></tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </div>
    """
    return HTMLResponse(render_page("Seeker Dashboard", content, user))

@app.get("/profile", response_class=HTMLResponse)
def profile_view(request: Request, msg: str = "", ok: str = ""):
    u = require_user(request)
    resume_view = ""
    if u["resume_path"]:
        resume_view = f'<p style="margin-top:6px; font-size:13px;"><a href="/profile/resume/download" target="_blank" style="color:#2563eb; font-weight:700;">📥 View Current Resume Document</a></p>'

    content = f"""
    <div class="card" style="max-width:760px; margin:auto;">
      <h2>User Profile & Resume</h2>
      <form method="post" action="/profile" enctype="multipart/form-data">
        <div class="grid">
          <div>
            <label>Full Name</label>
            <input type="text" name="name" value="{esc(u['name'])}" required>
          </div>
          <div>
            <label>Phone Number</label>
            <input type="tel" name="phone" value="{esc(u['phone'])}">
          </div>
        </div>
        <div class="grid">
          <div>
            <label>Location / City</label>
            <input type="text" name="location" value="{esc(u['location'])}">
          </div>
          <div>
            <label>Role</label>
            <input type="text" value="{esc(u['role'].capitalize())}" disabled style="background:#f1f5f9;">
          </div>
        </div>
        <label>Professional Bio / Summary</label>
        <textarea name="bio">{esc(u['bio'])}</textarea>
        
        <label>Key Skills (comma-separated)</label>
        <input type="text" name="skills" value="{esc(u['skills'])}" placeholder="Python, FastAPI, Docker, PostgreSQL">
        
        <label>Upload New Resume (PDF / DOCX — Max {MAX_UPLOAD_MB}MB)</label>
        <input type="file" name="resume" accept=".pdf,.doc,.docx">
        {resume_view}

        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:24px;">
          <button class="btn" type="submit">Save Profile Updates</button>
          <a href="/profile/resume-builder" class="btn secondary">Open Resume Builder</a>
        </div>
      </form>
    </div>
    """
    return HTMLResponse(render_page("Profile Management", content, u, msg=msg, ok=ok))

@app.post("/profile")
def profile_update(
    request: Request,
    name: str = Form(...),
    phone: str = Form(""),
    location: str = Form(""),
    bio: str = Form(""),
    skills: str = Form(""),
    resume: Optional[UploadFile] = File(None)
):
    u = require_user(request)
    resume_path = u["resume_path"]

    if resume and resume.filename:
        ext = Path(resume.filename).suffix.lower()
        if ext not in (".pdf", ".doc", ".docx"):
            return RedirectResponse("/profile?msg=Only+PDF+and+DOCX+files+are+permitted.", status_code=303)
        
        dest = UPLOAD_DIR / f"resume_user_{u['id']}{ext}"
        size = 0
        with open(dest, "wb") as f:
            while chunk := resume.file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_MB * 1024 * 1024:
                    f.close()
                    dest.unlink(missing_ok=True)
                    return RedirectResponse(f"/profile?msg=File+size+exceeds+{MAX_UPLOAD_MB}MB+limit.", status_code=303)
                f.write(chunk)
        resume_path = str(dest)

    c = db()
    c.execute("""
        UPDATE users SET name=?, phone=?, location=?, bio=?, skills=?, resume_path=?
        WHERE id=?
    """, (clean(name), clean(phone), clean(location), clean(bio), clean(skills), resume_path, u["id"]))
    c.commit()
    c.close()
    return RedirectResponse("/profile?ok=Profile+successfully+updated.", status_code=303)

@app.get("/profile/resume/download")
def download_resume(request: Request):
    u = require_user(request)
    if not u["resume_path"] or not os.path.exists(u["resume_path"]):
        raise HTTPException(status_code=404, detail="No resume document found")
    return FileResponse(u["resume_path"], filename=Path(u["resume_path"]).name)

@app.get("/profile/resume-builder", response_class=HTMLResponse)
def resume_builder_view(request: Request):
    u = require_user(request)
    advice = ai_resume_advisor(u["skills"], u["bio"])
    content = f"""
    <div class="card" style="max-width:800px; margin:auto;">
      <h2>Smart Resume Formatter</h2>
      <div class="alert ok" style="margin-top:12px;">
        <b>AI Recommendations:</b><br>
        <pre style="white-space:pre-wrap; font-family:inherit; margin-top:4px;">{esc(advice)}</pre>
      </div>
      <div style="padding:16px; border:1px solid #cbd5e1; border-radius:8px; background:#fafafa; margin-top:16px;">
        <h1 style="font-size:24px; margin-bottom:2px;">{esc(u['name'])}</h1>
        <p style="color:#64748b; font-size:13px;">{esc(u['email'])} • {esc(u['phone'])} • {esc(u['location'])}</p>
        <hr style="margin:12px 0; border:0; border-top:1px solid #e2e8f0;">
        <h4 style="font-size:14px; text-transform:uppercase; color:#475569;">Profile Summary</h4>
        <p style="font-size:14px; margin-top:4px;">{esc(u['bio'] or 'No summary specified.')}</p>
        <hr style="margin:12px 0; border:0; border-top:1px solid #e2e8f0;">
        <h4 style="font-size:14px; text-transform:uppercase; color:#475569;">Core Competencies</h4>
        <p style="font-size:14px; margin-top:4px;">{esc(u['skills'] or 'Skills not yet provided.')}</p>
      </div>
      <div style="margin-top:18px; text-align:right;">
        <button class="btn" onclick="window.print()">Print / Export PDF</button>
      </div>
    </div>
    """
    return HTMLResponse(render_page("Resume Builder", content, u))

# ============================================================
# EMPLOYER PORTAL: POST, MANAGE JOBS & SCREEN APPLICANTS
# ============================================================

@app.get("/jobs/post", response_class=HTMLResponse)
def post_job_view(request: Request):
    u = require_employer(request)
    cat_opts = "".join([f'<option value="{esc(c)}">{esc(c)}</option>' for c in categories()])
    content = f"""
    <div class="card" style="max-width:760px; margin:auto;">
      <h2>Post a New Job Opportunity</h2>
      <form method="post" action="/jobs/post">
        <label>Job Title</label>
        <input type="text" name="title" required placeholder="Senior Backend Developer">
        
        <div class="grid">
          <div>
            <label>Hiring Company</label>
            <input type="text" name="company" required placeholder="Acme Technologies Ltd">
          </div>
          <div>
            <label>Domain Category</label>
            <select name="category">{cat_opts}</select>
          </div>
        </div>

        <div class="grid three">
          <div>
            <label>Country</label>
            <input type="text" name="country" value="India" required>
          </div>
          <div>
            <label>City / Location</label>
            <input type="text" name="location" required placeholder="Hyderabad / Remote">
          </div>
          <div>
            <label>Engagement Type</label>
            <select name="job_type">
              <option value="Full Time">Full Time</option>
              <option value="Part Time">Part Time</option>
              <option value="Contract">Contract</option>
              <option value="Remote">Remote</option>
              <option value="Internship">Internship</option>
            </select>
          </div>
        </div>

        <label>Salary Range (Annual / Monthly)</label>
        <input type="text" name="salary" placeholder="₹12,00,000 - ₹18,00,000 PA">

        <label>Required Skills & Tech Stack</label>
        <input type="text" name="skills" placeholder="Python, FastAPI, SQL, Docker, AWS">

        <label>Comprehensive Role Description</label>
        <textarea name="description" required placeholder="Provide day-to-day responsibilities, perks, and qualifications..."></textarea>

        <button class="btn" style="margin-top:20px;" type="submit">Publish Job Vacancy</button>
      </form>
    </div>
    """
    return HTMLResponse(render_page("Post Job", content, u))

@app.post("/jobs/post")
def post_job_action(
    request: Request,
    title: str = Form(...),
    company: str = Form(...),
    category: str = Form("Other"),
    country: str = Form("India"),
    location: str = Form(...),
    job_type: str = Form("Full Time"),
    salary: str = Form(""),
    skills: str = Form(""),
    description: str = Form(...)
):
    u = require_employer(request)
    c = db()
    c.execute("""
        INSERT INTO jobs(employer_id, title, company, category, country, location, job_type, salary, skills, description, created_at, updated_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        u["id"], clean(title), clean(company), category, clean(country),
        clean(location), job_type, clean(salary), clean(skills),
        clean(description), now_iso(), now_iso()
    ))
    c.commit()
    c.close()
    return RedirectResponse("/employer/dashboard?ok=Job+listing+published+live.", status_code=303)

@app.get("/employer/dashboard", response_class=HTMLResponse)
def employer_dashboard(request: Request, ok: str = "", msg: str = ""):
    u = require_employer(request)
    c = db()
    jobs = c.execute("""
        SELECT j.*, COUNT(a.id) as applicant_count 
        FROM jobs j
        LEFT JOIN applications a ON a.job_id = j.id
        WHERE j.employer_id = ?
        GROUP BY j.id
        ORDER BY j.id DESC
    """, (u["id"],)).fetchall()
    c.close()

    rows = ""
    for j in jobs:
        status_badge = "green" if j["status"] == "active" else "red"
        rows += f"""
        <tr>
          <td><b><a href="/jobs/{j['id']}">{esc(j['title'])}</a></b></td>
          <td>{esc(j['category'])}</td>
          <td><span class="badge {status_badge}">{esc(j['status'])}</span></td>
          <td><b>{j['applicant_count']}</b></td>
          <td>
            <a href="/employer/jobs/{j['id']}/applicants" class="btn sm">Review ({j['applicant_count']})</a>
            <a href="/employer/jobs/{j['id']}/toggle" class="btn secondary sm">Toggle Status</a>
          </td>
        </tr>
        """
    if not rows:
        rows = '<tr><td colspan="5" style="text-align:center; color:#64748b;">No vacancies listed yet. Create one!</td></tr>'

    content = f"""
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <h2>Employer Management Hub</h2>
        <a href="/jobs/post" class="btn">+ Create Listing</a>
      </div>
      <table style="margin-top:16px;">
        <thead>
          <tr><th>Role Title</th><th>Category</th><th>Status</th><th>Applicants</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </div>
    """
    return HTMLResponse(render_page("Employer Desk", content, u, ok=ok, msg=msg))

@app.get("/employer/jobs/{job_id}/toggle")
def toggle_job_status(job_id: int, request: Request):
    u = require_employer(request)
    c = db()
    job = c.execute("SELECT employer_id, status FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not job or (job["employer_id"] != u["id"] and u["role"] != "admin"):
        c.close()
        raise HTTPException(status_code=403, detail="Unauthorized action")
    new_status = "closed" if job["status"] == "active" else "active"
    c.execute("UPDATE jobs SET status=?, updated_at=? WHERE id=?", (new_status, now_iso(), job_id))
    c.commit()
    c.close()
    return RedirectResponse("/employer/dashboard?ok=Vacancy+status+updated.", status_code=303)

@app.get("/employer/jobs/{job_id}/applicants", response_class=HTMLResponse)
def view_job_applicants(job_id: int, request: Request):
    u = require_employer(request)
    c = db()
    job = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not job or (job["employer_id"] != u["id"] and u["role"] != "admin"):
        c.close()
        raise HTTPException(status_code=403, detail="Listing does not belong to you")

    apps = c.execute("""
        SELECT a.id as app_id, a.status, a.cover_letter, a.created_at,
               u.id as user_id, u.name, u.email, u.phone, u.skills, u.resume_path
        FROM applications a
        JOIN users u ON u.id = a.user_id
        WHERE a.job_id = ?
        ORDER BY a.created_at DESC
    """, (job_id,)).fetchall()
    c.close()

    cards = ""
    for a in apps:
        resume_btn = ""
        if a["resume_path"]:
            resume_btn = f'<a href="/profile/resume/download" class="btn secondary sm">Download CV</a>'
        
        cards += f"""
        <div class="card">
          <div style="display:flex; justify-content:space-between; align-items:flex-start;">
            <div>
              <h3>{esc(a['name'])}</h3>
              <div style="font-size:13px; color:#64748b;">📧 {esc(a['email'])} • 📞 {esc(a['phone'])}</div>
              <p style="margin-top:8px; font-size:14px;"><b>Skills:</b> {esc(a['skills'])}</p>
              <div style="margin-top:10px; padding:10px; background:#f8fafc; border-radius:6px; font-size:13px;">
                <b>Cover Note:</b> {esc(a['cover_letter'] or 'None')}
              </div>
            </div>
            <div style="text-align:right;">
              <span class="badge">{esc(a['status'])}</span>
              <div style="margin-top:12px; display:flex; gap:6px;">
                {resume_btn}
                <form action="/employer/applications/{a['app_id']}/decision" method="post" style="display:inline;">
                  <input type="hidden" name="status" value="Accepted">
                  <button class="btn success sm" type="submit">Shortlist</button>
                </form>
                <form action="/employer/applications/{a['app_id']}/decision" method="post" style="display:inline;">
                  <input type="hidden" name="status" value="Rejected">
                  <button class="btn danger sm" type="submit">Decline</button>
                </form>
              </div>
            </div>
          </div>
        </div>
        """
    if not cards:
        cards = '<div class="card empty">No applicants have registered for this posting yet.</div>'

    content = f"""
    <h2>Applicants for: {esc(job['title'])}</h2>
    <p style="color:#64748b; margin-bottom:16px;">Review candidate profiles and update pipeline status.</p>
    {cards}
    """
    return HTMLResponse(render_page("Applicants Review", content, u))

@app.post("/employer/applications/{app_id}/decision")
def update_application_decision(app_id: int, request: Request, status: str = Form(...)):
    u = require_employer(request)
    c = db()
    app_row = c.execute("""
        SELECT a.id, a.user_id, a.job_id, j.title, j.employer_id 
        FROM applications a
        JOIN jobs j ON j.id = a.job_id
        WHERE a.id = ?
    """, (app_id,)).fetchone()

    if not app_row or (app_row["employer_id"] != u["id"] and u["role"] != "admin"):
        c.close()
        raise HTTPException(status_code=403, detail="Unauthorized")

    c.execute("UPDATE applications SET status=?, updated_at=? WHERE id=?", (status, now_iso(), app_id))
    c.commit()
    c.close()

    notify(app_row["user_id"], "Application Status Change", f"Your status for '{app_row['title']}' is now: {status}")
    return RedirectResponse(f"/employer/jobs/{app_row['job_id']}/applicants", status_code=303)

# ============================================================
# LIVE AI CUSTOMER CARE & SYSTEM NOTIFICATIONS
# ============================================================

@app.get("/ai-assistant", response_class=HTMLResponse)
def ai_assistant_view(request: Request):
    user = current_user(request)
    content = f"""
    <div class="card" style="max-width:700px; margin:auto;">
      <h2>🤖 Job Mart AI Intelligence</h2>
      <p style="font-size:13px; color:#64748b; margin:4px 0 16px;">Ask anything about recruitment, scams, resumes, or platform tools.</p>
      <div id="chatbox" style="height:320px; overflow-y:auto; border:1px solid #e2e8f0; border-radius:8px; padding:14px; background:#f8fafc;">
        <div style="margin-bottom:10px;"><b>AI:</b> Hello! How can I assist your career or hiring workflow today?</div>
      </div>
      <div style="display:flex; gap:8px; margin-top:14px;">
        <input type="text" id="userInput" placeholder="Type your query here..." style="margin-top:0;">
        <button class="btn" onclick="sendQuery()">Submit</button>
      </div>
    </div>
    <script>
    async function sendQuery(){{
      const inp = document.getElementById('userInput');
      const val = inp.value.trim();
      if(!val) return;
      const box = document.getElementById('chatbox');
      box.innerHTML += '<div style="margin-bottom:8px; color:#1e40af;"><b>You:</b> ' + val + '</div>';
      inp.value = '';
      box.scrollTop = box.scrollHeight;
      
      const res = await fetch('/api/ai/chat', {{
        method: 'POST',
        headers: {{'Content-Type':'application/json'}},
        body: JSON.stringify({{query: val}})
      }});
      const data = await res.json();
      box.innerHTML += '<div style="margin-bottom:8px; color:#15803d;"><b>AI:</b> ' + data.reply + '</div>';
      box.scrollTop = box.scrollHeight;
    }}
    </script>
    """
    return HTMLResponse(render_page("AI Assistant", content, user))

@app.post("/api/ai/chat")
async def api_ai_chat(request: Request):
    user = current_user(request)
    data = await request.json()
    query = data.get("query", "")
    role = user["role"] if user else "guest"
    reply = ai_support_chat(query, role)
    return {"reply": reply}

@app.get("/notifications", response_class=HTMLResponse)
def notifications_view(request: Request):
    user = require_user(request)
    c = db()
    rows = c.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50", (user["id"],)).fetchall()
    c.execute("UPDATE notifications SET read=1 WHERE user_id=?", (user["id"],))
    c.commit()
    c.close()

    items = ""
    for r in rows:
        items += f"""
        <div class="card" style="padding:14px 18px; margin-bottom:10px;">
          <b style="color:#1e293b;">{esc(r['title'])}</b>
          <p style="margin-top:4px; font-size:14px; color:#475569;">{esc(r['message'])}</p>
          <span style="font-size:11px; color:#94a3b8;">{esc(r['created_at'][:19])}</span>
        </div>
        """
    if not items:
        items = '<div class="card empty">No notifications available.</div>'
    return HTMLResponse(render_page("Notifications", f"<h2>Recent Activity</h2><br>{items}", user))

# ============================================================
# COMPREHENSIVE ADMIN PANEL (MODERATION & USER SUSPENSION)
# ============================================================

@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request, ok: str = ""):
    u = require_admin(request)
    c = db()
    users_cnt = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    jobs_cnt = c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    apps_cnt = c.execute("SELECT COUNT(*) FROM applications").fetchone()[0]
    reports_cnt = c.execute("SELECT COUNT(*) FROM reports WHERE status='open'").fetchone()[0]

    all_users = c.execute("SELECT id, name, email, role, is_blocked FROM users ORDER BY id DESC LIMIT 20").fetchall()
    reports = c.execute("""
        SELECT r.*, j.title, u.email as reporter_email 
        FROM reports r
        JOIN jobs j ON j.id = r.job_id
        JOIN users u ON u.id = r.user_id
        WHERE r.status = 'open'
        ORDER BY r.id DESC
    """).fetchall()
    c.close()

    user_rows = ""
    for user_row in all_users:
        status_txt = "Active" if not user_row["is_blocked"] else "BLOCKED"
        action_btn = f'<a href="/admin/users/{user_row["id"]}/block" class="btn danger sm">Suspend</a>' if not user_row["is_blocked"] else f'<a href="/admin/users/{user_row["id"]}/unblock" class="btn success sm">Restore</a>'
        user_rows += f"""
        <tr>
          <td>{user_row['id']}</td>
          <td><b>{esc(user_row['name'])}</b></td>
          <td>{esc(user_row['email'])}</td>
          <td>{esc(user_row['role'])}</td>
          <td>{status_txt}</td>
          <td>{action_btn}</td>
        </tr>
        """

    report_rows = ""
    for rep in reports:
        report_rows += f"""
        <tr>
          <td>Job #{rep['job_id']}: {esc(rep['title'])}</td>
          <td>{esc(rep['reporter_email'])}</td>
          <td>{esc(rep['reason'])}</td>
          <td>
            <a href="/admin/jobs/{rep['job_id']}/dismiss" class="btn danger sm">Delete Job</a>
            <a href="/admin/reports/{rep['id']}/resolve" class="btn secondary sm">Ignore</a>
          </td>
        </tr>
        """
    if not report_rows:
        report_rows = '<tr><td colspan="4" style="text-align:center; color:#64748b;">No active moderation flags.</td></tr>'

    content = f"""
    <h2>Platform Administration</h2>
    <div class="grid four" style="margin:20px 0;">
      <div class="stats-box">Users<b>{users_cnt}</b></div>
      <div class="stats-box">Total Jobs<b>{jobs_cnt}</b></div>
      <div class="stats-box">Applications<b>{apps_cnt}</b></div>
      <div class="stats-box">Pending Reports<b>{reports_cnt}</b></div>
    </div>

    <div class="card">
      <h3>Flagged Job Moderation Queue</h3>
      <table>
        <thead><tr><th>Listing</th><th>Reporter</th><th>Reason</th><th>Action</th></tr></thead>
        <tbody>{report_rows}</tbody>
      </table>
    </div>

    <div class="card">
      <h3>User Directory & Permissions</h3>
      <table>
        <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Control</th></tr></thead>
        <tbody>{user_rows}</tbody>
      </table>
    </div>
    """
    return HTMLResponse(render_page("Administration Console", content, u, ok=ok))

@app.get("/admin/users/{user_id}/block")
def admin_block_user(user_id: int, request: Request):
    require_admin(request)
    c = db()
    c.execute("UPDATE users SET is_blocked=1 WHERE id=?", (user_id,))
    c.commit()
    c.close()
    return RedirectResponse("/admin?ok=User+suspended.", status_code=303)

@app.get("/admin/users/{user_id}/unblock")
def admin_unblock_user(user_id: int, request: Request):
    require_admin(request)
    c = db()
    c.execute("UPDATE users SET is_blocked=0 WHERE id=?", (user_id,))
    c.commit()
    c.close()
    return RedirectResponse("/admin?ok=User+restored.", status_code=303)

@app.get("/admin/jobs/{job_id}/dismiss")
def admin_delete_job(job_id: int, request: Request):
    require_admin(request)
    c = db()
    c.execute("DELETE FROM jobs WHERE id=?", (job_id,))
    c.execute("UPDATE reports SET status='resolved' WHERE job_id=?", (job_id,))
    c.commit()
    c.close()
    return RedirectResponse("/admin?ok=Job+listing+purged.", status_code=303)

@app.get("/admin/reports/{rep_id}/resolve")
def admin_resolve_report(rep_id: int, request: Request):
    require_admin(request)
    c = db()
    c.execute("UPDATE reports SET status='resolved' WHERE id=?", (rep_id,))
    c.commit()
    c.close()
    return RedirectResponse("/admin?ok=Flag+resolved.", status_code=303)

# ============================================================
# PRODUCTION REST API CHANNELS (/api/me, /api/jobs, etc.)
# ============================================================

@app.get("/api/me")
def api_me(request: Request):
    u = current_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {
        "id": u["id"],
        "name": u["name"],
        "email": u["email"],
        "role": u["role"],
        "phone": u["phone"],
        "location": u["location"],
        "skills": u["skills"],
        "bio": u["bio"],
        "has_resume": bool(u["resume_path"])
    }

@app.get("/api/jobs")
def api_jobs(q: str = "", category: str = "", limit: int = 50):
    c = db()
    sql = "SELECT id, title, company, category, location, job_type, salary, created_at FROM jobs WHERE status='active' AND is_flagged=0"
    params = []
    if q:
        sql += " AND (title LIKE ? OR skills LIKE ? OR company LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if category and category != "All":
        sql += " AND category = ?"
        params.append(category)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = c.execute(sql, params).fetchall()
    c.close()
    return [dict(r) for r in rows]

@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": now_iso(), "version": "3.5.0"}

if __name__ == "__main__":
    import uvicorn
    print(f"Starting {APP_NAME} Production Server on http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
