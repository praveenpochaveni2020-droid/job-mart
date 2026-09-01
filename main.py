from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from pathlib import Path
from typing import Optional
import sqlite3, hashlib, secrets, os, smtplib, ssl, threading, time
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta

app = FastAPI(title="Job Mart")
DB_FILE = Path(os.getenv("DB_FILE", "job_mart.db"))

# =========================================================
# DATABASE
# =========================================================

def db():
    conn = sqlite3.connect(DB_FILE, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def now():
    return datetime.now(timezone.utc).isoformat()

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
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
    CREATE TABLE IF NOT EXISTS jobs(
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
    CREATE TABLE IF NOT EXISTS applications(
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
    CREATE TABLE IF NOT EXISTS saved_jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(job_id,user_id),
        FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS notifications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS otp_codes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        purpose TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        attempts INTEGER DEFAULT 0,
        used INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()

init_db()

# =========================================================
# AUTH / SECURITY
# =========================================================

SESSIONS = {}
OTP_LOCK = threading.Lock()

def hash_password(password: str):
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 150000).hex()
    return f"{salt}${key}"

def verify_password(password: str, stored: str):
    try:
        salt, key = stored.split("$", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 150000).hex()
        return secrets.compare_digest(check, key)
    except Exception:
        return False

def session_user(request: Request):
    token = request.cookies.get("jobmart_session")
    if not token:
        return None
    user_id = SESSIONS.get(token)
    if not user_id:
        return None
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return user

def require_user(request: Request):
    user = session_user(request)
    if not user:
        raise HTTPException(401, "Please login first")
    return user

def require_employer(request: Request):
    user = require_user(request)
    if user["role"] not in ("employer", "admin"):
        raise HTTPException(403, "Employer account required")
    return user

def clean_email(email):
    return email.strip().lower()

def make_token():
    return secrets.token_urlsafe(40)

# =========================================================
# EMAIL OTP
# =========================================================

def send_email(to_email, subject, body):
    host = os.getenv("SMTP_HOST", "").strip()
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "").strip()
    sender = os.getenv("SMTP_FROM", username).strip()

    if not host or not username or not password:
        print(f"[JOB MART OTP EMAIL NOT CONFIGURED] To={to_email} Subject={subject}\n{body}")
        return False

    msg = EmailMessage()
    msg["From"] = sender or username
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as server:
            server.login(username, password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=20) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(username, password)
            server.send_message(msg)
    return True

def create_otp(email, purpose):
    email = clean_email(email)
    code = f"{secrets.randbelow(1000000):06d}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    conn = db()
    conn.execute("UPDATE otp_codes SET used=1 WHERE email=? AND purpose=? AND used=0",
                 (email, purpose))
    conn.execute(
        "INSERT INTO otp_codes(email,purpose,code_hash,expires_at,created_at) VALUES(?,?,?,?,?)",
        (email, purpose, code_hash, expires, now())
    )
    conn.commit()
    conn.close()

    try:
        send_email(
            email,
            f"Job Mart {purpose.title()} OTP",
            f"Your Job Mart OTP is {code}. It expires in 10 minutes. Do not share this code with anyone."
        )
    except Exception as exc:
        print("SMTP ERROR:", exc)
        print(f"[JOB MART OTP FALLBACK] {email} -> {code}")
    return code

def verify_otp(email, purpose, code):
    email = clean_email(email)
    conn = db()
    row = conn.execute("""
        SELECT * FROM otp_codes
        WHERE email=? AND purpose=? AND used=0
        ORDER BY id DESC LIMIT 1
    """, (email, purpose)).fetchone()
    if not row:
        conn.close()
        return False
    if row["attempts"] >= 5:
        conn.close()
        return False
    try:
        expired = datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc)
    except Exception:
        expired = True
    if expired:
        conn.close()
        return False

    check = hashlib.sha256(code.strip().encode()).hexdigest()
    if not secrets.compare_digest(check, row["code_hash"]):
        conn.execute("UPDATE otp_codes SET attempts=attempts+1 WHERE id=?", (row["id"],))
        conn.commit()
        conn.close()
        return False

    conn.execute("UPDATE otp_codes SET used=1 WHERE id=?", (row["id"],))
    conn.commit()
    conn.close()
    return True

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

class OtpRequest(BaseModel):
    email: str

class OtpLoginData(BaseModel):
    email: str
    code: str

class ForgotVerifyData(BaseModel):
    email: str
    code: str
    new_password: str = Field(min_length=6)

class ProfileData(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    phone: str = ""
    country: str = ""
    city: str = ""
    bio: str = ""

class JobData(BaseModel):
    title: str = Field(min_length=2, max_length=150)
    company: str = Field(min_length=2, max_length=150)
    category: str = "Other"
    country: str = "India"
    location: str = ""
    job_type: str = "Full-time"
    work_mode: str = "On-site"
    salary: str = ""
    description: str = Field(min_length=5)
    skills: str = ""
    application_email: str = ""

class ApplicationData(BaseModel):
    cover_letter: str = ""

# =========================================================
# AUTH API
# =========================================================

@app.post("/api/register")
def register(data: RegisterData):
    role = data.role.lower().strip()
    if role not in ("jobseeker", "employer"):
        role = "jobseeker"
    email = clean_email(data.email)
    conn = db()
    if conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        conn.close()
        raise HTTPException(400, "Email already registered")
    cur = conn.execute("""
        INSERT INTO users(name,email,password,role,phone,country,city,created_at)
        VALUES(?,?,?,?,?,?,?,?)
    """, (data.name.strip(), email, hash_password(data.password), role,
          data.phone.strip(), data.country.strip(), data.city.strip(), now()))
    uid = cur.lastrowid
    conn.commit()
    conn.close()
    return {"ok": True, "message": "Registration successful", "user_id": uid}

@app.post("/api/login")
def login(data: LoginData):
    email = clean_email(data.email)
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(401, "Invalid email or password")
    token = make_token()
    SESSIONS[token] = user["id"]
    return {
        "ok": True,
        "message": "Login successful",
        "user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]},
        "session_token": token
    }

@app.post("/api/login/otp/request")
def request_login_otp(data: OtpRequest):
    email = clean_email(data.email)
    conn = db()
    exists = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not exists:
        raise HTTPException(404, "No account found with this email")
    create_otp(email, "login")
    return {"ok": True, "message": "OTP sent"}

@app.post("/api/login/otp")
def otp_login(data: OtpLoginData):
    email = clean_email(data.email)
    if not verify_otp(email, "login", data.code):
        raise HTTPException(400, "Invalid or expired OTP")
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not user:
        raise HTTPException(404, "Account not found")
    token = make_token()
    SESSIONS[token] = user["id"]
    return {
        "ok": True,
        "message": "OTP login successful",
        "user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]},
        "session_token": token
    }

@app.post("/api/forgot/request")
def forgot_request(data: OtpRequest):
    email = clean_email(data.email)
    conn = db()
    exists = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    # Do not reveal account existence in production; this UI keeps it simple.
    if not exists:
        raise HTTPException(404, "No account found with this email")
    create_otp(email, "password reset")
    return {"ok": True, "message": "Reset OTP sent"}

@app.post("/api/forgot/reset")
def forgot_reset(data: ForgotVerifyData):
    email = clean_email(data.email)
    if not verify_otp(email, "password reset", data.code):
        raise HTTPException(400, "Invalid or expired OTP")
    conn = db()
    conn.execute("UPDATE users SET password=? WHERE email=?",
                 (hash_password(data.new_password), email))
    conn.commit()
    conn.close()
    return {"ok": True, "message": "Password changed successfully"}

@app.post("/api/logout")
def logout(request: Request):
    token = request.cookies.get("jobmart_session")
    if token:
        SESSIONS.pop(token, None)
    return {"ok": True}

@app.get("/api/me")
def me(request: Request):
    user = session_user(request)
    if not user:
        return {"logged_in": False, "user": None}
    return {"logged_in": True, "user": {
        "id": user["id"], "name": user["name"], "email": user["email"],
        "role": user["role"], "phone": user["phone"], "country": user["country"],
        "city": user["city"], "bio": user["bio"]
    }}

# Header token fallback lets the SPA persist login if the browser did not retain a cookie.
@app.middleware("http")
async def session_header_middleware(request: Request, call_next):
    token = request.headers.get("X-JobMart-Session")
    if token and "jobmart_session" not in request.cookies and token in SESSIONS:
        request._jobmart_token = token
    response = await call_next(request)
    return response

def current_user_with_header(request):
    user = session_user(request)
    if user:
        return user
    token = getattr(request, "_jobmart_token", None)
    if token and token in SESSIONS:
        conn = db()
        user = conn.execute("SELECT * FROM users WHERE id=?", (SESSIONS[token],)).fetchone()
        conn.close()
        return user
    return None

# Replace helper behavior for API routes using header fallback.
def require_user2(request):
    user = current_user_with_header(request)
    if not user:
        raise HTTPException(401, "Please login first")
    return user

def require_employer2(request):
    user = require_user2(request)
    if user["role"] not in ("employer", "admin"):
        raise HTTPException(403, "Employer account required")
    return user

# =========================================================
# PROFILE / JOBS API
# =========================================================

@app.put("/api/profile")
def update_profile(data: ProfileData, request: Request):
    user = require_user2(request)
    conn = db()
    conn.execute("""UPDATE users SET name=?,phone=?,country=?,city=?,bio=? WHERE id=?""",
                 (data.name.strip(), data.phone.strip(), data.country.strip(),
                  data.city.strip(), data.bio.strip(), user["id"]))
    conn.commit()
    conn.close()
    return {"ok": True, "message": "Profile updated"}

@app.post("/api/jobs")
def create_job(data: JobData, request: Request):
    user = require_employer2(request)
    conn = db()
    cur = conn.execute("""
        INSERT INTO jobs(employer_id,title,company,category,country,location,job_type,
                         work_mode,salary,description,skills,application_email,status,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (user["id"], data.title.strip(), data.company.strip(), data.category.strip(),
          data.country.strip(), data.location.strip(), data.job_type.strip(),
          data.work_mode.strip(), data.salary.strip(), data.description.strip(),
          data.skills.strip(), data.application_email.strip(), "active", now()))
    jid = cur.lastrowid
    conn.commit()
    conn.close()
    return {"ok": True, "message": "Job posted successfully", "job_id": jid}

@app.get("/api/jobs")
def list_jobs(q: str = "", category: str = "", country: str = "",
              job_type: str = "", work_mode: str = "", mine: bool = False,
              request: Request = None):
    conn = db()
    sql = """SELECT j.*,u.name AS employer_name
             FROM jobs j JOIN users u ON u.id=j.employer_id
             WHERE j.status='active'"""
    params = []
    if q.strip():
        sql += """ AND (LOWER(j.title) LIKE ? OR LOWER(j.company) LIKE ?
                   OR LOWER(j.description) LIKE ? OR LOWER(j.skills) LIKE ?)"""
        v = "%" + q.strip().lower() + "%"
        params += [v, v, v, v]
    if category.strip():
        sql += " AND LOWER(j.category)=LOWER(?)"; params.append(category.strip())
    if country.strip():
        sql += " AND LOWER(j.country)=LOWER(?)"; params.append(country.strip())
    if job_type.strip():
        sql += " AND LOWER(j.job_type)=LOWER(?)"; params.append(job_type.strip())
    if work_mode.strip():
        sql += " AND LOWER(j.work_mode)=LOWER(?)"; params.append(work_mode.strip())
    if mine:
        user = require_employer2(request)
        sql += " AND j.employer_id=?"; params.append(user["id"])
    sql += " ORDER BY j.id DESC"
    rows = conn.execute(sql, params).fetchall()
    result = [dict(x) for x in rows]
    conn.close()
    return {"ok": True, "jobs": result, "count": len(result)}

@app.get("/api/jobs/{job_id}")
def get_job(job_id: int, request: Request):
    conn = db()
    row = conn.execute("""SELECT j.*,u.name AS employer_name,u.email AS employer_email
                          FROM jobs j JOIN users u ON u.id=j.employer_id WHERE j.id=?""",
                       (job_id,)).fetchone()
    if not row:
        conn.close(); raise HTTPException(404, "Job not found")
    user = current_user_with_header(request)
    res = dict(row)
    res["applied"] = False
    res["saved"] = False
    if user:
        res["applied"] = bool(conn.execute(
            "SELECT id FROM applications WHERE job_id=? AND applicant_id=?",
            (job_id, user["id"])).fetchone())
        res["saved"] = bool(conn.execute(
            "SELECT id FROM saved_jobs WHERE job_id=? AND user_id=?",
            (job_id, user["id"])).fetchone())
    conn.close()
    return {"ok": True, "job": res}

@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: int, request: Request):
    user = require_employer2(request)
    conn = db()
    job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        conn.close(); raise HTTPException(404, "Job not found")
    if job["employer_id"] != user["id"] and user["role"] != "admin":
        conn.close(); raise HTTPException(403, "Not allowed")
    conn.execute("UPDATE jobs SET status='closed' WHERE id=?", (job_id,))
    conn.commit(); conn.close()
    return {"ok": True, "message": "Job closed"}

@app.post("/api/jobs/{job_id}/apply")
def apply_job(job_id: int, data: ApplicationData, request: Request):
    user = require_user2(request)
    if user["role"] == "employer":
        raise HTTPException(403, "Employer accounts cannot apply")
    conn = db()
    job = conn.execute("SELECT * FROM jobs WHERE id=? AND status='active'", (job_id,)).fetchone()
    if not job:
        conn.close(); raise HTTPException(404, "Job not found")
    if conn.execute("SELECT id FROM applications WHERE job_id=? AND applicant_id=?",
                    (job_id, user["id"])).fetchone():
        conn.close(); raise HTTPException(400, "Already applied")
    conn.execute("""INSERT INTO applications(job_id,applicant_id,cover_letter,status,created_at)
                    VALUES(?,?,?,?,?)""",
                 (job_id, user["id"], data.cover_letter.strip(), "applied", now()))
    conn.execute("""INSERT INTO notifications(user_id,title,message,created_at)
                    VALUES(?,?,?,?)""",
                 (job["employer_id"], "New job application",
                  f"{user['name']} applied for {job['title']}", now()))
    conn.commit(); conn.close()
    return {"ok": True, "message": "Application submitted"}

@app.get("/api/applications")
def applications(request: Request):
    user = require_user2(request)
    conn = db()
    if user["role"] in ("employer","admin"):
        rows = conn.execute("""
            SELECT a.*,j.title,j.company,u.name applicant_name,u.email applicant_email,u.phone applicant_phone
            FROM applications a JOIN jobs j ON j.id=a.job_id
            JOIN users u ON u.id=a.applicant_id
            WHERE j.employer_id=? ORDER BY a.id DESC
        """, (user["id"],)).fetchall()
    else:
        rows = conn.execute("""
            SELECT a.*,j.title,j.company,j.country,j.location
            FROM applications a JOIN jobs j ON j.id=a.job_id
            WHERE a.applicant_id=? ORDER BY a.id DESC
        """, (user["id"],)).fetchall()
    result = [dict(x) for x in rows]
    conn.close()
    return {"ok": True, "applications": result}

@app.post("/api/jobs/{job_id}/save")
def save_job(job_id: int, request: Request):
    user = require_user2(request)
    conn = db()
    if not conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone():
        conn.close(); raise HTTPException(404, "Job not found")
    old = conn.execute("SELECT id FROM saved_jobs WHERE job_id=? AND user_id=?",
                       (job_id,user["id"])).fetchone()
    if old:
        conn.execute("DELETE FROM saved_jobs WHERE id=?", (old["id"],))
        msg = "Removed from saved jobs"
    else:
        conn.execute("INSERT INTO saved_jobs(job_id,user_id,created_at) VALUES(?,?,?)",
                     (job_id,user["id"],now()))
        msg = "Job saved"
    conn.commit(); conn.close()
    return {"ok": True, "message": msg}

@app.get("/api/saved-jobs")
def saved_jobs(request: Request):
    user = require_user2(request)
    conn = db()
    rows = conn.execute("""
        SELECT j.*,s.created_at saved_at FROM saved_jobs s
        JOIN jobs j ON j.id=s.job_id WHERE s.user_id=? ORDER BY s.id DESC
    """, (user["id"],)).fetchall()
    result = [dict(x) for x in rows]
    conn.close()
    return {"ok": True, "jobs": result}

@app.get("/api/notifications")
def notifications(request: Request):
    user = require_user2(request)
    conn = db()
    rows = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC",
                        (user["id"],)).fetchall()
    result = [dict(x) for x in rows]
    conn.close()
    return {"ok": True, "notifications": result}

@app.post("/api/notifications/read")
def notifications_read(request: Request):
    user = require_user2(request)
    conn = db()
    conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (user["id"],))
    conn.commit(); conn.close()
    return {"ok": True}

@app.get("/api/dashboard")
def dashboard(request: Request):
    user = require_user2(request)
    conn = db()
    if user["role"] in ("employer","admin"):
        jobs_count = conn.execute("SELECT COUNT(*) c FROM jobs WHERE employer_id=?",
                                  (user["id"],)).fetchone()["c"]
        active = conn.execute("""SELECT COUNT(*) c FROM jobs
                                 WHERE employer_id=? AND status='active'""",
                              (user["id"],)).fetchone()["c"]
        apps = conn.execute("""SELECT COUNT(*) c FROM applications a JOIN jobs j ON j.id=a.job_id
                               WHERE j.employer_id=?""", (user["id"],)).fetchone()["c"]
        res = {"role":"employer","jobs_posted":jobs_count,"active_jobs":active,"applications":apps}
    else:
        applied = conn.execute("SELECT COUNT(*) c FROM applications WHERE applicant_id=?",
                               (user["id"],)).fetchone()["c"]
        saved = conn.execute("SELECT COUNT(*) c FROM saved_jobs WHERE user_id=?",
                             (user["id"],)).fetchone()["c"]
        res = {"role":"jobseeker","applications":applied,"saved_jobs":saved}
    conn.close()
    return {"ok": True, "dashboard": res}

# =========================================================
# FRONTEND
# =========================================================

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>Job Mart</title>
<style>
:root{--blue:#0878e8;--blue2:#075fc0;--bg:#f4f7fb;--text:#17202a;--muted:#667085;--line:#e2e8f0;--card:#fff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}
button,input,select,textarea{font:inherit}
button{cursor:pointer;border:0}
.topbar{height:64px;background:var(--blue);color:#fff;display:flex;align-items:center;gap:12px;padding:0 14px;position:sticky;top:0;z-index:50;box-shadow:0 2px 8px #0002}
.menuBtn{font-size:26px;background:transparent;color:#fff;width:42px;height:42px;border-radius:9px}
.logo{font-size:23px;font-weight:800;flex:1}
.headerSearch{display:none;max-width:420px;flex:1}
.headerSearch input{width:100%;border:0;border-radius:8px;padding:11px 14px}
.authMini{display:flex;gap:7px}
.whiteBtn{background:#fff;color:var(--blue);padding:10px 13px;border-radius:8px;font-weight:700}
.side{position:fixed;left:-310px;top:0;width:300px;height:100%;background:#fff;z-index:100;box-shadow:4px 0 20px #0003;transition:.22s;overflow:auto}
.side.open{left:0}
.sideHead{background:var(--blue);color:#fff;padding:20px 17px}
.sideHead b{font-size:22px}
.sideUser{font-size:13px;margin-top:7px;opacity:.9}
.menuItem{display:flex;align-items:center;gap:13px;padding:14px 18px;border-bottom:1px solid #f1f3f5;font-weight:600;color:#273444}
.menuItem:hover{background:#f2f7ff}
.overlay{position:fixed;inset:0;background:#0006;z-index:90;display:none}
.overlay.show{display:block}
.main{max-width:1150px;margin:auto;padding:18px}
.page{display:none}.page.active{display:block}
.hero{background:linear-gradient(135deg,#0878e8,#075fc0);color:#fff;border-radius:18px;padding:28px 22px;margin-bottom:18px}
.hero h1{font-size:30px;margin:0 0 8px}
.hero p{margin:0 0 20px;opacity:.9}
.searchBox{background:#fff;border-radius:12px;padding:8px;display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:7px}
.searchBox input,.searchBox select{border:1px solid #dbe2ea;padding:12px;border-radius:8px;min-width:0}
.primary{background:var(--blue);color:#fff;padding:12px 17px;border-radius:9px;font-weight:700}
.secondary{background:#eef5ff;color:var(--blue);padding:11px 14px;border-radius:9px;font-weight:700}
.danger{background:#feecec;color:#c62828;padding:10px 13px;border-radius:9px}
.card{background:#fff;border:1px solid var(--line);border-radius:15px;padding:17px;margin-bottom:13px;box-shadow:0 2px 7px #0000000b}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}
.jobTitle{font-size:19px;font-weight:800;margin:0 0 5px}
.company{font-weight:700;color:#344054}
.meta{color:var(--muted);font-size:14px;line-height:1.8}
.badge{display:inline-block;background:#eaf3ff;color:var(--blue);padding:5px 8px;border-radius:20px;font-size:12px;margin:3px 3px 0 0}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.space{justify-content:space-between}
.formCard{max-width:700px;margin:15px auto;background:#fff;border-radius:16px;padding:22px;border:1px solid var(--line)}
label{display:block;font-weight:700;margin:12px 0 6px}
input,select,textarea{width:100%;padding:12px;border:1px solid #ccd5df;border-radius:9px;background:#fff}
textarea{min-height:110px;resize:vertical}
.tabs{display:flex;gap:7px;overflow:auto;margin-bottom:13px}
.tabs button{white-space:nowrap;padding:10px 14px;border-radius:9px;background:#fff;border:1px solid var(--line)}
.statGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.stat{background:#fff;padding:18px;border-radius:14px;border:1px solid var(--line)}
.stat b{display:block;font-size:27px;color:var(--blue);margin-top:7px}
.empty{background:#fff;border-radius:15px;padding:35px;text-align:center;color:var(--muted);border:1px solid var(--line)}
.toast{position:fixed;right:15px;bottom:15px;background:#17202a;color:#fff;padding:13px 16px;border-radius:10px;z-index:200;display:none;max-width:330px}
.modal{position:fixed;inset:0;background:#0007;z-index:150;display:none;align-items:center;justify-content:center;padding:15px}
.modal.show{display:flex}
.modalBox{background:#fff;border-radius:16px;width:min(650px,100%);max-height:90vh;overflow:auto;padding:20px}
.close{float:right;background:#eef1f5;border-radius:50%;width:34px;height:34px}
.small{font-size:13px;color:var(--muted)}
.footer{text-align:center;color:var(--muted);padding:30px 0}
@media(min-width:760px){.headerSearch{display:block}}
@media(max-width:700px){
 .topbar{height:58px}.logo{font-size:20px}.authMini .whiteBtn{padding:8px 9px;font-size:13px}
 .main{padding:12px}.hero{padding:22px 15px}.hero h1{font-size:25px}
 .searchBox{grid-template-columns:1fr}.grid{grid-template-columns:1fr}
}
</style>
</head>
<body>

<header class="topbar">
<button class="menuBtn" onclick="openMenu()">☰</button>
<div class="logo">Job Mart</div>
<div class="headerSearch"><input id="topSearch" placeholder="Search jobs..." onkeydown="if(event.key==='Enter') searchTop()"></div>
<div class="authMini" id="authMini"><button class="whiteBtn" onclick="showPage('login')">Login</button></div>
</header>

<div id="overlay" class="overlay" onclick="closeMenu()"></div>
<aside id="side" class="side">
  <div class="sideHead">
    <b>Job Mart</b>
    <div class="sideUser" id="sideUser">Find jobs. Build careers.</div>
  </div>
  <div class="menuItem" onclick="go('home')">🏠 Home</div>
  <div class="menuItem" onclick="go('jobs')">💼 Find Jobs</div>
  <div class="menuItem" onclick="go('saved')">❤️ Saved Jobs</div>
  <div class="menuItem" onclick="go('applications')">📄 My Applications</div>
  <div class="menuItem" onclick="go('notifications')">🔔 Notifications</div>
  <div class="menuItem" onclick="go('companies')">🏢 Companies</div>
  <div class="menuItem" id="postMenu" onclick="go('post')" style="display:none">➕ Post a Job</div>
  <div class="menuItem" id="dashboardMenu" onclick="go('dashboard')" style="display:none">📊 Dashboard</div>
  <div class="menuItem" onclick="go('profile')">👤 Profile</div>
  <div class="menuItem" onclick="go('login')">🔐 Login / Register</div>
  <div class="menuItem" id="logoutMenu" onclick="logout()" style="display:none">🚪 Logout</div>
</aside>

<main class="main">

<section id="home" class="page active">
  <div class="hero">
    <h1>Find your next opportunity</h1>
    <p>Search trusted job listings by role, country, company and skills.</p>
    <div class="searchBox">
      <input id="homeQ" placeholder="Job title, company or skills">
      <select id="homeCountry"><option value="">All countries</option><option>India</option><option>USA</option><option>UAE</option><option>Other</option></select>
      <select id="homeType"><option value="">All job types</option><option>Full-time</option><option>Part-time</option><option>Contract</option><option>Freelance</option></select>
      <button class="primary" onclick="homeSearch()">Search</button>
    </div>
  </div>
  <div class="row space"><h2>Latest Jobs</h2><button class="secondary" onclick="go('jobs')">View all</button></div>
  <div id="homeJobs" class="grid"></div>
</section>

<section id="jobs" class="page">
  <div class="card">
    <h2>Find Jobs</h2>
    <div class="searchBox">
      <input id="jobQ" placeholder="Search jobs">
      <select id="jobCountry"><option value="">All countries</option><option>India</option><option>USA</option><option>UAE</option><option>Other</option></select>
      <select id="jobType"><option value="">All types</option><option>Full-time</option><option>Part-time</option><option>Contract</option><option>Freelance</option></select>
      <button class="primary" onclick="loadJobs()">Search</button>
    </div>
  </div>
  <div id="jobsList"></div>
</section>

<section id="login" class="page">
  <div class="formCard">
    <h2>Welcome to Job Mart</h2>
    <p class="small">Login with password or email OTP.</p>
    <div class="tabs">
      <button onclick="loginMode('password')">Password Login</button>
      <button onclick="loginMode('otp')">OTP Login</button>
    </div>
    <div id="passwordLogin">
      <label>Email</label><input id="loginEmail" type="email">
      <label>Password</label><input id="loginPassword" type="password">
      <div class="row" style="margin-top:14px">
        <button class="primary" onclick="passwordLogin()">Login</button>
        <button class="secondary" onclick="showPage('register')">Create account</button>
      </div>
      <p><button class="secondary" onclick="showPage('forgot')">Forgot Password?</button></p>
    </div>
    <div id="otpLogin" style="display:none">
      <label>Email</label><input id="otpEmail" type="email">
      <button class="secondary" style="margin-top:10px" onclick="requestLoginOtp()">Send OTP</button>
      <label>OTP</label><input id="otpCode" inputmode="numeric" maxlength="6">
      <button class="primary" style="margin-top:10px" onclick="otpLogin()">Login with OTP</button>
    </div>
    <p id="loginMsg"></p>
  </div>
</section>

<section id="register" class="page">
 <div class="formCard">
  <h2>Create Account</h2>
  <label>Full name</label><input id="regName">
  <label>Email</label><input id="regEmail" type="email">
  <label>Password</label><input id="regPassword" type="password" placeholder="Minimum 6 characters">
  <label>Account type</label>
  <select id="regRole"><option value="jobseeker">Job Seeker</option><option value="employer">Employer</option></select>
  <label>Phone</label><input id="regPhone">
  <label>Country</label><input id="regCountry" value="India">
  <label>City</label><input id="regCity">
  <button class="primary" style="margin-top:15px" onclick="register()">Create Account</button>
  <p>Already have an account? <button class="secondary" onclick="showPage('login')">Login</button></p>
  <p id="regMsg"></p>
 </div>
</section>

<section id="forgot" class="page">
 <div class="formCard">
  <h2>Forgot Password</h2>
  <p class="small">We will send a 6-digit OTP to your email.</p>
  <label>Email</label><input id="forgotEmail" type="email">
  <button class="secondary" style="margin-top:10px" onclick="requestForgot()">Send Reset OTP</button>
  <label>OTP</label><input id="forgotCode" maxlength="6" inputmode="numeric">
  <label>New Password</label><input id="newPassword" type="password">
  <button class="primary" style="margin-top:10px" onclick="resetPassword()">Change Password</button>
  <p id="forgotMsg"></p>
 </div>
</section>

<section id="post" class="page">
 <div class="formCard">
  <h2>Post a Job</h2>
  <label>Job title</label><input id="jTitle" placeholder="Software Developer">
  <label>Company</label><input id="jCompany">
  <label>Category</label><select id="jCategory"><option>IT</option><option>Sales</option><option>Marketing</option><option>Finance</option><option>Healthcare</option><option>Engineering</option><option>Customer Support</option><option>Other</option></select>
  <label>Country</label><input id="jCountry" value="India">
  <label>Location</label><input id="jLocation" placeholder="Hyderabad / Remote">
  <label>Job type</label><select id="jType"><option>Full-time</option><option>Part-time</option><option>Contract</option><option>Freelance</option></select>
  <label>Work mode</label><select id="jMode"><option>On-site</option><option>Hybrid</option><option>Remote</option></select>
  <label>Salary</label><input id="jSalary" placeholder="₹3-6 LPA">
  <label>Skills</label><input id="jSkills" placeholder="Python, FastAPI, SQL">
  <label>Application email</label><input id="jEmail" type="email">
  <label>Description</label><textarea id="jDesc"></textarea>
  <button class="primary" style="margin-top:14px" onclick="postJob()">Post Job</button>
  <p id="postMsg"></p>
 </div>
</section>

<section id="saved" class="page"><h2>Saved Jobs</h2><div id="savedList"></div></section>
<section id="applications" class="page"><h2>Applications</h2><div id="applicationsList"></div></section>
<section id="notifications" class="page"><div class="row space"><h2>Notifications</h2><button class="secondary" onclick="markRead()">Mark all read</button></div><div id="notificationsList"></div></section>

<section id="dashboard" class="page">
 <h2>Dashboard</h2><div id="dashboardBox"></div>
 <div id="myJobsBox"></div>
</section>

<section id="companies" class="page">
 <h2>Companies & Employers</h2>
 <div class="card"><p>Browse jobs by company using the search and filters. Verified employer features can be expanded as your marketplace grows.</p></div>
 <div id="companyJobs" class="grid"></div>
</section>

<section id="profile" class="page">
 <div class="formCard">
  <h2>My Profile</h2>
  <label>Name</label><input id="pName">
  <label>Phone</label><input id="pPhone">
  <label>Country</label><input id="pCountry">
  <label>City</label><input id="pCity">
  <label>Bio</label><textarea id="pBio"></textarea>
  <button class="primary" style="margin-top:12px" onclick="saveProfile()">Save Profile</button>
  <p id="profileMsg"></p>
 </div>
</section>

<div class="footer">© Job Mart — Jobs, careers and opportunities</div>
</main>

<div id="jobModal" class="modal">
 <div class="modalBox"><button class="close" onclick="closeJob()">×</button><div id="jobDetail"></div></div>
</div>
<div id="toast" class="toast"></div>

<script>
let sessionToken = localStorage.getItem("jobmart_session") || "";
let me = null;

async async function api(url, opts={}){
  opts.headers = Object.assign({"Content-Type":"application/json"}, opts.headers||{});
  if(sessionToken) opts.headers["X-JobMart-Session"] = sessionToken;
  const r = await fetch(url, opts);
  let d={}; try{d=await r.json()}catch(e){}
  if(!r.ok) throw new Error(d.detail || "Request failed");
  return d;
}
function toast(s){const x=document.getElementById("toast");x.textContent=s;x.style.display="block";setTimeout(()=>x.style.display="none",2800)}
function openMenu(){document.getElementById("side").classList.add("open");document.getElementById("overlay").classList.add("show")}
function closeMenu(){document.getElementById("side").classList.remove("open");document.getElementById("overlay").classList.remove("show")}
function go(p){closeMenu();showPage(p)}
function showPage(p){
 document.querySelectorAll(".page").forEach(x=>x.classList.remove("active"));
 const el=document.getElementById(p); if(el) el.classList.add("active");
 window.scrollTo({top:0,behavior:"smooth"});
 if(p==="home") loadHome();
 if(p==="jobs") loadJobs();
 if(p==="saved") loadSaved();
 if(p==="applications") loadApplications();
 if(p==="notifications") loadNotifications();
 if(p==="dashboard") loadDashboard();
 if(p==="profile") loadProfile();
 if(p==="companies") loadCompanies();
}
function loginMode(m){
 document.getElementById("passwordLogin").style.display=m==="password"?"block":"none";
 document.getElementById("otpLogin").style.display=m==="otp"?"block":"none";
}
async function refreshMe(){
 try{
  const d=await api("/api/me"); me=d.user;
  updateUI();
 }catch(e){}
}
function updateUI(){
 const mini=document.getElementById("authMini");
 if(me){
  mini.innerHTML=`<button class="whiteBtn" onclick="go('profile')">👤 ${escapeHtml(me.name.split(" ")[0])}</button>`;
  document.getElementById("sideUser").textContent=`${me.name} • ${me.role}`;
  document.getElementById("logoutMenu").style.display="flex";
  document.getElementById("postMenu").style.display=(me.role==="employer"||me.role==="admin")?"flex":"none";
  document.getElementById("dashboardMenu").style.display="flex";
 }else{
  mini.innerHTML=`<button class="whiteBtn" onclick="showPage('login')">Login</button>`;
  document.getElementById("sideUser").textContent="Find jobs. Build careers.";
  document.getElementById("logoutMenu").style.display="none";
  document.getElementById("postMenu").style.display="none";
  document.getElementById("dashboardMenu").style.display="none";
 }
}
async function passwordLogin(){
 try{
  const d=await api("/api/login",{method:"POST",body:JSON.stringify({email:loginEmail.value,password:loginPassword.value})});
  sessionToken=d.session_token;localStorage.setItem("jobmart_session",sessionToken);me=d.user;updateUI();toast("Login successful");showPage("home");
 }catch(e){loginMsg.textContent=e.message}
}
async function requestLoginOtp(){
 try{await api("/api/login/otp/request",{method:"POST",body:JSON.stringify({email:otpEmail.value})});toast("OTP sent to your email")}catch(e){toast(e.message)}
}
async function otpLogin(){
 try{
  const d=await api("/api/login/otp",{method:"POST",body:JSON.stringify({email:otpEmail.value,code:otpCode.value})});
  sessionToken=d.session_token;localStorage.setItem("jobmart_session",sessionToken);me=d.user;updateUI();toast("OTP login successful");showPage("home");
 }catch(e){toast(e.message)}
}
async function register(){
 try{
  const d=await api("/api/register",{method:"POST",body:JSON.stringify({
   name:regName.value,email:regEmail.value,password:regPassword.value,role:regRole.value,
   phone:regPhone.value,country:regCountry.value,city:regCity.value
  })});
  regMsg.textContent=d.message;toast("Account created");showPage("login");
 }catch(e){regMsg.textContent=e.message}
}
async function requestForgot(){
 try{await api("/api/forgot/request",{method:"POST",body:JSON.stringify({email:forgotEmail.value})});toast("Reset OTP sent")}catch(e){forgotMsg.textContent=e.message}
}
async function resetPassword(){
 try{
  const d=await api("/api/forgot/reset",{method:"POST",body:JSON.stringify({
   email:forgotEmail.value,code:forgotCode.value,new_password:newPassword.value
  })});
  forgotMsg.textContent=d.message;toast("Password changed");showPage("login");
 }catch(e){forgotMsg.textContent=e.message}
}
async function logout(){
 try{await api("/api/logout",{method:"POST"})}catch(e){}
 sessionToken="";localStorage.removeItem("jobmart_session");me=null;updateUI();toast("Logged out");showPage("home");closeMenu()
}
function escapeHtml(s){return String(s??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]))}
function jobCard(j){
 return `<div class="card">
  <div class="jobTitle">${escapeHtml(j.title)}</div>
  <div class="company">${escapeHtml(j.company)}</div>
  <div class="meta">📍 ${escapeHtml(j.location||j.country)}<br>💼 ${escapeHtml(j.job_type)} • ${escapeHtml(j.work_mode)}<br>💰 ${escapeHtml(j.salary||"Salary not disclosed")}</div>
  <div>${String(j.skills||"").split(",").slice(0,5).map(x=>x.trim()?`<span class="badge">${escapeHtml(x.trim())}</span>`:"").join("")}</div>
  <div class="row" style="margin-top:12px">
   <button class="primary" onclick="openJob(${j.id})">View Job</button>
   <button class="secondary" onclick="saveJob(${j.id})">❤️ Save</button>
  </div>
 </div>`
}
async function loadHome(){
 try{const d=await api("/api/jobs");homeJobs.innerHTML=d.jobs.slice(0,6).map(jobCard).join("")||'<div class="empty">No jobs posted yet.</div>'}catch(e){homeJobs.innerHTML='<div class="empty">Unable to load jobs.</div>'}
}
async function loadJobs(){
 const p=new URLSearchParams({q:jobQ.value,country:jobCountry.value,job_type:jobType.value});
 try{const d=await api("/api/jobs?"+p.toString());jobsList.innerHTML=d.jobs.map(jobCard).join("")||'<div class="empty">No jobs found.</div>'}catch(e){jobsList.innerHTML='<div class="empty">'+escapeHtml(e.message)+'</div>'}
}
function homeSearch(){jobQ.value=homeQ.value;jobCountry.value=homeCountry.value;jobType.value=homeType.value;showPage("jobs")}
function searchTop(){homeQ.value=topSearch.value;homeSearch()}
async function openJob(id){
 try{
  const d=await api("/api/jobs/"+id),j=d.job;
  jobDetail.innerHTML=`<h2>${escapeHtml(j.title)}</h2><h3>${escapeHtml(j.company)}</h3>
   <p class="meta">📍 ${escapeHtml(j.location||j.country)}<br>💼 ${escapeHtml(j.job_type)} • ${escapeHtml(j.work_mode)}<br>💰 ${escapeHtml(j.salary||"Not disclosed")}<br>🏷️ ${escapeHtml(j.category)}</p>
   <p>${escapeHtml(j.description)}</p><p><b>Skills:</b> ${escapeHtml(j.skills||"Not specified")}</p>
   <div class="row">
    ${me&&me.role==="jobseeker"&&!j.applied?`<button class="primary" onclick="applyJob(${j.id})">Apply Now</button>`:""}
    ${me&&me.role==="jobseeker"?`<button class="secondary" onclick="saveJob(${j.id})">❤️ ${j.saved?"Saved":"Save Job"}</button>`:""}
   </div>`;
  document.getElementById("jobModal").classList.add("show")
 }catch(e){toast(e.message)}
}
function closeJob(){document.getElementById("jobModal").classList.remove("show")}
async function applyJob(id){
 const cover=prompt("Enter a short cover letter (optional):")||"";
 try{await api("/api/jobs/"+id+"/apply",{method:"POST",body:JSON.stringify({cover_letter:cover})});toast("Application submitted");closeJob()}catch(e){toast(e.message)}
}
async function saveJob(id){
 try{const d=await api("/api/jobs/"+id+"/save",{method:"POST"});toast(d.message);loadHome();if(document.getElementById("saved").classList.contains("active"))loadSaved()}catch(e){toast(e.message)}
}
async function loadSaved(){
 try{const d=await api("/api/saved-jobs");savedList.innerHTML=d.jobs.map(jobCard).join("")||'<div class="empty">No saved jobs.</div>'}catch(e){savedList.innerHTML='<div class="empty">Please login to view saved jobs.</div>'}
}
async function loadApplications(){
 try{const d=await api("/api/applications");applicationsList.innerHTML=d.applications.length?d.applications.map(a=>`<div class="card"><b>${escapeHtml(a.title)}</b><div class="company">${escapeHtml(a.company)}</div><div class="meta">Status: ${escapeHtml(a.status)}<br>${escapeHtml(a.location||"")}</div></div>`).join(""):'<div class="empty">No applications yet.</div>'}catch(e){applicationsList.innerHTML='<div class="empty">Please login first.</div>'}
}
async function loadNotifications(){
 try{const d=await api("/api/notifications");notificationsList.innerHTML=d.notifications.length?d.notifications.map(n=>`<div class="card"><b>${escapeHtml(n.title)}</b><p>${escapeHtml(n.message)}</p><span class="small">${escapeHtml(n.created_at)}</span></div>`).join(""):'<div class="empty">No notifications.</div>'}catch(e){notificationsList.innerHTML='<div class="empty">Please login first.</div>'}
}
async function markRead(){try{await api("/api/notifications/read",{method:"POST"});loadNotifications()}catch(e){toast(e.message)}}
async function postJob(){
 try{
  const d=await api("/api/jobs",{method:"POST",body:JSON.stringify({
   title:jTitle.value,company:jCompany.value,category:jCategory.value,country:jCountry.value,
   location:jLocation.value,job_type:jType.value,work_mode:jMode.value,salary:jSalary.value,
   skills:jSkills.value,application_email:jEmail.value,description:jDesc.value
  })});
  postMsg.textContent=d.message;toast("Job posted");showPage("dashboard")
 }catch(e){postMsg.textContent=e.message}
}
async function loadDashboard(){
 try{
  const d=await api("/api/dashboard");
  const x=d.dashboard;
  dashboardBox.innerHTML=`<div class="statGrid">${Object.entries(x).filter(([k])=>k!=="role").map(([k,v])=>`<div class="stat">${escapeHtml(k.replaceAll("_"," "))}<b>${v}</b></div>`).join("")}</div>`;
  if(x.role==="employer"){
   const j=await api("/api/jobs?mine=true");
   myJobsBox.innerHTML="<h3>My Jobs</h3>"+(j.jobs.map(jobCard).join("")||'<div class="empty">No jobs posted.</div>');
  }else myJobsBox.innerHTML="";
 }catch(e){dashboardBox.innerHTML='<div class="empty">'+escapeHtml(e.message)+'</div>'}
}
async function loadCompanies(){
 try{const d=await api("/api/jobs");const map={};d.jobs.forEach(j=>{map[j.company]=(map[j.company]||0)+1});
  companyJobs.innerHTML=Object.entries(map).map(([n,c])=>`<div class="card"><h3>🏢 ${escapeHtml(n)}</h3><p class="meta">${c} active job(s)</p><button class="secondary" onclick="jobQ.value='${escapeHtml(n).replace(/'/g,"\\'")}';showPage('jobs');loadJobs()">View jobs</button></div>`).join("")||'<div class="empty">No companies yet.</div>'
 }catch(e){companyJobs.innerHTML='<div class="empty">No companies found.</div>'}
}
async function loadProfile(){
 try{
  const d=await api("/api/me"); if(!d.logged_in){showPage("login");return}
  const u=d.user;pName.value=u.name;pPhone.value=u.phone||"";pCountry.value=u.country||"";pCity.value=u.city||"";pBio.value=u.bio||"";
 }catch(e){showPage("login")}
}
async function saveProfile(){
 try{
  const d=await api("/api/profile",{method:"PUT",body:JSON.stringify({name:pName.value,phone:pPhone.value,country:pCountry.value,city:pCity.value,bio:pBio.value})});
  profileMsg.textContent=d.message;await refreshMe();toast("Profile updated")
 }catch(e){profileMsg.textContent=e.message}
}
refreshMe();loadHome();
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(HTML)

@app.get("/health")
def health():
    return {"ok": True, "service": "Job Mart"}
