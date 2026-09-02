from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional
import sqlite3, hashlib, secrets, html, re, os, json, urllib.request, urllib.parse
import smtplib, base64
from email.message import EmailMessage

APP_NAME = "Job Mart"
DB_FILE = Path(os.getenv("JOBMART_DB", "job_mart.db"))
UPLOAD_DIR = Path(os.getenv("JOBMART_UPLOADS", "uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@jobmart.com").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@JobMart2026")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "no-reply@jobmart.com")

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM = os.getenv("TWILIO_FROM", "")

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "5"))

app = FastAPI(title=APP_NAME, version="4.0.0", docs_url="/docs", redoc_url="/redoc")

CATEGORIES = [
    "IT & Software", "Sales & Marketing", "Finance & Accounting",
    "Healthcare & Pharma", "Education & Training", "Engineering & Core",
    "Government & Public Sector", "Construction & Real Estate",
    "Retail & FMCG", "Logistics & Supply Chain", "Hospitality & Tourism",
    "Agriculture", "Customer Support", "Creative & Design", "Other"
]

JOB_TYPES = ["Full Time", "Part Time", "Contract", "Internship", "Remote"]

CSS = r"""
:root{
--primary:#1976ed;--primary-dark:#1256b0;--secondary:#f0f4f9;
--text:#172033;--muted:#657388;--border:#d6dfeb;--card:#fff;
--bg:#f6f8fb;--danger:#e03137;--success:#178c54;--warn:#f59e0b;
--shadow:0 8px 30px rgba(23,32,51,.08)
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
background:var(--bg);color:var(--text);line-height:1.5}
a{text-decoration:none;color:inherit}
button,input,textarea,select{font:inherit}
.header{position:sticky;top:0;z-index:100;background:var(--primary);color:#fff;
box-shadow:0 3px 12px rgba(0,0,0,.12)}
.navbar{max-width:1200px;margin:auto;padding:12px 18px;display:flex;
align-items:center;justify-content:space-between;gap:12px}
.brand{font-size:24px;font-weight:800;letter-spacing:-.5px}
.nav-menu{display:flex;align-items:center;gap:5px}
.nav-link{padding:8px 11px;border-radius:7px;font-size:14px;font-weight:600}
.nav-link:hover{background:rgba(255,255,255,.15)}
.menu-btn{display:none;border:0;background:transparent;color:#fff;font-size:27px;cursor:pointer}
.container{max-width:1200px;margin:auto;padding:28px 18px}
.hero{background:linear-gradient(135deg,#1976ed,#1256b0);color:#fff;padding:46px 24px;
border-radius:18px;margin-bottom:24px;box-shadow:var(--shadow)}
.hero h1{font-size:clamp(30px,5vw,48px);line-height:1.1;margin-bottom:10px}
.hero p{opacity:.94;margin-bottom:22px}
.search-grid{display:grid;grid-template-columns:2fr 1.2fr 1fr auto;gap:10px}
input,textarea,select{width:100%;padding:11px 12px;border:1px solid var(--border);
border-radius:9px;background:#fff;color:var(--text);outline:none}
input:focus,textarea:focus,select:focus{border-color:var(--primary);
box-shadow:0 0 0 3px rgba(25,118,237,.12)}
textarea{min-height:130px;resize:vertical}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;
padding:10px 15px;border:0;border-radius:9px;background:var(--primary);color:#fff;
font-weight:700;cursor:pointer}
.btn:hover{background:var(--primary-dark)}
.btn.secondary{background:#e9f1fc;color:var(--primary)}
.btn.danger{background:var(--danger)}
.btn.success{background:var(--success)}
.btn.warn{background:var(--warn)}
.btn.dark{background:#172033}
.btn.small{padding:7px 10px;font-size:13px}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;
padding:20px;box-shadow:var(--shadow);margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.two{display:grid;grid-template-columns:1.5fr 1fr;gap:18px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.stat{background:#fff;border:1px solid var(--border);border-radius:13px;padding:18px}
.stat strong{display:block;font-size:28px;color:var(--primary)}
.muted{color:var(--muted)}
.badge{display:inline-block;padding:4px 9px;border-radius:999px;background:#eaf2fd;
color:var(--primary);font-size:12px;font-weight:700;margin:2px}
.badge.green{background:#e6f7ef;color:var(--success)}
.badge.red{background:#fdebed;color:var(--danger)}
.badge.yellow{background:#fff5df;color:#a96800}
.job-title{font-size:20px;font-weight:800;margin-bottom:4px}
.job-meta{color:var(--muted);font-size:14px;margin:4px 0 10px}
.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.full{grid-column:1/-1}
label{display:block;font-size:13px;font-weight:700;margin-bottom:6px}
.alert{padding:12px 14px;border-radius:9px;margin-bottom:15px;background:#eaf2fd;color:#174a85}
.alert.error{background:#fdebed;color:#9d2026}
.alert.success{background:#e6f7ef;color:#11663e}
.table-wrap{overflow:auto}
table{width:100%;border-collapse:collapse;background:#fff}
th,td{padding:11px;border-bottom:1px solid var(--border);text-align:left;font-size:14px}
th{background:#f4f7fb}
.footer{margin-top:40px;padding:28px 18px;background:#172033;color:#dce4f0}
.footer-inner{max-width:1200px;margin:auto}
.empty{text-align:center;padding:35px;color:var(--muted)}
.avatar{width:48px;height:48px;border-radius:50%;background:#eaf2fd;color:var(--primary);
display:flex;align-items:center;justify-content:center;font-weight:800}
.profile-head{display:flex;align-items:center;gap:14px;margin-bottom:18px}
pre.ai{white-space:pre-wrap;background:#f4f7fb;border:1px solid var(--border);
padding:14px;border-radius:9px}
@media(max-width:850px){
.navbar{position:relative}.menu-btn{display:block}.nav-menu{display:none;width:100%;
flex-direction:column;align-items:stretch;padding-top:8px}.nav-menu.open{display:flex}
.nav-link{padding:11px 12px;background:rgba(255,255,255,.08)}
.search-grid,.two,.form-grid{grid-template-columns:1fr}.grid{grid-template-columns:1fr}
.stats{grid-template-columns:repeat(2,1fr)}.full{grid-column:auto}
.hero{padding:32px 18px}.container{padding:20px 13px}
}
@media(max-width:480px){.stats{grid-template-columns:1fr}.brand{font-size:21px}
.actions .btn{width:100%}}
"""

def db():
    c = sqlite3.connect(DB_FILE, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    return c

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def esc(v):
    return html.escape(str(v or ""))

def clean(v):
    return (v or "").strip()

def valid_email(v):
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", clean(v)) is not None

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 220000)
    return salt.hex()+":"+digest.hex()

def verify_password(password, stored):
    try:
        salt, digest = stored.split(":",1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 220000)
        return secrets.compare_digest(check.hex(), digest)
    except Exception:
        return False

def init_db():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'jobseeker',
      phone TEXT DEFAULT '',location TEXT DEFAULT '',bio TEXT DEFAULT '',
      skills TEXT DEFAULT '',education TEXT DEFAULT '',experience TEXT DEFAULT '',
      resume_path TEXT DEFAULT '',created_at TEXT NOT NULL,is_blocked INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS sessions(
      token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS companies(
      id INTEGER PRIMARY KEY AUTOINCREMENT,owner_id INTEGER NOT NULL,name TEXT NOT NULL UNIQUE,
      description TEXT DEFAULT '',website TEXT DEFAULT '',location TEXT DEFAULT '',
      logo_path TEXT DEFAULT '',created_at TEXT NOT NULL,
      FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS jobs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,employer_id INTEGER NOT NULL,title TEXT NOT NULL,
      company TEXT DEFAULT '',company_id INTEGER,description TEXT NOT NULL,skills TEXT DEFAULT '',
      country TEXT DEFAULT 'India',location TEXT DEFAULT '',job_type TEXT DEFAULT 'Full Time',
      salary TEXT DEFAULT '',experience TEXT DEFAULT '',education TEXT DEFAULT '',
      category TEXT DEFAULT 'Other',status TEXT DEFAULT 'active',views INTEGER DEFAULT 0,
      is_flagged INTEGER DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
      FOREIGN KEY(employer_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS applications(
      id INTEGER PRIMARY KEY AUTOINCREMENT,job_id INTEGER NOT NULL,user_id INTEGER NOT NULL,
      cover_letter TEXT DEFAULT '',status TEXT DEFAULT 'Applied',created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,UNIQUE(job_id,user_id),
      FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS saved_jobs(
      user_id INTEGER NOT NULL,job_id INTEGER NOT NULL,created_at TEXT NOT NULL,
      PRIMARY KEY(user_id,job_id),FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS notifications(
      id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,title TEXT NOT NULL,
      message TEXT NOT NULL,read INTEGER DEFAULT 0,created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS reports(
      id INTEGER PRIMARY KEY AUTOINCREMENT,job_id INTEGER NOT NULL,user_id INTEGER NOT NULL,
      reason TEXT NOT NULL,details TEXT DEFAULT '',status TEXT DEFAULT 'open',created_at TEXT NOT NULL,
      FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS otps(
      id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT NOT NULL,otp TEXT NOT NULL,purpose TEXT NOT NULL,
      expires_at INTEGER NOT NULL,used INTEGER DEFAULT 0,attempts INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS ai_chats(
      id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,role TEXT NOT NULL,message TEXT NOT NULL,
      created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS admin_logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,admin_email TEXT,action TEXT,details TEXT,created_at TEXT NOT NULL
    );
    """)
    c.commit(); c.close()

def ensure_admin():
    c=db()
    row=c.execute("SELECT id FROM users WHERE email=?",(ADMIN_EMAIL,)).fetchone()
    if not row:
        c.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                  ("Job Mart Admin",ADMIN_EMAIL,hash_password(ADMIN_PASSWORD),"admin",now_iso()))
    else:
        c.execute("UPDATE users SET role='admin' WHERE email=?",(ADMIN_EMAIL,))
    c.commit(); c.close()

init_db()
ensure_admin()

def create_session(user_id):
    token=secrets.token_urlsafe(48)
    expiry=(datetime.now(timezone.utc)+timedelta(days=30)).isoformat()
    c=db(); c.execute("INSERT INTO sessions VALUES(?,?,?,?)",(token,user_id,now_iso(),expiry))
    c.commit(); c.close(); return token

def current_user(request):
    token=request.cookies.get("jobmart_session")
    if not token:
        h=request.headers.get("Authorization","")
        if h.startswith("Bearer "): token=h[7:].strip()
    if not token: return None
    c=db()
    row=c.execute("""SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id
                     WHERE s.token=? AND s.expires_at>?""",(token,now_iso())).fetchone()
    c.close()
    return row

def require_user(request):
    u=current_user(request)
    if not u: raise HTTPException(401,"Authentication required")
    if u["is_blocked"]: raise HTTPException(403,"Your account is suspended")
    return u

def require_employer(request):
    u=require_user(request)
    if u["role"] not in ("employer","admin"): raise HTTPException(403,"Employer privileges required")
    return u

def require_admin(request):
    u=require_user(request)
    if u["role"]!="admin": raise HTTPException(403,"Admin privileges required")
    return u

def layout(request,title,body):
    u=current_user(request)
    nav = '<a class="nav-link" href="/">Home</a><a class="nav-link" href="/jobs">Find Jobs</a>'
    if u:
        nav += '<a class="nav-link" href="/dashboard">Dashboard</a>'
        nav += '<a class="nav-link" href="/profile">Profile</a>'
        if u["role"] in ("employer","admin"):
            nav += '<a class="nav-link" href="/employer">Employer Desk</a>'
        if u["role"]=="admin":
            nav += '<a class="nav-link" href="/admin">Admin</a>'
        nav += '<a class="nav-link" href="/logout">Logout</a>'
    else:
        nav += '<a class="nav-link" href="/login">Login</a><a class="nav-link" href="/register">Register</a>'
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} · {APP_NAME}</title><style>{CSS}</style></head><body>
<header class="header"><div class="navbar"><a class="brand" href="/">💼 Job Mart</a>
<button class="menu-btn" onclick="document.getElementById('nav').classList.toggle('open')">☰</button>
<nav id="nav" class="nav-menu">{nav}</nav></div></header>
<main class="container">{body}</main>
<footer class="footer"><div class="footer-inner"><b>Job Mart</b><br><span class="muted">A clean blue corporate job marketplace.</span></div></footer>
<script>
document.querySelectorAll('form').forEach(f=>f.addEventListener('submit',()=>{{
 const b=f.querySelector('button[type=submit]'); if(b){{b.disabled=true;b.style.opacity='.7';}}
}}));
</script></body></html>"""

def alert(msg,kind=""):
    return f'<div class="alert {kind}">{esc(msg)}</div>'

current_user_dummy = False

def render_job_card(j, saved=False, can_save=False):
    actions=f'<a class="btn" href="/job/{j["id"]}">View Job</a>'
    if can_save:
        actions += f'<form method="post" action="/save/{j["id"]}"><button class="btn secondary">♡ {"Unsave" if saved else "Save"}</button></form>'
    return f"""<article class="card"><div class="job-title">{esc(j["title"])}</div>
<div class="job-meta">🏢 {esc(j["company"] or "Company")} · 📍 {esc(j["location"] or "India")}</div>
<span class="badge">{esc(j["job_type"])}</span> <span class="badge">{esc(j["category"])}</span>
{('<span class="badge green">₹ '+esc(j["salary"])+'</span>') if j["salary"] else ''}
<p style="margin-top:10px">{esc((j["description"] or "")[:220])}</p>
<div class="actions">{actions}</div></article>"""

@app.get("/",response_class=HTMLResponse)
def home(request:Request):
    c=db(); jobs=c.execute("SELECT * FROM jobs WHERE status='active' AND is_flagged=0 ORDER BY id DESC LIMIT 6").fetchall()
    c.close()
    cards="".join(render_job_card(j,False,bool(current_user(request))) for j in jobs)
    body=f"""<section class="hero"><h1>Find your next opportunity.</h1>
<p>Search jobs, apply online, track applications and build your professional profile.</p>
<form method="get" action="/jobs"><div class="search-grid">
<input name="q" placeholder="Job title, skills or company">
<input name="location" placeholder="Location">
<select name="category"><option value="">All categories</option>
{''.join(f'<option>{esc(x)}</option>' for x in CATEGORIES)}</select>
<button class="btn dark">Search Jobs</button></div></form></section>
<h2 style="margin-bottom:14px">Latest Jobs</h2>
<div class="grid">{"".join(cards) or '<div class="card empty">No jobs posted yet.</div>'}</div>"""
    return layout(request,"Home",body)

@app.get("/jobs",response_class=HTMLResponse)
def jobs(request:Request,q:str="",location:str="",category:str="",job_type:str=""):
    c=db()
    sql="SELECT * FROM jobs WHERE status='active' AND is_flagged=0"
    params=[]
    if q:
        sql+=" AND (title LIKE ? OR description LIKE ? OR skills LIKE ? OR company LIKE ?)"
        x=f"%{q}%"; params += [x,x,x,x]
    if location:
        sql+=" AND location LIKE ?"; params.append(f"%{location}%")
    if category:
        sql+=" AND category=?"; params.append(category)
    if job_type:
        sql+=" AND job_type=?"; params.append(job_type)
    sql+=" ORDER BY id DESC"
    rows=c.execute(sql,params).fetchall()
    u=current_user(request)
    saved=set()
    if u:
        saved={r["job_id"] for r in c.execute("SELECT job_id FROM saved_jobs WHERE user_id=?",(u["id"],))}
    c.close()
    body=f"""<h1>Find Jobs</h1><div class="card"><form method="get">
<div class="form-grid"><div><label>Search</label><input name="q" value="{esc(q)}" placeholder="Title, skill, company"></div>
<div><label>Location</label><input name="location" value="{esc(location)}"></div>
<div><label>Category</label><select name="category"><option value="">All</option>
{''.join(f'<option {"selected" if category==x else ""}>{esc(x)}</option>' for x in CATEGORIES)}</select></div>
<div><label>Job Type</label><select name="job_type"><option value="">All</option>
{''.join(f'<option {"selected" if job_type==x else ""}>{esc(x)}</option>' for x in JOB_TYPES)}</select></div>
<div class="full"><button class="btn">Search</button></div></div></form></div>
<p class="muted" style="margin-bottom:14px">{len(rows)} job(s) found</p>
<div class="grid">{"".join(render_job_card(j,j["id"] in saved,bool(u)) for j in rows) or '<div class="card empty">No matching jobs found.</div>'}</div>"""
    return layout(request,"Find Jobs",body)

@app.get("/job/{job_id}",response_class=HTMLResponse)
def job_detail(request:Request,job_id:int):
    c=db(); j=c.execute("SELECT * FROM jobs WHERE id=?",(job_id,)).fetchone()
    if not j: c.close(); raise HTTPException(404,"Job not found")
    c.execute("UPDATE jobs SET views=views+1 WHERE id=?",(job_id,))
    u=current_user(request)
    applied=False
    saved=False
    if u:
        applied=bool(c.execute("SELECT 1 FROM applications WHERE job_id=? AND user_id=?",(job_id,u["id"])).fetchone())
        saved=bool(c.execute("SELECT 1 FROM saved_jobs WHERE job_id=? AND user_id=?",(job_id,u["id"])).fetchone())
    c.commit(); c.close()
    apply_block=""
    if u and u["role"]=="jobseeker":
        apply_block = alert("You already applied to this job.","success") if applied else f"""
<div class="card"><h3>Apply for this job</h3><form method="post" action="/apply/{job_id}">
<label>Cover Letter</label><textarea name="cover_letter" required placeholder="Tell the employer why you are a good fit."></textarea>
<button class="btn" style="margin-top:10px">Submit Application</button></form></div>"""
    elif not u:
        apply_block=alert("Please login as a jobseeker to apply.")
    body=f"""<div class="two"><section><div class="card"><h1>{esc(j["title"])}</h1>
<p class="job-meta">🏢 {esc(j["company"] or "Company")} · 📍 {esc(j["location"])} · 🌎 {esc(j["country"])}</p>
<span class="badge">{esc(j["job_type"])}</span> <span class="badge">{esc(j["category"])}</span>
<h3 style="margin-top:20px">Job Description</h3><p style="white-space:pre-wrap;margin-top:8px">{esc(j["description"])}</p>
<h3 style="margin-top:20px">Skills</h3><p>{esc(j["skills"] or "Not specified")}</p>
<h3 style="margin-top:20px">Requirements</h3><p>Experience: {esc(j["experience"] or "Not specified")}<br>
Education: {esc(j["education"] or "Not specified")}<br>Salary: {esc(j["salary"] or "Not specified")}</p>
<div class="actions">{f'<form method="post" action="/save/{job_id}"><button class="btn secondary">♡ {"Unsave" if saved else "Save Job"}</button></form>' if u and u["role"]=="jobseeker" else ''}
<form method="post" action="/report/{job_id}"><button class="btn danger">Report Job</button></form></div>
</div>{apply_block}</section>
<aside><div class="card"><h3>Job Safety</h3><p class="muted">Never pay an employer for an interview, job offer, training, equipment or registration. Report suspicious listings.</p></div></aside></div>"""
    return layout(request,j["title"],body)

@app.get("/register",response_class=HTMLResponse)
def register_page(request:Request,msg:str=""):
    body=f"""<div class="card" style="max-width:620px;margin:auto"><h1>Create Account</h1>
{alert(msg) if msg else ''}<form method="post" action="/register"><div class="form-grid">
<div><label>Full Name</label><input name="name" required></div>
<div><label>Email</label><input name="email" type="email" required></div>
<div><label>Phone</label><input name="phone" placeholder="+91..."></div>
<div><label>Role</label><select name="role"><option value="jobseeker">Job Seeker</option><option value="employer">Employer</option></select></div>
<div class="full"><label>Password</label><input name="password" type="password" minlength="8" required></div>
<div class="full"><button class="btn">Create Account</button></div></div></form></div>"""
    return layout(request,"Register",body)

@app.post("/register")
def register(name:str=Form(...),email:str=Form(...),phone:str=Form(""),role:str=Form("jobseeker"),password:str=Form(...)):
    name, email = clean(name), clean(email).lower()
    if not name or not valid_email(email) or len(password)<8 or role not in ("jobseeker","employer"):
        return RedirectResponse("/register?msg="+urllib.parse.quote("Enter valid details. Password must be at least 8 characters."),303)
    c=db()
    try:
        c.execute("INSERT INTO users(name,email,password_hash,role,phone,created_at) VALUES(?,?,?,?,?,?)",
                  (name,email,hash_password(password),role,clean(phone),now_iso()))
        uid=c.execute("SELECT last_insert_rowid()").fetchone()[0]
        c.commit()
    except sqlite3.IntegrityError:
        c.close()
        return RedirectResponse("/register?msg="+urllib.parse.quote("Email already registered."),303)
    c.close()
    token=create_session(uid); r=RedirectResponse("/dashboard",303)
    r.set_cookie("jobmart_session",token,httponly=True,samesite="lax",secure=COOKIE_SECURE,max_age=2592000)
    return r

@app.get("/login",response_class=HTMLResponse)
def login_page(request:Request,msg:str=""):
    body=f"""<div class="card" style="max-width:520px;margin:auto"><h1>Login</h1>{alert(msg) if msg else ''}
<form method="post" action="/login"><label>Email</label><input name="email" type="email" required style="margin-bottom:12px">
<label>Password</label><input name="password" type="password" required style="margin-bottom:14px">
<button class="btn">Login</button></form><p class="muted" style="margin-top:15px">Admin is created from ADMIN_EMAIL and ADMIN_PASSWORD environment variables.</p></div>"""
    return layout(request,"Login",body)

@app.post("/login")
def login(email:str=Form(...),password:str=Form(...)):
    c=db(); u=c.execute("SELECT * FROM users WHERE email=?",(clean(email).lower(),)).fetchone(); c.close()
    if not u or not verify_password(password,u["password_hash"]):
        return RedirectResponse("/login?msg="+urllib.parse.quote("Invalid email or password."),303)
    if u["is_blocked"]: return RedirectResponse("/login?msg="+urllib.parse.quote("Account suspended."),303)
    token=create_session(u["id"]); r=RedirectResponse("/dashboard",303)
    r.set_cookie("jobmart_session",token,httponly=True,samesite="lax",secure=COOKIE_SECURE,max_age=2592000)
    return r

@app.get("/logout")
def logout(request:Request):
    token=request.cookies.get("jobmart_session")
    if token:
        c=db(); c.execute("DELETE FROM sessions WHERE token=?",(token,)); c.commit(); c.close()
    r=RedirectResponse("/",303); r.delete_cookie("jobmart_session"); return r

@app.get("/dashboard",response_class=HTMLResponse)
def dashboard(request:Request):
    u=require_user(request); c=db()
    if u["role"]=="jobseeker":
        apps=c.execute("""SELECT a.*,j.title,j.company FROM applications a JOIN jobs j ON j.id=a.job_id
                          WHERE a.user_id=? ORDER BY a.id DESC""",(u["id"],)).fetchall()
        saved=c.execute("""SELECT j.* FROM saved_jobs s JOIN jobs j ON j.id=s.job_id
                           WHERE s.user_id=? ORDER BY s.created_at DESC""",(u["id"],)).fetchall()
        unread=c.execute("SELECT COUNT(*) n FROM notifications WHERE user_id=? AND read=0",(u["id"],)).fetchone()["n"]
        c.close()
        rows="".join(f'<tr><td><a href="/job/{a["job_id"]}"><b>{esc(a["title"])}</b></a></td><td>{esc(a["company"])}</td><td><span class="badge">{esc(a["status"])}</span></td></tr>' for a in apps)
        body=f"""<div class="profile-head"><div class="avatar">{esc(u["name"][:1].upper())}</div><div><h1>Welcome, {esc(u["name"])}</h1><span class="muted">Job Seeker</span></div></div>
<div class="stats"><div class="stat"><strong>{len(apps)}</strong>Applications</div><div class="stat"><strong>{len(saved)}</strong>Saved Jobs</div><div class="stat"><strong>{unread}</strong>Notifications</div><div class="stat"><strong>{len(clean(u["skills"]).split(",")) if u["skills"] else 0}</strong>Skill data</div></div>
<div class="two" style="margin-top:18px"><div class="card"><h2>My Applications</h2><div class="table-wrap"><table><tr><th>Job</th><th>Company</th><th>Status</th></tr>{rows or '<tr><td colspan="3">No applications yet.</td></tr>'}</table></div></div>
<div><div class="card"><h3>Quick Actions</h3><div class="actions"><a class="btn" href="/jobs">Find Jobs</a><a class="btn secondary" href="/profile">Edit Profile</a><a class="btn secondary" href="/ai">AI Assistant</a><a class="btn secondary" href="/notifications">Notifications</a></div></div></div></div>"""
    else:
        jobs=c.execute("SELECT * FROM jobs WHERE employer_id=? ORDER BY id DESC",(u["id"],)).fetchall()
        apps=c.execute("""SELECT COUNT(*) n FROM applications a JOIN jobs j ON j.id=a.job_id
                          WHERE j.employer_id=?""",(u["id"],)).fetchone()["n"]
        c.close()
        rows="".join(f'<tr><td>{esc(j["title"])}</td><td>{j["views"]}</td><td>{esc(j["status"])}</td><td><a class="btn small" href="/employer/job/{j["id"]}">Manage</a></td></tr>' for j in jobs)
        body=f"""<h1>Employer Dashboard</h1><div class="stats"><div class="stat"><strong>{len(jobs)}</strong>Jobs</div><div class="stat"><strong>{apps}</strong>Applications</div></div>
<div class="actions" style="margin:18px 0"><a class="btn" href="/employer/post">+ Post Job</a><a class="btn secondary" href="/employer">Employer Desk</a></div>
<div class="card"><h2>My Jobs</h2><div class="table-wrap"><table><tr><th>Job</th><th>Views</th><th>Status</th><th></th></tr>{rows or '<tr><td colspan="4">No jobs posted.</td></tr>'}</table></div></div>"""
    return layout(request,"Dashboard",body)

@app.get("/profile",response_class=HTMLResponse)
def profile(request:Request,msg:str=""):
    u=require_user(request)
    body=f"""<div class="card"><h1>My Profile</h1>{alert(msg,"success") if msg else ''}
<form method="post" action="/profile" enctype="multipart/form-data"><div class="form-grid">
<div><label>Name</label><input name="name" value="{esc(u["name"])}" required></div>
<div><label>Phone</label><input name="phone" value="{esc(u["phone"])}"></div>
<div><label>Location</label><input name="location" value="{esc(u["location"])}"></div>
<div><label>Skills</label><input name="skills" value="{esc(u["skills"])}" placeholder="Python, FastAPI, SQL"></div>
<div><label>Education</label><input name="education" value="{esc(u["education"])}"></div>
<div><label>Experience</label><input name="experience" value="{esc(u["experience"])}"></div>
<div class="full"><label>Bio</label><textarea name="bio">{esc(u["bio"])}</textarea></div>
<div><label>Resume PDF</label><input type="file" name="resume" accept=".pdf,.doc,.docx"></div>
<div><label>Current Resume</label>{f'<a class="btn secondary" href="/resume">View Resume</a>' if u["resume_path"] else '<span class="muted">None</span>'}</div>
<div class="full"><button class="btn">Save Profile</button></div></div></form></div>"""
    return layout(request,"Profile",body)

@app.post("/profile")
async def profile_save(request:Request,name:str=Form(...),phone:str=Form(""),location:str=Form(""),
                       skills:str=Form(""),education:str=Form(""),experience:str=Form(""),
                       bio:str=Form(""),resume:Optional[UploadFile]=File(None)):
    u=require_user(request)
    resume_path=u["resume_path"]
    if resume and resume.filename:
        ext=Path(resume.filename).suffix.lower()
        if ext not in (".pdf",".doc",".docx"): return RedirectResponse("/profile?msg="+urllib.parse.quote("Only PDF, DOC or DOCX allowed."),303)
        data=await resume.read()
        if len(data)>MAX_UPLOAD_MB*1024*1024: return RedirectResponse("/profile?msg="+urllib.parse.quote("Resume is too large."),303)
        safe=f"user_{u['id']}_{secrets.token_hex(8)}{ext}"
        path=UPLOAD_DIR/safe; path.write_bytes(data); resume_path=str(path)
    c=db(); c.execute("""UPDATE users SET name=?,phone=?,location=?,skills=?,education=?,experience=?,bio=?,resume_path=? WHERE id=?""",
                      (clean(name),clean(phone),clean(location),clean(skills),clean(education),clean(experience),clean(bio),resume_path,u["id"]))
    c.commit(); c.close()
    return RedirectResponse("/profile?msg="+urllib.parse.quote("Profile updated successfully."),303)

@app.get("/resume")
def resume(request:Request):
    u=require_user(request)
    p=Path(u["resume_path"]) if u["resume_path"] else None
    if not p or not p.exists(): raise HTTPException(404,"Resume not found")
    return FileResponse(p,filename=p.name)

@app.post("/save/{job_id}")
def save_job(request:Request,job_id:int):
    u=require_user(request)
    if u["role"]!="jobseeker": raise HTTPException(403,"Only jobseekers can save jobs")
    c=db(); exists=c.execute("SELECT 1 FROM saved_jobs WHERE user_id=? AND job_id=?",(u["id"],job_id)).fetchone()
    if exists: c.execute("DELETE FROM saved_jobs WHERE user_id=? AND job_id=?",(u["id"],job_id))
    else: c.execute("INSERT OR IGNORE INTO saved_jobs VALUES(?,?,?)",(u["id"],job_id,now_iso()))
    c.commit(); c.close(); return RedirectResponse(request.headers.get("referer") or "/jobs",303)

@app.post("/apply/{job_id}")
def apply(request:Request,job_id:int,cover_letter:str=Form(...)):
    u=require_user(request)
    if u["role"]!="jobseeker": raise HTTPException(403,"Only jobseekers can apply")
    c=db(); j=c.execute("SELECT * FROM jobs WHERE id=? AND status='active'",(job_id,)).fetchone()
    if not j: c.close(); raise HTTPException(404,"Job unavailable")
    try:
        c.execute("INSERT INTO applications(job_id,user_id,cover_letter,status,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                  (job_id,u["id"],clean(cover_letter),"Applied",now_iso(),now_iso()))
        c.execute("INSERT INTO notifications(user_id,title,message,created_at) SELECT employer_id,?,?,? FROM jobs WHERE id=?",
                  ("New application",f"{u['name']} applied for {j['title']}",now_iso(),job_id))
        c.commit()
    except sqlite3.IntegrityError:
        c.rollback()
    c.close(); return RedirectResponse(f"/job/{job_id}",303)

@app.post("/report/{job_id}")
def report(request:Request,job_id:int,reason:str=Form("Suspicious listing"),details:str=Form("")):
    u=require_user(request); c=db()
    if not c.execute("SELECT 1 FROM jobs WHERE id=?",(job_id,)).fetchone(): c.close(); raise HTTPException(404,"Job not found")
    c.execute("INSERT INTO reports(job_id,user_id,reason,details,created_at) VALUES(?,?,?,?,?)",
              (job_id,u["id"],clean(reason),clean(details),now_iso()))
    c.execute("UPDATE jobs SET is_flagged=1 WHERE id=?",(job_id,))
    c.commit(); c.close(); return RedirectResponse(f"/job/{job_id}",303)

@app.get("/notifications",response_class=HTMLResponse)
def notifications(request:Request):
    u=require_user(request); c=db(); rows=c.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100",(u["id"],)).fetchall()
    c.execute("UPDATE notifications SET read=1 WHERE user_id=?",(u["id"],)); c.commit(); c.close()
    body="<h1>Notifications</h1>"+("".join(f'<div class="card"><b>{esc(x["title"])}</b><p>{esc(x["message"])}</p><span class="muted">{esc(x["created_at"])}</span></div>' for x in rows) or '<div class="card empty">No notifications.</div>')
    return layout(request,"Notifications",body)

@app.get("/employer",response_class=HTMLResponse)
def employer(request:Request):
    u=require_employer(request); c=db()
    jobs=c.execute("SELECT * FROM jobs WHERE employer_id=? ORDER BY id DESC",(u["id"],)).fetchall()
    companies=c.execute("SELECT * FROM companies WHERE owner_id=? ORDER BY id DESC",(u["id"],)).fetchall()
    c.close()
    body=f"""<h1>Employer Desk</h1><div class="actions"><a class="btn" href="/employer/post">+ Post Job</a><a class="btn secondary" href="/employer/company">+ Company</a></div>
<div class="two" style="margin-top:18px"><div><h2>Jobs</h2>{''.join(f'<div class="card"><h3>{esc(j["title"])}</h3><p class="muted">{esc(j["location"])} · {esc(j["status"])} · {j["views"]} views</p><div class="actions"><a class="btn small" href="/employer/job/{j["id"]}">Manage</a></div></div>' for j in jobs) or '<div class="card empty">No jobs.</div>'}</div>
<div><h2>Companies</h2>{''.join(f'<div class="card"><b>{esc(x["name"])}</b><p>{esc(x["location"])}</p></div>' for x in companies) or '<div class="card empty">No company.</div>'}</div></div>"""
    return layout(request,"Employer Desk",body)

@app.get("/employer/company",response_class=HTMLResponse)
def company_page(request:Request):
    require_employer(request)
    body="""<div class="card"><h1>Create Company</h1><form method="post"><div class="form-grid">
<div><label>Company Name</label><input name="name" required></div><div><label>Website</label><input name="website" placeholder="https://example.com"></div>
<div><label>Location</label><input name="location"></div><div class="full"><label>Description</label><textarea name="description"></textarea></div>
<div class="full"><button class="btn">Create Company</button></div></div></form></div>"""
    return layout(request,"Company",body)

@app.post("/employer/company")
def company_create(request:Request,name:str=Form(...),website:str=Form(""),location:str=Form(""),description:str=Form("")):
    u=require_employer(request); c=db()
    try:
        c.execute("INSERT INTO companies(owner_id,name,website,location,description,created_at) VALUES(?,?,?,?,?,?)",
                  (u["id"],clean(name),clean(website),clean(location),clean(description),now_iso()))
        c.commit()
    except sqlite3.IntegrityError:
        c.rollback()
    c.close(); return RedirectResponse("/employer",303)

@app.get("/employer/post",response_class=HTMLResponse)
def post_job_page(request:Request):
    u=require_employer(request); c=db(); companies=c.execute("SELECT * FROM companies WHERE owner_id=?",(u["id"],)).fetchall(); c.close()
    body=f"""<div class="card"><h1>Post a Job</h1><form method="post"><div class="form-grid">
<div><label>Job Title</label><input name="title" required></div><div><label>Company</label><input name="company" required></div>
<div><label>Location</label><input name="location" placeholder="Hyderabad"></div><div><label>Country</label><input name="country" value="India"></div>
<div><label>Job Type</label><select name="job_type">{''.join(f'<option>{x}</option>' for x in JOB_TYPES)}</select></div>
<div><label>Category</label><select name="category">{''.join(f'<option>{esc(x)}</option>' for x in CATEGORIES)}</select></div>
<div><label>Salary</label><input name="salary" placeholder="₹5–8 LPA"></div><div><label>Experience</label><input name="experience"></div>
<div><label>Education</label><input name="education"></div><div><label>Skills</label><input name="skills" placeholder="Python, SQL, Excel"></div>
<div class="full"><label>Description</label><textarea name="description" required></textarea></div>
<div class="full"><button class="btn">Publish Job</button></div></div></form></div>"""
    return layout(request,"Post Job",body)

@app.post("/employer/post")
def post_job(request:Request,title:str=Form(...),company:str=Form(...),location:str=Form(""),country:str=Form("India"),
             job_type:str=Form("Full Time"),category:str=Form("Other"),salary:str=Form(""),experience:str=Form(""),
             education:str=Form(""),skills:str=Form(""),description:str=Form(...)):
    u=require_employer(request)
    if job_type not in JOB_TYPES: job_type="Full Time"
    if category not in CATEGORIES: category="Other"
    c=db(); t=now_iso()
    c.execute("""INSERT INTO jobs(employer_id,title,company,description,skills,country,location,job_type,salary,
              experience,education,category,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (u["id"],clean(title),clean(company),clean(description),clean(skills),clean(country),clean(location),
               job_type,clean(salary),clean(experience),clean(education),category,"active",t,t))
    c.commit(); c.close(); return RedirectResponse("/employer",303)

@app.get("/employer/job/{job_id}",response_class=HTMLResponse)
def manage_job(request:Request,job_id:int):
    u=require_employer(request); c=db()
    j=c.execute("SELECT * FROM jobs WHERE id=? AND employer_id=?",(job_id,u["id"])).fetchone()
    if not j: c.close(); raise HTTPException(404,"Job not found")
    apps=c.execute("""SELECT a.*,u.name,u.email,u.phone,u.resume_path FROM applications a JOIN users u ON u.id=a.user_id
                      WHERE a.job_id=? ORDER BY a.id DESC""",(job_id,)).fetchall(); c.close()
    rows="".join(f"""<tr><td>{esc(a["name"])}<br><span class="muted">{esc(a["email"])}</span></td>
<td>{esc(a["status"])}</td><td>{esc(a["cover_letter"])}</td><td>
<form method="post" action="/employer/application/{a["id"]}"><select name="status">
{''.join(f'<option {"selected" if a["status"]==s else ""}>{s}</option>' for s in ["Applied","Shortlisted","Interview","Selected","Rejected"])}</select>
<button class="btn small">Update</button></form></td></tr>""" for a in apps)
    body=f"""<div class="card"><h1>{esc(j["title"])}</h1><p>{esc(j["description"])}</p><div class="actions">
<form method="post" action="/employer/job/{job_id}/toggle"><button class="btn warn">{"Close" if j["status"]=="active" else "Reopen"} Job</button></form>
<form method="post" action="/employer/job/{job_id}/delete"><button class="btn danger">Delete Job</button></form></div></div>
<div class="card"><h2>Applicants ({len(apps)})</h2><div class="table-wrap"><table><tr><th>Candidate</th><th>Status</th><th>Cover Letter</th><th>Update</th></tr>{rows or '<tr><td colspan="4">No applicants.</td></tr>'}</table></div></div>"""
    return layout(request,"Manage Job",body)

@app.post("/employer/application/{app_id}")
def update_application(request:Request,app_id:int,status:str=Form(...)):
    u=require_employer(request)
    allowed={"Applied","Shortlisted","Interview","Selected","Rejected"}
    if status not in allowed: raise HTTPException(400,"Invalid status")
    c=db(); row=c.execute("""SELECT a.user_id,a.job_id FROM applications a JOIN jobs j ON j.id=a.job_id
                             WHERE a.id=? AND j.employer_id=?""",(app_id,u["id"])).fetchone()
    if not row: c.close(); raise HTTPException(404,"Application not found")
    c.execute("UPDATE applications SET status=?,updated_at=? WHERE id=?",(status,now_iso(),app_id))
    c.execute("INSERT INTO notifications(user_id,title,message,created_at) VALUES(?,?,?,?)",
              (row["user_id"],"Application updated",f"Your application status is now {status}.",now_iso()))
    c.commit(); c.close(); return RedirectResponse(f"/employer/job/{row['job_id']}",303)

@app.post("/employer/job/{job_id}/toggle")
def toggle_job(request:Request,job_id:int):
    u=require_employer(request); c=db()
    c.execute("UPDATE jobs SET status=CASE WHEN status='active' THEN 'closed' ELSE 'active' END,updated_at=? WHERE id=? AND employer_id=?",(now_iso(),job_id,u["id"]))
    c.commit(); c.close(); return RedirectResponse(f"/employer/job/{job_id}",303)

@app.post("/employer/job/{job_id}/delete")
def delete_job(request:Request,job_id:int):
    u=require_employer(request); c=db(); c.execute("DELETE FROM jobs WHERE id=? AND employer_id=?",(job_id,u["id"])); c.commit(); c.close()
    return RedirectResponse("/employer",303)

def openai_call(messages):
    if not OPENAI_API_KEY: return None
    payload={"model":OPENAI_MODEL,"messages":messages,"temperature":0.3}
    req=urllib.request.Request("https://api.openai.com/v1/chat/completions",
        data=json.dumps(payload).encode(),headers={"Content-Type":"application/json","Authorization":"Bearer "+OPENAI_API_KEY},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=30) as r:
            return json.loads(r.read().decode())["choices"][0]["message"]["content"].strip()
    except Exception:
        return None

def ai_fallback(msg):
    m=msg.lower()
    if "resume" in m or "cv" in m: return "Improve your resume with measurable achievements, relevant skills and keywords from the target job."
    if any(x in m for x in ("scam","fraud","money","fee")): return "Safety warning: never pay money for an interview or job offer. Report suspicious listings."
    if "interview" in m: return "Prepare a 60-second introduction, review the job description, and prepare 3 STAR examples."
    return "I’m Job Mart AI Assistant. Ask me about jobs, resumes, applications, interviews or safety."

@app.get("/ai",response_class=HTMLResponse)
def ai_page(request:Request):
    u=current_user(request)
    body="""<div class="card" style="max-width:800px;margin:auto"><h1>🤖 Job Mart AI Assistant</h1>
<p class="muted" style="margin:8px 0 16px">Ask about resumes, interviews, job applications or safety.</p>
<form method="post"><textarea name="message" required placeholder="How can I improve my resume?"></textarea>
<button class="btn" style="margin-top:10px">Ask AI</button></form></div>"""
    return layout(request,"AI Assistant",body)

@app.post("/ai",response_class=HTMLResponse)
def ai_ask(request:Request,message:str=Form(...)):
    u=current_user(request); role=u["role"] if u else "guest"
    answer=openai_call([{"role":"system","content":"You are Job Mart AI Assistant. Be concise, practical and safety-focused."},
                        {"role":"user","content":f"Role: {role}\nQuestion: {clean(message)}"}]) or ai_fallback(message)
    if u:
        c=db(); c.execute("INSERT INTO ai_chats(user_id,role,message,created_at) VALUES(?,?,?,?)",(u["id"],"user",clean(message),now_iso()))
        c.execute("INSERT INTO ai_chats(user_id,role,message,created_at) VALUES(?,?,?,?)",(u["id"],"assistant",answer,now_iso()))
        c.commit(); c.close()
    body=f"""<div class="card"><h1>🤖 AI Assistant</h1><div class="card"><b>You:</b><p>{esc(message)}</p></div>
<div class="card"><b>Job Mart AI:</b><pre class="ai">{esc(answer)}</pre></div>
<form method="post"><textarea name="message" required placeholder="Ask another question..."></textarea><button class="btn" style="margin-top:10px">Ask</button></form></div>"""
    return layout(request,"AI Assistant",body)

@app.get("/admin",response_class=HTMLResponse)
def admin(request:Request):
    u=require_admin(request); c=db()
    users=c.execute("SELECT id,name,email,role,is_blocked,created_at FROM users ORDER BY id DESC").fetchall()
    jobs=c.execute("SELECT j.*,u.name employer FROM jobs j JOIN users u ON u.id=j.employer_id ORDER BY j.id DESC").fetchall()
    reports=c.execute("""SELECT r.*,j.title,u.name FROM reports r JOIN jobs j ON j.id=r.job_id JOIN users u ON u.id=r.user_id ORDER BY r.id DESC""").fetchall()
    stats=(c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"],
           c.execute("SELECT COUNT(*) n FROM jobs").fetchone()["n"],
           c.execute("SELECT COUNT(*) n FROM applications").fetchone()["n"],
           c.execute("SELECT COUNT(*) n FROM reports WHERE status='open'").fetchone()["n"])
    c.close()
    users_html="".join(f"""<tr><td>{x["id"]}</td><td>{esc(x["name"])}<br>{esc(x["email"])}</td><td>{esc(x["role"])}</td>
<td>{'Blocked' if x["is_blocked"] else 'Active'}</td><td><form method="post" action="/admin/user/{x["id"]}/toggle"><button class="btn small">{'Unblock' if x["is_blocked"] else 'Block'}</button></form></td></tr>""" for x in users)
    jobs_html="".join(f"""<tr><td>{x["id"]}</td><td>{esc(x["title"])}</td><td>{esc(x["employer"])}</td><td>{'Flagged' if x["is_flagged"] else x["status"]}</td>
<td><form method="post" action="/admin/job/{x["id"]}/toggleflag"><button class="btn small">{'Clear Flag' if x["is_flagged"] else 'Flag'}</button></form></td></tr>""" for x in jobs)
    reports_html="".join(f"<tr><td>{r['id']}</td><td>{esc(r['title'])}</td><td>{esc(r['name'])}</td><td>{esc(r['reason'])}</td><td>{esc(r['status'])}</td></tr>" for r in reports)
    body=f"""<h1>Admin Panel</h1><div class="stats"><div class="stat"><strong>{stats[0]}</strong>Users</div><div class="stat"><strong>{stats[1]}</strong>Jobs</div><div class="stat"><strong>{stats[2]}</strong>Applications</div><div class="stat"><strong>{stats[3]}</strong>Open Reports</div></div>
<div class="card" style="margin-top:18px"><h2>Users</h2><div class="table-wrap"><table><tr><th>ID</th><th>User</th><th>Role</th><th>Status</th><th>Action</th></tr>{users_html}</table></div></div>
<div class="card"><h2>Jobs</h2><div class="table-wrap"><table><tr><th>ID</th><th>Job</th><th>Employer</th><th>Status</th><th>Action</th></tr>{jobs_html}</table></div></div>
<div class="card"><h2>Reports</h2><div class="table-wrap"><table><tr><th>ID</th><th>Job</th><th>Reporter</th><th>Reason</th><th>Status</th></tr>{reports_html or '<tr><td colspan="5">No reports.</td></tr>'}</table></div></div>"""
    return layout(request,"Admin",body)

@app.post("/admin/user/{user_id}/toggle")
def admin_user_toggle(request:Request,user_id:int):
    require_admin(request); c=db()
    c.execute("UPDATE users SET is_blocked=CASE WHEN is_blocked=1 THEN 0 ELSE 1 END WHERE id=? AND email<>?",(user_id,ADMIN_EMAIL))
    c.commit(); c.close(); return RedirectResponse("/admin",303)

@app.post("/admin/job/{job_id}/toggleflag")
def admin_job_flag(request:Request,job_id:int):
    require_admin(request); c=db(); c.execute("UPDATE jobs SET is_flagged=CASE WHEN is_flagged=1 THEN 0 ELSE 1 END WHERE id=?",(job_id,)); c.commit(); c.close()
    return RedirectResponse("/admin",303)

# ---------- REST API ----------
@app.get("/api/health")
def health():
    return {"status":"ok","app":APP_NAME,"version":"4.0.0","time":now_iso()}

@app.get("/api/jobs")
def api_jobs(q:str="",location:str="",category:str=""):
    c=db(); sql="SELECT id,title,company,location,job_type,salary,category,status,created_at FROM jobs WHERE status='active' AND is_flagged=0"; p=[]
    if q: sql+=" AND (title LIKE ? OR description LIKE ? OR skills LIKE ?)"; x=f"%{q}%"; p += [x,x,x]
    if location: sql+=" AND location LIKE ?"; p.append(f"%{location}%")
    if category: sql+=" AND category=?"; p.append(category)
    sql+=" ORDER BY id DESC LIMIT 100"
    rows=[dict(x) for x in c.execute(sql,p).fetchall()]; c.close(); return {"jobs":rows}

@app.get("/api/me")
def api_me(request:Request):
    u=require_user(request)
    return {"id":u["id"],"name":u["name"],"email":u["email"],"role":u["role"],"phone":u["phone"],"location":u["location"]}

@app.get("/api/stats")
def api_stats():
    c=db()
    data={"users":c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"],
          "jobs":c.execute("SELECT COUNT(*) n FROM jobs WHERE status='active'").fetchone()["n"],
          "applications":c.execute("SELECT COUNT(*) n FROM applications").fetchone()["n"]}
    c.close(); return data

@app.exception_handler(404)
async def not_found(request,exc):
    return HTMLResponse(layout(request,"Not Found",'<div class="card empty"><h1>404</h1><p>Page not found.</p><a class="btn" href="/">Go Home</a></div>'),404)

@app.exception_handler(500)
async def server_error(request,exc):
    return HTMLResponse(layout(request,"Error",'<div class="card empty"><h1>Something went wrong</h1><p>Please try again.</p></div>'),500)

if __name__=="__main__":
    import uvicorn
    uvicorn.run("main:app",host="0.0.0.0",port=int(os.getenv("PORT","8000")))
