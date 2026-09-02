from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional
import sqlite3, hashlib, secrets, html, re, os, json, urllib.request, urllib.error, urllib.parse, smtplib
from email.message import EmailMessage

# ============================================================
# JOB MART — FULL SINGLE-FILE VERSION
# Existing features are preserved and expanded.
# ============================================================

APP_NAME = "Job Mart"
DB_FILE = Path(os.getenv("JOBMART_DB", "job_mart.db"))
UPLOAD_DIR = Path(os.getenv("JOBMART_UPLOADS", "uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@jobmart.local").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "CHANGE_THIS_ADMIN_PASSWORD")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6-luna")

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)

# Optional Twilio SMS
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM = os.getenv("TWILIO_FROM", "")

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "5"))

app = FastAPI(title=APP_NAME, version="3.0.0")

# ============================================================
# DATABASE
# ============================================================

def db():
    conn = sqlite3.connect(DB_FILE, timeout=20)
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
        "IT & Software", "Sales & Marketing", "Finance", "Healthcare",
        "Education", "Engineering", "Government", "Construction",
        "Retail", "Logistics", "Hospitality", "Agriculture",
        "Customer Support", "Design", "Other"
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
        expires_at TEXT,
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
        UNIQUE(job_id,user_id),
        FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS saved_jobs(
        user_id INTEGER NOT NULL,
        job_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(user_id,job_id),
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

    # Compatibility migrations for the original Job Mart DB.
    migrations = {
        "users": {
            "bio":"TEXT DEFAULT ''", "skills":"TEXT DEFAULT ''",
            "education":"TEXT DEFAULT ''", "experience":"TEXT DEFAULT ''",
            "resume_path":"TEXT DEFAULT ''", "is_blocked":"INTEGER DEFAULT 0"
        },
        "sessions": {"expires_at":"TEXT"},
        "jobs": {
            "company":"TEXT DEFAULT ''", "company_id":"INTEGER",
            "category":"TEXT DEFAULT 'Other'", "views":"INTEGER DEFAULT 0",
            "updated_at":"TEXT"
        },
        "applications": {"updated_at":"TEXT"},
    }

    for table, cols in migrations.items():
        existing = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
        for col, definition in cols.items():
            if col not in existing:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {definition}")

    c.execute("UPDATE jobs SET updated_at=COALESCE(updated_at,created_at) WHERE updated_at IS NULL OR updated_at=''")
    c.execute("UPDATE applications SET updated_at=COALESCE(updated_at,created_at) WHERE updated_at IS NULL OR updated_at=''")
    c.execute("UPDATE sessions SET expires_at=COALESCE(expires_at, ?) WHERE expires_at IS NULL OR expires_at=''",
              ((datetime.now(timezone.utc)+timedelta(days=30)).isoformat(),))
    c.commit()
    c.close()

def hash_password(password):
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 220000)
    return salt.hex()+":"+h.hex()

def verify_password(password, stored):
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
            "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
            ("Job Mart Admin", ADMIN_EMAIL, hash_password(ADMIN_PASSWORD), "admin", now_iso())
        )
        c.commit()
    c.close()

init_db()
ensure_admin()

# ============================================================
# AUTH / SECURITY
# ============================================================

def create_session(user_id):
    token = secrets.token_urlsafe(48)
    expiry = (datetime.now(timezone.utc)+timedelta(days=30)).isoformat()
    c = db()
    c.execute("INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
              (token,user_id,now_iso(),expiry))
    c.commit()
    c.close()
    return token

def current_user(request: Request):
    token = request.cookies.get("jobmart_session")
    if not token:
        return None
    c = db()
    row = c.execute("""
        SELECT u.* FROM sessions s
        JOIN users u ON u.id=s.user_id
        WHERE s.token=? AND (s.expires_at IS NULL OR s.expires_at>?)
    """, (token, now_iso())).fetchone()
    c.close()
    return row

def set_login_cookie(response, token):
    response.set_cookie(
        "jobmart_session", token, httponly=True,
        samesite="lax", secure=COOKIE_SECURE,
        max_age=60*60*24*30
    )

def logout(request):
    token = request.cookies.get("jobmart_session")
    if token:
        c=db()
        c.execute("DELETE FROM sessions WHERE token=?", (token,))
        c.commit(); c.close()

def require_user(request):
    u = current_user(request)
    if not u:
        raise HTTPException(401, "Login required")
    if u["is_blocked"]:
        raise HTTPException(403, "Account is blocked")
    return u

def require_employer(request):
    u=require_user(request)
    if u["role"] not in ("employer","admin"):
        raise HTTPException(403,"Employer account required")
    return u

def admin_ok(request):
    u=current_user(request)
    return bool(u and u["role"]=="admin" and not u["is_blocked"])

def redirect_login(msg="Please login first."):
    return RedirectResponse("/login?msg="+urllib.parse.quote(msg), 303)

# ============================================================
# OTP / EMAIL / SMS
# ============================================================

def create_otp(email, purpose):
    otp=str(secrets.randbelow(900000)+100000)
    expires=int(datetime.now(timezone.utc).timestamp())+600
    c=db()
    c.execute("UPDATE otps SET used=1 WHERE email=? AND purpose=? AND used=0", (email,purpose))
    c.execute("INSERT INTO otps(email,otp,purpose,expires_at) VALUES(?,?,?,?)",
              (email,otp,purpose,expires))
    c.commit(); c.close()
    return otp

def verify_otp(email, otp, purpose):
    now=int(datetime.now(timezone.utc).timestamp())
    c=db()
    row=c.execute("""
        SELECT * FROM otps
        WHERE email=? AND purpose=? AND used=0 AND expires_at>? 
        ORDER BY id DESC LIMIT 1
    """,(email,purpose,now)).fetchone()
    if not row:
        c.close(); return False
    if row["attempts"] >= 5:
        c.close(); return False
    if not secrets.compare_digest(str(row["otp"]), clean(otp)):
        c.execute("UPDATE otps SET attempts=attempts+1 WHERE id=?", (row["id"],))
        c.commit(); c.close(); return False
    c.execute("UPDATE otps SET used=1 WHERE id=?", (row["id"],))
    c.commit(); c.close()
    return True

def send_email(to_email, subject, body):
    if not SMTP_HOST:
        return False, "SMTP not configured"
    try:
        msg=EmailMessage()
        msg["From"]=SMTP_FROM or SMTP_USER
        msg["To"]=to_email
        msg["Subject"]=subject
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST,SMTP_PORT,timeout=20) as s:
            s.starttls()
            if SMTP_USER:
                s.login(SMTP_USER,SMTP_PASSWORD)
            s.send_message(msg)
        return True,"sent"
    except Exception as e:
        return False,str(e)

def send_sms(phone, message):
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM and phone):
        return False, "SMS provider not configured"
    try:
        import base64
        data=urllib.parse.urlencode({"To":phone,"From":TWILIO_FROM,"Body":message}).encode()
        url=f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json"
        req=urllib.request.Request(url,data=data,method="POST")
        auth=base64.b64encode(f"{TWILIO_ACCOUNT_SID}:{TWILIO_AUTH_TOKEN}".encode()).decode()
        req.add_header("Authorization","Basic "+auth)
        urllib.request.urlopen(req,timeout=20).read()
        return True,"sent"
    except Exception as e:
        return False,str(e)

def deliver_otp(email, phone, otp, purpose):
    subject="Job Mart OTP"
    text=f"Your Job Mart OTP is {otp}. It expires in 10 minutes."
    email_result=send_email(email,subject,text)
    sms_result=send_sms(phone,text)
    # Demo fallback: return OTP only when no external channel is configured.
    demo = not email_result[0] and not sms_result[0]
    return demo, email_result, sms_result

# ============================================================
# NOTIFICATIONS
# ============================================================

def notify(user_id,title,message):
    c=db()
    c.execute("INSERT INTO notifications(user_id,title,message,created_at) VALUES(?,?,?,?)",
              (user_id,title,message,now_iso()))
    c.commit(); c.close()

def notify_job_owner(job_id,title,message):
    c=db()
    row=c.execute("SELECT employer_id FROM jobs WHERE id=?", (job_id,)).fetchone()
    c.close()
    if row: notify(row["employer_id"],title,message)

# ============================================================
# AI
# ============================================================

def openai_call(messages, temperature=0.3):
    if not OPENAI_API_KEY:
        return None
    payload={
        "model":OPENAI_MODEL,
        "input":messages
    }
    data=json.dumps(payload).encode()
    req=urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=data,
        headers={
            "Content-Type":"application/json",
            "Authorization":"Bearer "+OPENAI_API_KEY
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req,timeout=45) as r:
            obj=json.loads(r.read().decode())
        if obj.get("output_text"):
            return obj["output_text"]
        parts=[]
        for item in obj.get("output",[]):
            for content in item.get("content",[]):
                if content.get("text"):
                    parts.append(content["text"])
        return "\n".join(parts).strip() or None
    except Exception:
        return None

def ai_customer_reply(user_message, user):
    system = (
        "You are Job Mart AI Customer Support. Help users with jobs, applications, "
        "profiles, resumes, employer posting, account issues, safety and navigation. "
        "Be accurate and concise. Never claim you completed an action unless the app "
        "actually did it. For suspicious jobs, advise users not to pay money or share "
        "OTP/passwords. Ask one useful follow-up question when needed."
    )
    context = f"User role: {user['role'] if user else 'guest'}"
    answer=openai_call([
        {"role":"system","content":system},
        {"role":"user","content":context+"\nQuestion: "+user_message}
    ])
    if answer: return answer
    m=user_message.lower()
    if any(x in m for x in ("apply","application")):
        return "Open the job, review the details, and tap Apply Now. You can track the application from Applications."
    if any(x in m for x in ("resume","cv")):
        return "Open Profile → Resume Builder to create your resume, or upload an existing PDF/DOC/DOCX resume."
    if any(x in m for x in ("password","login","otp")):
        return "You can use Password Login, OTP Login, or Forgot Password from the Login screen."
    if any(x in m for x in ("post job","post a job","employer")):
        return "Employer accounts can use Post Job. Fill in the job details and publish it."
    if any(x in m for x in ("scam","fraud","fake")):
        return "Do not pay an employer for a job or share passwords/OTPs. Use Report Job on suspicious listings."
    return "I’m Job Mart AI Support. Tell me what you need help with—jobs, applications, resume, account, employer posting, or a suspicious listing."

# ============================================================
# UI
# ============================================================

CSS=r"""
*{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#f4f7fb;color:#172033}
a{text-decoration:none;color:inherit}.top{position:sticky;top:0;z-index:50;background:#1976ed;color:#fff;box-shadow:0 3px 14px #0002}
.nav{max-width:1180px;margin:auto;padding:12px 16px;display:flex;align-items:center;gap:12px}.brand{font-size:29px;font-weight:900}.tag{font-size:13px;opacity:.85}.grow{flex:1}
.nav a,.nav button{font-size:15px}.navlink{padding:9px 11px;border-radius:8px}.navlink:hover{background:#ffffff22}
.menu{display:none;border:0;background:#fff;color:#1769d5;border-radius:10px;padding:10px 12px;font-size:20px}
.search{background:#1976ed;padding:0 16px 14px}.search form{max-width:1180px;margin:auto;display:flex;gap:8px}.search input{flex:1}
.container{max-width:1180px;margin:28px auto;padding:0 16px}.card{background:#fff;border-radius:18px;padding:25px;box-shadow:0 2px 11px #00000012;margin-bottom:18px}
.hero{padding:38px}.hero h1{font-size:46px;margin:0 0 12px}.muted{color:#687386}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.three{grid-template-columns:repeat(3,1fr)}
input,select,textarea{width:100%;padding:13px;border:1px solid #cbd3df;border-radius:9px;font-size:16px;background:#fff}textarea{min-height:130px;resize:vertical}
label{font-weight:700;display:block;margin:12px 0 6px}.btn{display:inline-block;border:0;background:#1976ed;color:#fff;border-radius:9px;padding:12px 17px;font-weight:700;cursor:pointer}.btn.secondary{background:#edf3fb;color:#1769d5}.btn.success{background:#168a55}.btn.danger{background:#d9363e}.btn.warn{background:#f2a900;color:#111}
.job-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}.job{background:#fff;border-radius:16px;padding:22px;box-shadow:0 2px 9px #0001}.job h3{margin:0 0 8px;color:#155db7;font-size:23px}.company{font-weight:800}.meta{color:#667286;margin:7px 0}.badge{display:inline-block;padding:5px 9px;border-radius:18px;background:#eaf2ff;color:#1769d5;margin:3px;font-size:13px}
.alert{padding:13px;border-radius:10px;background:#fff0f0;color:#b22b2b;margin-bottom:15px}.ok{background:#ebfff3;color:#147743}.empty{text-align:center;padding:45px;color:#687386}
.profile{display:flex;gap:20px;align-items:center}.avatar{width:78px;height:78px;border-radius:50%;background:#1976ed;color:#fff;display:grid;place-items:center;font-size:30px;font-weight:900}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.stat{background:#f5f8fd;padding:18px;border-radius:13px}.stat b{display:block;font-size:29px;color:#1769d5}
.mobile-panel{display:none;background:#fff;color:#172033;padding:10px 16px}.mobile-panel a{display:block;padding:13px;border-bottom:1px solid #eee}
.ai{position:fixed;right:18px;bottom:18px;z-index:60}.ai button{width:62px;height:62px;border:0;border-radius:50%;background:#1976ed;color:#fff;font-size:25px;box-shadow:0 5px 20px #0003}
.chatbox{display:none;position:fixed;right:18px;bottom:90px;width:min(370px,calc(100vw - 30px));background:#fff;border-radius:17px;box-shadow:0 8px 35px #0004;z-index:61;overflow:hidden}.chathead{background:#1976ed;color:#fff;padding:15px;font-weight:800}.chatbody{height:330px;overflow:auto;padding:12px}.msg{padding:9px 11px;border-radius:12px;margin:8px 0;max-width:88%;white-space:pre-wrap}.me{background:#eaf2ff;margin-left:auto}.bot{background:#f1f3f6}.chatinput{display:flex;gap:6px;padding:10px;border-top:1px solid #eee}.chatinput input{padding:10px}
footer{text-align:center;padding:35px;color:#687386}
@media(max-width:760px){.tag,.navlink{display:none}.menu{display:block}.grid,.job-grid,.three{grid-template-columns:1fr}.hero{padding:25px}.hero h1{font-size:36px}.stats{grid-template-columns:repeat(2,1fr)}.container{margin:18px auto}.nav{padding:10px 12px}.brand{font-size:25px}}
"""

CHAT_JS = r"""<script>
function toggleMenu(){let x=document.getElementById('mobilePanel');x.style.display=x.style.display==='block'?'none':'block'}
function toggleChat(){let x=document.getElementById('chatbox');x.style.display=x.style.display==='block'?'none':'block'}
async function sendChat(){let i=document.getElementById('chatmsg'),m=i.value.trim();if(!m)return;let b=document.getElementById('chatbody');b.innerHTML+='<div class="msg me">'+escapeHtml(m)+'</div>';i.value='';b.scrollTop=b.scrollHeight;try{let r=await fetch('/api/ai/support',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:m})});let j=await r.json();b.innerHTML+='<div class="msg bot">'+escapeHtml(j.reply||'Please try again.')+'</div>';b.scrollTop=b.scrollHeight}catch(e){b.innerHTML+='<div class="msg bot">AI support is temporarily unavailable.</div>'}}
function escapeHtml(s){return s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]))}
</script>"""

def layout(title, body, user=None, q=""):
    if user:
        initial=esc(user["name"][:1].upper())
        nav=f"""
        <a class="navlink" href="/dashboard">Dashboard</a>
        <a class="navlink" href="/jobs">Jobs</a>
        <a class="navlink" href="/applications">Applications</a>
        <a class="navlink" href="/saved">Saved</a>
        <a class="navlink" href="/profile">Profile</a>
        <a class="navlink" href="/post-job">Post Job</a>
        {"<a class='navlink' href='/admin'>Admin</a>" if user["role"]=="admin" else ""}
        <form method="post" action="/logout"><button class="btn secondary">Logout</button></form>
        """
        mobile=nav.replace('class="navlink"','').replace('class="btn secondary"','class="btn secondary"')
    else:
        nav='<a class="navlink" href="/jobs">Jobs</a><a class="navlink" href="/login">Login</a><a class="btn" href="/register">Create Account</a>'
        mobile=nav
        initial=""
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} - Job Mart</title><style>{CSS}</style></head><body>
<header class="top"><div class="nav"><button class="menu" onclick="toggleMenu()">☰</button><a class="brand" href="/">Job Mart</a><span class="tag">Find • Apply • Grow</span><div class="grow"></div>{nav}</div>
<div id="mobilePanel" class="mobile-panel">{mobile}</div>
<div class="search"><form method="get" action="/jobs"><input name="q" value="{esc(q)}" placeholder="Search jobs, skills, companies, locations..."><button class="btn">🔍</button></form></div></header>
<main class="container">{body}</main>
<div class="ai"><button onclick="toggleChat()">✦</button></div>
<div id="chatbox" class="chatbox"><div class="chathead">Job Mart AI Customer Support <span style="float:right;cursor:pointer" onclick="toggleChat()">×</span></div>
<div id="chatbody" class="chatbody"><div class="msg bot">Hi! I’m Job Mart AI Support. How can I help?</div></div>
<div class="chatinput"><input id="chatmsg" placeholder="Ask Job Mart..." onkeydown="if(event.key==='Enter')sendChat()"><button class="btn" onclick="sendChat()">Send</button></div></div>
<footer>Job Mart • Jobs • Applications • Resume • AI Support</footer>
{CHAT_JS}</body></html>"""

# ============================================================
# JOB CARD / FRAUD SCORE
# ============================================================

def fraud_score(job):
    score=0
    text=(job["title"]+" "+job["description"]+" "+(job["salary"] or "")).lower()
    risky=["pay fee","registration fee","send money","investment required","otp","guaranteed income","crypto"]
    score += sum(12 for x in risky if x in text)
    if not job["company"] or job["company"].lower() in ("unknown","test"): score+=10
    if not job["description"] or len(job["description"])<80: score+=10
    if not job["location"]: score+=5
    return min(score,100)

def job_card(job, saved=False):
    skills="".join(f'<span class="badge">{esc(x.strip())}</span>' for x in (job["skills"] or "").split(",") if x.strip())
    save_form=""
    ucurrent=getattr(job,"_current_user",None)
    if saved:
        save_form=f'<form method="post" action="/save/{job["id"]}" style="display:inline"><button class="btn secondary">★ Saved</button></form>'
    else:
        save_form=f'<form method="post" action="/save/{job["id"]}" style="display:inline"><button class="btn secondary">☆ Save</button></form>'
    risk=fraud_score(job)
    risk_html=f'<span class="badge">Safety score: {100-risk}/100</span>' if risk>=35 else ""
    return f"""<article class="job"><h3><a href="/job/{job["id"]}">{esc(job["title"])}</a></h3>
<div class="company">{esc(job["company"] or "Company")}</div><div class="meta">📍 {esc(job["location"] or "India")} · 🌎 {esc(job["country"])}</div>
<div class="meta">💼 {esc(job["job_type"])} · 💰 {esc(job["salary"] or "Salary not specified")}</div>
<div class="meta">📂 {esc(job["category"])} · 👁 {job["views"]}</div><div>{skills}</div><div>{risk_html}</div><br>
<a class="btn" href="/job/{job["id"]}">View Job</a> {save_form}</article>"""

# ============================================================
# HOME / JOB SEARCH
# ============================================================

@app.get("/", response_class=HTMLResponse)
def home(request:Request):
    u=current_user(request)
    c=db()
    jobs=c.execute("SELECT * FROM jobs WHERE status='active' ORDER BY id DESC LIMIT 8").fetchall()
    companies=c.execute("SELECT * FROM companies ORDER BY id DESC LIMIT 6").fetchall()
    c.close()
    cards="".join(job_card(j) for j in jobs) or '<div class="card empty"><h2>No jobs yet</h2><p>Employers can post jobs from Post Job.</p></div>'
    company_html="".join(f'<div class="card"><h3>{esc(x["name"])}</h3><p class="muted">{esc(x["location"])}</p><p>{esc(x["description"][:150])}</p><a class="btn secondary" href="/company/{x["id"]}">View Company</a></div>' for x in companies)
    body=f"""<section class="card hero"><h1>Find your next opportunity 👋</h1><p class="muted">Search verified-style job listings, apply online, build your resume and get AI support.</p>
<form method="get" action="/jobs"><input name="q" placeholder="Job title, company, skills..."><br><br><div class="grid"><select name="category"><option value="">All categories</option>{''.join(f'<option>{esc(x)}</option>' for x in categories())}</select>
<select name="job_type"><option value="">All job types</option><option>Full Time</option><option>Part Time</option><option>Remote</option><option>Contract</option><option>Internship</option></select></div><br><button class="btn" style="width:100%">Search Jobs</button></form></section>
<h2>Latest Jobs</h2><div class="job-grid">{cards}</div>
<h2 style="margin-top:30px">Companies</h2><div class="job-grid">{company_html or '<div class="card empty">Company profiles will appear here.</div>'}</div>"""
    return layout("Home",body,u)

@app.get("/jobs", response_class=HTMLResponse)
def jobs(request:Request,q:str="",country:str="",job_type:str="",category:str="",location:str="",experience:str="",salary:str=""):
    u=current_user(request)
    sql="SELECT * FROM jobs WHERE status='active'"; p=[]
    if q:
        v="%"+q.strip()+"%"; sql+=" AND (title LIKE ? OR company LIKE ? OR description LIKE ? OR skills LIKE ? OR location LIKE ?)"; p += [v,v,v,v,v]
    for col,val in [("country",country),("job_type",job_type),("category",category),("location",location),("experience",experience)]:
        if clean(val): sql+=f" AND {col} LIKE ?"; p.append("%"+clean(val)+"%")
    if salary.strip(): sql+=" AND salary LIKE ?";p.append("%"+salary.strip()+"%")
    sql+=" ORDER BY id DESC"
    c=db(); rows=c.execute(sql,p).fetchall(); c.close()
    cards="".join(job_card(r) for r in rows) or '<div class="card empty"><h2>No jobs found</h2><p>Try different filters.</p></div>'
    body=f"""<div class="card"><h1>Find Jobs</h1><form method="get"><div class="grid">
<input name="q" value="{esc(q)}" placeholder="Keyword"><input name="location" value="{esc(location)}" placeholder="Location">
<select name="country"><option value="">All countries</option><option {"selected" if country=="India" else ""}>India</option><option {"selected" if country=="United States" else ""}>United States</option><option {"selected" if country=="United Kingdom" else ""}>United Kingdom</option><option {"selected" if country=="Canada" else ""}>Canada</option><option {"selected" if country=="Australia" else ""}>Australia</option></select>
<select name="job_type"><option value="">All job types</option>{''.join(f'<option {"selected" if job_type==x else ""}>{x}</option>' for x in ["Full Time","Part Time","Remote","Contract","Internship"])}</select>
<select name="category"><option value="">All categories</option>{''.join(f'<option {"selected" if category==x else ""}>{esc(x)}</option>' for x in categories())}</select>
<input name="experience" value="{esc(experience)}" placeholder="Experience e.g. 0-2 years"><input name="salary" value="{esc(salary)}" placeholder="Salary keyword"></div><br><button class="btn">Apply Filters</button> <a class="btn secondary" href="/jobs">Clear</a></form></div>
<p class="muted">{len(rows)} active job(s)</p><div class="job-grid">{cards}</div>"""
    return layout("Jobs",body,u,q)

@app.get("/job/{job_id}", response_class=HTMLResponse)
def job_detail(request:Request,job_id:int):
    u=current_user(request); c=db()
    job=c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        c.close(); return HTMLResponse(layout("Not Found",'<div class="card empty"><h1>Job not found</h1></div>',u),404)
    c.execute("UPDATE jobs SET views=views+1 WHERE id=?", (job_id,))
    c.commit()
    saved=bool(u and c.execute("SELECT 1 FROM saved_jobs WHERE user_id=? AND job_id=?",(u["id"],job_id)).fetchone())
    already=bool(u and c.execute("SELECT 1 FROM applications WHERE user_id=? AND job_id=?",(u["id"],job_id)).fetchone())
    c.close()
    skills="".join(f'<span class="badge">{esc(x.strip())}</span>' for x in (job["skills"] or "").split(",") if x.strip())
    apply_html=""
    if not u:
        apply_html='<div class="card"><h2>Interested?</h2><a class="btn" href="/login">Login to Apply</a> <a class="btn secondary" href="/register">Create Account</a></div>'
    elif u["role"]=="employer":
        apply_html='<div class="alert">Employer accounts cannot apply to jobs.</div>'
    elif already:
        apply_html='<div class="alert ok">You already applied for this job. Track it in Applications.</div>'
    else:
        apply_html=f"""<div class="card"><h2>Apply for this job</h2><form method="post" action="/apply/{job_id}">
<label>Cover Letter</label><textarea name="cover_letter" placeholder="Why are you suitable?"></textarea><br><button class="btn success">Apply Now</button></form></div>"""
    body=f"""<div class="card"><a href="/jobs" style="color:#1769d5">← Back to Jobs</a><h1>{esc(job["title"])}</h1><h2>{esc(job["company"])}</h2>
<p class="meta">📍 {esc(job["location"] or "India")} · 🌎 {esc(job["country"])}</p><p class="meta">💼 {esc(job["job_type"])} · 💰 {esc(job["salary"] or "Not specified")}</p>
<p class="meta">📂 {esc(job["category"])} · 🎓 {esc(job["education"] or "Not specified")} · 👨‍💼 Employer ID {job["employer_id"]}</p><div>{skills}</div>
<h2>Job Description</h2><p style="white-space:pre-wrap">{esc(job["description"])}</p><h2>Experience</h2><p>{esc(job["experience"] or "Not specified")}</p>
<form method="post" action="/save/{job_id}" style="display:inline"><button class="btn secondary">{"★ Saved" if saved else "☆ Save Job"}</button></form>
<a class="btn secondary" href="/report/{job_id}">Report Job</a></div>{apply_html}"""
    return layout(job["title"],body,u)

# ============================================================
# AUTH
# ============================================================

@app.get("/register", response_class=HTMLResponse)
def register_page(request:Request):
    u=current_user(request)
    if u:return RedirectResponse("/dashboard",303)
    body="""<div class="card" style="max-width:700px;margin:auto"><h1>Create Account</h1><form method="post">
<label>Full Name</label><input name="name" required><label>Email</label><input name="email" type="email" required>
<label>Phone</label><input name="phone"><label>Location</label><input name="location"><label>Account Type</label>
<select name="role"><option value="jobseeker">Job Seeker</option><option value="employer">Employer</option></select>
<label>Password</label><input type="password" name="password" minlength="6" required><label>Confirm Password</label><input type="password" name="confirm_password" minlength="6" required><br><br>
<button class="btn" style="width:100%">Create Account</button></form><p>Already registered? <a href="/login" style="color:#1769d5">Login</a></p></div>"""
    return layout("Register",body)

@app.post("/register")
def register(request:Request,name:str=Form(...),email:str=Form(...),phone:str=Form(""),location:str=Form(""),role:str=Form("jobseeker"),password:str=Form(...),confirm_password:str=Form(...)):
    name=clean(name);email=clean(email).lower()
    if not name or not valid_email(email) or len(password)<6 or password!=confirm_password:
        return HTMLResponse(layout("Registration Error",'<div class="card alert">Check your name, email and password. Password must be 6+ characters and match.</div>'),400)
    if role not in ("jobseeker","employer"):role="jobseeker"
    c=db()
    if c.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone():
        c.close();return HTMLResponse(layout("Account Exists",'<div class="card alert">An account already exists. <a href="/login">Login</a>.</div>'),400)
    cur=c.execute("INSERT INTO users(name,email,password_hash,role,phone,location,created_at) VALUES(?,?,?,?,?,?,?)",
                  (name,email,hash_password(password),role,clean(phone),clean(location),now_iso()))
    uid=cur.lastrowid;c.commit();c.close()
    token=create_session(uid);resp=RedirectResponse("/dashboard",303);set_login_cookie(resp,token);return resp

@app.get("/login", response_class=HTMLResponse)
def login_page(request:Request,msg:str=""):
    if current_user(request):return RedirectResponse("/dashboard",303)
    body=f"""<div class="card" style="max-width:620px;margin:auto"><h1>Welcome Back 👋</h1>{"<div class='alert'>"+esc(msg)+"</div>" if msg else ""}
<div class="grid"><a class="btn secondary" href="/login">Password Login</a><a class="btn secondary" href="/otp-login">OTP Login</a></div>
<form method="post"><label>Email</label><input type="email" name="email" required><label>Password</label><input type="password" name="password" required><br><br><button class="btn">Login</button></form>
<br><a class="btn secondary" href="/forgot-password">Forgot Password?</a> <a class="btn secondary" href="/register">Create Account</a></div>"""
    return layout("Login",body)

@app.post("/login")
def login(request:Request,email:str=Form(...),password:str=Form(...)):
    email=clean(email).lower();c=db();u=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone();c.close()
    if not u or u["is_blocked"] or not verify_password(password,u["password_hash"]):
        return HTMLResponse(layout("Login Failed",'<div class="card alert">Invalid email/password or blocked account.</div><a class="btn" href="/login">Try Again</a>'),401)
    token=create_session(u["id"]);resp=RedirectResponse("/dashboard",303);set_login_cookie(resp,token);return resp

@app.post("/logout")
def logout_route(request:Request):
    logout(request);resp=RedirectResponse("/",303);resp.delete_cookie("jobmart_session");return resp

@app.get("/otp-login", response_class=HTMLResponse)
def otp_page(request:Request,email:str="",sent:str="",error:str=""):
    body=f"""<div class="card" style="max-width:620px;margin:auto"><h1>OTP Login</h1>{"<div class='alert'>"+esc(error)+"</div>" if error else ""}
<form method="post" action="/send-login-otp"><label>Email</label><input name="email" type="email" value="{esc(email)}" required><br><br><button class="btn">Send OTP</button></form>
<form method="post" action="/verify-login-otp"><label>OTP</label><input name="email" value="{esc(email)}" type="hidden"><input name="otp" inputmode="numeric" maxlength="6" pattern="[0-9]{6}" required><br><button class="btn success">Login with OTP</button></form>
{"<div class='alert ok'>Demo mode: OTP is shown below because email/SMS is not configured.</div>" if sent else ""}</div>"""
    return layout("OTP Login",body)

@app.post("/send-login-otp")
def send_login_otp(email:str=Form(...)):
    email=clean(email).lower();c=db();u=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone();c.close()
    if not u:return RedirectResponse("/otp-login?error=No account found",303)
    otp=create_otp(email,"login");demo,email_result,sms_result=deliver_otp(email,u["phone"],otp,"login")
    if demo:return HTMLResponse(layout("OTP",f'<div class="card"><div class="alert ok">Demo OTP: <strong style="font-size:30px">{otp}</strong></div><a class="btn" href="/otp-login?email={urllib.parse.quote(email)}&sent=1">Enter OTP</a></div>'))
    return RedirectResponse("/otp-login?email="+urllib.parse.quote(email)+"&sent=1",303)

@app.post("/verify-login-otp")
def verify_login_otp(request:Request,email:str=Form(...),otp:str=Form(...)):
    email=clean(email).lower()
    if not verify_otp(email,otp,"login"):return RedirectResponse("/otp-login?email="+urllib.parse.quote(email)+"&error=Invalid or expired OTP",303)
    c=db();u=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone();c.close()
    if not u:return RedirectResponse("/login?msg=Account not found",303)
    token=create_session(u["id"]);resp=RedirectResponse("/dashboard",303);set_login_cookie(resp,token);return resp

@app.get("/forgot-password",response_class=HTMLResponse)
def forgot_page(request:Request,error:str=""):
    body=f"""<div class="card" style="max-width:620px;margin:auto"><h1>Forgot Password</h1>{"<div class='alert'>"+esc(error)+"</div>" if error else ""}
<form method="post"><label>Email</label><input name="email" type="email" required><br><br><button class="btn">Send Reset OTP</button></form></div>"""
    return layout("Forgot Password",body)

@app.post("/forgot-password")
def forgot_post(email:str=Form(...)):
    email=clean(email).lower();c=db();u=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone();c.close()
    if not u:return RedirectResponse("/forgot-password?error=Account not found",303)
    otp=create_otp(email,"reset");demo,*_=deliver_otp(email,u["phone"],otp,"reset")
    if demo:return HTMLResponse(layout("Reset OTP",f'<div class="card"><div class="alert ok">Demo reset OTP: <strong style="font-size:30px">{otp}</strong></div><a class="btn" href="/reset-password?email={urllib.parse.quote(email)}">Continue</a></div>'))
    return RedirectResponse("/reset-password?email="+urllib.parse.quote(email),303)

@app.get("/reset-password",response_class=HTMLResponse)
def reset_page(request:Request,email:str="",error:str=""):
    body=f"""<div class="card" style="max-width:620px;margin:auto"><h1>Reset Password</h1>{"<div class='alert'>"+esc(error)+"</div>" if error else ""}
<form method="post"><input type="hidden" name="email" value="{esc(email)}"><label>OTP</label><input name="otp" maxlength="6" required><label>New Password</label><input type="password" name="password" minlength="6" required><label>Confirm</label><input type="password" name="confirm_password" minlength="6" required><br><br><button class="btn">Reset Password</button></form></div>"""
    return layout("Reset Password",body)

@app.post("/reset-password")
def reset_post(email:str=Form(...),otp:str=Form(...),password:str=Form(...),confirm_password:str=Form(...)):
    email=clean(email).lower()
    if len(password)<6 or password!=confirm_password:return RedirectResponse("/reset-password?email="+urllib.parse.quote(email)+"&error=Passwords do not match",303)
    if not verify_otp(email,otp,"reset"):return RedirectResponse("/reset-password?email="+urllib.parse.quote(email)+"&error=Invalid or expired OTP",303)
    c=db();c.execute("UPDATE users SET password_hash=? WHERE email=?",(hash_password(password),email));c.commit();c.close()
    return RedirectResponse("/login?msg=Password reset successful",303)

# ============================================================
# DASHBOARD / PROFILE / RESUME
# ============================================================

@app.get("/dashboard",response_class=HTMLResponse)
def dashboard(request:Request):
    u=current_user(request)
    if not u:return redirect_login()
    c=db()
    apps=c.execute("SELECT COUNT(*) FROM applications WHERE user_id=?",(u["id"],)).fetchone()[0]
    posted=c.execute("SELECT COUNT(*) FROM jobs WHERE employer_id=?",(u["id"],)).fetchone()[0]
    saved=c.execute("SELECT COUNT(*) FROM saved_jobs WHERE user_id=?",(u["id"],)).fetchone()[0]
    unread=c.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND read=0",(u["id"],)).fetchone()[0]
    c.close()
    initial=esc(u["name"][:1].upper())
    employer_actions='<a class="btn success" href="/post-job">Post Job</a> <a class="btn secondary" href="/my-jobs">My Jobs</a>' if u["role"] in ("employer","admin") else ""
    body=f"""<div class="card"><div class="profile"><div class="avatar">{initial}</div><div><h1>Welcome, {esc(u["name"])} 👋</h1><p>{esc(u["email"])}</p><span class="badge">{esc(u["role"].title())}</span></div></div></div>
<div class="stats"><div class="stat"><b>{apps}</b>Applications</div><div class="stat"><b>{posted}</b>Jobs Posted</div><div class="stat"><b>{saved}</b>Saved Jobs</div><div class="stat"><b>{unread}</b>Unread Alerts</div></div><br>
<div class="card"><h2>Quick Actions</h2><a class="btn" href="/jobs">Find Jobs</a> <a class="btn secondary" href="/profile">Edit Profile</a> <a class="btn secondary" href="/resume-builder">Resume Builder</a> {employer_actions}</div>"""
    return layout("Dashboard",body,u)

@app.get("/profile",response_class=HTMLResponse)
def profile_page(request:Request,msg:str=""):
    u=current_user(request)
    if not u:return redirect_login()
    body=f"""<div class="card" style="max-width:850px;margin:auto"><h1>My Profile</h1>{"<div class='alert ok'>"+esc(msg)+"</div>" if msg else ""}
<form method="post"><div class="grid"><div><label>Name</label><input name="name" value="{esc(u["name"])}" required></div><div><label>Phone</label><input name="phone" value="{esc(u["phone"])}"></div><div><label>Location</label><input name="location" value="{esc(u["location"])}"></div><div><label>Education</label><input name="education" value="{esc(u["education"])}"></div><div><label>Experience</label><input name="experience" value="{esc(u["experience"])}"></div><div><label>Skills</label><input name="skills" value="{esc(u["skills"])}" placeholder="Python, Sales, Excel"></div></div><label>Bio</label><textarea name="bio">{esc(u["bio"])}</textarea><br><button class="btn">Save Profile</button></form></div>
<div class="card"><h2>Resume</h2><p>{esc(u["resume_path"] or "No uploaded resume")}</p><a class="btn secondary" href="/resume-builder">Build Resume</a> <a class="btn secondary" href="/resume-upload">Upload Resume</a></div>"""
    return layout("Profile",body,u)

@app.post("/profile")
def profile_post(request:Request,name:str=Form(...),phone:str=Form(""),location:str=Form(""),education:str=Form(""),experience:str=Form(""),skills:str=Form(""),bio:str=Form("")):
    u=require_user(request);c=db();c.execute("""UPDATE users SET name=?,phone=?,location=?,education=?,experience=?,skills=?,bio=? WHERE id=?""",
        (clean(name),clean(phone),clean(location),clean(education),clean(experience),clean(skills),clean(bio),u["id"]));c.commit();c.close()
    return RedirectResponse("/profile?msg=Profile saved",303)

@app.get("/resume-upload",response_class=HTMLResponse)
def resume_upload_page(request:Request):
    u=current_user(request)
    if not u:return redirect_login()
    body="""<div class="card" style="max-width:700px;margin:auto"><h1>Upload Resume</h1><p class="muted">PDF, DOC or DOCX. Maximum size is configured by MAX_UPLOAD_MB.</p>
<form method="post" enctype="multipart/form-data"><input type="file" name="resume" accept=".pdf,.doc,.docx" required><br><br><button class="btn">Upload Resume</button></form></div>"""
    return layout("Resume Upload",body,u)

@app.post("/resume-upload")
async def resume_upload(request:Request,resume:UploadFile=File(...)):
    u=require_user(request)
    ext=Path(resume.filename or "").suffix.lower()
    if ext not in (".pdf",".doc",".docx"):return HTMLResponse(layout("Upload Error",'<div class="card alert">Only PDF, DOC and DOCX files are allowed.</div>',u),400)
    data=await resume.read()
    if len(data)>MAX_UPLOAD_MB*1024*1024:return HTMLResponse(layout("Upload Error",'<div class="card alert">File is too large.</div>',u),400)
    safe=f"user_{u['id']}_{secrets.token_hex(8)}{ext}";path=UPLOAD_DIR/safe;path.write_bytes(data)
    c=db();c.execute("UPDATE users SET resume_path=? WHERE id=?",(safe,u["id"]));c.commit();c.close()
    return RedirectResponse("/profile?msg=Resume uploaded",303)

@app.get("/resume/{filename}")
def resume_file(request:Request,filename:str):
    u=require_user(request)
    if Path(filename).name!=filename:raise HTTPException(400,"Invalid filename")
    c=db()
    own=c.execute("SELECT resume_path FROM users WHERE id=?",(u["id"],)).fetchone()
    allowed=bool(own and own["resume_path"]==filename)
    if not allowed and u["role"] in ("employer","admin"):
        allowed=bool(c.execute("""SELECT 1 FROM applications a JOIN users x ON x.id=a.user_id JOIN jobs j ON j.id=a.job_id WHERE x.resume_path=? AND (j.employer_id=? OR ?='admin') LIMIT 1""",(filename,u["id"],u["role"])).fetchone())
    c.close()
    if not allowed:raise HTTPException(403,"Not allowed")
    p=UPLOAD_DIR/filename
    if not p.exists():raise HTTPException(404,"File not found")
    return FileResponse(p)

@app.get("/resume-builder",response_class=HTMLResponse)
def resume_builder(request:Request):
    u=current_user(request)
    if not u:return redirect_login()
    body=f"""<div class="card"><h1>Resume Builder</h1><p class="muted">Your profile data is used to generate a clean printable resume.</p>
<div class="grid"><div><h2>{esc(u["name"])}</h2><p>{esc(u["email"])} · {esc(u["phone"])} · {esc(u["location"])}</p></div><div><h3>Skills</h3><p>{esc(u["skills"])}</p></div></div>
<h2>Professional Summary</h2><p>{esc(u["bio"] or "Add a professional summary in your profile.")}</p><h2>Experience</h2><p style="white-space:pre-wrap">{esc(u["experience"] or "Add your experience in your profile.")}</p>
<h2>Education</h2><p>{esc(u["education"] or "Add your education in your profile.")}</p><button class="btn" onclick="window.print()">Print / Save as PDF</button> <a class="btn secondary" href="/profile">Edit Profile</a>
</div>"""
    return layout("Resume Builder",body,u)

# ============================================================
# SAVED JOBS
# ============================================================

@app.post("/save/{job_id}")
def save_job(request:Request,job_id:int):
    u=require_user(request);c=db()
    exists=c.execute("SELECT 1 FROM saved_jobs WHERE user_id=? AND job_id=?",(u["id"],job_id)).fetchone()
    if exists:c.execute("DELETE FROM saved_jobs WHERE user_id=? AND job_id=?",(u["id"],job_id))
    else:c.execute("INSERT OR IGNORE INTO saved_jobs(user_id,job_id,created_at) VALUES(?,?,?)",(u["id"],job_id,now_iso()))
    c.commit();c.close()
    return RedirectResponse(request.headers.get("referer") or "/jobs",303)

@app.get("/saved",response_class=HTMLResponse)
def saved_page(request:Request):
    u=current_user(request)
    if not u:return redirect_login()
    c=db();rows=c.execute("""SELECT jobs.* FROM saved_jobs JOIN jobs ON jobs.id=saved_jobs.job_id WHERE saved_jobs.user_id=? ORDER BY saved_jobs.created_at DESC""",(u["id"],)).fetchall();c.close()
    body=f"<h1>Saved Jobs</h1><div class='job-grid'>{''.join(job_card(x,True) for x in rows) or '<div class=\"card empty\">No saved jobs.</div>'}</div>"
    return layout("Saved Jobs",body,u)

# ============================================================
# EMPLOYER / COMPANY / JOB CRUD
# ============================================================

@app.get("/post-job",response_class=HTMLResponse)
def post_job_page(request:Request):
    u=current_user(request)
    if not u:return redirect_login("Login to post a job")
    if u["role"] not in ("employer","admin"):return HTMLResponse(layout("Access Denied",'<div class="card alert">Employer account required.</div>',u),403)
    body=f"""<div class="card"><h1>Post a New Job</h1><form method="post"><div class="grid">
<div><label>Job Title</label><input name="title" required></div><div><label>Company</label><input name="company" value="{esc(u["name"])}" required></div>
<div><label>Location</label><input name="location"></div><div><label>Country</label><select name="country"><option>India</option><option>United States</option><option>United Kingdom</option><option>Canada</option><option>Australia</option></select></div>
<div><label>Job Type</label><select name="job_type"><option>Full Time</option><option>Part Time</option><option>Remote</option><option>Contract</option><option>Internship</option></select></div>
<div><label>Category</label><select name="category">{''.join(f'<option>{esc(x)}</option>' for x in categories())}</select></div>
<div><label>Salary</label><input name="salary" placeholder="₹5 LPA - ₹10 LPA"></div><div><label>Experience</label><input name="experience" placeholder="0-2 years"></div><div><label>Education</label><input name="education"></div>
</div><label>Skills</label><input name="skills" placeholder="Python, SQL, Excel"><label>Description</label><textarea name="description" required></textarea><br><button class="btn success">Publish Job</button></form></div>"""
    return layout("Post Job",body,u)

@app.post("/post-job")
def post_job(request:Request,title:str=Form(...),company:str=Form(...),description:str=Form(...),skills:str=Form(""),country:str=Form("India"),location:str=Form(""),job_type:str=Form("Full Time"),salary:str=Form(""),experience:str=Form(""),education:str=Form(""),category:str=Form("Other")):
    u=require_employer(request);c=db();t=now_iso()
    cur=c.execute("""INSERT INTO jobs(employer_id,title,company,description,skills,country,location,job_type,salary,experience,education,category,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (u["id"],clean(title),clean(company),clean(description),clean(skills),clean(country),clean(location),clean(job_type),clean(salary),clean(experience),clean(education),category if category in categories() else "Other","active",t,t))
    jid=cur.lastrowid;c.commit();c.close()
    return RedirectResponse("/job/"+str(jid),303)

@app.get("/my-jobs",response_class=HTMLResponse)
def my_jobs(request:Request):
    u=current_user(request)
    if not u:return redirect_login()
    if u["role"] not in ("employer","admin"):return HTMLResponse(layout("Access Denied",'<div class="card alert">Employer account required.</div>',u),403)
    c=db();rows=c.execute("SELECT * FROM jobs WHERE employer_id=? ORDER BY id DESC",(u["id"],)).fetchall();c.close()
    content=""
    for r in rows:
        content+=f"""<div class="job"><h3>{esc(r["title"])}</h3><p>{esc(r["company"])} · {esc(r["location"])}</p><span class="badge">{esc(r["status"])}</span>
<br><br><a class="btn" href="/job/{r["id"]}">View</a> <a class="btn secondary" href="/edit-job/{r["id"]}">Edit</a>
<a class="btn secondary" href="/job-applications/{r["id"]}">Applicants</a><form method="post" action="/delete-job/{r["id"]}" style="display:inline" onsubmit="return confirm('Delete this job?')"><button class="btn danger">Delete</button></form></div>"""
    body=f"<h1>My Jobs</h1><div class='job-grid'>{content or '<div class=\"card empty\">No jobs posted.</div>'}</div>"
    return layout("My Jobs",body,u)

@app.get("/edit-job/{job_id}",response_class=HTMLResponse)
def edit_job_page(request:Request,job_id:int):
    u=require_employer(request);c=db();j=c.execute("SELECT * FROM jobs WHERE id=? AND employer_id=?",(job_id,u["id"])).fetchone();c.close()
    if not j:raise HTTPException(404,"Job not found")
    body=f"""<div class="card"><h1>Edit Job</h1><form method="post"><div class="grid">
<div><label>Title</label><input name="title" value="{esc(j["title"])}" required></div><div><label>Company</label><input name="company" value="{esc(j["company"])}" required></div>
<div><label>Location</label><input name="location" value="{esc(j["location"])}"></div><div><label>Country</label><input name="country" value="{esc(j["country"])}"></div>
<div><label>Job Type</label><input name="job_type" value="{esc(j["job_type"])}"></div><div><label>Category</label><select name="category">{''.join(f'<option {"selected" if j["category"]==x else ""}>{esc(x)}</option>' for x in categories())}</select></div>
<div><label>Salary</label><input name="salary" value="{esc(j["salary"])}"></div><div><label>Experience</label><input name="experience" value="{esc(j["experience"])}"></div><div><label>Education</label><input name="education" value="{esc(j["education"])}"></div></div>
<label>Skills</label><input name="skills" value="{esc(j["skills"])}"><label>Description</label><textarea name="description" required>{esc(j["description"])}</textarea><br><button class="btn">Save Changes</button></form></div>"""
    return layout("Edit Job",body,u)

@app.post("/edit-job/{job_id}")
def edit_job(request:Request,job_id:int,title:str=Form(...),company:str=Form(...),description:str=Form(...),skills:str=Form(""),country:str=Form("India"),location:str=Form(""),job_type:str=Form("Full Time"),salary:str=Form(""),experience:str=Form(""),education:str=Form(""),category:str=Form("Other")):
    u=require_employer(request);c=db()
    c.execute("""UPDATE jobs SET title=?,company=?,description=?,skills=?,country=?,location=?,job_type=?,salary=?,experience=?,education=?,category=?,updated_at=? WHERE id=? AND employer_id=?""",
              (clean(title),clean(company),clean(description),clean(skills),clean(country),clean(location),clean(job_type),clean(salary),clean(experience),clean(education),category,now_iso(),job_id,u["id"]))
    c.commit();c.close();return RedirectResponse("/job/"+str(job_id),303)

@app.post("/delete-job/{job_id}")
def delete_job(request:Request,job_id:int):
    u=require_employer(request);c=db();c.execute("DELETE FROM jobs WHERE id=? AND employer_id=?",(job_id,u["id"]));c.commit();c.close();return RedirectResponse("/my-jobs",303)

@app.post("/close-job/{job_id}")
def close_job(request:Request,job_id:int):
    u=require_employer(request);c=db();c.execute("UPDATE jobs SET status='closed',updated_at=? WHERE id=? AND employer_id=?",(now_iso(),job_id,u["id"]));c.commit();c.close();return RedirectResponse("/my-jobs",303)

@app.post("/reopen-job/{job_id}")
def reopen_job(request:Request,job_id:int):
    u=require_employer(request);c=db();c.execute("UPDATE jobs SET status='active',updated_at=? WHERE id=? AND employer_id=?",(now_iso(),job_id,u["id"]));c.commit();c.close();return RedirectResponse("/my-jobs",303)

@app.get("/company/{company_id}",response_class=HTMLResponse)
def company_page(request:Request,company_id:int):
    u=current_user(request);c=db();co=c.execute("SELECT * FROM companies WHERE id=?",(company_id,)).fetchone();jobs=c.execute("SELECT * FROM jobs WHERE company_id=? AND status='active'",(company_id,)).fetchall();c.close()
    if not co:return HTMLResponse(layout("Company Not Found",'<div class="card empty">Company not found.</div>',u),404)
    body=f"""<div class="card"><h1>{esc(co["name"])}</h1><p>{esc(co["location"])}</p><p>{esc(co["website"])}</p><p style="white-space:pre-wrap">{esc(co["description"])}</p></div><h2>Open Jobs</h2><div class="job-grid">{''.join(job_card(x) for x in jobs) or '<div class="card empty">No open jobs.</div>'}</div>"""
    return layout(co["name"],body,u)

@app.get("/company-create",response_class=HTMLResponse)
def company_create_page(request:Request):
    u=require_employer(request)
    body="""<div class="card"><h1>Create Company Profile</h1><form method="post"><label>Company Name</label><input name="name" required><label>Website</label><input name="website" placeholder="https://..."><label>Location</label><input name="location"><label>Description</label><textarea name="description"></textarea><br><button class="btn">Create Company</button></form></div>"""
    return layout("Company Profile",body,u)

@app.post("/company-create")
def company_create(request:Request,name:str=Form(...),website:str=Form(""),location:str=Form(""),description:str=Form("")):
    u=require_employer(request);c=db()
    try:
        cur=c.execute("INSERT INTO companies(owner_id,name,description,website,location,created_at) VALUES(?,?,?,?,?,?)",(u["id"],clean(name),clean(description),clean(website),clean(location),now_iso()))
        cid=cur.lastrowid;c.commit()
    except sqlite3.IntegrityError:
        c.close();return HTMLResponse(layout("Company Error",'<div class="card alert">Company name already exists.</div>',u),400)
    c.close();return RedirectResponse("/company/"+str(cid),303)

# ============================================================
# APPLICATIONS + STATUS
# ============================================================

APPLICATION_STATUSES=["Applied","Reviewing","Shortlisted","Interview","Accepted","Rejected","Withdrawn"]

@app.post("/apply/{job_id}")
def apply_job(request:Request,job_id:int,cover_letter:str=Form("")):
    u=require_user(request)
    if u["role"]!="jobseeker":return HTMLResponse(layout("Cannot Apply",'<div class="card alert">Only job seekers can apply.</div>',u),403)
    c=db();job=c.execute("SELECT * FROM jobs WHERE id=? AND status='active'",(job_id,)).fetchone()
    if not job:c.close();raise HTTPException(404,"Job not available")
    try:
        c.execute("INSERT INTO applications(job_id,user_id,cover_letter,status,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                  (job_id,u["id"],clean(cover_letter),"Applied",now_iso(),now_iso()))
        c.commit()
    except sqlite3.IntegrityError:
        c.close();return RedirectResponse("/applications",303)
    c.close();notify_job_owner(job_id,"New application",f"{u['name']} applied for {job['title']}.");return RedirectResponse("/applications",303)

@app.get("/applications",response_class=HTMLResponse)
def applications(request:Request):
    u=current_user(request)
    if not u:return redirect_login()
    c=db();rows=c.execute("""SELECT a.*,j.title,j.company,j.location FROM applications a JOIN jobs j ON j.id=a.job_id WHERE a.user_id=? ORDER BY a.id DESC""",(u["id"],)).fetchall();c.close()
    content=""
    for r in rows:
        content+=f"""<div class="job"><h3>{esc(r["title"])}</h3><p>{esc(r["company"])} · {esc(r["location"])}</p><span class="badge">{esc(r["status"])}</span><p class="muted">Applied {esc(r["created_at"][:10])}</p><p style="white-space:pre-wrap">{esc(r["cover_letter"])}</p></div>"""
    body=f"<div class='card'><h1>My Applications</h1><p class='muted'>Track every application.</p></div><div class='job-grid'>{content or '<div class=\"card empty\">No applications yet.</div>'}</div>"
    return layout("Applications",body,u)

@app.get("/job-applications/{job_id}",response_class=HTMLResponse)
def job_applications(request:Request,job_id:int):
    u=require_employer(request);c=db();job=c.execute("SELECT * FROM jobs WHERE id=? AND employer_id=?",(job_id,u["id"])).fetchone()
    if not job:c.close();raise HTTPException(404,"Job not found")
    rows=c.execute("""SELECT a.*,u.name,u.email,u.phone,u.location,u.skills,u.education,u.experience,u.resume_path FROM applications a JOIN users u ON u.id=a.user_id WHERE a.job_id=? ORDER BY a.id DESC""",(job_id,)).fetchall();c.close()
    content=""
    for r in rows:
        options="".join(f'<option {"selected" if r["status"]==x else ""}>{x}</option>' for x in APPLICATION_STATUSES)
        content+=f"""<div class="card"><h2>{esc(r["name"])}</h2><p>📧 {esc(r["email"])} · 📱 {esc(r["phone"])} · 📍 {esc(r["location"])}</p><p>Skills: {esc(r["skills"])}</p><p>Education: {esc(r["education"])}</p><p style="white-space:pre-wrap">{esc(r["cover_letter"] or "No cover letter")}</p>
<form method="post" action="/application/{r["id"]}/status"><select name="status">{options}</select> <button class="btn">Update Status</button></form>
{"<a class='btn secondary' href='/resume/"+esc(r["resume_path"])+"'>Resume</a>" if r["resume_path"] else ""}</div>"""
    body=f"<div class='card'><h1>Applicants</h1><p>Job: <strong>{esc(job['title'])}</strong></p></div>{content or '<div class=\"card empty\">No applications.</div>'}"
    return layout("Applicants",body,u)

@app.post("/application/{application_id}/status")
def application_status(request:Request,application_id:int,status:str=Form(...)):
    u=require_employer(request)
    if status not in APPLICATION_STATUSES:raise HTTPException(400,"Invalid status")
    c=db();row=c.execute("""SELECT a.*,j.title,j.employer_id FROM applications a JOIN jobs j ON j.id=a.job_id WHERE a.id=?""",(application_id,)).fetchone()
    if not row or row["employer_id"]!=u["id"]:c.close();raise HTTPException(403,"Not allowed")
    c.execute("UPDATE applications SET status=?,updated_at=? WHERE id=?",(status,now_iso(),application_id));c.commit();c.close()
    notify(row["user_id"],"Application update",f"Your application for {row['title']} is now {status}.")
    return RedirectResponse(request.headers.get("referer") or "/my-jobs",303)

# ============================================================
# NOTIFICATIONS
# ============================================================

@app.get("/notifications",response_class=HTMLResponse)
def notifications_page(request:Request):
    u=current_user(request)
    if not u:return redirect_login()
    c=db();rows=c.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100",(u["id"],)).fetchall();c.execute("UPDATE notifications SET read=1 WHERE user_id=?",(u["id"],));c.commit();c.close()
    body="<h1>Notifications</h1>"+("".join(f'<div class="card"><h3>{esc(x["title"])}</h3><p>{esc(x["message"])}</p><small>{esc(x["created_at"])}</small></div>' for x in rows) or '<div class="card empty">No notifications.</div>')
    return layout("Notifications",body,u)

# ============================================================
# REPORT / FRAUD
# ============================================================

@app.get("/report/{job_id}",response_class=HTMLResponse)
def report_page(request:Request,job_id:int):
    u=current_user(request)
    if not u:return redirect_login()
    body=f"""<div class="card" style="max-width:700px;margin:auto"><h1>Report Job</h1><form method="post"><input type="hidden" name="job_id" value="{job_id}">
<label>Reason</label><select name="reason"><option>Scam or fraud</option><option>Fake job</option><option>Requests money</option><option>Misleading information</option><option>Inappropriate content</option><option>Other</option></select>
<label>Details</label><textarea name="details" placeholder="Explain what looks suspicious."></textarea><br><button class="btn danger">Submit Report</button></form></div>"""
    return layout("Report Job",body,u)

@app.post("/report/{job_id}")
def report_post(request:Request,job_id:int,reason:str=Form(...),details:str=Form("")):
    u=require_user(request);c=db();c.execute("INSERT INTO reports(job_id,user_id,reason,details,created_at) VALUES(?,?,?,?,?)",(job_id,u["id"],clean(reason),clean(details),now_iso()));c.commit();c.close();notify_job_owner(job_id,"Job report received","A user reported one of your listings. Please review it.");return RedirectResponse("/job/"+str(job_id),303)

# ============================================================
# AI FEATURES
# ============================================================

@app.post("/api/ai/support")
async def ai_support(request:Request):
    data=await request.json();message=clean(data.get("message",""))
    if not message:return {"reply":"Please type a question."}
    u=current_user(request)
    c=db();c.execute("INSERT INTO ai_chats(user_id,role,message,created_at) VALUES(?,?,?,?)",(u["id"] if u else None,"user",message,now_iso()));c.commit();c.close()
    reply=ai_customer_reply(message,u)
    c=db();c.execute("INSERT INTO ai_chats(user_id,role,message,created_at) VALUES(?,?,?,?)",(u["id"] if u else None,"assistant",reply,now_iso()));c.commit();c.close()
    return {"reply":reply,"ai_enabled":bool(OPENAI_API_KEY)}

@app.post("/api/ai/resume")
async def ai_resume(request:Request):
    u=require_user(request);data=await request.json();target=clean(data.get("target_job",""))
    prompt=f"""Create practical resume improvement suggestions for this Job Mart user.
Name: {u['name']}
Skills: {u['skills']}
Education: {u['education']}
Experience: {u['experience']}
Bio: {u['bio']}
Target job: {target}
Give a concise summary, missing skills, stronger bullet examples and ATS keywords. Do not invent qualifications."""
    answer=openai_call([{"role":"system","content":"You are a professional resume assistant."},{"role":"user","content":prompt}])
    if not answer:
        answer="Add measurable achievements, relevant skills, clear job titles, education and keywords matching the target job. Avoid false claims."
    return {"answer":answer}

@app.post("/api/ai/application")
async def ai_application(request:Request):
    u=require_user(request);data=await request.json();job_id=int(data.get("job_id",0));c=db();job=c.execute("SELECT * FROM jobs WHERE id=?",(job_id,)).fetchone();c.close()
    if not job:raise HTTPException(404,"Job not found")
    prompt=f"""Help this candidate write a truthful job application cover letter.
Candidate skills: {u['skills']}
Experience: {u['experience']}
Education: {u['education']}
Job title: {job['title']}
Company: {job['company']}
Description: {job['description']}
Return a concise professional cover letter. Never invent experience."""
    answer=openai_call([{"role":"system","content":"You are a job application assistant."},{"role":"user","content":prompt}])
    if not answer:answer=f"Dear Hiring Team,\n\nI am interested in the {job['title']} position at {job['company']}. My skills and experience align with the requirements, and I would welcome the opportunity to contribute.\n\nRegards,\n{u['name']}"
    return {"cover_letter":answer}

@app.get("/api/ai/recommendations")
def recommendations(request:Request):
    u=require_user(request);c=db()
    rows=c.execute("SELECT * FROM jobs WHERE status='active' ORDER BY id DESC LIMIT 100").fetchall();c.close()
    user_text=(u["skills"]+" "+u["education"]+" "+u["experience"]+" "+u["location"]).lower()
    scored=[]
    for j in rows:
        text=(j["title"]+" "+j["skills"]+" "+j["category"]+" "+j["location"]).lower()
        score=sum(1 for token in re.findall(r"[a-z0-9+#.-]+",user_text) if len(token)>2 and token in text)
        if u["location"] and j["location"] and u["location"].lower() in j["location"].lower():score+=3
        scored.append((score,j))
    scored.sort(key=lambda x:(x[0],x[1]["id"]),reverse=True)
    return {"jobs":[dict(j) for _,j in scored[:10]]}

# ============================================================
# ADMIN
# ============================================================

@app.get("/admin",response_class=HTMLResponse)
def admin_page(request:Request):
    u=current_user(request)
    if not admin_ok(request):raise HTTPException(403,"Admin only")
    c=db()
    users=c.execute("SELECT * FROM users ORDER BY id DESC LIMIT 100").fetchall()
    jobs=c.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT 100").fetchall()
    reports=c.execute("""SELECT r.*,j.title,u.email FROM reports r JOIN jobs j ON j.id=r.job_id JOIN users u ON u.id=r.user_id ORDER BY r.id DESC LIMIT 100""").fetchall()
    stats=[c.execute("SELECT COUNT(*) FROM users").fetchone()[0],c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0],c.execute("SELECT COUNT(*) FROM applications").fetchone()[0],c.execute("SELECT COUNT(*) FROM reports WHERE status='open'").fetchone()[0]]
    c.close()
    users_html="".join(f'<div class="card"><b>{esc(x["name"])}</b> · {esc(x["email"])} · {esc(x["role"])} {"<span class=badge>BLOCKED</span>" if x["is_blocked"] else ""}<form method="post" action="/admin/user/{x["id"]}/toggle" style="margin-top:8px"><button class="btn {"success" if x["is_blocked"] else "danger"}">{"Unblock" if x["is_blocked"] else "Block"}</button></form></div>' for x in users)
    reports_html="".join(f'<div class="card"><b>{esc(x["title"])}</b><p>{esc(x["reason"])} — {esc(x["details"])}</p><p>Reporter: {esc(x["email"])}</p><form method="post" action="/admin/report/{x["id"]}"><select name="status"><option {"selected" if x["status"]=="open" else ""}>open</option><option {"selected" if x["status"]=="reviewed" else ""}>reviewed</option><option {"selected" if x["status"]=="dismissed" else ""}>dismissed</option></select> <button class="btn">Save</button></form></div>' for x in reports)
    body=f"""<h1>Admin Panel</h1><div class="stats"><div class="stat"><b>{stats[0]}</b>Users</div><div class="stat"><b>{stats[1]}</b>Jobs</div><div class="stat"><b>{stats[2]}</b>Applications</div><div class="stat"><b>{stats[3]}</b>Open Reports</div></div><br>
<h2>Reports</h2>{reports_html or '<div class="card empty">No reports.</div>'}<h2>Users</h2>{users_html}"""
    return layout("Admin",body,u)

@app.post("/admin/user/{uid}/toggle")
def admin_user_toggle(request:Request,uid:int):
    if not admin_ok(request):raise HTTPException(403,"Admin only")
    c=db();row=c.execute("SELECT is_blocked FROM users WHERE id=?",(uid,)).fetchone()
    if row:c.execute("UPDATE users SET is_blocked=? WHERE id=?",(0 if row["is_blocked"] else 1,uid))
    c.commit();c.close();return RedirectResponse("/admin",303)

@app.post("/admin/report/{rid}")
def admin_report(request:Request,rid:int,status:str=Form(...)):
    if not admin_ok(request):raise HTTPException(403,"Admin only")
    if status not in ("open","reviewed","dismissed"):raise HTTPException(400,"Invalid status")
    c=db();c.execute("UPDATE reports SET status=? WHERE id=?",(status,rid));c.commit();c.close();return RedirectResponse("/admin",303)

# ============================================================
# APIs / HEALTH
# ============================================================

@app.get("/api/me")
def api_me(request:Request):
    u=current_user(request)
    if not u:return {"logged_in":False,"user":None}
    return {"logged_in":True,"user":{k:u[k] for k in ("id","name","email","role","phone","location","bio","skills","education","experience","resume_path")}}

@app.get("/api/jobs")
def api_jobs(q:str="",country:str="",job_type:str="",category:str="",location:str=""):
    sql="SELECT * FROM jobs WHERE status='active'";p=[]
    if q:
        v="%"+q+"%";sql+=" AND (title LIKE ? OR company LIKE ? OR skills LIKE ? OR description LIKE ? OR location LIKE ?)";p += [v,v,v,v,v]
    for col,val in [("country",country),("job_type",job_type),("category",category),("location",location)]:
        if val:sql+=f" AND {col} LIKE ?";p.append("%"+val+"%")
    sql+=" ORDER BY id DESC";c=db();rows=c.execute(sql,p).fetchall();c.close()
    return {"count":len(rows),"jobs":[dict(x) for x in rows]}

@app.get("/api/notifications")
def api_notifications(request:Request):
    u=current_user(request)
    if not u:return {"notifications":[]}
    c=db();rows=c.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50",(u["id"],)).fetchall();c.close()
    return {"notifications":[dict(x) for x in rows]}

@app.post("/api/notifications/read-all")
def api_notifications_read_all(request:Request):
    u=require_user(request);c=db();c.execute("UPDATE notifications SET read=1 WHERE user_id=?",(u["id"],));c.commit();c.close();return {"ok":True}

@app.get("/health")
def health():
    c=db();c.execute("SELECT 1");c.close()
    return {"status":"ok","app":APP_NAME,"version":"3.0.0","database":"connected","ai_enabled":bool(OPENAI_API_KEY),"email_enabled":bool(SMTP_HOST),"sms_enabled":bool(TWILIO_ACCOUNT_SID)}

if __name__=="__main__":
    import uvicorn
    uvicorn.run("main:app",host="0.0.0.0",port=int(os.getenv("PORT","8000")),reload=True)
