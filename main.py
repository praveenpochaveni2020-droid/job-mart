from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from pathlib import Path
from datetime import datetime, timezone, timedelta
import sqlite3, hashlib, secrets, os, smtplib, ssl
from email.message import EmailMessage
import hmac

app = FastAPI(title="Job Mart")
DB_FILE = Path(os.getenv("DB_FILE", "job_mart.db"))
SESSION_DAYS = 30
OTP_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"

# =========================================================
# DATABASE
# =========================================================

def db():
    c = sqlite3.connect(DB_FILE, timeout=20)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def now():
    return datetime.now(timezone.utc).isoformat()

def init_db():
    c = db()
    c.executescript("""
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
    CREATE TABLE IF NOT EXISTS sessions(
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS otps(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      purpose TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      attempts INTEGER DEFAULT 0,
      used INTEGER DEFAULT 0,
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
      UNIQUE(job_id,applicant_id),
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
    """)
    c.commit(); c.close()

init_db()

# =========================================================
# SECURITY
# =========================================================

def hash_password(password):
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180000).hex()
    return f"{salt}${key}"

def verify_password(password, stored):
    try:
        salt, key = stored.split("$", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180000).hex()
        return hmac.compare_digest(check, key)
    except Exception:
        return False

def hash_token(value):
    return hashlib.sha256(value.encode()).hexdigest()

def make_otp():
    return f"{secrets.randbelow(1000000):06d}"

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

# =========================================================
# EMAIL OTP
# =========================================================

def send_email(to_email, subject, body):
    host = os.getenv("SMTP_HOST", "")
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME", "")
    password = os.getenv("SMTP_PASSWORD", "")
    sender = os.getenv("SMTP_FROM", username)

    if not host or not username or not password or not sender:
        # Development fallback: never use this as production OTP delivery.
        print(f"[JOB MART OTP - SMTP NOT CONFIGURED] {to_email}: {body}")
        return False

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    if port == 465:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as s:
            s.login(username, password)
            s.send_message(msg)
    else:
        context = ssl.create_default_context()
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls(context=context)
            s.login(username, password)
            s.send_message(msg)
    return True

def create_otp(email, purpose):
    email = email.strip().lower()
    c = db()
    recent = c.execute(
        "SELECT created_at FROM otps WHERE email=? AND purpose=? ORDER BY id DESC LIMIT 1",
        (email, purpose)
    ).fetchone()
    if recent:
        try:
            if datetime.fromisoformat(recent["created_at"]) > datetime.now(timezone.utc) - timedelta(seconds=60):
                c.close()
                raise HTTPException(429, "Please wait 60 seconds before requesting another OTP")
        except ValueError:
            pass

    otp = make_otp()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=OTP_MINUTES)).isoformat()
    c.execute("UPDATE otps SET used=1 WHERE email=? AND purpose=? AND used=0", (email, purpose))
    c.execute(
        "INSERT INTO otps(email,purpose,otp_hash,expires_at,attempts,used,created_at) VALUES(?,?,?,?,0,0,?)",
        (email, purpose, hash_otp(otp), expires, now())
    )
    c.commit(); c.close()

    subject = "Your Job Mart OTP"
    body = f"""Job Mart

Your OTP is: {otp}

This OTP expires in {OTP_MINUTES} minutes.
If you did not request this code, you can ignore this email.

Do not share your OTP with anyone."""
    sent = send_email(email, subject, body)
    return sent

def verify_otp(email, purpose, otp):
    email = email.strip().lower()
    c = db()
    row = c.execute(
        "SELECT * FROM otps WHERE email=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1",
        (email, purpose)
    ).fetchone()
    if not row:
        c.close(); raise HTTPException(400, "OTP not found. Request a new OTP.")
    if row["attempts"] >= OTP_MAX_ATTEMPTS:
        c.close(); raise HTTPException(429, "Too many OTP attempts. Request a new OTP.")
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        c.close(); raise HTTPException(400, "OTP expired. Request a new OTP.")

    if not hmac.compare_digest(row["otp_hash"], hash_otp(otp.strip())):
        c.execute("UPDATE otps SET attempts=attempts+1 WHERE id=?", (row["id"],))
        c.commit(); c.close()
        raise HTTPException(400, "Invalid OTP")

    c.execute("UPDATE otps SET used=1 WHERE id=?", (row["id"],))
    c.commit(); c.close()

# =========================================================
# AUTH
# =========================================================

def create_session(user_id, response):
    raw = secrets.token_urlsafe(48)
    c = db()
    c.execute(
        "INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
        (hash_token(raw), user_id,
         (datetime.now(timezone.utc)+timedelta(days=SESSION_DAYS)).isoformat(), now())
    )
    c.commit(); c.close()
    response.set_cookie(
        "jobmart_session", raw, max_age=SESSION_DAYS*86400,
        httponly=True, secure=COOKIE_SECURE, samesite="lax", path="/"
    )

def current_user(request):
    raw = request.cookies.get("jobmart_session")
    if not raw: return None
    c = db()
    row = c.execute("""
      SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
      WHERE s.token_hash=? AND s.expires_at>?
    """, (hash_token(raw), now())).fetchone()
    c.close()
    return row

def require_user(request):
    u = current_user(request)
    if not u: raise HTTPException(401, "Please login first")
    return u

def require_employer(request):
    u = require_user(request)
    if u["role"] not in ("employer", "admin"):
        raise HTTPException(403, "Employer account required")
    return u

# =========================================================
# MODELS
# =========================================================

class RegisterData(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str
    password: str = Field(min_length=6, max_length=128)
    role: str = "jobseeker"
    phone: str = ""
    country: str = ""
    city: str = ""

class LoginData(BaseModel):
    email: str
    password: str

class OTPRequest(BaseModel):
    email: str

class OTPLoginData(BaseModel):
    email: str
    otp: str

class ResetPasswordData(BaseModel):
    email: str
    otp: str
    new_password: str = Field(min_length=6, max_length=128)

class ChangePasswordData(BaseModel):
    current_password: str
    new_password: str = Field(min_length=6, max_length=128)

class ProfileData(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    phone: str = ""
    country: str = ""
    city: str = ""
    bio: str = ""

class JobData(BaseModel):
    title: str = Field(min_length=2, max_length=150)
    company: str = Field(min_length=2, max_length=150)
    category: str = Field(min_length=1, max_length=80)
    country: str = Field(min_length=1, max_length=80)
    location: str = ""
    job_type: str
    work_mode: str
    salary: str = ""
    description: str = Field(min_length=5, max_length=10000)
    skills: str = ""
    application_email: str = ""

class ApplicationData(BaseModel):
    cover_letter: str = ""

# =========================================================
# REGISTER / LOGIN / OTP / PASSWORD
# =========================================================

@app.post("/api/register")
def register(data: RegisterData, response: Response):
    role = data.role.lower().strip()
    if role not in ("jobseeker", "employer"): role = "jobseeker"
    email = data.email.strip().lower()
    c = db()
    if c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        c.close(); raise HTTPException(400, "Email already registered")
    cur = c.execute("""
      INSERT INTO users(name,email,password,role,phone,country,city,created_at)
      VALUES(?,?,?,?,?,?,?,?)
    """, (data.name.strip(), email, hash_password(data.password), role,
          data.phone.strip(), data.country.strip(), data.city.strip(), now()))
    uid = cur.lastrowid
    c.commit(); c.close()
    create_session(uid, response)
    return {"ok": True, "message": "Registration successful", "user_id": uid}

@app.post("/api/login")
def login(data: LoginData, response: Response):
    email = data.email.strip().lower()
    c = db(); u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone(); c.close()
    if not u or not verify_password(data.password, u["password"]):
        raise HTTPException(401, "Invalid email or password")
    create_session(u["id"], response)
    return {"ok": True, "message": "Login successful", "user": public_user(u)}

@app.post("/api/otp/request")
def request_otp(data: OTPRequest):
    email = data.email.strip().lower()
    c = db(); exists = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone(); c.close()
    if not exists: raise HTTPException(404, "No account found with this email")
    sent = create_otp(email, "login")
    return {"ok": True, "message": "OTP sent to your email" if sent else "OTP generated; configure SMTP to receive email"}

@app.post("/api/otp/login")
def otp_login(data: OTPLoginData, response: Response):
    email = data.email.strip().lower()
    verify_otp(email, "login", data.otp)
    c = db(); u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone(); c.close()
    if not u: raise HTTPException(404, "Account not found")
    create_session(u["id"], response)
    return {"ok": True, "message": "OTP login successful", "user": public_user(u)}

@app.post("/api/forgot/request")
def forgot_request(data: OTPRequest):
    email = data.email.strip().lower()
    c = db(); exists = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone(); c.close()
    # Generic response avoids revealing whether an email exists.
    if exists:
        create_otp(email, "reset")
    return {"ok": True, "message": "If the email is registered, a reset OTP has been sent"}

@app.post("/api/forgot/reset")
def forgot_reset(data: ResetPasswordData):
    email = data.email.strip().lower()
    verify_otp(email, "reset", data.otp)
    c = db()
    c.execute("UPDATE users SET password=? WHERE email=?", (hash_password(data.new_password), email))
    c.execute("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE email=?)", (email,))
    c.commit(); c.close()
    return {"ok": True, "message": "Password changed. Please login again."}

@app.post("/api/password/change")
def change_password(data: ChangePasswordData, request: Request):
    u = require_user(request)
    if not verify_password(data.current_password, u["password"]):
        raise HTTPException(400, "Current password is incorrect")
    if data.current_password == data.new_password:
        raise HTTPException(400, "New password must be different")
    c = db()
    c.execute("UPDATE users SET password=? WHERE id=?", (hash_password(data.new_password), u["id"]))
    c.commit(); c.close()
    return {"ok": True, "message": "Password changed successfully"}

@app.post("/api/logout")
def logout(request: Request, response: Response):
    raw = request.cookies.get("jobmart_session")
    if raw:
        c = db(); c.execute("DELETE FROM sessions WHERE token_hash=?", (hash_token(raw),)); c.commit(); c.close()
    response.delete_cookie("jobmart_session", path="/")
    return {"ok": True}

def public_user(u):
    return {"id":u["id"],"name":u["name"],"email":u["email"],"role":u["role"],
            "phone":u["phone"],"country":u["country"],"city":u["city"],"bio":u["bio"]}

@app.get("/api/me")
def me(request: Request):
    u = current_user(request)
    return {"logged_in": bool(u), "user": public_user(u) if u else None}

# =========================================================
# PROFILE
# =========================================================

@app.put("/api/profile")
def update_profile(data: ProfileData, request: Request):
    u = require_user(request)
    c = db()
    c.execute("UPDATE users SET name=?,phone=?,country=?,city=?,bio=? WHERE id=?",
              (data.name.strip(),data.phone.strip(),data.country.strip(),data.city.strip(),data.bio.strip(),u["id"]))
    c.commit(); c.close()
    return {"ok":True,"message":"Profile updated"}

# =========================================================
# JOBS
# =========================================================

@app.post("/api/jobs")
def create_job(data: JobData, request: Request):
    u = require_employer(request)
    c = db()
    cur = c.execute("""
      INSERT INTO jobs(employer_id,title,company,category,country,location,job_type,work_mode,
                       salary,description,skills,application_email,status,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """,(u["id"],data.title.strip(),data.company.strip(),data.category.strip(),data.country.strip(),
         data.location.strip(),data.job_type.strip(),data.work_mode.strip(),data.salary.strip(),
         data.description.strip(),data.skills.strip(),data.application_email.strip(),"active",now()))
    jid=cur.lastrowid; c.commit(); c.close()
    return {"ok":True,"message":"Job posted successfully","job_id":jid}

@app.get("/api/jobs")
def list_jobs(q:str="",category:str="",country:str="",job_type:str="",work_mode:str="",mine:bool=False,request:Request=None):
    c=db()
    sql="""SELECT j.*,u.name employer_name FROM jobs j JOIN users u ON u.id=j.employer_id WHERE 1=1"""
    p=[]
    if not mine: sql+=" AND j.status='active'"
    if q.strip():
        sql+=" AND (LOWER(j.title) LIKE ? OR LOWER(j.company) LIKE ? OR LOWER(j.description) LIKE ? OR LOWER(j.skills) LIKE ?)"
        v=f"%{q.strip().lower()}%"; p += [v,v,v,v]
    if category.strip(): sql+=" AND LOWER(j.category)=LOWER(?)"; p.append(category.strip())
    if country.strip(): sql+=" AND LOWER(j.country)=LOWER(?)"; p.append(country.strip())
    if job_type.strip(): sql+=" AND LOWER(j.job_type)=LOWER(?)"; p.append(job_type.strip())
    if work_mode.strip(): sql+=" AND LOWER(j.work_mode)=LOWER(?)"; p.append(work_mode.strip())
    if mine:
        u=require_employer(request); sql+=" AND j.employer_id=?"; p.append(u["id"])
    sql+=" ORDER BY j.id DESC"
    rows=c.execute(sql,p).fetchall(); result=[dict(x) for x in rows]; c.close()
    return {"ok":True,"jobs":result,"count":len(result)}

@app.get("/api/jobs/{job_id}")
def get_job(job_id:int,request:Request):
    c=db()
    j=c.execute("""SELECT j.*,u.name employer_name,u.email employer_email
                   FROM jobs j JOIN users u ON u.id=j.employer_id WHERE j.id=?""",(job_id,)).fetchone()
    if not j: c.close(); raise HTTPException(404,"Job not found")
    u=current_user(request); r=dict(j); r["applied"]=False; r["saved"]=False
    if u:
        r["applied"]=bool(c.execute("SELECT id FROM applications WHERE job_id=? AND applicant_id=?",(job_id,u["id"])).fetchone())
        r["saved"]=bool(c.execute("SELECT id FROM saved_jobs WHERE job_id=? AND user_id=?",(job_id,u["id"])).fetchone())
    c.close(); return {"ok":True,"job":r}

@app.delete("/api/jobs/{job_id}")
def close_job(job_id:int,request:Request):
    u=require_employer(request); c=db(); j=c.execute("SELECT * FROM jobs WHERE id=?",(job_id,)).fetchone()
    if not j: c.close(); raise HTTPException(404,"Job not found")
    if j["employer_id"]!=u["id"] and u["role"]!="admin": c.close(); raise HTTPException(403,"Not allowed")
    c.execute("UPDATE jobs SET status='closed' WHERE id=?",(job_id,)); c.commit(); c.close()
    return {"ok":True,"message":"Job closed"}

# =========================================================
# APPLICATIONS / SAVED / NOTIFICATIONS
# =========================================================

@app.post("/api/jobs/{job_id}/apply")
def apply_job(job_id:int,data:ApplicationData,request:Request):
    u=require_user(request)
    if u["role"]=="employer": raise HTTPException(403,"Employer accounts cannot apply")
    c=db(); j=c.execute("SELECT * FROM jobs WHERE id=? AND status='active'",(job_id,)).fetchone()
    if not j: c.close(); raise HTTPException(404,"Job not found")
    if c.execute("SELECT id FROM applications WHERE job_id=? AND applicant_id=?",(job_id,u["id"])).fetchone():
        c.close(); raise HTTPException(400,"Already applied")
    c.execute("INSERT INTO applications(job_id,applicant_id,cover_letter,status,created_at) VALUES(?,?,?,?,?)",
              (job_id,u["id"],data.cover_letter.strip(),"applied",now()))
    c.execute("INSERT INTO notifications(user_id,title,message,created_at) VALUES(?,?,?,?)",
              (j["employer_id"],"New job application",f"{u['name']} applied for {j['title']}",now()))
    c.commit(); c.close()
    return {"ok":True,"message":"Application submitted"}

@app.get("/api/applications")
def applications(request:Request):
    u=require_user(request); c=db()
    if u["role"] in ("employer","admin"):
        rows=c.execute("""SELECT a.*,j.title,j.company,j.country,j.location,u.name applicant_name,
                          u.email applicant_email,u.phone applicant_phone
                          FROM applications a JOIN jobs j ON j.id=a.job_id JOIN users u ON u.id=a.applicant_id
                          WHERE j.employer_id=? ORDER BY a.id DESC""",(u["id"],)).fetchall()
    else:
        rows=c.execute("""SELECT a.*,j.title,j.company,j.country,j.location
                          FROM applications a JOIN jobs j ON j.id=a.job_id
                          WHERE a.applicant_id=? ORDER BY a.id DESC""",(u["id"],)).fetchall()
    r=[dict(x) for x in rows]; c.close(); return {"ok":True,"applications":r}

@app.post("/api/jobs/{job_id}/save")
def save_job(job_id:int,request:Request):
    u=require_user(request); c=db()
    if not c.execute("SELECT id FROM jobs WHERE id=?",(job_id,)).fetchone():
        c.close(); raise HTTPException(404,"Job not found")
    old=c.execute("SELECT id FROM saved_jobs WHERE job_id=? AND user_id=?",(job_id,u["id"])).fetchone()
    if old:
        c.execute("DELETE FROM saved_jobs WHERE id=?",(old["id"],)); msg="Removed from saved jobs"
    else:
        c.execute("INSERT INTO saved_jobs(job_id,user_id,created_at) VALUES(?,?,?)",(job_id,u["id"],now())); msg="Job saved"
    c.commit(); c.close(); return {"ok":True,"message":msg}

@app.get("/api/saved-jobs")
def saved_jobs(request:Request):
    u=require_user(request); c=db()
    rows=c.execute("""SELECT j.*,s.created_at saved_at FROM saved_jobs s JOIN jobs j ON j.id=s.job_id
                      WHERE s.user_id=? ORDER BY s.id DESC""",(u["id"],)).fetchall()
    r=[dict(x) for x in rows]; c.close(); return {"ok":True,"jobs":r}

@app.get("/api/notifications")
def notifications(request:Request):
    u=require_user(request); c=db()
    rows=c.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC",(u["id"],)).fetchall()
    r=[dict(x) for x in rows]; c.close(); return {"ok":True,"notifications":r}

@app.post("/api/notifications/read")
def notifications_read(request:Request):
    u=require_user(request); c=db(); c.execute("UPDATE notifications SET is_read=1 WHERE user_id=?",(u["id"],))
    c.commit(); c.close(); return {"ok":True}

@app.get("/api/dashboard")
def dashboard(request:Request):
    u=require_user(request); c=db()
    if u["role"] in ("employer","admin"):
        a=c.execute("SELECT COUNT(*) c FROM applications a JOIN jobs j ON j.id=a.job_id WHERE j.employer_id=?",(u["id"],)).fetchone()["c"]
        total=c.execute("SELECT COUNT(*) c FROM jobs WHERE employer_id=?",(u["id"],)).fetchone()["c"]
        active=c.execute("SELECT COUNT(*) c FROM jobs WHERE employer_id=? AND status='active'",(u["id"],)).fetchone()["c"]
        r={"role":"employer","jobs_posted":total,"active_jobs":active,"applications":a}
    else:
        a=c.execute("SELECT COUNT(*) c FROM applications WHERE applicant_id=?",(u["id"],)).fetchone()["c"]
        s=c.execute("SELECT COUNT(*) c FROM saved_jobs WHERE user_id=?",(u["id"],)).fetchone()["c"]
        r={"role":"jobseeker","applications":a,"saved_jobs":s}
    c.close(); return {"ok":True,"dashboard":r}

# =========================================================
# FRONTEND
# =========================================================

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Job Mart</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#f1f3f6;color:#17202a}
button,input,select,textarea{font:inherit}button{cursor:pointer;border:0}
.header{background:#2874f0;color:#fff;position:sticky;top:0;z-index:100;box-shadow:0 2px 8px #0003}
.head{max-width:1250px;margin:auto;display:flex;align-items:center;gap:12px;padding:8px 15px;min-height:62px;flex-wrap:wrap}
.menu{background:none;color:white;font-size:25px}.logo{font-weight:bold;font-size:23px;white-space:nowrap}.logo small{display:block;font-size:9px;color:#ffe500;text-align:center}
.search{display:flex;flex:1;max-width:700px}.search input{flex:1;border:0;padding:12px;outline:0}.search button{width:52px;background:white;color:#2874f0}
.loginBtn{background:#fff;color:#2874f0;font-weight:bold;padding:10px 24px;border-radius:3px}
.user{display:none;font-weight:bold}.wrap{max-width:1250px;margin:auto;padding:16px}.hidden{display:none!important}
.hero,.card,.form,.detail,.section{background:#fff;border-radius:4px;box-shadow:0 1px 4px #0002}.hero{padding:25px;margin-bottom:15px}.hero h1{margin:0 0 8px}
.heroSearch{display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:9px;margin-top:18px}
input,select,textarea{width:100%;padding:12px;border:1px solid #d4d8dd;border-radius:3px;background:#fff}textarea{min-height:120px;resize:vertical}
.primary{background:#2874f0;color:white;padding:11px 18px;border-radius:3px;font-weight:bold}.outline{background:white;color:#2874f0;border:1px solid #2874f0;padding:10px 15px;border-radius:3px}.danger{background:#e53935;color:#fff;padding:10px 15px;border-radius:3px}
.categories{display:flex;gap:8px;overflow:auto;background:white;padding:15px;margin-bottom:15px}.cat{min-width:105px;text-align:center;padding:10px;cursor:pointer}.cat i{font-style:normal;font-size:28px;display:block}.cat b{font-size:12px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card{padding:16px}.card h3{margin:0 0 7px}.meta{font-size:13px;color:#667085;line-height:1.8}.badge{display:inline-block;background:#eef4ff;color:#2874f0;padding:4px 7px;margin:3px;border-radius:3px;font-size:11px}.salary{font-weight:bold;margin:10px 0}.actions{display:flex;gap:8px;margin-top:13px}.actions>*{flex:1}
.form{max-width:700px;margin:20px auto;padding:25px}.form h2{margin-top:0}.group{margin-bottom:13px}.group label{font-weight:bold;display:block;margin-bottom:6px;font-size:14px}
.side{position:fixed;left:-315px;top:0;bottom:0;width:300px;background:white;z-index:200;transition:.25s;box-shadow:4px 0 16px #0003;overflow:auto}.side.open{left:0}.shade{display:none;position:fixed;inset:0;background:#0006;z-index:150}.shade.show{display:block}.sideHead{background:#2874f0;color:#fff;padding:24px}.sideItem{padding:15px 20px;border-bottom:1px solid #eee;cursor:pointer}.sideItem:hover{background:#f2f6ff;color:#2874f0}
.table{overflow:auto;background:#fff;box-shadow:0 1px 4px #0002}.table table{width:100%;border-collapse:collapse}.table th,.table td{padding:12px;border-bottom:1px solid #eee;text-align:left;font-size:13px}.table th{background:#fafafa}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.stat{background:white;padding:22px;box-shadow:0 1px 4px #0002}.num{font-size:30px;color:#2874f0;font-weight:bold}
.msg{margin-top:10px;font-weight:bold}.ok{color:#16833a}.err{color:#d32f2f}.empty{background:white;padding:40px;text-align:center;color:#777}
.tabs{display:flex;gap:7px;margin-bottom:12px}.tabs button{padding:10px 14px;background:#fff;border:1px solid #ddd;border-radius:3px}.tabs button.active{background:#2874f0;color:white}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}.heroSearch{grid-template-columns:1fr 1fr}}
@media(max-width:600px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:1fr}.heroSearch{grid-template-columns:1fr}.logo{font-size:19px}.head{gap:8px}.search{order:5;flex-basis:100%;max-width:none}.loginBtn{padding:9px 14px}}
</style>
</head>
<body>

<div id="shade" class="shade" onclick="closeMenu()"></div>
<aside id="side" class="side">
  <div class="sideHead"><h2 style="margin:0">Job Mart</h2><div id="sideUser">Please Login</div></div>
  <div class="sideItem" onclick="go('home')">🏠 Home</div>
  <div class="sideItem" onclick="go('jobs')">💼 All Jobs</div>
  <div class="sideItem" onclick="go('categories')">📂 Categories</div>
  <div class="sideItem" onclick="go('saved')">❤️ Saved Jobs</div>
  <div class="sideItem" onclick="go('applications')">📋 Applications</div>
  <div class="sideItem" onclick="go('notifications')">🔔 Notifications</div>
  <div class="sideItem" onclick="go('dashboard')">📊 Dashboard</div>
  <div class="sideItem" onclick="go('profile')">👤 My Profile</div>
  <div class="sideItem" onclick="go('password')">🔑 Change Password</div>
  <div id="employerMenu">
    <div class="sideItem" onclick="go('post')">➕ Post a Job</div>
    <div class="sideItem" onclick="go('myjobs')">💼 My Jobs</div>
  </div>
  <div class="sideItem" onclick="logout()">🚪 Logout</div>
</aside>

<header class="header">
<div class="head">
  <button class="menu" onclick="toggleMenu()">☰</button>
  <div class="logo">Job Mart<small>Find • Apply • Grow</small></div>
  <div class="search"><input id="globalSearch" placeholder="Search jobs, companies, skills..." onkeydown="if(event.key==='Enter')searchGlobal()"><button onclick="searchGlobal()">🔍</button></div>
  <button id="loginBtn" class="loginBtn" onclick="go('login')">Login</button>
  <div id="userBox" class="user">👤 <span id="userName"></span></div>
</div>
</header>

<main class="wrap">

<section id="home" class="page">
  <div class="hero">
    <h1>Find your next opportunity</h1>
    <p>Search jobs from employers and apply from your phone.</p>
    <div class="heroSearch">
      <input id="homeQ" placeholder="Job title, company, skills">
      <select id="homeCountry"><option value="">All Countries</option><option>India</option><option>USA</option><option>UAE</option><option>Other</option></select>
      <select id="homeType"><option value="">All Job Types</option><option>Full-time</option><option>Part-time</option><option>Contract</option><option>Freelance</option></select>
      <button class="primary" onclick="homeSearch()">Search</button>
    </div>
  </div>
  <div class="categories">
    <div class="cat" onclick="catSearch('IT')"><i>💻</i><b>IT</b></div>
    <div class="cat" onclick="catSearch('Sales')"><i>📈</i><b>Sales</b></div>
    <div class="cat" onclick="catSearch('Marketing')"><i>📣</i><b>Marketing</b></div>
    <div class="cat" onclick="catSearch('Finance')"><i>💰</i><b>Finance</b></div>
    <div class="cat" onclick="catSearch('Teaching')"><i>📚</i><b>Teaching</b></div>
    <div class="cat" onclick="catSearch('Healthcare')"><i>🏥</i><b>Healthcare</b></div>
    <div class="cat" onclick="catSearch('Driver')"><i>🚗</i><b>Driver</b></div>
  </div>
  <div class="section" style="padding:17px;margin-bottom:1px"><h2 style="margin:0">Latest Jobs</h2></div>
  <div id="homeJobs"></div>
</section>

<section id="jobs" class="page hidden">
  <div class="hero">
    <h2>All Jobs</h2>
    <div class="heroSearch">
      <input id="jobQ" placeholder="Search jobs">
      <select id="jobCountry"><option value="">All Countries</option><option>India</option><option>USA</option><option>UAE</option><option>Other</option></select>
      <select id="jobType"><option value="">All Types</option><option>Full-time</option><option>Part-time</option><option>Contract</option><option>Freelance</option></select>
      <button class="primary" onclick="loadJobs()">Search</button>
    </div>
  </div>
  <div id="jobsList"></div>
</section>

<section id="login" class="page hidden">
  <div class="form">
    <h2>Welcome Back 👋</h2>
    <div class="tabs"><button id="passTab" class="active" onclick="loginMode('password')">Password</button><button id="otpTab" onclick="loginMode('otp')">OTP Login</button></div>
    <div id="passwordLogin">
      <div class="group"><label>Email</label><input id="loginEmail" type="email"></div>
      <div class="group"><label>Password</label><input id="loginPassword" type="password"></div>
      <button class="primary" onclick="login()">Login</button>
      <button class="outline" onclick="go('forgot')">Forgot Password?</button>
    </div>
    <div id="otpLogin" class="hidden">
      <div class="group"><label>Email</label><input id="otpEmail" type="email"></div>
      <button class="outline" onclick="requestLoginOtp()">Send OTP</button>
      <div class="group"><label>6-digit OTP</label><input id="otpCode" inputmode="numeric" maxlength="6"></div>
      <button class="primary" onclick="otpLogin()">Login with OTP</button>
    </div>
    <br><button class="outline" onclick="go('register')">Create Account</button>
    <div id="loginMsg" class="msg"></div>
  </div>
</section>

<section id="register" class="page hidden">
  <div class="form">
    <h2>Create Account</h2>
    <div class="group"><label>Name</label><input id="regName"></div>
    <div class="group"><label>Email</label><input id="regEmail" type="email"></div>
    <div class="group"><label>Password</label><input id="regPassword" type="password" minlength="6"></div>
    <div class="group"><label>Account Type</label><select id="regRole"><option value="jobseeker">Job Seeker</option><option value="employer">Employer</option></select></div>
    <div class="group"><label>Phone</label><input id="regPhone"></div>
    <div class="group"><label>Country</label><input id="regCountry" value="India"></div>
    <div class="group"><label>City</label><input id="regCity"></div>
    <button class="primary" onclick="register()">Register</button>
    <button class="outline" onclick="go('login')">Login</button>
    <div id="regMsg" class="msg"></div>
  </div>
</section>

<section id="forgot" class="page hidden">
  <div class="form">
    <h2>Forgot Password 🔑</h2>
    <p>Enter your registered email and request an OTP.</p>
    <div class="group"><label>Email</label><input id="forgotEmail" type="email"></div>
    <button class="outline" onclick="forgotOtp()">Send Reset OTP</button>
    <div class="group"><label>OTP</label><input id="forgotOtpCode" maxlength="6" inputmode="numeric"></div>
    <div class="group"><label>New Password</label><input id="newPassword" type="password"></div>
    <button class="primary" onclick="resetPassword()">Change Password</button>
    <button class="outline" onclick="go('login')">Back to Login</button>
    <div id="forgotMsg" class="msg"></div>
  </div>
</section>

<section id="password" class="page hidden">
  <div class="form">
    <h2>Change Password</h2>
    <div class="group"><label>Current Password</label><input id="currentPassword" type="password"></div>
    <div class="group"><label>New Password</label><input id="changePassword" type="password"></div>
    <button class="primary" onclick="changePassword()">Change Password</button>
    <div id="passwordMsg" class="msg"></div>
  </div>
</section>

<section id="jobdetail" class="page hidden"><div id="jobDetail"></div></section>
<section id="saved" class="page hidden"><div class="hero"><h2>❤️ Saved Jobs</h2></div><div id="savedList"></div></section>
<section id="applications" class="page hidden"><div class="hero"><h2>📋 Applications</h2></div><div id="applicationList"></div></section>
<section id="notifications" class="page hidden"><div class="hero"><h2>🔔 Notifications</h2><button class="outline" onclick="readNotifications()">Mark All Read</button></div><div id="notificationList"></div></section>

<section id="profile" class="page hidden">
<div class="form">
<h2>👤 My Profile</h2>
<div class="group"><label>Name</label><input id="pName"></div>
<div class="group"><label>Phone</label><input id="pPhone"></div>
<div class="group"><label>Country</label><input id="pCountry"></div>
<div class="group"><label>City</label><input id="pCity"></div>
<div class="group"><label>Bio</label><textarea id="pBio"></textarea></div>
<button class="primary" onclick="saveProfile()">Save Profile</button><div id="profileMsg" class="msg"></div>
</div>
</section>

<section id="post" class="page hidden">
<div class="form">
<h2>➕ Post a Job</h2>
<div class="group"><label>Job Title</label><input id="jTitle"></div>
<div class="group"><label>Company</label><input id="jCompany"></div>
<div class="group"><label>Category</label><input id="jCategory" placeholder="IT"></div>
<div class="group"><label>Country</label><input id="jCountry" value="India"></div>
<div class="group"><label>Location</label><input id="jLocation" placeholder="Hyderabad"></div>
<div class="group"><label>Job Type</label><select id="jType"><option>Full-time</option><option>Part-time</option><option>Contract</option><option>Freelance</option></select></div>
<div class="group"><label>Work Mode</label><select id="jMode"><option>Remote</option><option>Hybrid</option><option>Office</option></select></div>
<div class="group"><label>Salary</label><input id="jSalary" placeholder="₹6-10 LPA"></div>
<div class="group"><label>Skills</label><input id="jSkills" placeholder="Python, SQL, FastAPI"></div>
<div class="group"><label>Application Email</label><input id="jEmail" type="email"></div>
<div class="group"><label>Description</label><textarea id="jDescription"></textarea></div>
<button class="primary" onclick="postJob()">Post Job</button><div id="postMsg" class="msg"></div>
</div>
</section>

<section id="myjobs" class="page hidden"><div class="hero"><h2>💼 My Jobs</h2></div><div id="myJobs"></div></section>
<section id="dashboard" class="page hidden"><div class="hero"><h2>📊 Dashboard</h2></div><div id="dash"></div></section>

<section id="categories" class="page hidden">
<div class="hero"><h2>📂 Categories</h2><div class="grid">
<div class="card" onclick="catSearch('IT')">💻 IT & Software</div><div class="card" onclick="catSearch('Sales')">📈 Sales</div>
<div class="card" onclick="catSearch('Marketing')">📣 Marketing</div><div class="card" onclick="catSearch('Finance')">💰 Finance</div>
<div class="card" onclick="catSearch('Teaching')">📚 Teaching</div><div class="card" onclick="catSearch('Healthcare')">🏥 Healthcare</div>
<div class="card" onclick="catSearch('Driver')">🚗 Driver</div><div class="card" onclick="catSearch('Other')">📦 Other Jobs</div>
</div></div>
</section>

</main>

<script>
let ME=null;

async function api(url,opt={}){
  const r=await fetch(url,{credentials:"same-origin",...opt,headers:{"Content-Type":"application/json",...(opt.headers||{})}});
  let d={}; try{d=await r.json()}catch(e){}
  if(!r.ok)throw new Error(d.detail||"Something went wrong");
  return d;
}
function esc(v){return String(v??"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;")}
function toggleMenu(){document.getElementById("side").classList.toggle("open");document.getElementById("shade").classList.toggle("show")}
function closeMenu(){document.getElementById("side").classList.remove("open");document.getElementById("shade").classList.remove("show")}
function go(p){
  if(["saved","applications","notifications","profile","password","post","myjobs","dashboard"].includes(p)&&!ME){closeMenu();return showPage("login")}
  closeMenu();showPage(p)
}
function showPage(p){
  document.querySelectorAll(".page").forEach(x=>x.classList.add("hidden"));
  document.getElementById(p)?.classList.remove("hidden");window.scrollTo(0,0);
  if(p==="home")loadHome(); if(p==="jobs")loadJobs(); if(p==="saved")loadSaved();
  if(p==="applications")loadApplications(); if(p==="notifications")loadNotifications();
  if(p==="profile")loadProfile(); if(p==="myjobs")loadMyJobs(); if(p==="dashboard")loadDashboard();
}
function authUI(){
  document.getElementById("loginBtn").style.display=ME?"none":"block";
  document.getElementById("userBox").style.display=ME?"flex":"none";
  document.getElementById("userName").textContent=ME?.name||"";
  document.getElementById("sideUser").textContent=ME?`Hello, ${ME.name}`:"Please Login";
  document.getElementById("employerMenu").style.display=ME&&(ME.role==="employer"||ME.role==="admin")?"block":"none";
}
async function checkMe(){try{const d=await api("/api/me");ME=d.user;authUI()}catch(e){ME=null;authUI()}}
async function register(){
  msg("regMsg","Creating account...","");
  try{await api("/api/register",{method:"POST",body:JSON.stringify({
    name:regName.value,email:regEmail.value,password:regPassword.value,role:regRole.value,
    phone:regPhone.value,country:regCountry.value,city:regCity.value})});
    await checkMe();msg("regMsg","Account created and logged in.","ok");setTimeout(()=>showPage("home"),500)
  }catch(e){msg("regMsg",e.message,"err")}
}
async function login(){
  try{const d=await api("/api/login",{method:"POST",body:JSON.stringify({email:loginEmail.value,password:loginPassword.value})});
  ME=d.user;authUI();msg("loginMsg","Login successful.","ok");setTimeout(()=>showPage("home"),400)}catch(e){msg("loginMsg",e.message,"err")}
}
function loginMode(mode){
  document.getElementById("passwordLogin").classList.toggle("hidden",mode!=="password");
  document.getElementById("otpLogin").classList.toggle("hidden",mode!=="otp");
  passTab.classList.toggle("active",mode==="password");otpTab.classList.toggle("active",mode==="otp");
}
async function requestLoginOtp(){
  try{const d=await api("/api/otp/request",{method:"POST",body:JSON.stringify({email:otpEmail.value})});alert(d.message)}catch(e){alert(e.message)}
}
async function otpLogin(){
  try{const d=await api("/api/otp/login",{method:"POST",body:JSON.stringify({email:otpEmail.value,otp:otpCode.value})});
  ME=d.user;authUI();showPage("home")}catch(e){msg("loginMsg",e.message,"err")}
}
async function forgotOtp(){
  try{const d=await api("/api/forgot/request",{method:"POST",body:JSON.stringify({email:forgotEmail.value})});msg("forgotMsg",d.message,"ok")}catch(e){msg("forgotMsg",e.message,"err")}
}
async function resetPassword(){
  try{const d=await api("/api/forgot/reset",{method:"POST",body:JSON.stringify({
    email:forgotEmail.value,otp:forgotOtpCode.value,new_password:newPassword.value})});
    msg("forgotMsg",d.message,"ok");setTimeout(()=>showPage("login"),700)
  }catch(e){msg("forgotMsg",e.message,"err")}
}
async function changePassword(){
  try{const d=await api("/api/password/change",{method:"POST",body:JSON.stringify({current_password:currentPassword.value,new_password:changePassword.value})});
  msg("passwordMsg",d.message,"ok");currentPassword.value="";changePassword.value=""}catch(e){msg("passwordMsg",e.message,"err")}
}
async function logout(){try{await api("/api/logout",{method:"POST"})}catch(e){}ME=null;authUI();showPage("home")}
function card(j){
  return `<div class="card"><h3>${esc(j.title)}</h3><b>${esc(j.company)}</b>
  <div class="meta">📍 ${esc(j.location||j.country)}<br>💼 ${esc(j.job_type)}<br>🏠 ${esc(j.work_mode)}</div>
  <div class="salary">${esc(j.salary||"Salary not disclosed")}</div>
  <span class="badge">${esc(j.category)}</span><span class="badge">${esc(j.country)}</span>
  <div class="actions"><button class="primary" onclick="viewJob(${j.id})">View Job</button>${ME?`<button class="outline" onclick="saveJob(${j.id})">❤️</button>`:""}</div></div>`
}
async function loadHome(){
  try{const d=await api("/api/jobs");homeJobs.innerHTML=d.jobs.length?`<div class="grid">${d.jobs.slice(0,8).map(card).join("")}</div>`:`<div class="empty">No jobs available yet.</div>`}
  catch(e){homeJobs.innerHTML=`<div class="empty">${esc(e.message)}</div>`}
}
function homeSearch(){jobQ.value=homeQ.value;jobCountry.value=homeCountry.value;jobType.value=homeType.value;showPage("jobs");loadJobs()}
function searchGlobal(){jobQ.value=globalSearch.value;showPage("jobs");loadJobs()}
function catSearch(c){showPage("jobs");loadJobs(c)}
async function loadJobs(category=""){
  try{let u=`/api/jobs?q=${encodeURIComponent(jobQ.value)}&country=${encodeURIComponent(jobCountry.value)}&job_type=${encodeURIComponent(jobType.value)}`;
  if(category)u+=`&category=${encodeURIComponent(category)}`;
  const d=await api(u);jobsList.innerHTML=d.jobs.length?`<div class="grid">${d.jobs.map(card).join("")}</div>`:`<div class="empty">No jobs found.</div>`
  }catch(e){jobsList.innerHTML=`<div class="empty">${esc(e.message)}</div>`}
}
async function viewJob(id){
  showPage("jobdetail");jobDetail.innerHTML=`<div class="empty">Loading...</div>`;
  try{const d=await api("/api/jobs/"+id),j=d.job;
  jobDetail.innerHTML=`<div class="detail"><h1>${esc(j.title)}</h1><h3>${esc(j.company)}</h3>
  <div class="meta">📍 ${esc(j.location||j.country)}<br>💼 ${esc(j.job_type)}<br>🏠 ${esc(j.work_mode)}<br>💰 ${esc(j.salary||"Not disclosed")}<br>👤 ${esc(j.employer_name)}</div>
  <hr><h3>Description</h3><p>${esc(j.description)}</p><h3>Skills</h3><p>${esc(j.skills||"Not specified")}</p>
  <div class="actions">${ME&&ME.role==="jobseeker"?`<button class="primary" onclick="applyJob(${j.id})">${j.applied?"Already Applied":"Apply Now"}</button>`:""}
  ${ME?`<button class="outline" onclick="saveJob(${j.id})">❤️ ${j.saved?"Saved":"Save Job"}</button>`:`<button class="primary" onclick="go('login')">Login to Apply</button>`}</div></div>`
  }catch(e){jobDetail.innerHTML=`<div class="empty">${esc(e.message)}</div>`}
}
async function applyJob(id){
  const cover=prompt("Cover letter:","I am interested in this position.");
  if(cover===null)return;
  try{const d=await api(`/api/jobs/${id}/apply`,{method:"POST",body:JSON.stringify({cover_letter:cover})});alert(d.message);viewJob(id)}catch(e){alert(e.message)}
}
async function saveJob(id){if(!ME)return go("login");try{const d=await api(`/api/jobs/${id}/save`,{method:"POST"});alert(d.message)}catch(e){alert(e.message)}}
async function loadSaved(){try{const d=await api("/api/saved-jobs");savedList.innerHTML=d.jobs.length?`<div class="grid">${d.jobs.map(card).join("")}</div>`:`<div class="empty">No saved jobs.</div>`}catch(e){savedList.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}
async function loadApplications(){
  try{const d=await api("/api/applications");const l=d.applications;
  if(!l.length)return applicationList.innerHTML=`<div class="empty">No applications yet.</div>`;
  if(ME.role==="employer"||ME.role==="admin")applicationList.innerHTML=`<div class="table"><table><tr><th>Job</th><th>Applicant</th><th>Email</th><th>Phone</th><th>Status</th></tr>${l.map(a=>`<tr><td>${esc(a.title)}</td><td>${esc(a.applicant_name)}</td><td>${esc(a.applicant_email)}</td><td>${esc(a.applicant_phone||"-")}</td><td>${esc(a.status)}</td></tr>`).join("")}</table></div>`;
  else applicationList.innerHTML=`<div class="table"><table><tr><th>Job</th><th>Company</th><th>Location</th><th>Status</th></tr>${l.map(a=>`<tr><td>${esc(a.title)}</td><td>${esc(a.company)}</td><td>${esc(a.location||a.country)}</td><td>${esc(a.status)}</td></tr>`).join("")}</table></div>`
  }catch(e){applicationList.innerHTML=`<div class="empty">${esc(e.message)}</div>`}
}
async function loadNotifications(){try{const d=await api("/api/notifications");notificationList.innerHTML=d.notifications.length?`<div class="grid">${d.notifications.map(n=>`<div class="card"><h3>${esc(n.title)}</h3><p>${esc(n.message)}</p><div class="meta">${esc(n.created_at)}</div></div>`).join("")}</div>`:`<div class="empty">No notifications.</div>`}catch(e){notificationList.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}
async function readNotifications(){try{await api("/api/notifications/read",{method:"POST"});loadNotifications()}catch(e){alert(e.message)}}
function loadProfile(){if(!ME)return go("login");pName.value=ME.name||"";pPhone.value=ME.phone||"";pCountry.value=ME.country||"";pCity.value=ME.city||"";pBio.value=ME.bio||""}
async function saveProfile(){try{await api("/api/profile",{method:"PUT",body:JSON.stringify({name:pName.value,phone:pPhone.value,country:pCountry.value,city:pCity.value,bio:pBio.value})});await checkMe();msg("profileMsg","Profile updated.","ok")}catch(e){msg("profileMsg",e.message,"err")}}
async function postJob(){
  try{const d=await api("/api/jobs",{method:"POST",body:JSON.stringify({
    title:jTitle.value,company:jCompany.value,category:jCategory.value,country:jCountry.value,location:jLocation.value,
    job_type:jType.value,work_mode:jMode.value,salary:jSalary.value,skills:jSkills.value,application_email:jEmail.value,description:jDescription.value})});
  msg("postMsg",d.message,"ok");document.querySelectorAll("#post input,#post textarea").forEach(x=>x.value="");setTimeout(()=>showPage("myjobs"),600)
  }catch(e){msg("postMsg",e.message,"err")}
}
async function loadMyJobs(){try{const d=await api("/api/jobs?mine=true");myJobs.innerHTML=d.jobs.length?`<div class="grid">${d.jobs.map(j=>`<div class="card"><h3>${esc(j.title)}</h3><b>${esc(j.company)}</b><div class="meta">${esc(j.location)}<br>Status: ${esc(j.status)}</div><div class="actions"><button class="primary" onclick="viewJob(${j.id})">View</button>${j.status==="active"?`<button class="danger" onclick="closeJob(${j.id})">Close</button>`:""}</div></div>`).join("")}</div>`:`<div class="empty">No jobs posted.</div>`}catch(e){myJobs.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}
async function closeJob(id){if(!confirm("Close this job?"))return;try{const d=await api("/api/jobs/"+id,{method:"DELETE"});alert(d.message);loadMyJobs()}catch(e){alert(e.message)}}
async function loadDashboard(){try{const d=await api("/api/dashboard"),x=d.dashboard;dash.innerHTML=x.role==="employer"?`<div class="stats"><div class="stat">Total Jobs<div class="num">${x.jobs_posted}</div></div><div class="stat">Active Jobs<div class="num">${x.active_jobs}</div></div><div class="stat">Applications<div class="num">${x.applications}</div></div></div>`:`<div class="stats"><div class="stat">Applications<div class="num">${x.applications}</div></div><div class="stat">Saved Jobs<div class="num">${x.saved_jobs}</div></div></div>`}catch(e){dash.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}
function msg(id,text,type){const x=document.getElementById(id);x.textContent=text;x.className="msg "+type}
checkMe().then(loadHome)
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML

@app.on_event("startup")
def cleanup():
    c=db()
    c.execute("DELETE FROM sessions WHERE expires_at<=?", (now(),))
    c.execute("DELETE FROM otps WHERE expires_at<=? OR used=1", (now(),))
    c.commit(); c.close()

# Run:
# uvicorn main:app --host 0.0.0.0 --port 8000
