
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import sqlite3
import hashlib
import secrets
from pathlib import Path

app = FastAPI(title="Job Mart")

DB = Path("jobmart.db")
SESSIONS = {}

# ================= DATABASE =================

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()

    con.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'candidate',
        phone TEXT DEFAULT '',
        location TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        company TEXT NOT NULL,
        location TEXT NOT NULL,
        salary TEXT DEFAULT '',
        job_type TEXT DEFAULT 'Full Time',
        description TEXT DEFAULT '',
        skills TEXT DEFAULT '',
        employer_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS applications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER,
        user_id INTEGER,
        status TEXT DEFAULT 'Applied',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(job_id,user_id)
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS saved_jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER,
        user_id INTEGER,
        UNIQUE(job_id,user_id)
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS services(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        provider TEXT,
        location TEXT
    )
    """)

    # Demo jobs
    count = con.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]

    if count == 0:
        jobs = [
            (
                "Software Developer",
                "Job Mart Technologies",
                "Hyderabad",
                "₹4L - ₹8L",
                "Full Time",
                "Build and maintain modern web applications.",
                "Python, FastAPI, JavaScript",
                None
            ),
            (
                "Sales Executive",
                "Local Business Group",
                "Warangal",
                "₹18,000 - ₹30,000",
                "Full Time",
                "Customer handling and sales activities.",
                "Sales, Communication",
                None
            ),
            (
                "Delivery Partner",
                "Quick Services",
                "Hyderabad",
                "₹20,000 - ₹35,000",
                "Part Time",
                "Local delivery and customer support.",
                "Driving, Smartphone",
                None
            )
        ]

        con.executemany("""
        INSERT INTO jobs
        (title,company,location,salary,job_type,description,skills,employer_id)
        VALUES(?,?,?,?,?,?,?,?)
        """, jobs)

    service_count = con.execute(
        "SELECT COUNT(*) FROM services"
    ).fetchone()[0]

    if service_count == 0:
        services = [
            ("Electrician", "Electrical repair and installation", "Local Electrician", "Hyderabad"),
            ("Plumber", "Home plumbing services", "Local Plumber", "Warangal"),
            ("AC Service", "AC repair and maintenance", "AC Service Team", "Hyderabad"),
            ("Driver", "Personal and commercial driving", "Local Drivers", "Telangana")
        ]

        con.executemany("""
        INSERT INTO services(title,description,provider,location)
        VALUES(?,?,?,?)
        """, services)

    con.commit()
    con.close()

def password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

init_db()

# ================= HELPERS =================

def current_user(request):
    token = request.headers.get("X-Session")
    if not token:
        return None

    user_id = SESSIONS.get(token)

    if not user_id:
        return None

    con = db()
    user = con.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,)
    ).fetchone()
    con.close()

    return dict(user) if user else None

# ================= API =================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": "Job Mart"
    }

@app.post("/api/register")
async def register(request: Request):
    data = await request.json()

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    role = data.get("role", "candidate")

    if not name or not email or not password:
        return JSONResponse(
            {"ok": False, "message": "All fields are required"},
            status_code=400
        )

    if len(password) < 6:
        return JSONResponse(
            {"ok": False, "message": "Password must be at least 6 characters"},
            status_code=400
        )

    if role not in ("candidate", "employer"):
        role = "candidate"

    con = db()

    try:
        cur = con.execute("""
        INSERT INTO users(name,email,password,role)
        VALUES(?,?,?,?)
        """, (
            name,
            email,
            password_hash(password),
            role
        ))

        user_id = cur.lastrowid
        con.commit()

    except sqlite3.IntegrityError:
        con.close()
        return JSONResponse(
            {"ok": False, "message": "Email already registered"},
            status_code=400
        )

    con.close()

    token = secrets.token_urlsafe(32)
    SESSIONS[token] = user_id

    return {
        "ok": True,
        "token": token,
        "message": "Registration successful"
    }

@app.post("/api/login")
async def login(request: Request):
    data = await request.json()

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    con = db()

    user = con.execute("""
    SELECT * FROM users
    WHERE email=? AND password=?
    """, (
        email,
        password_hash(password)
    )).fetchone()

    con.close()

    if not user:
        return JSONResponse(
            {"ok": False, "message": "Invalid email or password"},
            status_code=401
        )

    token = secrets.token_urlsafe(32)
    SESSIONS[token] = user["id"]

    return {
        "ok": True,
        "token": token,
        "user": dict(user)
    }

@app.post("/api/logout")
def logout(request: Request):
    token = request.headers.get("X-Session")

    if token:
        SESSIONS.pop(token, None)

    return {"ok": True}

@app.get("/api/me")
def me(request: Request):
    user = current_user(request)

    if not user:
        return {"ok": False}

    return {
        "ok": True,
        "user": user
    }

@app.get("/api/jobs")
def jobs(search: str = "", location: str = ""):
    con = db()

    sql = """
    SELECT
        jobs.*,
        users.name AS employer_name
    FROM jobs
    LEFT JOIN users
        ON jobs.employer_id = users.id
    WHERE 1=1
    """

    params = []

    if search:
        sql += """
        AND (
            jobs.title LIKE ?
            OR jobs.company LIKE ?
            OR jobs.skills LIKE ?
        )
        """
        s = f"%{search}%"
        params.extend([s, s, s])

    if location:
        sql += " AND jobs.location LIKE ?"
        params.append(f"%{location}%")

    sql += " ORDER BY jobs.id DESC"

    rows = con.execute(sql, params).fetchall()
    con.close()

    return {
        "ok": True,
        "jobs": [dict(x) for x in rows]
    }

@app.post("/api/jobs")
async def create_job(request: Request):
    user = current_user(request)

    if not user:
        return JSONResponse(
            {"ok": False, "message": "Please login"},
            status_code=401
        )

    if user["role"] != "employer":
        return JSONResponse(
            {"ok": False, "message": "Employer account required"},
            status_code=403
        )

    data = await request.json()

    title = data.get("title", "").strip()
    company = data.get("company", "").strip()
    location = data.get("location", "").strip()

    if not title or not company or not location:
        return JSONResponse(
            {"ok": False, "message": "Title, company and location required"},
            status_code=400
        )

    con = db()

    con.execute("""
    INSERT INTO jobs
    (title,company,location,salary,job_type,description,skills,employer_id)
    VALUES(?,?,?,?,?,?,?,?)
    """, (
        title,
        company,
        location,
        data.get("salary", ""),
        data.get("job_type", "Full Time"),
        data.get("description", ""),
        data.get("skills", ""),
        user["id"]
    ))

    con.commit()
    con.close()

    return {
        "ok": True,
        "message": "Job posted successfully"
    }

@app.post("/api/jobs/{job_id}/apply")
def apply(job_id: int, request: Request):
    user = current_user(request)

    if not user:
        return JSONResponse(
            {"ok": False, "message": "Please login"},
            status_code=401
        )

    con = db()

    try:
        con.execute("""
        INSERT INTO applications(job_id,user_id)
        VALUES(?,?)
        """, (
            job_id,
            user["id"]
        ))
        con.commit()

    except sqlite3.IntegrityError:
        con.close()
        return {
            "ok": False,
            "message": "Already applied"
        }

    con.close()

    return {
        "ok": True,
        "message": "Application submitted"
    }

@app.post("/api/jobs/{job_id}/save")
def save_job(job_id: int, request: Request):
    user = current_user(request)

    if not user:
        return JSONResponse(
            {"ok": False, "message": "Please login"},
            status_code=401
        )

    con = db()

    try:
        con.execute("""
        INSERT INTO saved_jobs(job_id,user_id)
        VALUES(?,?)
        """, (
            job_id,
            user["id"]
        ))
        con.commit()
        message = "Job saved"

    except sqlite3.IntegrityError:
        con.execute("""
        DELETE FROM saved_jobs
        WHERE job_id=? AND user_id=?
        """, (
            job_id,
            user["id"]
        ))
        con.commit()
        message = "Job removed from saved"

    con.close()

    return {
        "ok": True,
        "message": message
    }

@app.get("/api/applications")
def applications(request: Request):
    user = current_user(request)

    if not user:
        return JSONResponse(
            {"ok": False},
            status_code=401
        )

    con = db()

    rows = con.execute("""
    SELECT
        applications.*,
        jobs.title,
        jobs.company,
        jobs.location
    FROM applications
    JOIN jobs
        ON applications.job_id=jobs.id
    WHERE applications.user_id=?
    ORDER BY applications.id DESC
    """, (
        user["id"],
    )).fetchall()

    con.close()

    return {
        "ok": True,
        "applications": [dict(x) for x in rows]
    }

@app.get("/api/saved")
def saved(request: Request):
    user = current_user(request)

    if not user:
        return JSONResponse(
            {"ok": False},
            status_code=401
        )

    con = db()

    rows = con.execute("""
    SELECT jobs.*
    FROM saved_jobs
    JOIN jobs
        ON saved_jobs.job_id=jobs.id
    WHERE saved_jobs.user_id=?
    ORDER BY saved_jobs.id DESC
    """, (
        user["id"],
    )).fetchall()

    con.close()

    return {
        "ok": True,
        "jobs": [dict(x) for x in rows]
    }

@app.get("/api/services")
def services():
    con = db()

    rows = con.execute("""
    SELECT * FROM services
    ORDER BY id DESC
    """).fetchall()

    con.close()

    return {
        "ok": True,
        "services": [dict(x) for x in rows]
    }

# ================= FRONTEND =================

HTML = r"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width,initial-scale=1,maximum-scale=1">

<title>Job Mart</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    font-family:Arial,sans-serif;
    background:#f4f6f9;
    color:#17202a;
}

header{
    position:sticky;
    top:0;
    z-index:10;
    background:#0878e8;
    color:white;
    padding:14px 16px;
}

.top{
    display:flex;
    justify-content:space-between;
    align-items:center;
}

.logo{
    font-size:24px;
    font-weight:bold;
}

.menu{
    font-size:26px;
    cursor:pointer;
}

.container{
    max-width:900px;
    margin:auto;
    padding:14px;
}

.searchbox{
    background:white;
    padding:14px;
    border-radius:16px;
    margin-bottom:14px;
    box-shadow:0 2px 8px #ddd;
}

input,select,textarea{
    width:100%;
    padding:13px;
    border:1px solid #ddd;
    border-radius:9px;
    font-size:15px;
    margin-bottom:10px;
}

textarea{
    min-height:100px;
}

button{
    border:0;
    padding:12px 16px;
    border-radius:9px;
    background:#0878e8;
    color:white;
    font-weight:bold;
    cursor:pointer;
}

button.secondary{
    background:#e9eef5;
    color:#222;
}

button.danger{
    background:#e53935;
}

.hero{
    background:linear-gradient(135deg,#0878e8,#0052b4);
    color:white;
    padding:22px;
    border-radius:18px;
    margin-bottom:15px;
}

.hero h1{
    margin:0 0 8px;
}

.categories{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:9px;
    margin-bottom:15px;
}

.category{
    background:white;
    border-radius:13px;
    padding:13px 5px;
    text-align:center;
    box-shadow:0 2px 6px #ddd;
    cursor:pointer;
}

.category div{
    font-size:27px;
}

.job{
    background:white;
    border-radius:15px;
    padding:16px;
    margin-bottom:12px;
    box-shadow:0 2px 7px #ddd;
}

.job h3{
    margin:0 0 5px;
}

.company{
    color:#0878e8;
    font-weight:bold;
}

.meta{
    color:#666;
    margin:7px 0;
    font-size:14px;
}

.actions{
    display:flex;
    gap:7px;
    flex-wrap:wrap;
    margin-top:10px;
}

.nav{
    position:fixed;
    bottom:0;
    left:0;
    right:0;
    background:white;
    border-top:1px solid #ddd;
    display:grid;
    grid-template-columns:repeat(5,1fr);
    padding:7px 3px;
    z-index:20;
}

.nav button{
    background:white;
    color:#555;
    padding:7px 2px;
    font-size:11px;
}

.nav button.active{
    color:#0878e8;
}

.page{
    padding-bottom:80px;
}

.card{
    background:white;
    border-radius:15px;
    padding:18px;
    margin-bottom:13px;
    box-shadow:0 2px 7px #ddd;
}

.hidden{
    display:none !important;
}

.modal{
    position:fixed;
    inset:0;
    background:#0008;
    display:flex;
    align-items:center;
    justify-content:center;
    z-index:50;
    padding:15px;
}

.modalbox{
    background:white;
    width:100%;
    max-width:450px;
    max-height:90vh;
    overflow:auto;
    padding:20px;
    border-radius:18px;
}

.close{
    float:right;
    background:#eee;
    color:#222;
}

.service{
    background:white;
    padding:15px;
    border-radius:14px;
    margin-bottom:10px;
    box-shadow:0 2px 6px #ddd;
}

.badge{
    display:inline-block;
    padding:5px 9px;
    border-radius:20px;
    background:#e7f1ff;
    color:#0878e8;
    font-size:12px;
}

@media(max-width:500px){
    .categories{
        grid-template-columns:repeat(2,1fr);
    }
}

</style>
</head>

<body>

<header>
<div class="top">
<div class="logo">💼 Job Mart</div>
<div class="menu" onclick="openMenu()">☰</div>
</div>
</header>

<div class="page">

<div class="container">

<section id="home">

<div class="hero">
<h1>Find Your Next Job</h1>
<p>Jobs • Recruitment • Services</p>
<button onclick="showPage('jobs')">
Find Jobs
</button>
</div>

<div class="searchbox">
<input id="search"
placeholder="🔎 Search jobs, skills, companies..."
oninput="loadJobs()">

<input id="location"
placeholder="📍 Location"
oninput="loadJobs()">
</div>

<div class="categories">

<div class="category" onclick="searchCategory('Software')">
<div>💻</div>
IT Jobs
</div>

<div class="category" onclick="searchCategory('Sales')">
<div>📈</div>
Sales
</div>

<div class="category" onclick="searchCategory('Driver')">
<div>🚗</div>
Driver
</div>

<div class="category" onclick="showPage('services')">
<div>🛠️</div>
Services
</div>

</div>

<h2>Latest Jobs</h2>

<div id="homeJobs"></div>

</section>

<section id="jobs" class="hidden">

<h2>🔎 Jobs</h2>

<div class="searchbox">
<input id="jobSearch"
placeholder="Search jobs..."
oninput="loadAllJobs()">

<input id="jobLocation"
placeholder="Location..."
oninput="loadAllJobs()">
</div>

<div id="allJobs"></div>

</section>

<section id="services" class="hidden">

<h2>🛠️ Services</h2>

<div id="servicesList"></div>

</section>

<section id="profile" class="hidden">

<div id="profileContent"></div>

</section>

<section id="saved" class="hidden">

<h2>❤️ Saved Jobs</h2>

<div id="savedJobs"></div>

</section>

<section id="applications" class="hidden">

<h2>📋 My Applications</h2>

<div id="applicationsList"></div>

</section>

<section id="postjob" class="hidden">

<div class="card">

<h2>📢 Post a Job</h2>

<input id="postTitle" placeholder="Job title">

<input id="postCompany" placeholder="Company name">

<input id="postLocation" placeholder="Location">

<input id="postSalary" placeholder="Salary">

<select id="postType">
<option>Full Time</option>
<option>Part Time</option>
<option>Contract</option>
<option>Remote</option>
<option>Internship</option>
</select>

<input id="postSkills" placeholder="Skills">

<textarea id="postDescription"
placeholder="Job description"></textarea>

<button onclick="postJob()">
Publish Job
</button>

</div>

</section>

</div>

</div>

<nav class="nav">

<button onclick="showPage('home')">
🏠<br>Home
</button>

<button onclick="showPage('jobs')">
💼<br>Jobs
</button>

<button onclick="showPage('saved')">
❤️<br>Saved
</button>

<button onclick="showPage('applications')">
📋<br>Applications
</button>

<button onclick="showPage('profile')">
👤<br>Profile
</button>

</nav>

<div id="modal" class="modal hidden">

<div class="modalbox">

<button class="close" onclick="closeModal()">✕</button>

<div id="modalContent"></div>

</div>

</div>

<script>

let token = localStorage.getItem("jobmart_token");
let user = null;

function headers(){

    let h = {
        "Content-Type":"application/json"
    };

    if(token){
        h["X-Session"] = token;
    }

    return h;
}

async function api(url, options={}){

    options.headers = {
        ...(options.headers || {}),
        ...headers()
    };

    let r = await fetch(url, options);
    return await r.json();
}

async function checkLogin(){

    let data = await api("/api/me");

    if(data.ok){
        user = data.user;
    }

    renderProfile();
}

async function loadJobs(){

    let s = document.getElementById("search")?.value || "";
    let l = document.getElementById("location")?.value || "";

    let data = await fetch(
        "/api/jobs?search="+
        encodeURIComponent(s)+
        "&location="+
        encodeURIComponent(l)
    ).then(r=>r.json());

    renderJobs(data.jobs || [], "homeJobs");
}

async function loadAllJobs(){

    let s = document.getElementById("jobSearch")?.value || "";
    let l = document.getElementById("jobLocation")?.value || "";

    let data = await fetch(
        "/api/jobs?search="+
        encodeURIComponent(s)+
        "&location="+
        encodeURIComponent(l)
    ).then(r=>r.json());

    renderJobs(data.jobs || [], "allJobs");
}

function renderJobs(jobs,id){

    let box = document.getElementById(id);

    if(!box) return;

    if(!jobs.length){

        box.innerHTML =
        `<div class="card">
        No jobs found.
        </div>`;

        return;
    }

    box.innerHTML = jobs.map(j => `

    <div class="job">

        <h3>${esc(j.title)}</h3>

        <div class="company">
        ${esc(j.company)}
        </div>

        <div class="meta">
        📍 ${esc(j.location)}
        </div>

        <div class="meta">
        💰 ${esc(j.salary || "Salary not specified")}
        </div>

        <span class="badge">
        ${esc(j.job_type)}
        </span>

        <p>${esc(j.description || "")}</p>

        <div class="meta">
        🧠 ${esc(j.skills || "Skills not specified")}
        </div>

        <div class="actions">

        <button onclick="applyJob(${j.id})">
        Apply
        </button>

        <button
        class="secondary"
        onclick="saveJob(${j.id})">
        ❤️ Save
        </button>

        <button
        class="secondary"
        onclick='viewJob(${JSON.stringify(j)})'>
        View
        </button>

        </div>

    </div>

    `).join("");
}

function esc(v){

    return String(v || "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

async function applyJob(id){

    if(!token){

        loginModal();
        return;
    }

    let data = await api(
        "/api/jobs/"+id+"/apply",
        {method:"POST"}
    );

    alert(data.message || "Done");

    if(data.ok){
        showPage("applications");
    }
}

async function saveJob(id){

    if(!token){

        loginModal();
        return;
    }

    let data = await api(
        "/api/jobs/"+id+"/save",
        {method:"POST"}
    );

    alert(data.message || "Done");
}

function viewJob(j){

    document.getElementById("modalContent").innerHTML = `

    <h2>${esc(j.title)}</h2>

    <h3>${esc(j.company)}</h3>

    <p>📍 ${esc(j.location)}</p>

    <p>💰 ${esc(j.salary)}</p>

    <p>💼 ${esc(j.job_type)}</p>

    <h3>Description</h3>

    <p>${esc(j.description)}</p>

    <h3>Skills</h3>

    <p>${esc(j.skills)}</p>

    <button onclick="applyJob(${j.id})">
    Apply Now
    </button>

    `;

    document.getElementById("modal")
    .classList.remove("hidden");
}

function closeModal(){

    document.getElementById("modal")
    .classList.add("hidden");
}

function loginModal(){

    document.getElementById("modalContent").innerHTML = `

    <h2>🔐 Login</h2>

    <input id="loginEmail"
    placeholder="Email">

    <input id="loginPassword"
    type="password"
    placeholder="Password">

    <button onclick="login()">
    Login
    </button>

    <button class="secondary"
    onclick="registerModal()">
    Create Account
    </button>

    `;

    document.getElementById("modal")
    .classList.remove("hidden");
}

function registerModal(){

    document.getElementById("modalContent").innerHTML = `

    <h2>📝 Create Account</h2>

    <input id="regName"
    placeholder="Full name">

    <input id="regEmail"
    placeholder="Email">

    <input id="regPassword"
    type="password"
    placeholder="Password">

    <select id="regRole">
        <option value="candidate">
        Job Seeker
        </option>

        <option value="employer">
        Employer / Recruiter
        </option>
    </select>

    <button onclick="register()">
    Register
    </button>

    <button class="secondary"
    onclick="loginModal()">
    Already have account?
    </button>

    `;

    document.getElementById("modal")
    .classList.remove("hidden");
}

async function login(){

    let data = await api(
        "/api/login",
        {
            method:"POST",
            body:JSON.stringify({
                email:document.getElementById("loginEmail").value,
                password:document.getElementById("loginPassword").value
            })
        }
    );

    if(!data.ok){

        alert(data.message);
        return;
    }

    token = data.token;

    localStorage.setItem(
        "jobmart_token",
        token
    );

    user = data.user;

    closeModal();
    renderProfile();

    alert("Login successful");
}

async function register(){

    let data = await api(
        "/api/register",
        {
            method:"POST",
            body:JSON.stringify({
                name:document.getElementById("regName").value,
                email:document.getElementById("regEmail").value,
                password:document.getElementById("regPassword").value,
                role:document.getElementById("regRole").value
            })
        }
    );

    if(!data.ok){

        alert(data.message);
        return;
    }

    token = data.token;

    localStorage.setItem(
        "jobmart_token",
        token
    );

    await checkLogin();

    closeModal();

    alert("Account created successfully");
}

async function logout(){

    await api(
        "/api/logout",
        {method:"POST"}
    );

    token = null;
    user = null;

    localStorage.removeItem(
        "jobmart_token"
    );

    renderProfile();

    showPage("home");

    alert("Logged out");
}

function renderProfile(){

    let box =
    document.getElementById("profileContent");

    if(!box) return;

    if(!user){

        box.innerHTML = `

        <div class="card">

        <h2>👤 My Account</h2>

        <p>
        Login to access your Job Mart account.
        </p>

        <button onclick="loginModal()">
        Login
        </button>

        <button
        class="secondary"
        onclick="registerModal()">
        Register
        </button>

        </div>

        `;

        return;
    }

    let post = "";

    if(user.role === "employer"){

        post = `
        <button onclick="showPage('postjob')">
        📢 Post a Job
        </button>
        `;
    }

    box.innerHTML = `

    <div class="card">

    <h2>👤 ${esc(user.name)}</h2>

    <p>📧 ${esc(user.email)}</p>

    <p>
    Account:
    <span class="badge">
    ${esc(user.role)}
    </span>
    </p>

    <div class="actions">

    ${post}

    <button class="danger"
    onclick="logout()">
    Logout
    </button>

    </div>

    </div>

    `;
}

async function loadSaved(){

    let box =
    document.getElementById("savedJobs");

    if(!token){

        box.innerHTML = `
        <div class="card">
        Please login first.
        <br><br>
        <button onclick="loginModal()">
        Login
        </button>
        </div>
        `;

        return;
    }

    let data = await api("/api/saved");

    renderJobs(
        data.jobs || [],
        "savedJobs"
    );
}

async function loadApplications(){

    let box =
    document.getElementById("applicationsList");

    if(!token){

        box.innerHTML = `
        <div class="card">
        Please login first.
        </div>
        `;

        return;
    }

    let data =
    await api("/api/applications");

    if(!data.applications?.length){

        box.innerHTML = `
        <div class="card">
        No applications yet.
        </div>
        `;

        return;
    }

    box.innerHTML =
    data.applications.map(a => `

    <div class="job">

    <h3>${esc(a.title)}</h3>

    <div class="company">
    ${esc(a.company)}
    </div>

    <div class="meta">
    📍 ${esc(a.location)}
    </div>

    <span class="badge">
    ${esc(a.status)}
    </span>

    </div>

    `).join("");
}

async function loadServices(){

    let data =
    await fetch("/api/services")
    .then(r=>r.json());

    let box =
    document.getElementById("servicesList");

    box.innerHTML =
    (data.services || []).map(s => `

    <div class="service">

    <h3>🛠️ ${esc(s.title)}</h3>

    <p>${esc(s.description)}</p>

    <p>
    👨‍🔧 ${esc(s.provider)}
    </p>

    <p>
    📍 ${esc(s.location)}
    </p>

    <button onclick="alert('Service request feature ready for next integration')">
    Request Service
    </button>

    </div>

    `).join("");
}

async function postJob(){

    if(!token){

        loginModal();
        return;
    }

    let data = await api(
        "/api/jobs",
        {
            method:"POST",
            body:JSON.stringify({

                title:
                document.getElementById("postTitle").value,

                company:
                document.getElementById("postCompany").value,

                location:
                document.getElementById("postLocation").value,

                salary:
                document.getElementById("postSalary").value,

                job_type:
                document.getElementById("postType").value,

                skills:
                document.getElementById("postSkills").value,

                description:
                document.getElementById("postDescription").value

            })
        }
    );

    alert(data.message || "Done");

    if(data.ok){

        document.getElementById("postTitle").value="";
        document.getElementById("postCompany").value="";
        document.getElementById("postLocation").value="";
        document.getElementById("postSalary").value="";
        document.getElementById("postSkills").value="";
        document.getElementById("postDescription").value="";

        showPage("jobs");
    }
}

function searchCategory(text){

    document.getElementById("search").value = text;

    showPage("home");

    loadJobs();
}

function showPage(name){

    const pages = [
        "home",
        "jobs",
        "services",
        "profile",
        "saved",
        "applications",
        "postjob"
    ];

    pages.forEach(p => {

        let el =
        document.getElementById(p);

        if(el){

            el.classList.toggle(
                "hidden",
                p !== name
            );
        }
    });

    if(name === "home")
        loadJobs();

    if(name === "jobs")
        loadAllJobs();

    if(name === "services")
        loadServices();

    if(name === "saved")
        loadSaved();

    if(name === "applications")
        loadApplications();

    if(name === "profile")
        renderProfile();

    window.scrollTo(0,0);
}

function openMenu(){

    if(user){

        document.getElementById("modalContent").innerHTML = `

        <h2>☰ Job Mart Menu</h2>

        <button onclick="showPage('home');closeModal()">
        🏠 Home
        </button>

        <br><br>

        <button onclick="showPage('jobs');closeModal()">
        💼 Jobs
        </button>

        <br><br>

        <button onclick="showPage('services');closeModal()">
        🛠️ Services
        </button>

        <br><br>

        <button onclick="showPage('saved');closeModal()">
        ❤️ Saved Jobs
        </button>

        <br><br>

        <button onclick="showPage('applications');closeModal()">
        📋 Applications
        </button>

        <br><br>

        <button onclick="showPage('profile');closeModal()">
        👤 Profile
        </button>

        `;

    }else{

        loginModal();
        return;
    }

    document.getElementById("modal")
    .classList.remove("hidden");
}

checkLogin();
loadJobs();

</script>

</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML
