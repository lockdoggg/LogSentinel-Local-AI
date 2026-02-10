import os
import re
import sqlite3
import json
import asyncio
import time
import io
import sys
import logging
import hashlib
import traceback
import secrets
import httpx
from collections import deque
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext

# ==========================================
# 1. CONFIGURATION & LOGGING
# ==========================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("LogSentinel_Core")

# --- URL SANITIZATION (Robust) ---
def get_clean_ollama_url() -> str:
    """Cleans up the OLLAMA_URL environment variable to prevent protocol errors."""
    raw = os.getenv("OLLAMA_URL", "")
    if "](" in raw: raw = raw.split("](")[0].replace("[", "")
    clean = raw.replace("[", "").replace("]", "").replace('"', '').replace("'", "").strip()
    clean = clean.replace("/api/chat", "").replace("/api/tags", "").rstrip('/')
    if not clean or "http" not in clean: return "http://host.docker.internal:11434"
    if not clean.startswith("http"): clean = "http://" + clean
    return clean

OLLAMA_BASE = get_clean_ollama_url()
OLLAMA_CHAT_URL = f"{OLLAMA_BASE}/api/chat"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE}/api/tags"

logger.info(f"🔧 CONFIG LOADED: {OLLAMA_BASE}")

# Global Model Variable
CURRENT_MODEL = os.getenv("MODEL_NAME", "") 

# Security Configuration
SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY or SECRET_KEY == "CHANGE_THIS_SECRET":
    SECRET_KEY = secrets.token_urlsafe(32)
    logger.warning("⚠️ SECURITY WARNING: Using ephemeral JWT secret. Sessions will reset on restart.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DB_FILE = "/app/data/qs_base.db"
SHAREABLE_DEBUG_FILE = "/app/data/last_analysis_debug.json"
KB_FILE = "/app/data/knowledge_base.json"
os.makedirs("/app/data", exist_ok=True)

# Cache & Rate Limiting
MAX_CACHE_SIZE = 5000
RESPONSE_CACHE: Dict[str, str] = {}
BLOCKED_IPS: Dict[str, float] = {}
BLOCK_DURATION = 1800 

# Regex Patterns for Log Parsing
CRITICAL_REGEX = re.compile(r"error|fatal|fail|panic|alert|critical|exception|traceback|deadlock|killed|cannot|denied|refused|timeout|rejected|declined|unauthorized|unavailable|unreachable|warn|warning|\b500\b|\b502\b|\b503\b|\b504\b|\b403\b", re.IGNORECASE)
NOISE_REGEX = re.compile(r"\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}|\[\d+\]")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
ANALYSIS_SEMAPHORE = asyncio.Semaphore(10)
SCRIPT_SEMAPHORE = asyncio.Semaphore(5)

app = FastAPI(title="LogSentinel Enterprise", version="4.4.0-Stable")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ==========================================
# 2. MODEL AUTO-DISCOVERY
# ==========================================

async def force_find_any_model() -> str:
    """Scans the Ollama instance for any available models."""
    logger.info(f"🔎 Scanning for models at: {OLLAMA_TAGS_URL}")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(OLLAMA_TAGS_URL)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                if models:
                    model_names = [m["name"] for m in models]
                    logger.info(f"📦 Discovered models: {model_names}")
                    best_match = model_names[0]
                    for m in model_names:
                        if "qwen" in m or "llama" in m: best_match = m; break
                    return best_match
    except Exception as e:
        logger.error(f"❌ Discovery Error: {e}")
    return "llama3" # Fallback

@app.on_event("startup")
async def startup_check():
    global CURRENT_MODEL
    logger.info(f"🚀 System Startup Initiated...")
    init_db() # Run DB Init & Migrations
    if CURRENT_MODEL:
        logger.info(f"🔒 Model locked by ENV: {CURRENT_MODEL}")
    else:
        CURRENT_MODEL = await force_find_any_model()
        logger.info(f"✅ Auto-Selected Model: {CURRENT_MODEL}")

# ==========================================
# 3. SECURITY & MASKING UTILS
# ==========================================

def extract_ai_content(json_data: dict) -> str:
    try:
        if "message" in json_data: return json_data["message"].get("content", "").strip()
        if "response" in json_data: return json_data.get("response", "").strip()
        if "choices" in json_data: return json_data["choices"][0].get("message", {}).get("content", "").strip()
    except: pass
    return ""

def mask_sensitive_data(text: str) -> str:
    if not text: return ""
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP_HIDDEN]', text)
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_HIDDEN]', text)
    text = re.sub(r'(?<!\d)(?:\d{4}[-. ]?){3}\d{4}(?!\d)', '[CARD_HIDDEN]', text)
    text = re.sub(r'(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{6}(?!\d)', '[ID_HIDDEN]', text)
    return text

def sanitize_ai_response(text: str) -> str:
    if re.search(r"rm\s+-rf|mkfs|chmod\s+777|dd\s+if|:(){ :|:& };:", text, re.IGNORECASE):
        return "⚠️ **SECURITY WARNING:** Malicious command patterns detected and blocked by LogSentinel."
    return text

def detect_security_threat(text: str, ip: str) -> Optional[str]:
    if "union select" in text.lower() or "information_schema" in text.lower():
        BLOCKED_IPS[ip] = time.time() + BLOCK_DURATION
        return "🚨 **SQL INJECTION ATTEMPT BLOCKED**"
    return None

def normalize_log_for_cache(text: str) -> str:
    clean = NOISE_REGEX.sub("", text[:10000]) 
    return hashlib.md5(clean.encode('utf-8')).hexdigest()

def validate_password_complexity(p: str):
    # RELAXED FOR TESTING
    if not p:
        raise HTTPException(400, "Password cannot be empty.")

def save_shareable_debug(source: str, prompt: str, response: str, duration: float, error: str = None):
    try:
        debug_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "ERROR" if error else "OK",
            "error_msg": str(error) if error else None,
            "url_target": OLLAMA_CHAT_URL,
            "model_active": CURRENT_MODEL,
            "prompt_size": len(prompt)
        }
        with open(SHAREABLE_DEBUG_FILE, "w", encoding="utf-8") as f:
            json.dump(debug_data, f, indent=2)
    except: pass

# ==========================================
# 4. DATABASE & AUTHENTICATION
# ==========================================

def get_password_hash(p): return pwd_context.hash(p)
def verify_password(p, h): return pwd_context.verify(p, h)

def init_db():
    """Initializes DB with AUTO-MIGRATION for existing data."""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        # 1. Base Users Table
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, 
            hashed_password TEXT, 
            role TEXT
        )''')
        
        # 2. MIGRATIONS: Add new columns safely
        try: 
            c.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
            logger.info("ℹ️ DB Migration: Added failed_attempts")
        except: 
            pass

        try: 
            c.execute("ALTER TABLE users ADD COLUMN is_locked INTEGER DEFAULT 0")
            logger.info("ℹ️ DB Migration: Added is_locked")
        except: 
            pass

        try: 
            c.execute("ALTER TABLE users ADD COLUMN force_change INTEGER DEFAULT 1")
            logger.info("ℹ️ DB Migration: Added force_change")
        except: 
            pass

        # 3. Saved Reports Table
        c.execute('''CREATE TABLE IF NOT EXISTS saved_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            user_id TEXT, 
            filename TEXT, 
            summary TEXT, 
            solution TEXT, 
            original_context TEXT, 
            source TEXT, 
            severity INTEGER, 
            created_at TEXT
        )''')
        
        # 4. Migration for Reports
        try: 
            c.execute("ALTER TABLE saved_reports ADD COLUMN log_hash TEXT")
        except: 
            pass
        
        # 5. Usage Stats
        c.execute('''CREATE TABLE IF NOT EXISTS usage_stats (
            user_id TEXT, 
            module TEXT, 
            usage_count INTEGER DEFAULT 0, 
            last_used TEXT, 
            PRIMARY KEY(user_id, module)
        )''')
        
        conn.commit()
        
        # Create default admin if missing
        c.execute("SELECT username FROM users WHERE username='admin'")
        if not c.fetchone(): 
            logger.info("👤 Creating default admin user.")
            c.execute("INSERT INTO users (username, hashed_password, role, failed_attempts, is_locked, force_change) VALUES (?, ?, ?, 0, 0, 1)", 
                      ("admin", get_password_hash("admin"), "senior_admin"))
            conn.commit()
        
        conn.close()
    except Exception as e: logger.error(f"DB Init Critical Failure: {e}")

def update_stats(user: str, module: str):
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(DB_FILE) as db:
            db.execute("INSERT OR IGNORE INTO usage_stats (user_id, module, usage_count, last_used) VALUES (?, ?, 0, ?)", (user, module, ts))
            db.execute("UPDATE usage_stats SET usage_count = usage_count + 1, last_used = ? WHERE user_id = ? AND module = ?", (ts, user, module))
            db.commit()
    except: pass

class User(BaseModel): username: str; role: str; force_change: bool
class UserCreate(BaseModel): username: str; password: str; role: str
class PasswordChange(BaseModel): old_password: str; new_password: str
class UserReset(BaseModel): new_password: str
class LogRequest(BaseModel): log_text: str
class ScriptRequest(BaseModel): task: str; language: str

def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try: payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except: raise HTTPException(401, "Token expired")
    
    with sqlite3.connect(DB_FILE) as db:
        row = db.execute("SELECT username, role, is_locked, force_change FROM users WHERE username=?", (payload.get("sub"),)).fetchone()
    
    if not row: raise HTTPException(401, "User not found")
    if row[2]: raise HTTPException(403, "Account locked")
    return User(username=row[0], role=row[1], force_change=bool(row[3]))

async def check_setup(u: User = Depends(get_current_user)):
    if u.force_change: raise HTTPException(403, "Password change required")
    return u

@app.post("/token")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    with sqlite3.connect(DB_FILE) as db:
        try:
            row = db.execute("SELECT username, hashed_password, failed_attempts, is_locked, force_change, role FROM users WHERE username=?", (form.username,)).fetchone()
        except sqlite3.OperationalError:
            raise HTTPException(500, "Database schema error. Please delete data/qs_base.db and restart.")

    if not row: 
        time.sleep(1)
        raise HTTPException(401, "Invalid credentials")
    
    if row[3]: raise HTTPException(403, "Account is locked")
    
    if not verify_password(form.password, row[1]):
        with sqlite3.connect(DB_FILE) as db: 
            db.execute("UPDATE users SET failed_attempts=failed_attempts+1 WHERE username=?", (form.username,))
            if row[2] >= 5 and row[0] != 'admin':
                db.execute("UPDATE users SET is_locked=1 WHERE username=?", (form.username,))
            db.commit()
        raise HTTPException(401, "Invalid credentials")
    
    with sqlite3.connect(DB_FILE) as db: 
        db.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (row[0],))
        db.commit()
    
    update_stats(row[0], "LOGIN")
    return {"access_token": create_access_token({"sub": row[0], "role": row[5]}), "token_type": "bearer", "force_change": bool(row[4]), "role": row[5]}

@app.get("/users/me")
async def me(u: User = Depends(get_current_user)): 
    return {"username": u.username, "role": u.role, "force_change": u.force_change}

# ==========================================
# 5. CORE LOGIC (AI ANALYSIS)
# ==========================================

def extract_smart_context_string(text: str) -> str:
    lines = text.splitlines()
    extracted = []
    i = 0
    while i < len(lines):
        if CRITICAL_REGEX.search(lines[i]):
            lines[i] = f"🔴 >>> {lines[i]} <<< 🔴"
            start = max(0, i - 5)
            end = min(len(lines), i + 10)
            extracted.append("\n".join(lines[start:end]))
            i = end
            if len(extracted) > 15: break
        else:
            i += 1
    return "\n---\n".join(extracted) if extracted else "\n".join(lines[-20:])

async def process_log_stream(file_obj) -> str:
    buffer = b""
    prev_lines = deque(maxlen=5)
    extracted = []
    capture = 0
    total_len = 0
    while True:
        chunk = await file_obj.read(64 * 1024)
        if not chunk: break
        buffer += chunk
        while True:
            try:
                nl = buffer.index(b'\n')
                line = buffer[:nl].decode('utf-8', errors='ignore').strip()
                buffer = buffer[nl+1:]
                if capture > 0:
                    if extracted: extracted[-1] += f"\n{line}"; capture -= 1; continue
                if CRITICAL_REGEX.search(line):
                    block = "... [CTX] ...\n" + "\n".join(prev_lines) + f"\n🔴 >>> {line} <<< 🔴"
                    extracted.append(block); capture = 8; total_len += len(block)
                else: prev_lines.append(line)
                if total_len > 12000: break
            except ValueError: break
        if total_len > 12000: break
    return "\n---\n".join(extracted) if extracted else "CLEAN_LOG_MARKER"

def check_db_cache(log_hash: str) -> Optional[str]:
    try:
        with sqlite3.connect(DB_FILE) as db:
            row = db.execute("SELECT solution FROM saved_reports WHERE log_hash=? ORDER BY id DESC LIMIT 1", (log_hash,)).fetchone()
            if row: return row[0]
    except: pass
    return None

async def query_ollama_prod(context: str, raw_len: int) -> str:
    global CURRENT_MODEL
    cache_key = normalize_log_for_cache(context)
    if cache_key in RESPONSE_CACHE: return RESPONSE_CACHE[cache_key]
    db_hit = await run_in_threadpool(check_db_cache, cache_key)
    if db_hit:
        RESPONSE_CACHE[cache_key] = db_hit; return db_hit

    sys_prompt = "YOU ARE: A Senior SRE. Tone: Professional. TASK: Analyze log. Identify Root Cause. Provide Fix. OUTPUT: Markdown."
    user_prompt = f"LOG DATA:\n{context}\n\nGENERATE SRE REPORT:"
    
    start_t = time.perf_counter()
    async with ANALYSIS_SEMAPHORE:
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                target_url = OLLAMA_CHAT_URL
                if not target_url.startswith("http"): target_url = "http://host.docker.internal:11434/api/chat"
                
                if not CURRENT_MODEL: CURRENT_MODEL = await force_find_any_model()
                
                payload = {"model": CURRENT_MODEL, "messages": [{"role": "system", "content": sys_prompt}, {"role": "user", "content": user_prompt}], "stream": False, "options": {"temperature": 0.3}}
                
                r = await client.post(target_url, json=payload)
                if r.status_code == 404:
                    CURRENT_MODEL = await force_find_any_model()
                    payload["model"] = CURRENT_MODEL
                    r = await client.post(target_url, json=payload)

                if r.status_code != 200:
                    err = f"AI Error: {r.status_code}"; save_shareable_debug("AI_FAIL", user_prompt, "", 0, err); return err
                
                clean_resp = sanitize_ai_response(extract_ai_content(r.json()))
                if len(RESPONSE_CACHE) > MAX_CACHE_SIZE: RESPONSE_CACHE.pop(next(iter(RESPONSE_CACHE)))
                RESPONSE_CACHE[cache_key] = clean_resp
                
                # DB Cache Save
                try:
                    log_hash = normalize_log_for_cache(context)
                    with sqlite3.connect(DB_FILE) as db:
                         db.execute("INSERT INTO saved_reports (user_id, filename, summary, solution, original_context, source, severity, created_at, log_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                    ("system", "Auto", clean_resp[:100], clean_resp, context, "AI", 50, datetime.now().strftime("%Y-%m-%d %H:%M"), log_hash))
                         db.commit()
                except: 
                    pass

                save_shareable_debug("AI_OK", user_prompt, clean_resp, time.perf_counter()-start_t)
                return clean_resp
            except Exception as e: return f"System Error: {e}"

async def stream_ollama_script(task: str, lang: str) -> str:
    sys_p = f"Role: Senior Dev. Lang: {lang}. OUTPUT CODE ONLY."
    async with SCRIPT_SEMAPHORE:
        async with httpx.AsyncClient(timeout=180.0) as client:
            try:
                target_url = OLLAMA_CHAT_URL
                if not target_url.startswith("http"): target_url = "http://host.docker.internal:11434/api/chat"
                r = await client.post(target_url, json={"model": CURRENT_MODEL, "messages": [{"role": "system", "content": sys_p}, {"role": "user", "content": task}], "stream": False, "options": {"temperature": 0.2}})
                return extract_ai_content(r.json()).replace("```", "").strip()
            except Exception as e: return f"Error: {e}"

# ==========================================
# 6. API ENDPOINTS
# ==========================================

@app.post("/analyze")
async def analyze(r: LogRequest, request: Request, u: User = Depends(check_setup)):
    update_stats(u.username, "ANALYZE")
    if t := detect_security_threat(r.log_text, request.client.host): return {"results": [{"filename": "Input", "status": "alert", "solution": t}]}
    
    ctx = await run_in_threadpool(extract_smart_context_string, r.log_text)
    ctx_clean = mask_sensitive_data(ctx)
    if ctx == "CLEAN_LOG_MARKER": return {"results": [{"filename": "Input", "status": "clean", "solution": "✅ No critical errors."}]}
    
    ai_res = await query_ollama_prod(ctx_clean, len(r.log_text))
    
    try:
        log_hash = normalize_log_for_cache(ctx_clean)
        with sqlite3.connect(DB_FILE) as db:
             db.execute("INSERT INTO saved_reports (user_id, filename, summary, solution, original_context, source, severity, created_at, log_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                        (u.username, "Input", ai_res[:100], ai_res, ctx_clean, "AI", 50, datetime.now().strftime("%Y-%m-%d %H:%M"), log_hash))
             db.commit()
    except: 
        pass
    
    return {"results": [{"filename": "Input", "status": "ok", "solution": ai_res, "original_context": ctx_clean, "source": "AI"}]}

@app.post("/analyze-files")
async def files_an(request: Request, files: List[UploadFile] = File(...), u: User = Depends(check_setup)):
    update_stats(u.username, f"FILES({len(files)})")
    res = []
    for f in files:
        head = await f.read(2048); await f.seek(0)
        if t := detect_security_threat(head.decode(errors='ignore'), request.client.host):
            res.append({"filename": f.filename, "status": "alert", "solution": t}); continue

        ctx = await process_log_stream(f); ctx_clean = mask_sensitive_data(ctx)
        ai_res = await query_ollama_prod(ctx_clean, 0)
        
        try:
            log_hash = normalize_log_for_cache(ctx_clean)
            with sqlite3.connect(DB_FILE) as db:
                db.execute("INSERT INTO saved_reports (user_id, filename, summary, solution, original_context, source, severity, created_at, log_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                        (u.username, f.filename, ai_res[:100], ai_res, ctx_clean, "AI", 50, datetime.now().strftime("%Y-%m-%d %H:%M"), log_hash))
                db.commit()
        except: 
            pass
        res.append({"filename": f.filename, "status": "ok", "solution": ai_res, "original_context": ctx_clean})
    return {"results": res}

@app.post("/generate-script")
async def gen(req: ScriptRequest, u: User = Depends(check_setup)):
    update_stats(u.username, "GEN")
    if any(b in req.task.lower() for b in ["rm -rf", "mkfs"]): raise HTTPException(400, "Unsafe request detected")
    return {"script": await stream_ollama_script(req.task, req.language)}

# --- ADMINISTRATION ENDPOINTS ---

@app.get("/users")
async def u_list(u: User = Depends(get_current_user)):
    with sqlite3.connect(DB_FILE) as db: 
        return {"users": [{"username": r[0], "role": r[1], "is_locked": bool(r[2])} for r in db.execute("SELECT username, role, is_locked FROM users").fetchall()]}

@app.post("/users/create")
async def u_cr(n: UserCreate, u: User = Depends(get_current_user)):
    if u.role != "senior_admin": raise HTTPException(403, "Insufficient privileges")
    validate_password_complexity(n.password)
    logger.info(f"👤 Creating user: {n.username}")
    try:
        with sqlite3.connect(DB_FILE) as db: 
            # FIX: Explicit columns to match schema even if old DB exists
            db.execute("INSERT INTO users (username, hashed_password, role, failed_attempts, is_locked, force_change) VALUES (?, ?, ?, 0, 0, 1)", 
                       (n.username, get_password_hash(n.password), n.role))
            db.commit()
            logger.info(f"✅ User {n.username} created.")
    except sqlite3.IntegrityError:
        logger.warning(f"⚠️ User creation failed: {n.username} already exists")
        raise HTTPException(400, "Username already exists")
    except Exception as e:
        logger.error(f"❌ DB Error during user creation: {e}")
        raise HTTPException(500, f"Database error: {e}")
    return {"status": "ok"}

@app.post("/users/change-password")
async def ch_p(p: PasswordChange, u: User = Depends(get_current_user)):
    validate_password_complexity(p.new_password)
    with sqlite3.connect(DB_FILE) as db:
        stored = db.execute("SELECT hashed_password FROM users WHERE username=?", (u.username,)).fetchone()
        if not verify_password(p.old_password, stored[0]): raise HTTPException(400, "Wrong old password")
        db.execute("UPDATE users SET hashed_password=?, force_change=0 WHERE username=?", (get_password_hash(p.new_password), u.username))
        db.commit()
    return {"status": "ok"}

@app.post("/users/{username}/reset-password")
async def reset_pwd(username: str, d: UserReset, u: User = Depends(get_current_user)):
    if u.role != "senior_admin": raise HTTPException(403)
    with sqlite3.connect(DB_FILE) as db:
        db.execute("UPDATE users SET hashed_password=?, force_change=1 WHERE username=?", (get_password_hash(d.new_password), username))
        db.commit()
    return {"status": "ok"}

@app.get("/admin/stats")
async def ast(u: User = Depends(get_current_user)):
    with sqlite3.connect(DB_FILE) as db: 
        return {"stats": [{"user":r[0],"module":r[1],"count":r[2],"last":r[3]} for r in db.execute("SELECT user_id, module, usage_count, last_used FROM usage_stats ORDER BY last_used DESC").fetchall()]}

@app.get("/saved-reports")
async def reps(u: User = Depends(check_setup)):
    with sqlite3.connect(DB_FILE) as db:
        q = "SELECT id, filename, summary, solution, original_context, created_at FROM saved_reports WHERE user_id=? ORDER BY id DESC LIMIT 50"
        args = (u.username,)
        if u.role == "senior_admin": 
            q = "SELECT id, filename, summary, solution, original_context, created_at FROM saved_reports ORDER BY id DESC LIMIT 100"
            args = ()
        res = [{"id":r[0],"filename":r[1],"summary":r[2],"solution":r[3],"context":r[4],"date":r[5]} for r in db.execute(q, args).fetchall()]
    return {"reports": res}

@app.delete("/saved-reports/{rid}")
async def d_rep(rid: int, u: User = Depends(get_current_user)):
    with sqlite3.connect(DB_FILE) as db:
        if u.role == "senior_admin": db.execute("DELETE FROM saved_reports WHERE id=?", (rid,))
        else: db.execute("DELETE FROM saved_reports WHERE id=? AND user_id=?", (rid, u.username))
        db.commit()
    return {"status": "ok"}

@app.post("/users/{name}/block")
async def bl_u(name: str, u: User = Depends(get_current_user)):
    if u.role != "senior_admin" or name == 'admin': raise HTTPException(403)
    with sqlite3.connect(DB_FILE) as db: 
        db.execute("UPDATE users SET is_locked=1 WHERE username=?", (name,))
        db.commit()
    return {"status": "ok"}

@app.post("/users/{name}/unblock")
async def unbl_u(name: str, u: User = Depends(get_current_user)):
    if u.role != "senior_admin": raise HTTPException(403)
    with sqlite3.connect(DB_FILE) as db: 
        db.execute("UPDATE users SET is_locked=0, failed_attempts=0 WHERE username=?", (name,))
        db.commit()
    return {"status": "ok"}

@app.delete("/users/{name}")
async def del_u(name: str, u: User = Depends(get_current_user)):
    if u.role != "senior_admin" or name == 'admin': raise HTTPException(403)
    with sqlite3.connect(DB_FILE) as db: 
        db.execute("DELETE FROM users WHERE username=?", (name,))
        db.commit()
    return {"status": "ok"}

@app.get("/debug/export")
async def debug_export(u: User = Depends(get_current_user)):
    if u.role != "senior_admin": raise HTTPException(403)
    if not os.path.exists(SHAREABLE_DEBUG_FILE): return {"status": "No debug data"}
    with open(SHAREABLE_DEBUG_FILE, "r", encoding="utf-8") as f: return json.load(f)

@app.get("/system/status")
async def sys_stat():
    return {"db": "OK", "model": CURRENT_MODEL, "mode": "Enterprise-Stable"}

@app.get("/")
async def root(): return FileResponse("index.html") if os.path.exists("index.html") else "Backend OK"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
