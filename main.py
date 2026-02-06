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
from collections import deque
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
import requests
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

# --- SMART AUTO-DISCOVERY START ---
def autodiscover_ollama() -> str:
    """
    Автоматически ищет Ollama.
    Приоритет:
    1. Переменная окружения (если задана вручную).
    2. Внутренний контейнер (режим full-stack).
    3. Хост машина (режим по умолчанию).
    """
    # 1. Если пользователь явно задал URL, верим ему
    env_url = os.getenv("OLLAMA_URL")
    if env_url and "host.docker.internal" not in env_url:
        logger.info(f"🔧 Configuration: Using custom OLLAMA_URL: {env_url}")
        return env_url

    # 2. Пробуем найти соседа (внутренний контейнер)
    internal_url = "http://ollama-service:11434/api/chat"
    try:
        # Быстрый чек (timeout 0.5 сек)
        requests.get(internal_url.replace("/api/chat", ""), timeout=0.5)
        logger.info("🐳 Discovery: Found internal 'ollama-service'. Using Full-Stack mode.")
        return internal_url
    except:
        pass # Не нашли, идем дальше

    # 3. Если не нашли, используем хост
    logger.info("💻 Discovery: Internal Ollama not found. Defaulting to Host Machine.")
    return "http://host.docker.internal:11434/api/chat"

# Инициализируем URL при старте
OLLAMA_URL = autodiscover_ollama()
# --- SMART AUTO-DISCOVERY END ---

SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY or SECRET_KEY == "CHANGE_THIS_SECRET":
    SECRET_KEY = secrets.token_urlsafe(32)
    logger.warning("⚠️ No JWT_SECRET set. Generated random.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
MODEL_NAME = os.getenv("MODEL_NAME", "llama3")

# PATHS (MAPPED TO DOCKER VOLUME)
DB_FILE = "/app/data/qs_base.db"
SHAREABLE_DEBUG_FILE = "/app/data/last_analysis_debug.json"
KB_FILE = "/app/data/knowledge_base.json"

# Ensure persistence directory exists
os.makedirs("/app/data", exist_ok=True)

# CACHE & PROTECTION
MAX_CACHE_SIZE = 5000
RESPONSE_CACHE: Dict[str, str] = {}
BLOCKED_IPS: Dict[str, float] = {}
BLOCK_DURATION = 1800 

# REGEX PATTERNS
CRITICAL_REGEX = re.compile(r"error|fatal|fail|panic|alert|critical|exception|traceback|deadlock|killed|cannot|denied|refused|timeout|rejected|declined|unauthorized|unavailable|unreachable|warn|warning|\b500\b|\b502\b|\b503\b|\b504\b|\b403\b", re.IGNORECASE)
NOISE_REGEX = re.compile(r"\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}|\[\d+\]")

# SECURITY CONTEXTS
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# CONCURRENCY CONTROL
ANALYSIS_SEMAPHORE = asyncio.Semaphore(10) # Max 10 parallel AI requests
SCRIPT_SEMAPHORE = asyncio.Semaphore(5)

app = FastAPI(title="LogSentinel Enterprise", version="1.3.0-Production")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ==========================================
# 2. DATA MASKING & SANITIZATION
# ==========================================

def extract_ai_content(json_data: dict) -> str:
    """Parses responses from both Ollama and OpenAI-compatible APIs"""
    try:
        if "choices" in json_data and isinstance(json_data["choices"], list):
            if len(json_data["choices"]) > 0:
                msg = json_data["choices"][0].get("message", {})
                return msg.get("content", "").strip()
        if "message" in json_data:
            return json_data["message"].get("content", "").strip()
        if "response" in json_data:
            return json_data.get("response", "").strip()
    except Exception as e:
        logger.error(f"JSON Parse Error: {e}")
    return ""

def mask_sensitive_data(text: str) -> str:
    """Removes PII (IPs, Emails, Credit Cards, National IDs)"""
    if not text: return ""
    
    # Mask IPs
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP_HIDDEN]', text)
    # Mask Emails
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_HIDDEN]', text)
    
    # Mask Credit Cards (PAN)
    pan_pattern = r'(?<!\d)(?:\d{4}[-. ]?){3}\d{4}(?!\d)'
    text = re.sub(pan_pattern, '[CARD_HIDDEN]', text)

    # Mask Kazakhstan IIN (National ID)
    iin_pattern = r'(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{6}(?!\d)'
    text = re.sub(iin_pattern, '[IIN_HIDDEN]', text)
    
    return text

def sanitize_ai_response(text: str) -> str:
    """Removes potentially destructive commands from AI output"""
    dangerous = [r"rm\s+-rf", r"mkfs", r"dd\s+if", r"chmod\s+777", r":\(\)\{ :\|:& \};:"]
    for pat in dangerous:
        if re.search(pat, text, re.IGNORECASE):
            text = re.sub(pat, "[BLOCKED]", text, flags=re.IGNORECASE)
            text += "\n\n⚠️ **SECURITY WARNING:** Malicious commands removed."
    return text

def save_shareable_debug(source: str, prompt: str, response: str, duration: float, error: str = None, raw_body: str = None):
    try:
        debug_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": source,
            "status": "ERROR" if error else "OK",
            "error_msg": str(error) if error else None,
            "metrics": {"duration_sec": round(duration, 4), "target": OLLAMA_URL},
            "prompt_preview": mask_sensitive_data(prompt[:1000]),
            "response_preview": mask_sensitive_data(response[:1000]) if response else "None",
            "raw_server_response": raw_body[:2000] if raw_body else None
        }
        with open(SHAREABLE_DEBUG_FILE, "w", encoding="utf-8") as f:
            json.dump(debug_data, f, indent=2, ensure_ascii=False)
    except: pass

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"CRITICAL: {exc}\n{traceback.format_exc()}")
    return JSONResponse(status_code=500, content={"detail": "System Error", "error": str(exc)})

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    client_ip = request.client.host
    if client_ip in BLOCKED_IPS:
        if time.time() < BLOCKED_IPS[client_ip]:
            return JSONResponse(status_code=403, content={"detail": "IP Banned"})
        else:
            del BLOCKED_IPS[client_ip]
    return await call_next(request)

def detect_security_threat(text: str, ip: str) -> Optional[str]:
    t = text.lower()
    if "union select" in t or "information_schema" in t:
        BLOCKED_IPS[ip] = time.time() + BLOCK_DURATION
        return "🚨 **SQL INJECTION** blocked."
    return None

def validate_script_safety(t: str):
    if any(b in t.lower() for b in ["rm -rf", "mkfs", ":(){:|:&};:"]): 
        raise HTTPException(400, "Malicious content")

def normalize_log_for_cache(text: str) -> str:
    clean = NOISE_REGEX.sub("", text[:10000]) 
    return hashlib.md5(clean.encode('utf-8')).hexdigest()

def validate_password_complexity(p: str):
    if len(p) < 8 or not re.search(r"\d", p): raise HTTPException(400, "Weak password")

# ==========================================
# 3. DATABASE MANAGEMENT
# ==========================================

def get_password_hash(p): return pwd_context.hash(p)
def verify_password(p, h): return pwd_context.verify(p, h)

def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute("PRAGMA journal_mode=WAL;")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, hashed_password TEXT, role TEXT, failed_attempts INTEGER DEFAULT 0, is_locked INTEGER DEFAULT 0, force_change INTEGER DEFAULT 1)''')
        
        # [UPDATED] Added log_hash column for persistent caching
        try:
            c.execute('''CREATE TABLE IF NOT EXISTS saved_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, filename TEXT, summary TEXT, solution TEXT, original_context TEXT, source TEXT, severity INTEGER, created_at TEXT, log_hash TEXT, FOREIGN KEY(user_id) REFERENCES users(username))''')
            # Migration for existing databases
            try:
                c.execute("ALTER TABLE saved_reports ADD COLUMN log_hash TEXT")
            except: 
                pass # Column likely exists
        except Exception as e:
            logger.warning(f"DB Migration warning: {e}")

        c.execute('''CREATE TABLE IF NOT EXISTS usage_stats (user_id TEXT, module TEXT, usage_count INTEGER DEFAULT 0, last_used TEXT, PRIMARY KEY(user_id, module))''')
        conn.commit()
        # Create default admin if not exists
        c.execute("SELECT username FROM users WHERE username='admin'")
        if not c.fetchone(): 
            c.execute("INSERT INTO users VALUES (?, ?, ?, 0, 0, 1)", ("admin", get_password_hash("admin"), "senior_admin"))
            conn.commit()
        conn.close()
    except Exception as e: logger.error(f"DB Init Failed: {e}")

def update_stats(user: str, module: str):
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(DB_FILE) as db:
            db.execute("INSERT OR IGNORE INTO usage_stats (user_id, module, usage_count, last_used) VALUES (?, ?, 0, ?)", (user, module, ts))
            db.execute("UPDATE usage_stats SET usage_count = usage_count + 1, last_used = ? WHERE user_id = ? AND module = ?", (ts, user, module))
    except: pass

init_db()

# ==========================================
# 4. KNOWLEDGE BASE & PERSISTENT CACHE
# ==========================================

KNOWLEDGE_BASE = []

if os.path.exists(KB_FILE):
    try:
        with open(KB_FILE, "r", encoding="utf-8") as f:
            KNOWLEDGE_BASE = json.load(f)
        logger.info(f"Loaded Knowledge Base: {len(KNOWLEDGE_BASE)} entries")
    except Exception as e:
        logger.error(f"Failed to load KB: {e}")

def check_knowledge_base(text: str) -> Optional[Dict]:
    tl = text.lower()
    for r in KNOWLEDGE_BASE:
        if any(tr in tl for tr in r.get("triggers", [])): 
            return r["response"]
    return None

def check_db_cache(log_hash: str) -> Optional[str]:
    """Retrieves solution from SQLite if RAM cache misses"""
    try:
        with sqlite3.connect(DB_FILE) as db:
            # Get the most recent solution for this exact error hash
            row = db.execute("SELECT solution FROM saved_reports WHERE log_hash=? ORDER BY id DESC LIMIT 1", (log_hash,)).fetchone()
            if row: return row[0]
    except: pass
    return None

# ==========================================
# 5. AUTHENTICATION & USERS
# ==========================================

class Token(BaseModel): access_token: str; token_type: str; force_change: bool; role: str
class User(BaseModel): username: str; role: str; force_change: bool
class UserCreate(BaseModel): username: str; password: str; role: str
class UserReset(BaseModel): new_password: str
class PasswordChange(BaseModel): old_password: str; new_password: str
class LogRequest(BaseModel): log_text: str
class ScriptRequest(BaseModel): task: str; language: str

def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try: payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except: raise HTTPException(401)
    with sqlite3.connect(DB_FILE) as db:
        row = db.execute("SELECT username, role, is_locked, force_change FROM users WHERE username=?", (payload.get("sub"),)).fetchone()
    if not row or row[2]: raise HTTPException(401)
    return User(username=row[0], role=row[1], force_change=bool(row[3]))

async def check_setup(u: User = Depends(get_current_user)):
    if u.force_change: raise HTTPException(403, "CHANGE_PASS_REQ")
    return u

@app.post("/token")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    with sqlite3.connect(DB_FILE) as db:
        row = db.execute("SELECT username, hashed_password, failed_attempts, is_locked, force_change, role FROM users WHERE username=?", (form.username,)).fetchone()
    if not row: time.sleep(1); raise HTTPException(401)
    if row[3]: raise HTTPException(403, "LOCKED")
    
    if not verify_password(form.password, row[1]):
        fail = row[2] + 1
        lock = 1 if fail >= 3 and row[5] != 'senior_admin' else 0
        with sqlite3.connect(DB_FILE) as db: db.execute("UPDATE users SET failed_attempts=?, is_locked=? WHERE username=?", (fail, lock, row[0]))
        raise HTTPException(401)
    
    with sqlite3.connect(DB_FILE) as db: db.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (row[0],))
    update_stats(row[0], "LOGIN")
    return {"access_token": create_access_token({"sub": row[0], "role": row[5]}), "token_type": "bearer", "force_change": bool(row[4]), "role": row[5]}

@app.get("/users/me")
async def me(u: User = Depends(get_current_user)): return {"username": u.username, "role": u.role, "force_change": u.force_change}

# ==========================================
# 6. CORE LOGIC (STREAMING & AI)
# ==========================================

async def process_log_stream(file_obj) -> str:
    """Reads file stream, highlights errors, and extracts context"""
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
                    if extracted: extracted[-1] += f"\n{line}"
                    capture -= 1
                    continue
                if CRITICAL_REGEX.search(line):
                    block = "... [CTX] ...\n" + "\n".join(prev_lines) + f"\n🔴 >>> {line} <<< 🔴"
                    extracted.append(block)
                    capture = 8
                    total_len += len(block)
                else:
                    prev_lines.append(line)
                if total_len > 12000: break
            except ValueError: break
        if total_len > 12000: break
    return "\n---\n".join(extracted) if extracted else "CLEAN_LOG_MARKER"

def extract_smart_context_string(text: str) -> str:
    """Extracts windows of text around errors from manual input"""
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

async def query_ollama_prod(context: str, raw_len: int) -> str:
    # 1. Calculate Hash
    cache_key = normalize_log_for_cache(context)
    
    # 2. Check RAM Cache
    if cache_key in RESPONSE_CACHE:
        save_shareable_debug("RAM_HIT", context, RESPONSE_CACHE[cache_key], 0.001, raw_len)
        return RESPONSE_CACHE[cache_key]
    
    # 3. Check DB Cache (Persistent)
    db_hit = await run_in_threadpool(check_db_cache, cache_key)
    if db_hit:
        RESPONSE_CACHE[cache_key] = db_hit # Revive to RAM
        save_shareable_debug("DB_HIT", context, db_hit, 0.005, raw_len)
        return db_hit

    # 4. AI Generation (US MARKET PROMPT)
    sys_prompt = (
        "YOU ARE: A Senior SRE at a top-tier tech company. Your tone is professional, direct, and highly technical.\n"
        "TASK: Diagnose the root cause from the provided log snippet.\n"
        "CONSTRAINTS:\n"
        "1. DO NOT repeat the error message. The user already sees it.\n"
        "2. IGNORE masked PII like [IP_HIDDEN] or [CARD_HIDDEN]. Treat them as valid infrastructure data.\n"
        "3. PROVIDE actionable solutions only.\n"
        "\n"
        "OUTPUT FORMAT (Markdown):\n"
        "### 🔴 Root Cause\n"
        "(Explain exactly WHAT happened and WHY in 1-2 sentences)\n\n"
        "### 🔍 Technical Analysis\n"
        "(Explain the underlying system failure, e.g., permission issues, volume mounts, or network timeouts)\n\n"
        "### 🛠️ Remediation\n"
        "(Step-by-step fix with exact commands in code blocks)"
    )
    user_prompt = f"LOG DATA:\n{context}\n\nGENERATE SRE REPORT:"
    
    start_t = time.perf_counter()
    try:
        async with ANALYSIS_SEMAPHORE:
            def _req():
                return requests.post(OLLAMA_URL, json={
                    "model": MODEL_NAME, 
                    "messages": [{"role": "system", "content": sys_prompt}, {"role": "user", "content": user_prompt}],
                    "stream": False, 
                    "keep_alive": -1,
                    # OPTIONS OPTIMIZED FOR SRE TASK
                    "options": {"temperature": 0.3, "num_predict": 600}
                }, timeout=120)
            
            r = await run_in_threadpool(_req)
            duration = time.perf_counter() - start_t
            
            if r.status_code != 200:
                err = f"HTTP {r.status_code}: {r.text[:200]}"
                save_shareable_debug("AI_FAIL", user_prompt, "", duration, err, r.text)
                return f"AI Error: {err}"
            
            try: json_resp = r.json()
            except: json_resp = {}
            
            resp = extract_ai_content(json_resp)
            if not resp:
                save_shareable_debug("AI_EMPTY", user_prompt, "", duration, "Empty content", r.text)
                return "Error: Could not read AI response."

            clean_resp = sanitize_ai_response(resp)
            
            # Save to RAM
            if len(RESPONSE_CACHE) > MAX_CACHE_SIZE: RESPONSE_CACHE.pop(next(iter(RESPONSE_CACHE)))
            RESPONSE_CACHE[cache_key] = clean_resp
            
            save_shareable_debug("AI_OK", user_prompt, clean_resp, duration)
            return clean_resp
    except Exception as e:
        save_shareable_debug("SYS_FAIL", user_prompt, "", time.perf_counter() - start_t, str(e))
        return f"System Error: {e}"

async def stream_ollama_script(task: str, lang: str) -> str:
    sys_p = f"Role: Senior Dev. Lang: {lang}. Comments: English. OUTPUT CODE ONLY. No markdown wrapper."
    start_t = time.perf_counter()
    try:
        async with SCRIPT_SEMAPHORE:
            def _req():
                return requests.post(OLLAMA_URL, json={
                    "model": MODEL_NAME, 
                    "messages": [{"role": "system", "content": sys_p}, {"role": "user", "content": task}],
                    "stream": False, 
                    "options": {"temperature": 0.2, "num_predict": 2048} 
                }, timeout=180)
            r = await run_in_threadpool(_req)
            duration = time.perf_counter() - start_t
            
            if r.status_code != 200:
                return f"// Error: {r.status_code}"
            
            try: json_resp = r.json()
            except: json_resp = {}
            
            resp = extract_ai_content(json_resp).replace("```", "").strip()
            if not resp: return "// Error: Empty response."
            
            save_shareable_debug("SCRIPT_OK", task, resp, duration)
            return resp
    except Exception as e: return f"// Error: {e}"

# ==========================================
# 7. API ENDPOINTS
# ==========================================

@app.post("/analyze")
async def analyze(r: LogRequest, request: Request, u: User = Depends(check_setup)):
    update_stats(u.username, "ANALYZE")
    if t := detect_security_threat(r.log_text, request.client.host):
        return {"results": [{"filename": "Input", "status": "alert", "solution": t}]}
    
    ctx = await run_in_threadpool(extract_smart_context_string, r.log_text)
    ctx_clean = mask_sensitive_data(ctx)
    if ctx == "CLEAN_LOG_MARKER": return {"results": [{"filename": "Input", "status": "clean", "solution": "✅ No errors found."}]}
    
    if kb := check_knowledge_base(ctx):
        return {"results": [{"filename": "Input", "status": "ok", "solution": f"**SOLUTION (KB)**\n{kb['summary']}", "original_context": ctx_clean, "source": "KB"}]}
    
    ai_res = await query_ollama_prod(ctx_clean, len(r.log_text))
    
    # [UPDATED] Save result + hash to DB for persistent caching
    try:
        log_hash = normalize_log_for_cache(ctx_clean)
        with sqlite3.connect(DB_FILE) as db:
             db.execute("INSERT INTO saved_reports (user_id, filename, summary, solution, original_context, source, severity, created_at, log_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                        (u.username, "Input", ai_res[:100], ai_res, ctx_clean, "AI", 50, datetime.now().strftime("%Y-%m-%d %H:%M"), log_hash))
    except Exception as e:
        logger.error(f"DB Save Error: {e}")
    
    return {"results": [{"filename": "Input", "status": "ok", "solution": ai_res, "original_context": ctx_clean, "source": "AI"}]}

@app.post("/analyze-files")
async def files_an(request: Request, files: List[UploadFile] = File(...), u: User = Depends(check_setup)):
    update_stats(u.username, f"FILES({len(files)})")
    res = []
    for f in files:
        head = await f.read(2048)
        await f.seek(0)
        if t := detect_security_threat(head.decode(errors='ignore'), request.client.host):
            res.append({"filename": f.filename, "status": "alert", "solution": t}); continue
        
        ctx = await process_log_stream(f)
        ctx_clean = mask_sensitive_data(ctx)
        if ctx == "CLEAN_LOG_MARKER": res.append({"filename": f.filename, "status": "clean", "solution": "Clean"}); continue
        if kb := check_knowledge_base(ctx): res.append({"filename": f.filename, "status": "ok", "solution": f"KB: {kb['summary']}", "original_context": ctx_clean}); continue
        
        ai_res = await query_ollama_prod(ctx_clean, 0)
        
        # [UPDATED] Save to DB
        try:
            log_hash = normalize_log_for_cache(ctx_clean)
            with sqlite3.connect(DB_FILE) as db:
                db.execute("INSERT INTO saved_reports (user_id, filename, summary, solution, original_context, source, severity, created_at, log_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                        (u.username, f.filename, ai_res[:100], ai_res, ctx_clean, "AI", 50, datetime.now().strftime("%Y-%m-%d %H:%M"), log_hash))
        except: pass
        
        res.append({"filename": f.filename, "status": "ok", "solution": ai_res, "original_context": ctx_clean})
    return {"results": res}

@app.post("/generate-script")
async def gen(req: ScriptRequest, u: User = Depends(check_setup)):
    update_stats(u.username, "GEN")
    validate_script_safety(req.task)
    return {"script": await stream_ollama_script(req.task, req.language)}

# ==========================================
# 8. ADMIN DASHBOARD & USER MANAGEMENT
# ==========================================

@app.get("/users")
async def u_list(u: User = Depends(get_current_user)):
    with sqlite3.connect(DB_FILE) as db: return {"users": [{"username": r[0], "role": r[1], "is_locked": bool(r[2])} for r in db.execute("SELECT username, role, is_locked FROM users").fetchall()]}

@app.post("/users/create")
async def u_cr(n: UserCreate, u: User = Depends(get_current_user)):
    if u.role != "senior_admin": raise HTTPException(403)
    with sqlite3.connect(DB_FILE) as db: db.execute("INSERT INTO users VALUES (?, ?, ?, 0, 0, 1)", (n.username, get_password_hash(n.password), n.role))
    return {"status": "ok"}

@app.post("/users/change-password")
async def ch_p(p: PasswordChange, u: User = Depends(get_current_user)):
    validate_password_complexity(p.new_password)
    with sqlite3.connect(DB_FILE) as db:
        if not verify_password(p.old_password, db.execute("SELECT hashed_password FROM users WHERE username=?", (u.username,)).fetchone()[0]): raise HTTPException(400)
        db.execute("UPDATE users SET hashed_password=?, force_change=0 WHERE username=?", (get_password_hash(p.new_password), u.username))
    return {"status": "ok"}

@app.get("/admin/stats")
async def ast(u: User = Depends(get_current_user)):
    with sqlite3.connect(DB_FILE) as db: 
        return {"stats": [{"user":r[0],"module":r[1],"count":r[2],"last":r[3]} for r in db.execute("SELECT user_id, module, usage_count, last_used FROM usage_stats ORDER BY last_used DESC").fetchall()]}

@app.get("/saved-reports")
async def reps(u: User = Depends(check_setup)):
    with sqlite3.connect(DB_FILE) as db:
        if u.role == "senior_admin":
            q = "SELECT id, filename, summary, solution, original_context, created_at, user_id FROM saved_reports ORDER BY id DESC LIMIT 100"
            res = [{"id":r[0],"filename":r[1],"summary":r[2],"solution":r[3],"context":r[4],"date":r[5], "owner": r[6]} for r in db.execute(q).fetchall()]
        else:
            q = "SELECT id, filename, summary, solution, original_context, created_at FROM saved_reports WHERE user_id=? ORDER BY id DESC LIMIT 50"
            res = [{"id":r[0],"filename":r[1],"summary":r[2],"solution":r[3],"context":r[4],"date":r[5]} for r in db.execute(q, (u.username,)).fetchall()]
    return {"reports": res}

@app.delete("/saved-reports/{rid}")
async def d_rep(rid: int, u: User = Depends(get_current_user)):
    with sqlite3.connect(DB_FILE) as db:
        if u.role == "senior_admin":
            db.execute("DELETE FROM saved_reports WHERE id=?", (rid,))
        else:
            db.execute("DELETE FROM saved_reports WHERE id=? AND user_id=?", (rid, u.username))
    return {"status": "ok"}

@app.post("/users/{name}/block")
async def bl_u(name: str, u: User = Depends(get_current_user)):
    if u.role != "senior_admin": raise HTTPException(403)
    if name == 'admin': raise HTTPException(400, "Cannot block root")
    with sqlite3.connect(DB_FILE) as db: db.execute("UPDATE users SET is_locked=1 WHERE username=?", (name,))
    return {"status": "ok"}

@app.post("/users/{name}/unblock")
async def unbl_u(name: str, u: User = Depends(get_current_user)):
    if u.role != "senior_admin": raise HTTPException(403)
    with sqlite3.connect(DB_FILE) as db: db.execute("UPDATE users SET is_locked=0, failed_attempts=0 WHERE username=?", (name,))
    return {"status": "ok"}

@app.delete("/users/{name}")
async def del_u(name: str, u: User = Depends(get_current_user)):
    if u.role != "senior_admin": raise HTTPException(403)
    if name.lower() == 'admin': raise HTTPException(400)
    with sqlite3.connect(DB_FILE) as db: db.execute("DELETE FROM users WHERE username=?", (name,))
    return {"status": "ok"}

@app.get("/debug/export")
async def debug_export(u: User = Depends(get_current_user)):
    if u.role != "senior_admin": raise HTTPException(403)
    if not os.path.exists(SHAREABLE_DEBUG_FILE): return {"status": "No debug data"}
    with open(SHAREABLE_DEBUG_FILE, "r", encoding="utf-8") as f: return json.load(f)

@app.get("/system/status")
async def sys_stat():
    ai = False
    try: ai = await run_in_threadpool(lambda: requests.get(OLLAMA_URL.replace("/api/chat",""), timeout=1).status_code==200)
    except: pass
    return {"db": "OK", "ai": "OK" if ai else "FAIL", "model": MODEL_NAME}

@app.get("/favicon.ico", include_in_schema=False)
async def favicon(): return Response(status_code=204)

@app.get("/")
async def root(): return FileResponse("index.html") if os.path.exists("index.html") else "Backend OK"

@app.on_event("startup")
async def start():
    logger.info("Starting LogSentinel Enterprise...")
    logger.info(f"Target AI URL: {OLLAMA_URL}")
    try: 
        requests.post(OLLAMA_URL, json={"model": MODEL_NAME, "keep_alive": -1}, timeout=2)
        logger.info(f"✅ Ollama Connection Verified")
    except: 
        logger.warning(f"⚠️ Ollama unreachable at startup. It might still be loading.")
