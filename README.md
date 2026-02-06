# LogSentinel: Local AI Log Analyzer (Dockerized)

> Watch the Live Demo: https://youtu.be/mWN2Xe3-ipo

LogSentinel is a secure, self-hosted web application designed for System Administrators and SREs. It allows you to analyze server logs using Local LLMs (via Ollama) directly on your machine, ensuring no sensitive data is sent to the cloud.

KEY FEATURES
---------------------------------------------------------
1. Privacy First: automatically masks IPs, Emails, and Credit Cards before analysis.
2. Docker Native: deploys instantly using standard `docker-compose`.
3. Persistent Memory: caches results in a local SQLite database for instant retrieval.
4. Enterprise Security: includes JWT Authentication and Role-Based Access Control.

QUICK START
---------------------------------------------------------

1. PREREQUISITES
   - Install Ollama (https://ollama.com)
   - Install Docker Desktop

2. PREPARE AI MODEL
   Run this in your terminal to download the brain:
   $ ollama pull llama3

3. INSTALL & LAUNCH
   $ git clone https://github.com/lockdoggg/LogSentinel-Local-AI.git
   $ cd LogSentinel-Local-AI
   $ docker-compose up -d --build

4. ACCESS DASHBOARD
   - URL: http://localhost:8000
   - User: admin
   - Pass: admin (Change immediately after login)

CONFIGURATION
---------------------------------------------------------
You can change settings in `docker-compose.yml`:

- OLLAMA_URL: Defaults to http://host.docker.internal:11434/api/chat (Host machine).
- MODEL_NAME: Defaults to 'llama3'. Change this if you use 'mistral' or 'qwen'.

LICENSE
---------------------------------------------------------
MIT License. Free for personal and commercial use.
