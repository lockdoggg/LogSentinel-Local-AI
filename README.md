# 🛡️ LogSentinel: Local AI Log Analyzer (Dockerized)

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)
[![Ollama](https://img.shields.io/badge/AI-Ollama-black)](https://ollama.com/)
![Status](https://img.shields.io/badge/status-production--ready-orange)

### 📺 [Watch the Live Demo (YouTube)](https://youtu.be/mWN2Xe3-ipo)

**LogSentinel** is a secure, self-hosted web application for System Administrators and SREs. It leverages **Local LLMs** (via Ollama) to analyze server logs, diagnose errors, and suggest fixes—all without sending sensitive data to the cloud.

> **Privacy First:** All analysis happens locally. PII (IPs, Emails, Credit Cards) is masked *before* processing.

---

## 🏗️ Architecture

LogSentinel runs inside Docker and connects securely to your Host machine's Ollama instance via `host.docker.internal`.

```mermaid
graph TD
    User[👨‍💻 SysAdmin] -->|Browser| UI[Web Dashboard :8000]
    subgraph "Docker Container"
        UI -->|API| FastAPI[FastAPI Backend]
        FastAPI -->|1. Masking| PII[PII Redactor]
        PII -->|2. Cache Check| DB[(SQLite DB)]
    end
    PII -->|3. Inference| Ollama[🦙 Ollama (Host Machine)]
    Ollama -->|4. Report| FastAPI
🚀 Key Features

    🐳 Docker Native: Uses standard docker-compose. Zero config required.

    🔒 Privacy First: Automatically masks IPs, Emails, Credit Cards, and National IDs before analysis.

    ⚡ Persistent Memory: Caches analysis results in SQLite. Repeated errors are solved instantly.

    🔐 Enterprise Security: JWT Authentication, RBAC (Admin/Senior), and Audit Logs.

🛠️ Installation & Setup
Prerequisites

    Ollama installed and running.

    Docker Desktop (Mac/Windows) installed.

Step 1: Prepare AI Model

Ensure you have a model downloaded in Ollama (on your host machine).
Bash

ollama pull llama3
# OR
ollama pull qwen2.5-coder:1.5b

Step 2: Clone & Launch
Bash

git clone [https://github.com/lockdoggg/LogSentinel-Local-AI.git](https://github.com/lockdoggg/LogSentinel-Local-AI.git)
cd LogSentinel-Local-AI

# Build and start the container
docker-compose up -d --build

Step 3: Access Dashboard

    Open http://localhost:8000.

    Login with default credentials:

        Username: admin

        Password: admin (Change on first login)

⚙️ Configuration

You can customize the AI connection in docker-compose.yml:
Variable	Default	Description
OLLAMA_URL	http://host.docker.internal:11434/api/chat	Connects to Ollama on host.
MODEL_NAME	llama3	The model used for analysis.
JWT_SECRET	(Auto-generated)	Set a fixed string for persistent sessions.
🤝 Contributing

Pull requests are welcome!
📄 License

MIT
