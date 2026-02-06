# 🛡️ LogSentinel: Local AI Log Analyzer (Dockerized)

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)
[![Status](https://img.shields.io/badge/status-production--ready-orange)](https://github.com/lockdoggg/LogSentinel-Local-AI)

### 📺 [Watch the Live Demo (YouTube)](https://youtu.be/mWN2Xe3-ipo)

**LogSentinel** is a secure, self-hosted web application for System Administrators and SREs. It allows you to analyze server logs using **Local LLMs** (like Llama 3 via Ollama) without sending sensitive data to the cloud.

> **Privacy First:** All analysis happens locally. PII (IPs, Emails, Credit Cards) is automatically masked *before* processing.

---

## 🚀 Key Features

* **🐳 Docker Native:** Deploy instantly using standard `docker-compose`. No extra scripts required.
* **🔒 Smart Data Masking:** Automatically redacts IPs, Emails, Credit Cards (PAN), and National IDs.
* **⚡ Persistent Memory:** Caches analysis results in a local SQLite database. Repeated errors are solved instantly.
* **📝 Actionable Reports:** AI provides Root Cause, Analysis Steps, and Fixes.
* **🔐 Enterprise Security:** JWT Authentication, Role-Based Access Control (RBAC), and Audit Logs.

---

## 🛠️ Quick Start

### Prerequisites
1.  **[Ollama](https://ollama.com)** installed and running on your host machine.
2.  **Docker Desktop** installed.

### Step 1: Prepare AI Model
Open your terminal and pull a model (we recommend Llama 3 or Qwen 2.5):
```bash
ollama pull llama3
```
Step 2: Clone & Launch
```bash
git clone [https://github.com/lockdoggg/LogSentinel-Local-AI.git](https://github.com/lockdoggg/LogSentinel-Local-AI.git)
cd LogSentinel-Local-AI
```
# Build and start the container
```bash
docker-compose up -d --build
```
Step 3: Access Dashboard

    Open your browser at http://localhost:8000.

    Login with default credentials:

        Username: admin

        Password: admin (You will be forced to change this on first login)

⚙️ Configuration

You can customize the connection settings in docker-compose.yml:
Variable,Default,Description
OLLAMA_URL,http://host.docker.internal:11434/api/chat,Connects to Ollama running on the host machine.
MODEL_NAME,llama3,The AI model to use (must be pulled in Ollama).
JWT_SECRET,(Auto-generated),Set a fixed string if you want persistent sessions across restarts.

🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.
📄 License

MIT
