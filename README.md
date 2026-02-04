## 📺 Watch the Live Demo
[![Watch the video]([https://img.youtube.com/vi/VIDEO_ID/maxresdefault.jpg](https://youtu.be/mWN2Xe3-ipo))]

*(Click the URL to watch the demo on YouTube)*

---
# 🛡️ LogSentinel: Local AI Log Analyzer (Dockerized)

![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.9-blue)
![Docker](https://img.shields.io/badge/docker-ready-blue)
![Status](https://img.shields.io/badge/status-production--ready-orange)

**LogSentinel** is a secure, self-hosted web application for System Administrators and SREs. It allows you to analyze server logs using **Local LLMs** (like Llama 3 via Ollama) without sending sensitive data to the cloud.

> **Privacy First:** All analysis happens locally. PII (IPs, Emails, Credit Cards) is masked *before* processing.

---

## 🚀 Key Features

* **🐳 Docker Ready:** Deploy in seconds with `docker-compose`.
* **🔒 Smart Data Masking:** Automatically redacts IPs, Emails, Credit Cards (PAN), and National IDs.
* **⚡ Async & Resilient:** Built on FastAPI with semaphore concurrency control to prevent server overload.
* **📝 Actionable Reports:** AI provides Root Cause, Analysis Steps, and Fixes.
* **🔐 Enterprise Security:** JWT Auth, Role-Based Access Control (RBAC), and Audit Logs.

---

## 🛠️ Quick Start (Docker) - Recommended

### Prerequisites
1.  **[Ollama](https://ollama.com)** installed and running.
2.  **Docker Desktop** installed.

### 1. Run Ollama
Ensure you have a model (e.g., Llama 3) pulled:
```bash
ollama run llama3
