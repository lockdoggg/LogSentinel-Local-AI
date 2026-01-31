# QS Enterprise - AI Log Analyzer & Admin Tool

**QS Enterprise** is a secure, self-hosted web application designed for System Administrators and SREs. It leverages AI (LLMs) to analyze server logs, detect critical errors, and generate remediation scripts, all while strictly prioritizing data privacy and security.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-green.svg)
![Status](https://img.shields.io/badge/Status-Production--Ready-success)

## 🚀 Key Features

* **🛡️ Smart Data Masking (PCI DSS/PII Compliant)**
    * Automatically redacts sensitive data *before* sending it to the AI.
    * Masks **IP Addresses**, **Emails**, **Credit Card Numbers (PAN)** (aggressive detection), and **Kazakhstan IINs** (with date validation).
    * AI is instructed to ignore masked tokens (`[IP_HIDDEN]`, etc.) to prevent hallucinations.

* **🧠 AI-Powered Analysis**
    * **Log Parsing:** Detects stack traces, HTTP errors (500/503), and critical failures using "Smart Context" windowing.
    * **Solutions:** Provides structured reports with: 1. Issue Summary, 2. Analysis Steps, 3. Recommendations.
    * **Universal Parser:** Compatible with both **Ollama** and **OpenAI-compatible** API responses.

* **📜 Script Generator**
    * Generates ready-to-use **Bash**, **SQL**, and **Python** scripts based on natural language descriptions.
    * Includes a safety filter to block malicious commands (e.g., `rm -rf`).

* **🔐 Enterprise Security**
    * **Role-Based Access Control (RBAC):** `admin` (Root) vs. `senior_admin` roles.
    * **Secure Auth:** JWT (JSON Web Tokens) with HS256 encryption.
    * **Account Protection:** Auto-lockout after 3 failed login attempts.
    * **Privacy:** Regular users see *only* their own report history. Admins have a global audit view.

* **💾 Local & Offline First**
    * Zero external dependencies for the UI (Single HTML file).
    * Uses **SQLite** for user management and report archiving.
    * Designed to work behind corporate firewalls.

---

## 🛠️ Prerequisites

1.  **Python 3.8+** installed.
2.  **AI Endpoint:** Access to an LLM API (e.g., a local **Ollama** instance or a corporate vLLM load balancer).

## 📦 Installation

1.  **Clone the repository** (or download the source files):
    ```bash
    git clone [https://github.com/your-username/qs-enterprise.git](https://github.com/your-username/qs-enterprise.git)
    cd qs-enterprise
    ```

2.  **Create a virtual environment (Recommended):**
    ```bash
    python -m venv venv
    # Linux/Mac:
    source venv/bin/activate
    # Windows:
    .\venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## ⚙️ Configuration

Before running the server, you must configure the connection to your AI model.

Open `main.py` and edit the **Configuration Section** (lines 35-43), or set Environment Variables.

| Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `OLLAMA_URL` | **Required.** The URL of your AI API. | `http://192.168.1.50:11434/api/chat` |
| `MODEL_NAME` | The model tag to use on the server. | `qwen2.5-latest:latest` |
| `JWT_SECRET_KEY` | Secret key for signing tokens. | **CHANGE THIS IN PROD!** |

> **⚠️ SECURITY WARNING:** Never commit your real `JWT_SECRET_KEY` or internal IP addresses to a public GitHub repository. Use Environment Variables in production.

---

## 🚀 Usage

1.  **Start the Server:**
    ```bash
    uvicorn main:app --host 0.0.0.0 --port 8000
    ```

2.  **Access the Web Interface:**
    Open your browser and navigate to: `http://localhost:8000`

3.  **First Login:**
    * **Username:** `admin`
    * **Password:** `admin`
    * *Note:* The system will force you to change the password immediately upon the first login.

---

## 🛡️ Security & Privacy

* **Database:** The system automatically creates `qs_base.db` (SQLite) on the first run. This file contains hashed passwords and report history. **Do not commit this file to Git.**
* **Logs:** The application generates debug logs (`last_analysis_debug.json`) containing raw interactions with the AI. These are for debugging only and are excluded via `.gitignore`.
* **Isolation:** The archive system prevents users from viewing reports created by other colleagues.

---

## ⚠️ Disclaimer

This tool is provided "as is". While it includes safety filters for generated scripts, **always review code and commands before executing them on production servers.** The authors are not responsible for any damage caused by the execution of AI-generated suggestions.

