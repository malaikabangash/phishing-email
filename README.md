# 🛡️ PhishGuard AI — Email Phishing & Malware Threat Scanner

PhishGuard AI is an interactive cybersecurity web application built with Python and Streamlit. It analyzes suspicious emails for phishing links, domain spoofing, double-extension virus attachments, and psychological manipulation tactics.

## 🚀 Key Security Features

* **Hybrid Threat Detection Engine:** Combines instant Python Regex heuristics with deep LLM analysis via the Groq API (`llama-3.3-70b-versatile`).
* **Automatic URL Defanging:** Extracts embedded links and converts them into safe, non-clickable formats (`hxxp://example[.]com`) so analysts never accidentally trigger a live phishing link.
* **Malware Signature Checks:** Flags dangerous double-extension executables disguised as normal documents (such as `.pdf.exe` or `.doc.scr`).
* **Raw Email File Parser:** Supports both copy-pasted text and direct `.eml` or `.txt` file uploads.
* **1-Click Demo Samples:** Includes built-in test cases for credential harvesting, fake invoice malware, and safe emails.

## 📂 Project Architecture

* `app.py` — Main Streamlit dashboard interface and user controls.
* `scanner.py` — Local Regex engine for URL extraction, URL defanging, and heuristic scoring.
* `ai_analyzer.py` — Groq API client for evaluating social engineering tactics.
* `sample_emails.py` — Pre-loaded test cases for instant demonstration.
* `requirements.txt` — Required Python packages.

## 🛠️ How to Run Locally

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/phishguard-ai.git](https://github.com/your-username/phishguard-ai.git)
   cd phishguard-ai
