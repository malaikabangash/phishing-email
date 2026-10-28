# app.py

import os
import time
import streamlit as st
from dotenv import load_dotenv

from sample_emails import SAMPLES
from scanner import parse_eml_content, run_heuristic_scan
from ai_analyzer import run_ai_analysis

# Load environment variables from .env if present
load_dotenv()

# 1. Page Configuration
st.set_page_config(
    page_title="PhishGuard AI | Email Threat Scanner",
    page_icon="🛡️",
    layout="wide"
)

# 2. Sidebar Configuration
with st.sidebar:
    st.header("⚙️ Scanner Configuration")
    
    api_key_input = st.text_input(
        "Groq API Key",
        value=os.getenv("GROQ_API_KEY", ""),
        type="password",
        placeholder="gsk_...",
        help="Required for AI Social Engineering Analysis. Leave blank to run local heuristic checks only."
    )
    
    sensitivity_mode = st.selectbox(
        "Scan Sensitivity",
        ["Standard", "Zero-Trust (Strict)"]
    )
    
    st.divider()
    st.subheader("🧪 1-Click Test Samples")
    selected_sample = st.selectbox(
        "Load a preset email:",
        list(SAMPLES.keys())
    )
    
    st.divider()
    st.caption(
        "**PhishGuard AI** inspects emails for domain spoofing, raw IP links, "
        "double-extension malware attachments, and psychological urgency traps."
    )

# 3. Main Header
st.title("🛡️ PhishGuard AI — Email & Malware Threat Scanner")
st.write("Analyze suspicious emails for phishing links, virus attachments, and social engineering tactics.")

# 4. Main Input Area (Tabs)
tab_paste, tab_upload = st.tabs(["📋 Paste Email Content", "📁 Upload .EML / .TXT File"])

with tab_paste:
    col_sender, col_subject = st.columns(2)
    with col_sender:
        sender_input = st.text_input(
            "Sender Email Address",
            value=SAMPLES[selected_sample]["sender"],
            placeholder="e.g., support@security-verify.com"
        )
    with col_subject:
        subject_input = st.text_input(
            "Email Subject Line",
            value=SAMPLES[selected_sample]["subject"],
            placeholder="e.g., URGENT: Account Suspended"
        )
    
    body_input = st.text_area(
        "Email Body Content",
        value=SAMPLES[selected_sample]["body"],
        height=200,
        placeholder="Paste the email text here, including any links or attachment names..."
    )

with tab_upload:
    uploaded_file = st.file_uploader("Upload a raw `.eml` or `.txt` email file", type=["eml", "txt"])
    if uploaded_file is not None:
        raw_file_text = uploaded_file.read().decode("utf-8", errors="ignore")
        parsed_sender, parsed_subject, parsed_body = parse_eml_content(raw_file_text)
        
        if parsed_sender:
            sender_input = parsed_sender
        if parsed_subject:
            subject_input = parsed_subject
        body_input = parsed_body
        
        st.success("File parsed successfully! Click the scan button below to analyze.")

# 5. Live Scanning Execution
if st.button("🔍 Scan Email for Threats", type="primary", use_container_width=True):
    if not body_input.strip():
        st.warning("Please paste an email body, upload a file, or choose a preset sample from the sidebar.")
    else:
        with st.status("Running PhishGuard Security Engine...", expanded=True) as status:
            st.write("🔎 Checking sender domain and header anomalies...")
            time.sleep(0.3)
            
            st.write("🔗 Extracting and defanging embedded URLs...")
            time.sleep(0.3)
            
            st.write("🦠 Scanning for double-extension malware signatures...")
            risk_score, defanged_links, red_flags = run_heuristic_scan(
                sender_input, subject_input, body_input, sensitivity_mode
            )
            time.sleep(0.3)
            
            st.write("🧠 Running AI threat & social engineering analysis...")
            ai_report = run_ai_analysis(
                api_key_input, sender_input, subject_input, body_input, red_flags
            )
            
            status.update(label="Security Scan Complete!", state="complete", expanded=False)

        st.divider()

        # 6. Threat Verdict Banner
        if risk_score >= 70:
            st.error(
                "### 🚨 VERDICT: HIGH PHISHING / MALWARE RISK DETECTED\n"
                "Do not click any links, open attachments, or reply to this sender."
            )
            risk_label = "Critical Risk"
            delta_color = "inverse"
        elif risk_score >= 35:
            st.warning(
                "### ⚠️ VERDICT: SUSPICIOUS EMAIL\n"
                "This email contains manipulation or link anomalies. Verify the sender independently."
            )
            risk_label = "Moderate Risk"
            delta_color = "off"
        else:
            st.success(
                "### ✅ VERDICT: SAFE / LOW RISK\n"
                "No obvious phishing links, spoofed domains, or malware signatures were detected."
            )
            risk_label = "Clean"
            delta_color = "normal"

        # 7. KPI Metric Cards
        m1, m2, m3 = st.columns(3)
        m1.metric("Threat Score", f"{risk_score} / 100", delta=risk_label, delta_color=delta_color)
        m2.metric("Extracted Links", f"{len(defanged_links)} Found", delta="Defanged below" if defanged_links else "No links")
        m3.metric("Red Flags Triggered", f"{len(red_flags)} Alerts", delta="Review findings" if red_flags else "0 Alerts", delta_color=delta_color)

        st.progress(risk_score / 100)

        # 8. Two Expanders for Heuristic Findings & Defanged URLs
        col_left, col_right = st.columns([3, 2])

        with col_left:
            with st.expander("🚩 Triggered Security Red Flags", expanded=True):
                if red_flags:
                    for flag in red_flags:
                        st.markdown(f"- {flag}")
                else:
                    st.write("- No domain spoofing, panic triggers, or malware extensions found.")

        with col_right:
            with st.expander("🔗 Defanged URLs (Safe View)", expanded=True):
                if defanged_links:
                    st.caption("Links are defanged so you cannot accidentally click them:")
                    for link in defanged_links:
                        st.code(link, language="text")
                else:
                    st.write("- No URLs detected in the email body.")

        # 9. AI Deep Analysis Report
        with st.expander("🧠 AI Threat & Social Engineering Breakdown", expanded=True):
            st.markdown(ai_report)
