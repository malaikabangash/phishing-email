# ai_analyzer.py

import os
from groq import Groq

def run_ai_analysis(api_key, sender, subject, body, local_flags):
    """Sends the email details to Groq LLM for deep social engineering analysis."""
    active_key = api_key or os.getenv("GROQ_API_KEY")
    
    if not active_key or active_key == "gsk_your_actual_groq_api_key_here":
        return (
            "### ℹ️ AI Deep Analysis Skipped\n"
            "* Enter a valid **Groq API Key** in the left sidebar to unlock live LLM social engineering analysis.\n"
            "* Local heuristic and regex security checks above have still been completed."
        )

    try:
        client = Groq(api_key=active_key)
        
        system_prompt = (
            "You are a Senior Cybersecurity Threat Analyst. Analyze the provided email for phishing, "
            "social engineering, and malware risks. "
            "Format your response strictly using clear headings, bullet points, and plain English. "
            "Do NOT use markdown tables or dense paragraphs. "
            "Include these three sections:\n"
            "### 1. Social Engineering & Intent\n"
            "### 2. Technical Anomalies\n"
            "### 3. Recommended Security Action"
        )

        user_prompt = (
            f"Sender: {sender}\n"
            f"Subject: {subject}\n"
            f"Email Body:\n{body}\n\n"
            f"Local Heuristics Triggered: {len(local_flags)} flags."
        )

        response = client.chat.completions.create(
            model="llama-3.1-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2,
            max_tokens=500
        )
        return response.choices[0].message.content

    except Exception as e:
        return f"### ⚠️ AI Analysis Error\n* Could not complete LLM scan: `{str(e)}`"
