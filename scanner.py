# scanner.py

import re
from email import message_from_string

def parse_eml_content(raw_text):
    """Extracts Sender, Subject, and Body from a raw .eml or .txt file."""
    msg = message_from_string(raw_text)
    sender = msg.get("From", "")
    subject = msg.get("Subject", "")
    
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if content_type == "text/plain" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="ignore")
        else:
            body = raw_text

    # Fallback if the uploaded file was just plain text without headers
    if not sender and not subject and not body.strip():
        body = raw_text

    return sender, subject, body.strip()


def defang_url(url):
    """Converts live links into safe, non-clickable text (e.g., hxxp://example[.]com)."""
    safe_url = re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)
    safe_url = safe_url.replace(".", "[.]")
    return safe_url


def run_heuristic_scan(sender, subject, body, sensitivity="Standard"):
    """Runs local regex and heuristic checks for phishing and malware indicators."""
    combined_text = f"{subject} {body}".lower()
    sender_lower = sender.lower()
    
    red_flags = []
    score = 5

    # 1. Extract all URLs from the email body
    raw_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
    defanged_urls = [defang_url(u) for u in raw_urls]

    # 2. Check for Typosquatting / Brand Spoofing in Sender Address
    spoof_patterns = ["paypa1", "micr0soft", "g00gle", "amaz0n", "app1e", "netf1ix", "verify", "security-alert"]
    triggered_spoofs = [p for p in spoof_patterns if p in sender_lower]
    if triggered_spoofs:
        red_flags.append(
            f"**Suspicious Sender Domain:** The address `{sender}` contains lookalike characters "
            f"or high-risk security keywords ({', '.join(triggered_spoofs)})."
        )
        score += 30

    # 3. Check for Psychological Urgency & Social Engineering Triggers
    urgency_keywords = [
        "urgent", "immediately", "suspended", "24 hours", "unauthorized",
        "frozen", "verify your identity", "overdue", "legal action", "wire transfer"
    ]
    found_urgency = [word for word in urgency_keywords if word in combined_text]
    if found_urgency:
        red_flags.append(
            f"**Social Engineering Urgency:** Uses high-pressure panic phrases "
            f"({', '.join(found_urgency[:4])}) designed to rush the victim into acting."
        )
        score += 20

    # 4. Inspect Extracted URLs for IP Hosts, HTTP, and Link Shorteners
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd"]
    for url in raw_urls:
        url_lower = url.lower()
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url_lower):
            red_flags.append(
                f"**Raw IP Address URL:** `{defang_url(url)}` routes directly to an IP address "
                f"instead of a verified domain name."
            )
            score += 35
        elif any(short in url_lower for short in shorteners):
            red_flags.append(
                f"**Obfuscated Short Link:** `{defang_url(url)}` uses a URL shortener to hide the true destination."
            )
            score += 20
        elif url_lower.startswith("http://"):
            red_flags.append(
                f"**Unencrypted Link (HTTP):** `{defang_url(url)}` lacks SSL/TLS encryption."
            )
            score += 15

    # 5. Scan for Malware Double Extensions & Executable Payloads
    double_ext_match = re.findall(
        r'\b[\w-]+\.(?:pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(?:exe|bat|scr|vbs|js|ps1|cmd)\b',
        combined_text
    )
    if double_ext_match:
        red_flags.append(
            f"**Malware Double Extension Detected:** Found `{', '.join(double_ext_match)}` — "
            f"an executable virus disguised as a safe document."
        )
        score += 45

    # Apply Zero-Trust sensitivity multiplier if selected
    if sensitivity == "Zero-Trust (Strict)" and red_flags:
        score = int(score * 1.25)

    # Cap score between 5 and 99
    final_score = min(score, 99) if red_flags else 5

    return final_score, defanged_urls, red_flags
