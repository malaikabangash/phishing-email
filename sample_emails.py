# sample_emails.py

SAMPLES = {
    "Custom Input": {
        "sender": "",
        "subject": "",
        "body": ""
    },
    "Phishing: Fake Bank Alert": {
        "sender": "security-alert@paypa1-account-verify.com",
        "subject": "URGENT: Your account has been suspended due to unauthorized login!",
        "body": (
            "Dear Customer,\n\n"
            "We detected an unauthorized login attempt to your account from an unrecognized IP address. "
            "For your safety, we have temporarily frozen your account.\n\n"
            "You must verify your identity within 24 hours or your account will be permanently closed.\n\n"
            "Click here to restore access immediately:\n"
            "http://192.168.45.12/login-paypal-secure/verify.php\n\n"
            "Thank you,\nAccount Security Team"
        )
    },
    "Malware: Fake Invoice Attachment": {
        "sender": "billing-dept@vendor-payments-portal.net",
        "subject": "OVERDUE: Unpaid Invoice #88492 - Legal Action Pending",
        "body": (
            "Hello,\n\n"
            "Your company has an overdue balance of $4,250.00. Immediate payment is required today "
            "to avoid late penalties and legal collection proceedings.\n\n"
            "Please download and open the attached invoice document to view the wire transfer details:\n"
            "Attachment: Invoice_Statement_Oct2026.pdf.exe\n\n"
            "You can also view the payment tracker here:\n"
            "http://bit.ly/3xYz99MaliciousLink\n\n"
            "Regards,\nAccounts Receivable"
        )
    },
    "Safe: University Lab Schedule": {
        "sender": "cs-department@university.edu.pk",
        "subject": "Schedule Update: Cybersecurity Lab Submission",
        "body": (
            "Hi everyone,\n\n"
            "Please note that the final submission for the Cybersecurity lab report has been moved "
            "to Friday at 5:00 PM.\n\n"
            "Make sure your documentation and code snippets are clearly formatted before uploading "
            "to the official student portal:\n"
            "https://portal.university.edu.pk/submissions\n\n"
            "Best regards,\nLab Instructor"
        )
    }
}
