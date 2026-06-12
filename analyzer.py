import re
from urllib.parse import urlparse

import email
from email import policy
from threat_intel import check_url_virustotal
TRUSTED_DOMAINS = [
    "paypal.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com"
]
BEC_KEYWORDS = [
    "payment authorization",
    "wire transfer",
    "bank transfer",
    "process payment",
    "urgent payment",
    "payment document",
    "invoice attached",
    "attached invoice",
    "gift cards",
    "confidential request",
    "end of the day",
    "speed is a priority",
    "quick payment",
    "sending this from my phone",
    "in meetings",
    "back-to-back meetings",
    "ceo",
    "finance department"
]
SUSPICIOUS_TLDS = [".xyz", ".ru", ".top", ".info", ".click"]
PAYROLL_KEYWORDS = [
    "direct deposit",
    "payroll",
    "salary",
    "disbursements",
    "bank account",
    "account details",
    "payment details",
    "review direct deposit",
    "updated your direct deposit",
    "change notification",
    "routing number",
    "employee benefits",
    "hr department"
]
KEYWORDS_HIGH = [
    "urgent",
    "immediately",
    "account locked",
    "password expired",
    "verify now",
    "click now",
    "security alert",
    "recover account",
    "refund",
    "refund pending",
    "overcharge",
    "transaction",
    "verify your mobile number",
    "registered mobile number",
    "funds will be processed",
    "scan the qr code",
    "payment failed",
    "bank account",
    "upi",
    "wallet",
    "irctc"
]

ACCOUNT_CHANGE_KEYWORDS = [
    "information was updated",
    "review or edit changes",
    "change notification",
    "new account details",
    "without your knowledge",
    "reversing it promptly",
    "secure link below"
]
KEYWORDS_MEDIUM = [
    "verify",
    "login",
    "update",
    "confirm",
    "password",
    "security",
    "account",
    "access"
]
JOB_SCAM_KEYWORDS = [
    "congratulations",
    "selected for the position",
    "job pairing system",
    "remote position",
    "remote work",
    "work from home",
    "salary range",
    "attached job description",
    "fill out the attached form",
    "confirm your interest",
    "introductory call",
    "immediate hiring",
    "no interview required",
    "linkedin profile",
    "recruitment team"
]
ATTACHMENT_KEYWORDS = [
    "attached form",
    "attached job description",
    "attachment",
    ".doc",
    ".docx",
    ".pdf",
    ".zip"
]
URGENCY_PHRASES = [
    "expires in",
    "limited time",
    "within 24 hours",
    "within 48 hours",
    "action required",
    "immediate action",
    "business days"
]
QR_KEYWORDS = [
    "qr code",
    "scan qr",
    "scan the qr code"
]
LOOKALIKE_PATTERNS = {
    "paypa1.com": "paypal.com",
    "g00gle.com": "google.com",
    "micr0soft.com": "microsoft.com"
}

def parse_email_content(raw_email):
    msg = email.message_from_string(raw_email, policy=policy.default)

    return {
        "from": str(msg.get("From", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "reply_to": str(msg.get("Reply-To", ""))
    }

def check_sender_mismatch(headers):
    score = 0
    reasons = []

    from_addr = headers.get("from", "").lower()
    reply_to = headers.get("reply_to", "").lower()

    if reply_to and reply_to != from_addr:
        score += 25
        reasons.append("Reply-To differs from sender")

    return score, reasons

def extract_urls(text):
    return re.findall(r"https?://[^\s]+", text)


def get_domain(url):
    try:
        return urlparse(url).netloc.replace("www.", "")
    except:
        return ""


def check_domain(domain):
    if domain in TRUSTED_DOMAINS:
        return 0, "Trusted domain"

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return 40, f"Suspicious domain extension: {tld}"

    for trusted in TRUSTED_DOMAINS:
        name = trusted.split(".")[0]
        if name in domain and domain != trusted:
            return 50, f"Possible impersonation of {trusted}"

    for word in ["login", "secure", "verify", "account"]:
        if word in domain:
            return 30, f"Suspicious word in domain: {word}"

    return 10, "Unknown domain"


def analyze_email(text):
    text_lower = text.lower()

    score = 0
    reasons = []

    salary_pattern = re.search(
        r"\$([0-9,]{5,})",
        text
    )

    if salary_pattern:
        score += 20
        reasons.append(
            "High salary offer detected"
        )
    # -----------------------------
    # Parse Email Headers
    # -----------------------------
    headers = parse_email_content(text)

    sender_score, sender_reasons = check_sender_mismatch(headers)
    score += sender_score
    reasons.extend(sender_reasons)

    # -----------------------------
    # Extract URLs
    # -----------------------------
    urls = extract_urls(text)

    # -----------------------------
    # Keyword Analysis
    # -----------------------------
    for word in KEYWORDS_HIGH:
        if word in text_lower:
            score += 25
            reasons.append(f"High-risk keyword detected: {word}")

    for word in KEYWORDS_MEDIUM:
        if word in text_lower:
            score += 10
            reasons.append(f"Suspicious keyword detected: {word}")
    
    for item in ATTACHMENT_KEYWORDS:
        if item in text_lower:
            score += 15
            reasons.append(
                f"Attachment indicator detected: {item}"
            )
    # -----------------------------
# Job Scam Detection
# -----------------------------
    for phrase in JOB_SCAM_KEYWORDS:
        if phrase in text_lower:
            score += 15
            reasons.append(
                f"Job recruitment scam indicator: {phrase}"
            )
    
    # -----------------------------
# Payroll Scam Detection
# -----------------------------
    for phrase in PAYROLL_KEYWORDS:
        if phrase in text_lower:
            score += 20
            reasons.append(
                f"Payroll-related indicator detected: {phrase}"
            )
    
    for phrase in ACCOUNT_CHANGE_KEYWORDS:
        if phrase in text_lower:
            score += 15
            reasons.append(
                f"Account change indicator detected: {phrase}"
            )
    # -----------------------------
# Business Email Compromise Detection
# -----------------------------
    for phrase in BEC_KEYWORDS:
        if phrase in text_lower:
            score += 20
            reasons.append(
                f"BEC indicator detected: {phrase}"
            )
    # -----------------------------
# Urgency Detection
# -----------------------------
    for phrase in URGENCY_PHRASES:
        if phrase in text_lower:
            score += 15
            reasons.append(
                f"Urgency phrase detected: {phrase}"
            )

# -----------------------------
# QR Code Detection
# -----------------------------
    for word in QR_KEYWORDS:
        if word in text_lower:
            score += 25
            reasons.append(
                "QR code payment/verification request detected"
            )

# -----------------------------
# Refund Scam Detection
# -----------------------------
    if "refund" in text_lower:
        score += 20
        reasons.append(
            "Refund-related social engineering detected"
        )

# -----------------------------
# Domain Analysis + VirusTotal
# -----------------------------
    threat_intelligence = []

    for url in urls:

        domain = get_domain(url)

    # Lookalike domains
        if domain in LOOKALIKE_PATTERNS:
            score += 50
            reasons.append(
                f"Possible impersonation of {LOOKALIKE_PATTERNS[domain]}"
            )

    # Local domain checks
        domain_score, reason = check_domain(domain)

        score += domain_score
        reasons.append(f"{domain}: {reason}")

    # HTTP check
        if not url.startswith("https"):
            score += 10
            reasons.append("Non-secure HTTP link detected")

    # VirusTotal check
        vt_result = check_url_virustotal(url)

        if vt_result:

            malicious = vt_result.get("malicious", 0)
            suspicious = vt_result.get("suspicious", 0)

            if malicious > 0:
                score += 40

                reasons.append(
                    f"{domain}: flagged malicious by VirusTotal"
                )

            elif suspicious > 0:
                score += 20

                reasons.append(
                    f"{domain}: suspicious according to VirusTotal"
                )

            threat_intelligence.append({
                "url": url,
                "malicious": malicious,
                "suspicious": suspicious
            })

    # -----------------------------
    # Final Score
    # -----------------------------
    score = min(score, 100)

    if score <= 30:
        level = "Low"
    elif score <= 75:
        level = "Medium"
    else:
        level = "High"

    return {
    "headers": headers,
    "risk_score": score,
    "risk_level": level,
    "urls_found": urls,
    "reasons": reasons,
    "threat_intelligence": threat_intelligence
}