import re
import json
import email
import argparse
import urllib.parse
from difflib import SequenceMatcher
from email import policy
from email.parser import BytesParser, Parser
from datetime import datetime
from pathlib import Path
from collections import defaultdict
 

 
 
# ===== PHISHING KEYWORDS ================================================================================================================================================
 
URGENCY_KEYWORDS = [
    "urgent", "immediate", "action required", "verify now", "confirm now",
    "account suspended", "account locked", "unusual activity", "suspicious login",
    "limited time", "expires soon", "final notice", "last chance", "act now",
    "click here immediately", "respond immediately", "within 24 hours",
    "within 48 hours", "your account will be", "failure to respond",
    "security alert", "unauthorized access", "password expired",
]
 
SUSPICIOUS_KEYWORDS = [
    "click here", "click the link", "click below", "verify your account",
    "confirm your identity", "update your information", "update your details",
    "enter your password", "enter your credentials", "log in to your account",
    "reset your password", "unlock your account", "validate your account",
    "dear customer", "dear user", "dear account holder", "dear valued customer",
    "congratulations you won", "you have been selected", "claim your prize",
    "wire transfer", "bank transfer", "gift card", "bitcoin", "crypto payment",
]
 
# Words that describe a role or department rather than a brand. If one of these
# sits next to a brand-like word in a display name ("PayPal Security"), the
# display name is claiming to be an organization rather than a person.
GENERIC_DISPLAY_WORDS = [
    "security", "team", "support", "service", "services", "notification",
    "notifications", "alert", "alerts", "noreply", "admin", "administrator",
    "customer", "account", "accounts", "update", "updates", "department",
    "official", "info", "information", "help", "helpdesk", "billing",
    "online", "verify", "verification", "the",
    # department and function names
    "payable", "payables", "receivable", "receivables", "payroll", "accounting",
    "finance", "sales", "marketing", "orders", "shipping", "delivery", "invoice",
    "invoices", "hr", "mail", "reply", "team",
]
 
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".info", ".biz", ".click", ".link",
]
 
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
    "tiny.cc", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
]
 
DANGEROUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".com", ".vbs", ".js", ".jse", ".wsf",
    ".scr", ".pif", ".hta", ".ps1", ".reg", ".msi", ".jar",
]
 
SUSPICIOUS_EXTENSIONS = [
    ".zip", ".rar", ".7z", ".iso", ".img", ".doc", ".docm",
    ".xls", ".xlsm", ".ppt", ".pptm",
]
 
# ===== HELPERS ==========================================================================================================================================================
 
def extract_domain(email_address):
    # Use a regular expression to extract the domain from the email address.
    # Lowercase it so PayPal.com and paypal.com compare as equal, and return an empty string (not None) when there is no match so callers never crash.
    match = re.search(r'@([\w.-]+)', (email_address or "").lower())
    return match.group(1) if match else ""
 
def extract_url(text):
    # Use a regular expression to extract URLs from the text.
    # Always returns a list (empty if nothing is found) so it is safe to loop over.
    url_pattern = re.compile(r'https?://[^\s<>"\'}\]\)]+|www\.[^\s<>"\'}\]\)]+', re.IGNORECASE)
    return url_pattern.findall(text or "")
 
def get_domain_from_url(url):
    # Use urllib.parse to extract the domain from the URL.
    # urlparse finds no domain without a scheme, so add one for www.example.com links.
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        return ""
    # removeprefix removes the exact text "www." only (lstrip would strip characters)
    return host.lower().removeprefix("www.")
 
def is_ip_address(domain):
    # Check if domain is an IP address (each part must be 0-255)
    match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', domain)
    return bool(match) and all(int(part) <= 255 for part in match.groups())
 
def get_domain_core(domain):
    # Pull out the brand-like part of a domain: the second-level label with anything after a hyphen removed. paypall-alerts.com -> paypall, mail.google.com -> google
    if not domain:
        return ""
    labels = domain.lower().split(".")
    core_label = labels[-2] if len(labels) >= 2 else labels[0]
    return core_label.split("-")[0]
 
def string_similarity(a, b):
    # Similarity from 0.0 to 1.0 between two strings (works on different lengths)
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()
 
def extract_display_name(from_header):
    # Pull the display name out of a From header.
    # "PayPal Security" <security@paypal.com> -> PayPal Security
    match = re.match(r'^\s*"?([^"<]+?)"?\s*<', from_header or "")
    return match.group(1).strip() if match else ""
 
def detect_display_name_spoofing(from_header):
    # Compare the identity claimed in the display name against the domain that is actually in the same address
    display_name = extract_display_name(from_header)
    domain = extract_domain(from_header)
    domain_core = get_domain_core(domain)
 
    result = {
        "display_name": display_name, "claimed_brand": "", "domain": domain,
        "domain_core": domain_core, "status": "none", "similarity": 0.0,
    }
    if not display_name or not domain_core:
        return result
 
    words = [w.lower() for w in re.findall(r"[A-Za-z]{3,}", display_name)]
    candidates = [w for w in words if w not in GENERIC_DISPLAY_WORDS]
    if not candidates:
        return result

    # A role word next to the brand word is what separates "PayPal Security" from an ordinary personal name like "John Smith"
    has_org_word = any(w in GENERIC_DISPLAY_WORDS for w in words)
 
    # Treat the longest remaining word as the claimed brand
    brand = max(candidates, key=len)
    similarity = round(string_similarity(brand, domain_core), 2)
    result["claimed_brand"] = brand
    result["similarity"] = similarity
 
    if brand == domain_core:
        result["status"] = "consistent"
    elif similarity >= 0.75:
        result["status"] = "typosquat"
    elif has_org_word:
        result["status"] = "unrelated"
    return result
 
def detect_link_domain_mismatch(link_domain, sender_domain):
    # Compare a link's domain against the sender's own domain. A link that is very close to the sender domain but not identical is a typosquat signal.
    link_core = get_domain_core(link_domain)
    sender_core = get_domain_core(sender_domain)
    if not link_core or not sender_core or link_core == sender_core:
        return "none", 0.0
    similarity = round(string_similarity(link_core, sender_core), 2)
    return ("typosquat" if similarity >= 0.75 else "none"), similarity


 # ==================== PARSER ==============================================

def parse_email_file(file_path):
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

def parse_email_bytes(email_bytes):
    return BytesParser(policy=policy.default).parsebytes(email_bytes)

def read_msg(msg):
    plaintext = ""
    html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                plaintext += part.get_content() or ""
            elif ct == "text/html":
                html += part.get_content() or ""
    else:
        ct = msg.get_content_type()
        if ct == "text/plain":
            plaintext = msg.get_content() or ""
        elif ct == "text/html":
            html = msg.get_content() or ""
    return plaintext, html

def extract_attachments(msg):
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "unknown"
            content_type = part.get_content_type()
            attachments.append({"filename": filename, "type": content_type})
    return attachments+
