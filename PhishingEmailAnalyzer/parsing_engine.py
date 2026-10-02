import re
import json
import email
import argparse
import urllib.parse
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

TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "apple.com",
    "amazon.com", "paypal.com", "facebook.com", "twitter.com", "linkedin.com",
    "github.com", "dropbox.com", "icloud.com", "yahoo.com", "hotmail.com",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".info", ".biz", ".click", ".link",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
    "tiny.cc", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
]
# ==================================================================================================================================================================

def extract_domain(email):
    # Use a regular expression to extract the domain from the email
    match = re.search(r'@([\w.-]+)', email)
    return match.group(1) if match else None

def extract_url(text):
    # Use a regular expression to extract URLs from the text
    url_pattern = re.compile(r'https?://[^\s<>"\'}\]\)]+|www\.[^\s<>"\'}\]\)]+', re.IGNORECASE)
    return url_pattern.findall(text) or None

def get_domain_from_url(url):
    # Use urllib.parse to extract the domain from the URL
    parsed_url = urllib.parse.urlparse(url)
    return parsed_url.netloc

def is_ip_address(domain):
    # Check if domain is an IP address
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))


def domain_similarity(d1, d2):
    # Simple check for typosquatting — similar but not equal domains
    if d1 == d2:
        return False
    
    # Check if one domain contains most of the other (e.g. paypa1.com vs paypal.com)
    base1 = d1.split(".")[0]
    base2 = d2.split(".")[0]
    
    if len(base1) > 3 and len(base2) > 3:
        # Count matching characters
        matches = sum(c1 == c2 for c1, c2 in zip(base1, base2))
        similarity = matches / max(len(base1), len(base2))
        return similarity > 0.75
    return False

