import re
import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "secure",
    "security",
    "suspended",
    "confirm",
    "urgent",
    "update",
    "payment",
]


def is_ip_address(hostname):
    """Check whether the hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(url):
    """
    Analyze a URL for common phishing and security indicators.

    Returns a risk score from 0 to 100 and a list of findings.
    """

    findings = []
    score = 0

    url = url.strip()

    if not url:
        return {
            "url": url,
            "risk_score": 100,
            "findings": ["Empty URL"]
        }

    try:
        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:
            return {
                "url": url,
                "risk_score": 100,
                "findings": ["Invalid URL"]
            }

        hostname = hostname.lower()

        # Check for HTTP
        if parsed.scheme.lower() != "https":
            findings.append("URL does not use HTTPS")
            score += 15

        # Check for IP address
        if is_ip_address(hostname):
            findings.append("URL uses an IP address instead of a domain")
            score += 30

        # Check for suspicious keywords
        url_lower = url.lower()

        matched_keywords = []

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                matched_keywords.append(keyword)

        if matched_keywords:
            findings.append(
                "Suspicious keywords detected: "
                + ", ".join(matched_keywords)
            )
            score += min(len(matched_keywords) * 5, 20)

        # Check for unusually long URLs
        if len(url) > 150:
            findings.append("Unusually long URL")
            score += 10

        # Check for excessive subdomains
        if hostname.count(".") >= 4:
            findings.append("Unusually large number of subdomains")
            score += 10

        # Check for @ symbol
        if "@" in url:
            findings.append("URL contains an @ symbol")
            score += 20

        # Check for encoded characters
        if "%" in url:
            findings.append("URL contains encoded characters")
            score += 5

        # Check for suspicious hyphen usage
        if hostname.count("-") >= 3:
            findings.append("Domain contains multiple hyphens")
            score += 5

        score = min(score, 100)

        return {
            "url": url,
            "risk_score": score,
            "findings": findings
        }

    except Exception as error:
        return {
            "url": url,
            "risk_score": 100,
            "findings": [f"URL analysis error: {error}"]
        }


def extract_urls(text):
    """
    Extract HTTP and HTTPS URLs from text.
    """

    pattern = r'https?://[^\s<>"\']+'

    return re.findall(pattern, text, re.IGNORECASE)


def analyze_text_urls(text):
    """
    Find and analyze every URL contained in a piece of text.
    """

    urls = extract_urls(text)

    results = []

    for url in urls:
        results.append(analyze_url(url))

    return results