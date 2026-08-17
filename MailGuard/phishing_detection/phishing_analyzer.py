import re


PHISHING_KEYWORDS = [
    "urgent",
    "immediately",
    "immediate verification",
    "account verification",
    "verify your account",
    "verify account",
    "verify your identity",
    "confirm your account",
    "confirm your identity",
    "account suspended",
    "account locked",
    "account requires verification",
    "reset your password",
    "password",
    "login",
    "sign in",
    "security alert",
    "unusual activity",
    "suspicious activity",
    "payment required",
    "payment failed",
    "update your payment",
    "click here",
]


def detect_phishing(text):
    """
    Analyze email text for common phishing indicators.
    Returns a phishing score from 0 to 100.
    """

    text_lower = text.lower()

    score = 0
    findings = []

    # Phishing language
    matched_keywords = []

    for keyword in PHISHING_KEYWORDS:
        if keyword in text_lower:
            matched_keywords.append(keyword)

    if matched_keywords:
        keyword_score = min(len(matched_keywords) * 10, 50)
        score += keyword_score

        findings.append(
            "Phishing language detected: "
            + ", ".join(matched_keywords)
        )

    # Account verification
    verification_patterns = [
        r"verify your account",
        r"verify account",
        r"account verification",
        r"verify your identity",
        r"confirm your identity",
        r"confirm your account",
        r"account requires verification"
    ]

    for pattern in verification_patterns:
        if re.search(pattern, text_lower):
            score += 15
            findings.append(
                "Account verification request detected"
            )
            break

    # Credential requests
    credential_patterns = [
        r"enter your password",
        r"provide your password",
        r"enter your username",
        r"confirm your password",
        r"verify your credentials",
        r"enter your credentials"
    ]

    for pattern in credential_patterns:
        if re.search(pattern, text_lower):
            score += 25
            findings.append(
                "Possible credential request detected"
            )
            break

    # Urgency
    urgency_patterns = [
        r"within \d+ hours?",
        r"within \d+ minutes?",
        r"immediately",
        r"immediate",
        r"act now",
        r"action required",
        r"requires immediate",
        r"urgent"
    ]

    for pattern in urgency_patterns:
        if re.search(pattern, text_lower):
            score += 20
            findings.append(
                "Urgency or pressure detected"
            )
            break

    # Threats
    threat_patterns = [
        r"account will be closed",
        r"account will be suspended",
        r"account will be deleted",
        r"you will lose access",
        r"failure to respond"
    ]

    for pattern in threat_patterns:
        if re.search(pattern, text_lower):
            score += 20
            findings.append(
                "Threat or account pressure detected"
            )
            break

    score = min(score, 100)

    if score <= 29:
        level = "Low"
    elif score <= 59:
        level = "Medium"
    elif score <= 79:
        level = "High"
    else:
        level = "Critical"

    return {
        "phishing_score": score,
        "phishing_level": level,
        "findings": findings
    }