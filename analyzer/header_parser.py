import re

def extract_field(pattern, text):
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def extract_received_ips(text):
    # better IP extraction from Received headers
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return list(set(ips))


def extract_auth_results(text, key):
    """
    Extracts SPF, DKIM, DMARC from Authentication-Results lines
    """
    pattern = rf"{key}=([a-zA-Z]+)"
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).upper() if match else "NOT FOUND"


def normalize(text):
    return text.lower().replace(" ", "")


def check_spf(text):
    lines = text.lower().splitlines()

    for line in lines:
        if "spf" in line:
            if "pass" in line:
                return "PASS"
            if "fail" in line:
                return "FAIL"

    return "NOT FOUND"


def check_dkim(text):
    lines = text.lower().splitlines()

    for line in lines:
        if "dkim" in line:
            if "pass" in line:
                return "PASS"
            if "fail" in line:
                return "FAIL"

    return "NOT FOUND"


def check_dmarc(text):
    lines = text.lower().splitlines()

    for line in lines:
        if "dmarc" in line:
            if "pass" in line:
                return "PASS"
            if "fail" in line:
                return "FAIL"

    return "NOT FOUND"


def detect_spoof(from_field, return_path, received_ips, spf, dkim, dmarc):
    score = 0

    # missing headers
    if not from_field:
        score += 2
    if not return_path:
        score += 2

    # auth failures
    if spf != "PASS":
        score += 2
    if dkim != "PASS":
        score += 2
    if dmarc != "PASS":
        score += 1

    # no IPs is suspicious
    if not received_ips:
        score += 1

    # mismatch check
    if from_field and return_path:
        if "@" in from_field and "@" in return_path:
            if from_field.split("@")[-1] != return_path.split("@")[-1]:
                score += 2

    return score


def risk_level(score):
    if score <= 2:
        return "Low Risk"
    if score <= 5:
        return "Medium Risk"
    return "High Risk"


def analyze_header(text):

    from_field = extract_field(r"From:\s*(.*)", text)
    return_path = extract_field(r"Return-Path:\s*(.*)", text)
    message_id = extract_field(r"Message-ID:\s*(.*)", text)

    received_ips = extract_received_ips(text)

    spf = check_spf(text)
    dkim = check_dkim(text)
    dmarc = check_dmarc(text)

    score = detect_spoof(
        from_field,
        return_path,
        received_ips,
        spf,
        dkim,
        dmarc
    )

    return {
        "From": from_field,
        "Return-Path": return_path,
        "Message-ID": message_id,
        "Received IPs": received_ips,
        "SPF": spf,
        "DKIM": dkim,
        "DMARC": dmarc,
        "Spoof Detected": score >= 5,
        "Risk Score": score,
        "Risk Level": risk_level(score)
    }