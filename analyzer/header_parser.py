import re
import csv
import socket
import os

# Ensure logs folder exists
LOG_FOLDER = os.path.join(os.getcwd(), "logs")
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

LOG_FILE = os.path.join(LOG_FOLDER, "analyzed_headers.csv")

def analyze_header(header_text):
    lines = header_text.splitlines()
    report = {}

    # Extract From, Return-Path, Message-ID
    report["From"] = extract_field(lines, "From") or ""
    report["Return-Path"] = extract_field(lines, "Return-Path") or ""
    report["Message-ID"] = extract_field(lines, "Message-ID") or ""
    report["Received"] = [line for line in lines if line.startswith("Received:")]

    # Spoof check
    report["Spoof Suspected"] = report["From"] != report["Return-Path"]

    # SPF check (basic)
    sending_ip = extract_sending_ip(report["Received"])
    report["SPF Check"] = check_spf_basic(report["From"], sending_ip) if sending_ip else "No IP found"

    # DKIM check (presence only)
    report["DKIM"] = check_dkim_basic(header_text)

    # Risk label
    report["Risk Level"] = determine_risk(report)

    # Log result
    log_result(report)
    return report

# --- Helper functions ---

def extract_field(lines, field_name):
    for line in lines:
        if line.startswith(field_name + ":"):
            return line.split(":", 1)[1].strip()
    return None

def extract_sending_ip(received_list):
    if not received_list:
        return None
    for line in reversed(received_list):
        match = re.search(r"\[([0-9\.]+)\]", line)
        if match:
            return match.group(1)
    return None

def check_spf_basic(from_address, sending_ip):
    domain = from_address.split("@")[-1]
    try:
        answers = socket.getaddrinfo(domain, None)
        ip_list = [info[4][0] for info in answers]
        return "SPF Pass" if sending_ip in ip_list else "SPF Fail"
    except Exception:
        return "SPF Check Error"

def check_dkim_basic(header_text):
    for line in header_text.splitlines():
        if line.startswith("DKIM-Signature:"):
            match = re.search(r"d=([^;]+);", line)
            domain = match.group(1) if match else "Unknown"
            return f"DKIM Present: domain={domain}"
    return "DKIM Missing"

def determine_risk(report):
    risk = 0
    if report["Spoof Suspected"]:
        risk += 1
    if report["SPF Check"] == "SPF Fail":
        risk += 1
    if "Missing" in report["DKIM"]:
        risk += 1

    if risk == 0:
        return "Likely Safe"
    elif risk == 1:
        return "Suspicious"
    else:
        return "High Risk"

def log_result(report):
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            report.get("From"),
            report.get("Return-Path"),
            report.get("Message-ID"),
            report.get("Spoof Suspected"),
            report.get("SPF Check"),
            report.get("DKIM"),
            report.get("Risk Level")
        ])