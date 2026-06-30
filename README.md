# Email Header Analyzer

## Overview

The **Email Header Analyzer** is a Python and Flask web application that analyzes email headers to identify common phishing indicators and email authentication issues. The tool extracts key header information, evaluates authentication records, and calculates a risk score to help users recognize potentially malicious emails.

This project was built to strengthen my understanding of email security, phishing detection, and email authentication standards.

---

## Features

* Analyze email headers for security indicators
* Extract sender and routing information
* Detect potential email spoofing attempts
* Check for SPF, DKIM, and DMARC authentication records
* Calculate a phishing risk score
* Classify emails as Low, Medium, or High Risk
* Simple web-based interface with sample headers

---

## Tech Stack

* Python
* Flask
* HTML
* CSS
* Regular Expressions (Regex)

---

## Example Analysis

Input:

```text
From: fake paypal security
Return-Path: attacker
Received: 192.168.1.1
Subject: verify account
```

Output:

```text
SPF: NOT FOUND
DKIM: NOT FOUND
DMARC: NOT FOUND

Spoof Detected: True

Risk Score: 9

Risk Level: High Risk
```

---

## How It Works

1. The user pastes an email header into the analyzer.
2. The application extracts key header fields.
3. Email authentication records are evaluated.
4. The analyzer checks for spoofing indicators.
5. A risk score and security assessment are generated.
6. The results are displayed through the web interface.

---

## Installation

Install the required dependency:

```bash
pip install flask
```

Run the application:

```bash
python app.py
```

Open your browser:

```text
http://127.0.0.1:5000
```

---

## Skills Demonstrated

* Email security
* Phishing detection
* Email header analysis
* SPF, DKIM, and DMARC validation
* Risk assessment
* Flask web development
* Python programming

---

## Security Concepts Covered

* Email spoofing
* Phishing detection
* Sender authentication
* SPF
* DKIM
* DMARC
* Email header analysis

---

## Key Learning Outcomes

* Understanding how email headers are structured
* Evaluating email authentication mechanisms
* Detecting common phishing indicators
* Building cybersecurity tools with Python and Flask
* Developing security-focused web applications

---

## Future Improvements

* Full RFC-compliant email header parsing
* DNS lookups for live SPF, DKIM, and DMARC validation
* Attachment and URL analysis
* Export analysis reports
* Threat intelligence integration
* Support for `.eml` file uploads

---

## Author

**Manav Patel**

Cybersecurity Student at Drexel University
