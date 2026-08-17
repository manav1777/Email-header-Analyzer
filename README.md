# MailGuard

## Overview

**MailGuard** is a Python and Flask based email security and analysis platform designed to help users identify potentially malicious, suspicious, and unwanted emails.

The application analyzes email headers, URLs, phishing indicators, spam indicators, and other security characteristics to calculate an overall risk score. MailGuard also provides a web based dashboard for organizing analyzed emails and managing actions such as moving emails to spam, trash, blocked senders, or unsubscribed messages.

MailGuard can also connect to a Gmail inbox through IMAP and import emails into the application for automated security analysis.

This project was built to strengthen my understanding of cybersecurity, email security, phishing detection, spam detection, email authentication, risk assessment, Python development, Flask web applications, and database management.

---

## Features

### Email Security Analysis

* Analyze email headers for security indicators
* Extract sender and routing information
* Detect potential email spoofing
* Analyze email authentication information
* Evaluate SPF, DKIM, and DMARC related indicators
* Detect phishing indicators
* Detect spam indicators
* Analyze URLs contained in emails
* Calculate an overall email risk score
* Assign security risk levels
* Identify high risk emails

### Gmail Integration

* Connect a Gmail account using an App Password
* Retrieve emails from the Gmail inbox through IMAP
* Import email headers and message content
* Analyze imported emails automatically
* Track Gmail message identifiers
* Prevent duplicate email imports
* Synchronize deleted Gmail messages with the local database
* Preserve email metadata such as sender, subject, message ID, and received time

### Email Dashboard

MailGuard provides a centralized dashboard for reviewing analyzed emails.

The dashboard includes:

* All Emails
* High Risk
* Phishing
* Spam
* Trash
* Blocked
* Unsubscribed
* Email categories
* Risk scores
* Read and unread email status
* Bulk email actions

### Email Management

Users can perform actions on individual emails or multiple emails at once.

Supported actions include:

* Move to Inbox
* Move to Spam
* Move to Trash
* Block Sender
* Unsubscribe
* Permanently Delete Emails
* Mark Emails as Read
* Mark Emails as Unread

---

## Risk Analysis

MailGuard combines multiple security analysis components to produce an overall risk assessment.

The application evaluates:

* Email header risk
* URL risk
* Phishing risk
* Spam risk
* Authentication indicators
* Other suspicious characteristics

The resulting analysis produces a numerical risk score and security classification.

Example:

```text
Overall Risk Score: 75/100

Risk Level: High Risk

Phishing Detected: True

Spam Detected: False
```

---

## Architecture

MailGuard is organized into multiple security analysis components.

```text
MailGuard
│
├── Flask Web Application
│
├── Email Header Analyzer
│
├── URL Security Analyzer
│
├── Phishing Detection
│
├── Spam Detection
│
├── Category Detection
│
├── Risk Engine
│
├── Gmail IMAP Connector
│
├── SQLite Database
│
└── Web Dashboard
```

The application processes an email through multiple analyzers before storing the results in the database.

---

## How It Works

### Manual Email Analysis

1. The user provides an email header or email content.
2. MailGuard extracts relevant email information.
3. The header analyzer evaluates email security indicators.
4. The URL analyzer evaluates URLs found in the email.
5. The phishing analyzer searches for phishing indicators.
6. The spam analyzer evaluates potential spam characteristics.
7. The category analyzer assigns an email category.
8. The risk engine calculates the overall risk.
9. The results are displayed through the Flask web interface.
10. The analyzed email can be stored in the local database.

### Gmail Analysis

1. The user connects a Gmail account.
2. MailGuard connects to Gmail using IMAP.
3. Email messages are retrieved from the inbox.
4. MailGuard extracts headers, sender information, subject, body, and message identifiers.
5. Each email is analyzed by the security analyzers.
6. The results are stored in SQLite.
7. Duplicate messages are identified using Gmail message information.
8. Deleted Gmail messages can be synchronized with the local database.
9. The dashboard displays the analyzed emails and their security results.

---

## Gmail Security

MailGuard uses Gmail IMAP to retrieve messages.

For security, Gmail users should use a **Gmail App Password** rather than their normal Gmail account password.

Credentials should never be hard coded into the source code or committed to GitHub.

Sensitive files and local databases should be excluded using `.gitignore`.

---

## Dashboard

The MailGuard dashboard allows users to quickly review their email security status.

Example dashboard categories include:

```text
All Emails
High Risk
Phishing
Spam
Trash
Blocked
Unsubscribed
```

Each email can display information such as:

```text
Sender
Subject
Category
Risk Score
Risk Level
Phishing Status
Spam Status
```

---

## Database

MailGuard uses **SQLite** for local email storage.

The database stores information including:

* Sender
* Subject
* Email body
* Received time
* Category
* Spam status
* Phishing status
* High risk status
* Overall risk score
* Risk level
* Header risk
* URL risk
* Phishing risk
* Spam risk
* Email action
* Read status
* Gmail UID
* Gmail account
* Gmail mailbox
* Message ID

The database also maintains information about:

* Categories
* Blocked senders
* Unsubscribe records

The local database is intentionally excluded from GitHub.

---

## Tech Stack

### Backend

* Python
* Flask
* SQLite
* IMAP
* Regular Expressions

### Frontend

* HTML
* CSS
* Jinja2 Templates

### Security Analysis

* Email header analysis
* SPF
* DKIM
* DMARC
* Phishing detection
* Spam detection
* URL security analysis
* Risk scoring

---

## Project Structure

A simplified version of the project structure is:

```text
Email-header-Analyzer/
│
├── app.py
├── database.py
├── gmail_connector.py
│
├── analyzer/
│   └── header_parser.py
│
├── MailGuard/
│   ├── url_security/
│   ├── risk_engine/
│   ├── phishing_detection/
│   ├── spam_detection/
│   └── category_detection/
│
├── templates/
│   ├── index.html
│   ├── dashboard.html
│   ├── email_detail.html
│   └── connect_gmail.html
│
├── data/
│   └── mailguard.db
│
└── .gitignore
```

The database file in the `data` directory should not be committed to GitHub.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/manav1777/Email-header-Analyzer.git
```

Navigate into the project:

```bash
cd Email-header-Analyzer
```

Install Flask:

```bash
pip install flask
```

If the project contains a requirements file, install all dependencies with:

```bash
pip install -r requirements.txt
```

---

## Running the Application

Start the Flask application:

```bash
python app.py
```

The application will normally run on:

```text
http://127.0.0.1:5001
```

Open the address in a web browser.

---

## Example Security Analysis

Example input:

```text
From: fake paypal security
Return-Path: attacker
Received: 192.168.1.1
Subject: verify account
```

Example analysis:

```text
SPF: NOT FOUND
DKIM: NOT FOUND
DMARC: NOT FOUND

Spoof Detected: True

Risk Score: 75/100

Risk Level: High Risk

Phishing Detected: True
```

The exact score depends on the security analysis performed by the current version of MailGuard.

---

## Skills Demonstrated

This project demonstrates experience with:

* Python programming
* Flask web development
* SQLite database development
* IMAP email integration
* Email security
* Email header analysis
* Phishing detection
* Spam detection
* URL security analysis
* SPF
* DKIM
* DMARC
* Risk assessment
* Database design
* Web application development
* Security focused software development

---

## Cybersecurity Concepts

MailGuard covers several important cybersecurity concepts:

* Email spoofing
* Phishing
* Spam
* Sender authentication
* Email headers
* SPF
* DKIM
* DMARC
* URL based threats
* Risk scoring
* Security classification
* Account security
* Secure credential handling
* Threat detection

---

## Key Learning Outcomes

Through this project, I developed practical experience with:

* Understanding the structure of email messages and headers
* Analyzing email authentication information
* Identifying common phishing indicators
* Detecting suspicious URLs
* Developing phishing and spam detection logic
* Creating a risk scoring system
* Connecting a web application to Gmail through IMAP
* Designing a SQLite database for email security data
* Building a Flask based cybersecurity application
* Developing dashboard based security workflows
* Implementing email management functionality
* Using Git and GitHub for version control

---

## Future Improvements

Potential future improvements include:

* Full RFC compliant email header parsing
* Live DNS based SPF validation
* Live DKIM verification
* Live DMARC validation
* Improved phishing detection using machine learning
* Machine learning based spam classification
* Advanced URL reputation analysis
* Threat intelligence integration
* Attachment malware analysis
* `.eml` file upload support
* PDF security reports
* Email security analytics
* Security statistics and visualizations
* Multiple Gmail account support
* OAuth based Gmail authentication
* Automated threat response
* Improved email categorization

---

## Disclaimer

MailGuard is an educational cybersecurity project designed for email security analysis and research.

The application should not be considered a replacement for commercial email security systems, antivirus software, spam filters, or enterprise security solutions.

Users should avoid entering sensitive credentials into the application and should follow secure credential management practices when connecting email accounts.

---

## Author

**Manav Patel**

Cybersecurity Student
Drexel University

GitHub: [@manav1777](https://github.com/manav1777)
