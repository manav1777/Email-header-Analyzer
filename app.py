import os
import importlib.util

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for
)

from MailGuard.url_security.url_analyzer import (
    analyze_text_urls
)

from MailGuard.risk_engine.risk_engine import (
    calculate_risk
)

from MailGuard.phishing_detection.phishing_analyzer import (
    detect_phishing
)

from MailGuard.spam_detection.spam_analyzer import (
    detect_spam
)

from MailGuard.category_detection.category_analyzer import (
    detect_category
)

from gmail_connector import fetch_emails

from database import (
    initialize_database,
    add_email,
    get_all_emails,
    get_email,
    get_email_by_gmail_uid,
    sync_gmail_messages,
    update_email_action,
    delete_email,
    delete_all_emails,
    mark_email_as_read,
    mark_email_as_unread,
    mark_emails_as_read,
    mark_emails_as_unread,
    update_emails_action
)


# =========================================================
# Project Setup
# =========================================================

project_root = os.path.dirname(
    os.path.abspath(__file__)
)


# =========================================================
# Optional Database Functions
# =========================================================

try:
    from database import block_sender
except ImportError:
    block_sender = None


try:
    from database import add_unsubscribe_record
except ImportError:
    add_unsubscribe_record = None


# =========================================================
# Header Analyzer
# =========================================================

header_parser_path = os.path.join(
    project_root,
    "analyzer",
    "header_parser.py"
)

spec = importlib.util.spec_from_file_location(
    "header_parser",
    header_parser_path
)

header_parser = importlib.util.module_from_spec(
    spec
)

spec.loader.exec_module(
    header_parser
)

analyze_header = header_parser.analyze_header


# =========================================================
# Flask
# =========================================================

app = Flask(__name__)


# =========================================================
# Database
# =========================================================

initialize_database()


# =========================================================
# Helper Functions
# =========================================================

def get_value(
    data,
    *keys,
    default=0
):

    if not isinstance(data, dict):
        return default

    for key in keys:

        if key in data:
            return data[key]

    return default


def get_sender(header_result):

    if not isinstance(
        header_result,
        dict
    ):
        return "Unknown"

    sender = header_result.get(
        "From",
        "Unknown"
    )

    if not sender:
        return "Unknown"

    return sender.strip()


def get_subject(text):

    if not text:
        return ""

    for line in text.splitlines():

        if line.lower().startswith(
            "subject:"
        ):

            return line.split(
                ":",
                1
            )[1].strip()

    return ""


def get_url_risk(url_results):

    if not isinstance(
        url_results,
        list
    ):
        return 0

    scores = []

    for item in url_results:

        if not isinstance(
            item,
            dict
        ):
            continue

        score = item.get(
            "risk_score",
            0
        )

        try:

            score = float(score)

            score = min(
                max(score, 0),
                100
            )

            scores.append(score)

        except (
            TypeError,
            ValueError
        ):

            continue

    if not scores:
        return 0

    return round(
        max(scores)
    )


# =========================================================
# Email Analysis
# =========================================================

def analyze_email_text(
    input_text
):

    header_result = analyze_header(
        input_text
    )

    url_results = analyze_text_urls(
        input_text
    )

    phishing_result = detect_phishing(
        input_text
    )

    spam_result = detect_spam(
        input_text
    )

    category_result = detect_category(
        input_text
    )

    phishing_score = get_value(
        phishing_result,
        "phishing_score",
        default=0
    )

    header_score = get_value(
        header_result,
        "Risk Score",
        "risk_score",
        default=0
    )

    mailguard_risk = calculate_risk(
        header_score,
        url_results,
        phishing_score
    )

    overall_risk = get_value(
        mailguard_risk,
        "risk_score",
        "overall_risk",
        "Overall Risk",
        "overall_score",
        default=0
    )

    risk_level = get_value(
        mailguard_risk,
        "risk_level",
        "Risk Level",
        "overall_risk_level",
        default="Low Risk"
    )

    spam_score = get_value(
        spam_result,
        "spam_score",
        "Spam Score",
        "score",
        default=0
    )

    try:

        overall_risk = round(
            float(overall_risk)
        )

    except (
        TypeError,
        ValueError
    ):

        overall_risk = 0

    try:

        phishing_score = round(
            float(phishing_score)
        )

    except (
        TypeError,
        ValueError
    ):

        phishing_score = 0

    try:

        spam_score = round(
            float(spam_score)
        )

    except (
        TypeError,
        ValueError
    ):

        spam_score = 0

    try:

        header_score = float(
            header_score
        )

    except (
        TypeError,
        ValueError
    ):

        header_score = 0

    phishing_detected = (
        phishing_score >= 50
    )

    spam_detected = (
        spam_score >= 50
    )

    high_risk = (
        overall_risk >= 60
        or phishing_detected
    )

    category = get_value(
        category_result,
        "category",
        "Category",
        default="Other"
    )

    if not isinstance(
        category,
        str
    ):
        category = "Other"

    category = category.strip()

    if not category:
        category = "Other"

    return {
        "header_result": header_result,
        "url_results": url_results,
        "phishing_result": phishing_result,
        "spam_result": spam_result,
        "category_result": category_result,
        "phishing_score": phishing_score,
        "spam_score": spam_score,
        "header_score": header_score,
        "mailguard_risk": mailguard_risk,
        "overall_risk": overall_risk,
        "risk_level": risk_level,
        "phishing_detected": phishing_detected,
        "spam_detected": spam_detected,
        "high_risk": high_risk,
        "category": category
    }


# =========================================================
# Home Page
# =========================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def index():

    result = None
    input_text = ""

    if request.method == "POST":

        input_text = request.form.get(
            "emailheader",
            ""
        )

        if input_text.strip():

            analysis = analyze_email_text(
                input_text
            )

            result = dict(
                analysis["header_result"]
            )

            result["URL Results"] = (
                analysis["url_results"]
            )

            result["Phishing Results"] = (
                analysis["phishing_result"]
            )

            result["Spam Results"] = (
                analysis["spam_result"]
            )

            result["Category"] = (
                analysis["category_result"]
            )

            result["MailGuard Risk"] = (
                analysis["mailguard_risk"]
            )

            sender = get_sender(
                analysis["header_result"]
            )

            subject = get_subject(
                input_text
            )

            add_email(
                sender=sender,
                subject=subject,
                body=input_text,
                category=analysis["category"],
                spam=analysis["spam_detected"],
                phishing=analysis["phishing_detected"],
                high_risk=analysis["high_risk"],
                risk_score=analysis["overall_risk"],
                risk_level=analysis["risk_level"],
                header_risk=round(
                    min(
                        max(
                            analysis["header_score"] * 10,
                            0
                        ),
                        100
                    )
                ),
                url_risk=get_url_risk(
                    analysis["url_results"]
                ),
                phishing_risk=analysis[
                    "phishing_score"
                ],
                spam_risk=analysis[
                    "spam_score"
                ]
            )

    return render_template(
        "index.html",
        result=result,
        input_text=input_text
    )


# =========================================================
# Email Detail
# =========================================================

@app.route(
    "/email/<int:email_id>"
)
def email_detail(
    email_id
):

    email_record = get_email(
        email_id
    )

    if email_record is None:

        return (
            "Email not found",
            404
        )

    email_record = dict(
        email_record
    )

    mark_email_as_read(
        email_id
    )

    email_record["is_read"] = 1

    all_emails = [
        dict(item)
        for item in get_all_emails()
    ]

    current_action = email_record.get(
        "action",
        "none"
    )

    hidden_actions = [
        "spam",
        "trash",
        "blocked",
        "unsubscribed"
    ]

    if current_action in hidden_actions:

        navigation_emails = [
            item
            for item in all_emails
            if item.get("action")
            == current_action
        ]

    else:

        navigation_emails = [
            item
            for item in all_emails
            if item.get("action")
            not in hidden_actions
        ]

    current_index = None

    for index, item in enumerate(
        navigation_emails
    ):

        if item["id"] == email_id:

            current_index = index
            break

    previous_email = None
    next_email = None

    if current_index is not None:

        if current_index > 0:

            previous_email = (
                navigation_emails[
                    current_index - 1
                ]
            )

        if current_index < (
            len(navigation_emails) - 1
        ):

            next_email = (
                navigation_emails[
                    current_index + 1
                ]
            )

    return render_template(
        "email_detail.html",
        email=email_record,
        previous_email=previous_email,
        next_email=next_email
    )


# =========================================================
# Email Action
# =========================================================

@app.route(
    "/email/<int:email_id>/action/<action>",
    methods=["POST"]
)
def email_action(
    email_id,
    action
):

    allowed_actions = {
        "inbox",
        "spam",
        "trash",
        "blocked",
        "unsubscribed"
    }

    if action not in allowed_actions:

        return (
            "Invalid action",
            400
        )

    email_record = get_email(
        email_id
    )

    if email_record is None:

        return (
            "Email not found",
            404
        )

    if action == "blocked":

        if block_sender is not None:

            try:

                block_sender(
                    email_record["sender"]
                )

            except Exception:

                pass

    if action == "unsubscribed":

        if add_unsubscribe_record is not None:

            try:

                add_unsubscribe_record(
                    sender=email_record["sender"],
                    email=email_record["sender"],
                    status="completed"
                )

            except Exception:

                pass

    update_email_action(
        email_id,
        action
    )

    return redirect(
        url_for(
            "email_detail",
            email_id=email_id
        )
    )


# =========================================================
# Delete One Email
# =========================================================

@app.route(
    "/email/<int:email_id>/delete",
    methods=["POST"]
)
def delete_email_route(
    email_id
):

    email_record = get_email(
        email_id
    )

    if email_record is None:

        return (
            "Email not found",
            404
        )

    delete_email(
        email_id
    )

    return redirect(
        url_for(
            "dashboard",
            filter="trash"
        )
    )


# =========================================================
# Delete Selected Emails
# =========================================================

@app.route(
    "/emails/delete",
    methods=["POST"]
)
def delete_selected_emails():

    selected_ids = request.form.getlist(
        "selected_emails"
    )

    if not selected_ids:

        return redirect(
            url_for(
                "dashboard",
                filter="trash"
            )
        )

    email_ids = []

    for email_id in selected_ids:

        try:

            email_ids.append(
                int(email_id)
            )

        except (
            TypeError,
            ValueError
        ):

            continue

    if email_ids:

        delete_all_emails(
            email_ids
        )

    return redirect(
        url_for(
            "dashboard",
            filter="trash"
        )
    )


# =========================================================
# Health Check
# =========================================================

@app.route(
    "/health"
)
def health():

    return "running"


# =========================================================
# Dashboard
# =========================================================

@app.route(
    "/dashboard"
)
def dashboard():

    all_emails = [
        dict(email)
        for email in get_all_emails()
    ]

    filter_type = request.args.get(
        "filter",
        "all"
    )

    hidden_actions = [
        "spam",
        "trash",
        "blocked",
        "unsubscribed"
    ]

    if filter_type == "all":

        emails = [
            email
            for email in all_emails
            if email.get("action")
            not in hidden_actions
        ]

    elif filter_type == "high_risk":

        emails = [
            email
            for email in all_emails
            if email.get("high_risk")
            and email.get("action")
            not in hidden_actions
        ]

    elif filter_type == "phishing":

        emails = [
            email
            for email in all_emails
            if email.get("phishing")
            and email.get("action")
            not in hidden_actions
        ]

    elif filter_type == "spam":

        emails = [
            email
            for email in all_emails
            if email.get("action")
            == "spam"
        ]

    elif filter_type == "trash":

        emails = [
            email
            for email in all_emails
            if email.get("action")
            == "trash"
        ]

    elif filter_type == "blocked":

        emails = [
            email
            for email in all_emails
            if email.get("action")
            == "blocked"
        ]

    elif filter_type == "unsubscribed":

        emails = [
            email
            for email in all_emails
            if email.get("action")
            == "unsubscribed"
        ]

    else:

        emails = [
            email
            for email in all_emails
            if email.get("action")
            not in hidden_actions
        ]

    stats = {

        "all_emails": sum(
            1
            for email in all_emails
            if email.get("action")
            not in hidden_actions
        ),

        "high_risk": sum(
            1
            for email in all_emails
            if email.get("high_risk")
            and email.get("action")
            not in hidden_actions
        ),

        "phishing": sum(
            1
            for email in all_emails
            if email.get("phishing")
            and email.get("action")
            not in hidden_actions
        ),

        "spam": sum(
            1
            for email in all_emails
            if email.get("action")
            == "spam"
        ),

        "trash": sum(
            1
            for email in all_emails
            if email.get("action")
            == "trash"
        ),

        "blocked": sum(
            1
            for email in all_emails
            if email.get("action")
            == "blocked"
        ),

        "unsubscribed": sum(
            1
            for email in all_emails
            if email.get("action")
            == "unsubscribed"
        )
    }

    category_counts = {}

    for email in emails:

        category = email.get(
            "category"
        )

        if not category:
            category = "Other"

        category_counts[category] = (
            category_counts.get(
                category,
                0
            ) + 1
        )

    return render_template(
        "dashboard.html",
        emails=emails,
        stats=stats,
        categories=category_counts,
        filter_type=filter_type
    )


# =========================================================
# Gmail Connection
# =========================================================

@app.route(
    "/connect-gmail",
    methods=["GET", "POST"]
)
def connect_gmail():

    error = None
    success = None

    if request.method == "POST":

        email_address = request.form.get(
            "email_address",
            ""
        ).strip()

        app_password = request.form.get(
            "app_password",
            ""
        ).strip()

        if (
            not email_address
            or not app_password
        ):

            error = (
                "Please enter your Gmail address "
                "and App Password."
            )

        else:

            try:

                gmail_data = fetch_emails(
                    email_address,
                    app_password,
                    limit=None,
                    mailbox="INBOX"
                )

                emails = gmail_data.get(
                    "emails",
                    []
                )

                current_uids = gmail_data.get(
                    "current_uids",
                    []
                )

                removed = sync_gmail_messages(
                    gmail_account=email_address,
                    gmail_mailbox="INBOX",
                    current_uids=current_uids
                )

                imported = 0
                updated = 0

                for gmail_email in emails:

                    gmail_uid = str(
                        gmail_email.get(
                            "gmail_uid",
                            ""
                        )
                    )

                    if not gmail_uid:
                        continue

                    email_body = gmail_email.get(
                        "body",
                        ""
                    )

                    raw_headers = gmail_email.get(
                        "headers",
                        ""
                    )

                    if not email_body.strip():

                        email_body = raw_headers

                    input_text = (
                        raw_headers
                        if raw_headers.strip()
                        else email_body
                    )

                    analysis = analyze_email_text(
                        input_text
                    )

                    existing = (
                        get_email_by_gmail_uid(
                            gmail_uid,
                            email_address,
                            "INBOX"
                        )
                    )

                    email_id = add_email(
                        sender=gmail_email.get(
                            "sender",
                            "Unknown"
                        ),
                        subject=gmail_email.get(
                            "subject",
                            ""
                        ),
                        body=email_body,
                        received_at=gmail_email.get(
                            "received_at",
                            ""
                        ),
                        category=analysis[
                            "category"
                        ],
                        spam=analysis[
                            "spam_detected"
                        ],
                        phishing=analysis[
                            "phishing_detected"
                        ],
                        high_risk=analysis[
                            "high_risk"
                        ],
                        risk_score=analysis[
                            "overall_risk"
                        ],
                        risk_level=analysis[
                            "risk_level"
                        ],
                        header_risk=round(
                            min(
                                max(
                                    analysis[
                                        "header_score"
                                    ] * 10,
                                    0
                                ),
                                100
                            )
                        ),
                        url_risk=get_url_risk(
                            analysis[
                                "url_results"
                            ]
                        ),
                        phishing_risk=analysis[
                            "phishing_score"
                        ],
                        spam_risk=analysis[
                            "spam_score"
                        ],
                        gmail_uid=gmail_uid,
                        gmail_account=email_address,
                        gmail_mailbox="INBOX",
                        message_id=gmail_email.get(
                            "message_id",
                            ""
                        )
                    )

                    is_read = gmail_email.get(
                        "is_read",
                        False
                    )

                    if is_read:
                        mark_email_as_read(
                            email_id
                        )
                    else:
                        mark_email_as_unread(
                            email_id
                        )

                    if existing:

                        updated += 1

                    else:

                        imported += 1

                success = (
                    f"Gmail sync complete. "
                    f"{imported} new emails, "
                    f"{updated} existing emails updated, "
                    f"{removed} deleted emails removed."
                )

            except Exception as e:

                error = (
                    "Gmail connection failed: "
                    + str(e)
                )

    return render_template(
        "connect_gmail.html",
        error=error,
        success=success
    )


# =========================================================
# Dashboard Bulk Actions
# =========================================================

@app.route(
    "/dashboard/bulk-action",
    methods=["POST"]
)
def dashboard_bulk_action():

    email_ids = request.form.getlist(
        "email_ids"
    )

    action = request.form.get(
        "action",
        ""
    )

    filter_type = request.form.get(
        "filter_type",
        "all"
    )

    allowed_actions = {
        "inbox",
        "spam",
        "trash",
        "blocked",
        "unsubscribed",
        "delete"
    }

    if action not in allowed_actions:

        return redirect(
            url_for(
                "dashboard",
                filter=filter_type
            )
        )

    for email_id in email_ids:

        try:

            email_id = int(
                email_id
            )

        except (
            TypeError,
            ValueError
        ):

            continue

        email_record = get_email(
            email_id
        )

        if not email_record:
            continue

        if action == "blocked":

            if block_sender is not None:

                try:

                    block_sender(
                        email_record["sender"]
                    )

                except Exception:

                    pass

            update_email_action(
                email_id,
                "blocked"
            )

        elif action == "unsubscribed":

            if add_unsubscribe_record is not None:

                try:

                    add_unsubscribe_record(
                        sender=email_record[
                            "sender"
                        ],
                        email=email_record[
                            "sender"
                        ],
                        status="completed"
                    )

                except Exception:

                    pass

            update_email_action(
                email_id,
                "unsubscribed"
            )

        elif action in {
            "inbox",
            "spam",
            "trash"
        }:

            update_email_action(
                email_id,
                action
            )

        elif action == "delete":

            delete_email(
                email_id
            )

    return redirect(
        url_for(
            "dashboard",
            filter=filter_type
        )
    )


# =========================================================
# Start Application
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5001
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )