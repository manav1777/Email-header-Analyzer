import re
import ssl
import smtplib
import urllib.parse
import urllib.request

from email import message_from_bytes
from email.utils import parseaddr


ALLOWED_SCHEMES = {
    "http",
    "https",
    "mailto"
}


def normalize_url(url):

    if not url:
        return ""

    url = url.strip()

    if url.startswith("<") and url.endswith(">"):
        url = url[1:-1].strip()

    return url


def is_valid_unsubscribe_url(url):

    if not url:
        return False

    try:

        parsed = urllib.parse.urlparse(url)

        scheme = parsed.scheme.lower()

        if scheme not in ALLOWED_SCHEMES:
            return False

        if scheme in {"http", "https"}:

            if not parsed.netloc:
                return False

        if scheme == "mailto":

            if not parsed.path:
                return False

        return True

    except Exception:

        return False


def extract_unsubscribe_urls(message):

    urls = []

    list_unsubscribe = message.get(
        "List-Unsubscribe",
        ""
    )

    if not list_unsubscribe:
        return urls

    matches = re.findall(
        r"<([^>]+)>",
        list_unsubscribe
    )

    for value in matches:

        value = normalize_url(value)

        if is_valid_unsubscribe_url(value):

            urls.append(value)

    return urls


def get_unsubscribe_post_support(message):

    value = message.get(
        "List-Unsubscribe-Post",
        ""
    )

    if not value:
        return False

    return (
        "List-Unsubscribe=One-Click"
        in value
    )


def extract_sender_email(message):

    sender = message.get(
        "From",
        ""
    )

    name, address = parseaddr(sender)

    return address.strip().lower()


def analyze_unsubscribe(message):

    urls = extract_unsubscribe_urls(
        message
    )

    supports_one_click = (
        get_unsubscribe_post_support(
            message
        )
    )

    https_urls = [
        url
        for url in urls
        if url.lower().startswith(
            "https://"
        )
    ]

    http_urls = [
        url
        for url in urls
        if url.lower().startswith(
            "http://"
        )
    ]

    mailto_urls = [
        url
        for url in urls
        if url.lower().startswith(
            "mailto:"
        )
    ]

    if supports_one_click and https_urls:

        method = "one_click"
        unsubscribe_url = https_urls[0]

    elif https_urls:

        method = "https"
        unsubscribe_url = https_urls[0]

    elif mailto_urls:

        method = "mailto"
        unsubscribe_url = mailto_urls[0]

    elif http_urls:

        method = "http"
        unsubscribe_url = http_urls[0]

    else:

        method = "none"
        unsubscribe_url = ""

    return {
        "available": method != "none",
        "method": method,
        "url": unsubscribe_url,
        "all_urls": urls,
        "one_click": supports_one_click,
        "sender_email": extract_sender_email(
            message
        )
    }


def parse_raw_email(raw_email):

    if not raw_email:
        return None

    if isinstance(raw_email, bytes):

        return message_from_bytes(
            raw_email
        )

    return message_from_bytes(
        raw_email.encode(
            "utf8",
            errors="replace"
        )
    )


def analyze_raw_email(raw_email):

    message = parse_raw_email(
        raw_email
    )

    if not message:

        return {
            "available": False,
            "method": "none",
            "url": "",
            "all_urls": [],
            "one_click": False,
            "sender_email": ""
        }

    return analyze_unsubscribe(
        message
    )


def is_safe_http_url(url):

    if not url:
        return False

    try:

        parsed = urllib.parse.urlparse(
            url
        )

        scheme = parsed.scheme.lower()

        if scheme != "https":
            return False

        if not parsed.netloc:
            return False

        hostname = parsed.hostname

        if not hostname:
            return False

        hostname = hostname.lower()

        blocked_hosts = {
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1"
        }

        if hostname in blocked_hosts:
            return False

        return True

    except Exception:

        return False


def perform_one_click_unsubscribe(url):

    if not is_safe_http_url(url):

        return {
            "success": False,
            "status": "unsafe",
            "message": (
                "The unsubscribe destination "
                "could not be verified safely."
            )
        }

    try:

        request = urllib.request.Request(
            url,
            method="POST",
            headers={
                "User-Agent": "MailGuard/1.0",
                "Content-Type":
                    "application/x-www-form-urlencoded"
            },
            data=b"List-Unsubscribe=One-Click"
        )

        ssl_context = (
            ssl.create_default_context()
        )

        with urllib.request.urlopen(
            request,
            timeout=10,
            context=ssl_context
        ) as response:

            status_code = (
                response.getcode()
            )

            if 200 <= status_code < 300:

                return {
                    "success": True,
                    "status": "completed",
                    "message": (
                        "The unsubscribe request "
                        "was successfully submitted."
                    ),
                    "http_status": status_code
                }

            return {
                "success": False,
                "status": "failed",
                "message": (
                    "The unsubscribe server "
                    "returned an unexpected response."
                ),
                "http_status": status_code
            }

    except Exception as error:

        return {
            "success": False,
            "status": "failed",
            "message": (
                "The unsubscribe request "
                "could not be completed."
            ),
            "error": str(error)
        }


def send_mailto_unsubscribe(
    unsubscribe_url,
    gmail_account,
    gmail_app_password
):

    if not unsubscribe_url:
        return {
            "success": False,
            "status": "failed",
            "message": "No unsubscribe address was found."
        }

    try:

        parsed = urllib.parse.urlparse(
            unsubscribe_url
        )

        if parsed.scheme.lower() != "mailto":
            return {
                "success": False,
                "status": "failed",
                "message": "Invalid mailto unsubscribe address."
            }

        recipient = parsed.path.strip()

        if not recipient:
            return {
                "success": False,
                "status": "failed",
                "message": "No unsubscribe recipient was found."
            }

        query = urllib.parse.parse_qs(
            parsed.query
        )

        subject = query.get(
            "subject",
            ["Unsubscribe"]
        )[0]

        body = query.get(
            "body",
            [""]
        )[0]

        message_lines = [
            "From: " + gmail_account,
            "To: " + recipient,
            "Subject: " + subject,
            "",
            body
        ]

        message_text = "\n".join(
            message_lines
        )

        context = (
            ssl.create_default_context()
        )

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=15
        ) as smtp:

            smtp.login(
                gmail_account,
                gmail_app_password
            )

            smtp.sendmail(
                gmail_account,
                [recipient],
                message_text
            )

        return {
            "success": True,
            "status": "completed",
            "message": (
                "The unsubscribe email "
                "was successfully sent."
            )
        }

    except Exception as error:

        return {
            "success": False,
            "status": "failed",
            "message": (
                "The unsubscribe email "
                "could not be sent."
            ),
            "error": str(error)
        }


def get_unsubscribe_method_description(
    analysis
):

    method = analysis.get(
        "method",
        "none"
    )

    if method == "one_click":

        return (
            "This sender supports "
            "one click unsubscribe."
        )

    if method == "https":

        return (
            "This sender provides a secure "
            "HTTPS unsubscribe page."
        )

    if method == "mailto":

        return (
            "This sender provides an email based "
            "unsubscribe method."
        )

    if method == "http":

        return (
            "This sender provides an HTTP "
            "unsubscribe link."
        )

    return (
        "This email does not provide a "
        "standard unsubscribe mechanism."
    )