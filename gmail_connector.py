import imaplib
import email

from email.header import decode_header
from email.utils import parsedate_to_datetime


GMAIL_IMAP_SERVER = "imap.gmail.com"
GMAIL_IMAP_PORT = 993


def decode_text(value):

    if not value:
        return ""

    decoded_parts = decode_header(value)

    result = ""

    for part, encoding in decoded_parts:

        if isinstance(part, bytes):

            try:

                result += part.decode(
                    encoding or "utf8",
                    errors="replace"
                )

            except Exception:

                result += part.decode(
                    "utf8",
                    errors="replace"
                )

        else:

            result += part

    return result


def get_email_body(message):

    body = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            content_disposition = str(
                part.get("Content-Disposition") or ""
            )

            if (
                content_type == "text/plain"
                and "attachment" not in content_disposition.lower()
            ):

                payload = part.get_payload(
                    decode=True
                )

                if payload:

                    charset = (
                        part.get_content_charset()
                        or "utf8"
                    )

                    try:

                        body = payload.decode(
                            charset,
                            errors="replace"
                        )

                    except Exception:

                        body = payload.decode(
                            "utf8",
                            errors="replace"
                        )

                    if body.strip():
                        break

    else:

        payload = message.get_payload(
            decode=True
        )

        if payload:

            charset = (
                message.get_content_charset()
                or "utf8"
            )

            try:

                body = payload.decode(
                    charset,
                    errors="replace"
                )

            except Exception:

                body = payload.decode(
                    "utf8",
                    errors="replace"
                )

    return body


def get_received_at(message):

    date_value = message.get(
        "Date",
        ""
    )

    if not date_value:
        return ""

    try:

        parsed_date = parsedate_to_datetime(
            date_value
        )

        return parsed_date.isoformat()

    except Exception:

        return date_value


def get_flags(data):

    flags = set()

    if not data:
        return flags

    for item in data:

        if isinstance(item, tuple):

            header = item[0]

            if isinstance(header, bytes):
                header = header.decode(
                    "utf8",
                    errors="replace"
                )

            if "FLAGS" in header:

                start = header.find("(")
                end = header.find(")")

                if start >= 0 and end > start:

                    flag_text = header[
                        start + 1:end
                    ]

                    for flag in flag_text.split():

                        flags.add(
                            flag.strip()
                        )

    return flags


def get_raw_email(data):

    if not data:
        return None

    for item in data:

        if not isinstance(item, tuple):
            continue

        header = item[0]

        if isinstance(header, bytes):
            header = header.decode(
                "utf8",
                errors="replace"
            )

        if "RFC822" in header:

            return item[1]

    return None


def connect_gmail(
    email_address,
    app_password
):

    mail = imaplib.IMAP4_SSL(
        GMAIL_IMAP_SERVER,
        GMAIL_IMAP_PORT
    )

    mail.login(
        email_address,
        app_password
    )

    return mail


def fetch_emails(
    email_address,
    app_password,
    limit=None,
    mailbox="INBOX"
):

    mail = connect_gmail(
        email_address,
        app_password
    )

    try:

        status, _ = mail.select(
            mailbox,
            readonly=True
        )

        if status != "OK":

            return {
                "emails": [],
                "current_uids": []
            }

        status, data = mail.uid(
            "search",
            None,
            "ALL"
        )

        if status != "OK":

            return {
                "emails": [],
                "current_uids": []
            }

        raw_uids = data[0].split()

        uids = []

        for uid in raw_uids:

            try:

                uid_text = uid.decode(
                    "ascii"
                )

            except Exception:

                uid_text = str(uid)

            uids.append(
                uid_text
            )

        uids.reverse()

        if limit is not None:

            try:

                limit = int(limit)

                if limit > 0:

                    uids = uids[:limit]

            except (
                TypeError,
                ValueError
            ):

                pass

        results = []

        for uid in uids:

            status, data = mail.uid(
                "fetch",
                uid,
                "(RFC822 FLAGS)"
            )

            if status != "OK":

                continue

            raw_email = get_raw_email(
                data
            )

            if not raw_email:
                continue

            message = email.message_from_bytes(
                raw_email
            )

            sender = decode_text(
                message.get(
                    "From",
                    ""
                )
            )

            subject = decode_text(
                message.get(
                    "Subject",
                    ""
                )
            )

            body = get_email_body(
                message
            )

            received_at = get_received_at(
                message
            )

            message_id = decode_text(
                message.get(
                    "Message ID",
                    ""
                )
            )

            flags = get_flags(
                data
            )

            is_read = (
                "\\Seen" in flags
            )

            headers = ""

            for key, value in message.items():

                headers += (
                    f"{key}: {value}\n"
                )

            headers += "\n"
            headers += body

            results.append(
                {
                    "gmail_uid": str(uid),
                    "gmail_account": email_address,
                    "gmail_mailbox": mailbox,
                    "sender": sender,
                    "subject": subject,
                    "body": body,
                    "headers": headers,
                    "received_at": received_at,
                    "message_id": message_id,
                    "is_read": is_read
                }
            )

        return {
            "emails": results,
            "current_uids": [
                str(uid)
                for uid in raw_uids
            ]
        }

    finally:

        try:
            mail.close()
        except Exception:
            pass

        try:
            mail.logout()
        except Exception:
            pass