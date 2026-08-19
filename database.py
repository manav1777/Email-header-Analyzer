import sqlite3
import os


DATABASE_DIR = os.path.join(
    os.path.dirname(__file__),
    "data"
)

DATABASE_PATH = os.path.join(
    DATABASE_DIR,
    "mailguard.db"
)


def get_connection():

    os.makedirs(
        DATABASE_DIR,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gmail_uid TEXT,
            gmail_account TEXT,
            gmail_mailbox TEXT,
            message_id TEXT,
            sender TEXT NOT NULL,
            subject TEXT,
            body TEXT,
            received_at TEXT,
            category TEXT DEFAULT 'Other',
            spam INTEGER DEFAULT 0,
            phishing INTEGER DEFAULT 0,
            high_risk INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'Low Risk',
            header_risk INTEGER DEFAULT 0,
            url_risk INTEGER DEFAULT 0,
            phishing_risk INTEGER DEFAULT 0,
            spam_risk INTEGER DEFAULT 0,
            action TEXT DEFAULT 'none',
            raw_email TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    existing_columns = [
        row["name"]
        for row in cursor.execute(
            "PRAGMA table_info(emails)"
        ).fetchall()
    ]

    required_columns = {
        "gmail_uid": "TEXT",
        "gmail_account": "TEXT",
        "gmail_mailbox": "TEXT",
        "message_id": "TEXT",
        "received_at": "TEXT",
        "category": "TEXT DEFAULT 'Other'",
        "spam": "INTEGER DEFAULT 0",
        "phishing": "INTEGER DEFAULT 0",
        "high_risk": "INTEGER DEFAULT 0",
        "risk_score": "INTEGER DEFAULT 0",
        "risk_level": "TEXT DEFAULT 'Low Risk'",
        "header_risk": "INTEGER DEFAULT 0",
        "url_risk": "INTEGER DEFAULT 0",
        "phishing_risk": "INTEGER DEFAULT 0",
        "spam_risk": "INTEGER DEFAULT 0",
        "action": "TEXT DEFAULT 'none'",
        "is_read": "INTEGER DEFAULT 0",
        "raw_email": "TEXT",
        "created_at": "TEXT DEFAULT CURRENT_TIMESTAMP"
    }

    for column_name, column_definition in required_columns.items():

        if column_name not in existing_columns:

            cursor.execute(
                f"""
                ALTER TABLE emails
                ADD COLUMN {column_name}
                {column_definition}
                """
            )

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_senders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT UNIQUE NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS unsubscribe_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            email TEXT,
            status TEXT DEFAULT 'pending',
            unsubscribe_url TEXT,
            attempted_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    default_categories = [
        "Food",
        "Shopping",
        "Travel",
        "Finance",
        "Entertainment",
        "News",
        "Work",
        "Education",
        "Gaming",
        "Subscriptions",
        "Other"
    ]

    for category in default_categories:

        cursor.execute(
            """
            INSERT OR IGNORE INTO categories (
                name
            )
            VALUES (?)
            """,
            (category,)
        )

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_emails_gmail_lookup
        ON emails(
            gmail_account,
            gmail_mailbox,
            gmail_uid
        )
    """)

    connection.commit()

    connection.close()


def add_email(
    sender,
    subject="",
    body="",
    received_at="",
    raw_email="",
    category="Other",
    spam=False,
    phishing=False,
    high_risk=False,
    risk_score=0,
    risk_level="Low Risk",
    header_risk=0,
    url_risk=0,
    phishing_risk=0,
    spam_risk=0,
    gmail_uid=None,
    gmail_account=None,
    gmail_mailbox=None,
    message_id=None,
    is_read=False
):

    connection = get_connection()

    cursor = connection.cursor()

    existing = None

    if (
        gmail_uid
        and gmail_account
        and gmail_mailbox
    ):

        existing = cursor.execute(
            """
            SELECT id
            FROM emails
            WHERE gmail_uid = ?
            AND gmail_account = ?
            AND gmail_mailbox = ?
            """,
            (
                str(gmail_uid),
                gmail_account,
                gmail_mailbox
            )
        ).fetchone()

    if existing:

        cursor.execute(
            """
            UPDATE emails
            SET sender = ?,
                subject = ?,
                body = ?,
                received_at = ?,
                category = ?,
                spam = ?,
                raw_email = ?,
                phishing = ?,
                high_risk = ?,
                risk_score = ?,
                risk_level = ?,
                header_risk = ?,
                url_risk = ?,
                phishing_risk = ?,
                spam_risk = ?,
                message_id = ?
            WHERE id = ?
            """,
            (
                sender,
                subject,
                body,
                received_at,
                category,
                int(spam),
                raw_email,
                int(phishing),
                int(high_risk),
                risk_score,
                risk_level,
                header_risk,
                url_risk,
                phishing_risk,
                spam_risk,
                message_id,
                existing["id"]
            )
        )

        email_id = existing["id"]

        connection.commit()

        connection.close()

        return email_id

    cursor.execute(
        """
        INSERT INTO emails (
            gmail_uid,
            gmail_account,
            gmail_mailbox,
            message_id,
            sender,
            subject,
            body,
            raw_email,
            received_at,
            category,
            spam,
            phishing,
            high_risk,
            risk_score,
            risk_level,
            header_risk,
            url_risk,
            phishing_risk,
            spam_risk,
            action,
            is_read
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, 'none', ?
        )
        """,
        (
            str(gmail_uid)
            if gmail_uid
            else None,
            gmail_account,
            gmail_mailbox,
            message_id,
            sender,
            subject,
            body,
            raw_email,
            received_at,
            category,
            int(spam),
            int(phishing),
            int(high_risk),
            risk_score,
            risk_level,
            header_risk,
            url_risk,
            phishing_risk,
            spam_risk,
            int(is_read)
        )
    )

    email_id = cursor.lastrowid

    connection.commit()

    connection.close()

    return email_id


def get_all_emails():

    connection = get_connection()

    emails = connection.execute(
        """
        SELECT *
        FROM emails
        ORDER BY
            COALESCE(
                NULLIF(received_at, ''),
                created_at
            ) DESC
        """
    ).fetchall()

    connection.close()

    return emails


def get_email(email_id):

    connection = get_connection()

    result = connection.execute(
        """
        SELECT *
        FROM emails
        WHERE id = ?
        """,
        (email_id,)
    ).fetchone()

    connection.close()

    return result


def get_email_by_gmail_uid(
    gmail_uid,
    gmail_account,
    gmail_mailbox
):

    connection = get_connection()

    result = connection.execute(
        """
        SELECT *
        FROM emails
        WHERE gmail_uid = ?
        AND gmail_account = ?
        AND gmail_mailbox = ?
        """,
        (
            str(gmail_uid),
            gmail_account,
            gmail_mailbox
        )
    ).fetchone()

    connection.close()

    return result

def sync_gmail_messages(
    gmail_account,
    gmail_mailbox,
    current_uids
):

    connection = get_connection()

    current_uids = {
        str(uid)
        for uid in current_uids
    }

    rows = connection.execute(
        """
        SELECT id, gmail_uid
        FROM emails
        WHERE gmail_account = ?
        AND gmail_mailbox = ?
        AND gmail_uid IS NOT NULL
        """,
        (
            gmail_account,
            gmail_mailbox
        )
    ).fetchall()

    deleted_ids = []

    for row in rows:

        stored_uid = str(
            row["gmail_uid"]
        )

        if stored_uid not in current_uids:

            deleted_ids.append(
                row["id"]
            )

    if deleted_ids:

        placeholders = ",".join(
            "?"
            for _ in deleted_ids
        )

        connection.execute(
            f"""
            DELETE FROM emails
            WHERE id IN ({placeholders})
            """,
            deleted_ids
        )

    connection.commit()

    connection.close()

    return len(deleted_ids)


def update_email_action(
    email_id,
    action
):

    connection = get_connection()

    connection.execute(
        """
        UPDATE emails
        SET action = ?
        WHERE id = ?
        """,
        (
            action,
            email_id
        )
    )

    connection.commit()

    connection.close()


def update_emails_action(
    email_ids,
    action
):

    if not email_ids:
        return

    connection = get_connection()

    placeholders = ",".join(
        "?"
        for _ in email_ids
    )

    connection.execute(
        f"""
        UPDATE emails
        SET action = ?
        WHERE id IN ({placeholders})
        """,
        [action] + list(email_ids)
    )

    connection.commit()

    connection.close()


def delete_email(email_id):

    connection = get_connection()

    connection.execute(
        """
        DELETE FROM emails
        WHERE id = ?
        """,
        (email_id,)
    )

    connection.commit()

    connection.close()


def delete_all_emails(email_ids):

    if not email_ids:
        return

    connection = get_connection()

    placeholders = ",".join(
        "?"
        for _ in email_ids
    )

    connection.execute(
        f"""
        DELETE FROM emails
        WHERE id IN ({placeholders})
        """,
        email_ids
    )

    connection.commit()

    connection.close()


def delete_emails(email_ids):

    delete_all_emails(
        email_ids
    )


def mark_email_as_read(email_id):

    connection = get_connection()

    connection.execute(
        """
        UPDATE emails
        SET is_read = 1
        WHERE id = ?
        """,
        (email_id,)
    )

    connection.commit()

    connection.close()


def mark_email_as_unread(email_id):

    connection = get_connection()

    connection.execute(
        """
        UPDATE emails
        SET is_read = 0
        WHERE id = ?
        """,
        (email_id,)
    )

    connection.commit()

    connection.close()


def mark_emails_as_read(email_ids):

    if not email_ids:
        return

    connection = get_connection()

    placeholders = ",".join(
        "?"
        for _ in email_ids
    )

    connection.execute(
        f"""
        UPDATE emails
        SET is_read = 1
        WHERE id IN ({placeholders})
        """,
        email_ids
    )

    connection.commit()

    connection.close()


def mark_emails_as_unread(email_ids):

    if not email_ids:
        return

    connection = get_connection()

    placeholders = ",".join(
        "?"
        for _ in email_ids
    )

    connection.execute(
        f"""
        UPDATE emails
        SET is_read = 0
        WHERE id IN ({placeholders})
        """,
        email_ids
    )

    connection.commit()

    connection.close()


def block_sender(sender):

    connection = get_connection()

    connection.execute(
        """
        INSERT OR IGNORE INTO blocked_senders (
            sender
        )
        VALUES (?)
        """,
        (sender,)
    )

    connection.commit()

    connection.close()


def get_blocked_senders():

    connection = get_connection()

    senders = connection.execute(
        """
        SELECT *
        FROM blocked_senders
        ORDER BY created_at DESC
        """
    ).fetchall()

    connection.close()

    return senders


def add_unsubscribe_record(
    sender,
    email="",
    status="pending",
    unsubscribe_url=""
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO unsubscribe_records (
            sender,
            email,
            status,
            unsubscribe_url
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            sender,
            email,
            status,
            unsubscribe_url
        )
    )

    record_id = cursor.lastrowid

    connection.commit()

    connection.close()

    return record_id


def get_unsubscribe_records():

    connection = get_connection()

    records = connection.execute(
        """
        SELECT *
        FROM unsubscribe_records
        ORDER BY created_at DESC
        """
    ).fetchall()

    connection.close()

    return records


def update_unsubscribe_status(
    record_id,
    status
):

    connection = get_connection()

    connection.execute(
        """
        UPDATE unsubscribe_records
        SET status = ?,
            attempted_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            status,
            record_id
        )
    )

    connection.commit()

    connection.close()

def get_categories():

    connection = get_connection()

    categories = connection.execute(
        """
        SELECT *
        FROM categories
        ORDER BY name
        """
    ).fetchall()

    connection.close()

    return categories


def add_category(name):

    connection = get_connection()

    connection.execute(
        """
        INSERT OR IGNORE INTO categories (
            name
        )
        VALUES (?)
        """,
        (name,)
    )

    connection.commit()

    connection.close()


if __name__ == "__main__":

    initialize_database()

    print(
        "MailGuard database initialized."
    )

    print(
        f"Database location: {DATABASE_PATH}"
    )