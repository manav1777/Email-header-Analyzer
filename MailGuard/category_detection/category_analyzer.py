CATEGORY_KEYWORDS = {

    "Food": [
        "restaurant",
        "food",
        "pizza",
        "burger",
        "doordash",
        "ubereats",
        "uber eats",
        "grubhub",
        "dominos",
        "domino's",
        "chipotle",
        "mcdonalds",
        "hello fresh",
        "hellofresh",
        "meal",
        "food delivery"
    ],

    "Shopping": [
        "shopping",
        "purchase",
        "amazon",
        "walmart",
        "target",
        "ebay",
        "best buy",
        "coupon",
        "discount",
        "sale",
        "shipment",
        "shopping order",
        "product order"
    ],

    "Travel": [
        "flight",
        "airline",
        "hotel",
        "booking",
        "reservation",
        "travel",
        "vacation",
        "trip",
        "boarding pass",
        "airport",
        "expedia",
        "airbnb"
    ],

    "Finance": [
        "bank",
        "banking",
        "credit card",
        "debit card",
        "payment",
        "transaction",
        "invoice",
        "account balance",
        "loan",
        "mortgage",
        "investment",
        "investing",
        "paypal",
        "venmo",
        "capital"
    ],

    "Entertainment": [
        "movie",
        "music",
        "concert",
        "streaming",
        "netflix",
        "spotify",
        "youtube",
        "ticket",
        "entertainment"
    ],

    "News": [
        "news",
        "breaking news",
        "daily news",
        "newsletter",
        "headline",
        "world news",
        "weekly news"
    ],

    "Work": [
        "meeting",
        "project",
        "office",
        "employee",
        "coworker",
        "business",
        "company",
        "deadline",
        "teams",
        "slack"
    ],

    "Education": [
        "school",
        "university",
        "college",
        "class",
        "course",
        "student",
        "professor",
        "assignment",
        "exam",
        "education"
    ],

    "Gaming": [
        "game",
        "gaming",
        "steam",
        "playstation",
        "xbox",
        "nintendo",
        "esports",
        "gameplay"
    ],

    "Subscriptions": [
        "subscription",
        "renewal",
        "membership",
        "subscription renewal",
        "monthly plan",
        "annual plan"
    ]
}


SECURITY_KEYWORDS = [
    "phishing",
    "security alert",
    "security warning",
    "verify your account",
    "account verification",
    "confirm your identity",
    "unusual activity",
    "suspicious activity",
    "password",
    "login",
    "sign in",
    "credential",
    "security verification"
]


def detect_category(text):

    if not text:

        return {
            "category": "Other",
            "confidence": 0,
            "matches": []
        }

    text_lower = text.lower()


    # -----------------------------------------------------
    # Security messages should remain Other
    # -----------------------------------------------------

    security_matches = []

    for keyword in SECURITY_KEYWORDS:

        if keyword in text_lower:

            security_matches.append(
                keyword
            )

    if security_matches:

        return {
            "category": "Other",
            "confidence": 0,
            "matches": security_matches
        }


    # -----------------------------------------------------
    # Category matching
    # -----------------------------------------------------

    category_scores = {}

    category_matches = {}


    for category, keywords in CATEGORY_KEYWORDS.items():

        matches = []

        for keyword in keywords:

            if keyword in text_lower:

                matches.append(
                    keyword
                )

        if matches:

            category_scores[category] = len(
                matches
            )

            category_matches[category] = matches


    # -----------------------------------------------------
    # No category found
    # -----------------------------------------------------

    if not category_scores:

        return {
            "category": "Other",
            "confidence": 0,
            "matches": []
        }


    # -----------------------------------------------------
    # Highest scoring category
    # -----------------------------------------------------

    best_category = max(
        category_scores,
        key=category_scores.get
    )

    best_score = category_scores[
        best_category
    ]


    confidence = min(
        best_score * 20,
        100
    )


    return {
        "category": best_category,
        "confidence": confidence,
        "matches": category_matches[
            best_category
        ]
    }


if __name__ == "__main__":

    test_emails = [

        """
        Order your favorite pizza from Domino's.
        Get free delivery today.
        """,

        """
        Your Amazon order has shipped.
        """,

        """
        Your flight reservation is confirmed.
        """,

        """
        Your bank account payment was processed.
        """,

        """
        Your account requires immediate verification.
        Please login and confirm your identity.
        """
    ]


    print(
        "MailGuard Category Detection"
    )

    print(
        "----------------------------"
    )


    for email in test_emails:

        result = detect_category(
            email
        )

        print(
            f"Category: {result['category']}"
        )

        print(
            f"Confidence: {result['confidence']}"
        )

        print(
            f"Matches: {result['matches']}"
        )

        print()