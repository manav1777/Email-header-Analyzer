import re


SPAM_PATTERNS = {
    "promotional": [
        "special offer",
        "limited time offer",
        "exclusive offer",
        "buy now",
        "shop now",
        "save money",
        "save big",
        "discount",
        "sale",
        "promotion",
        "promo",
        "deal",
        "coupon",
        "free shipping"
    ],

    "marketing": [
        "marketing",
        "advertisement",
        "advertising",
        "unsubscribe",
        "newsletter",
        "weekly update",
        "monthly update",
        "special promotion"
    ],

    "financial": [
        "casino",
        "betting",
        "bonus",
        "jackpot",
        "win money",
        "free money",
        "claim your prize"
    ],

    "excessive_sales": [
        "act now",
        "don't miss",
        "last chance",
        "hurry",
        "order today",
        "click here",
        "limited availability"
    ]
}


def detect_spam(text):

    if not text:
        return {
            "spam_score": 0,
            "spam_level": "Low",
            "is_spam": False,
            "findings": []
        }

    text_lower = text.lower()

    score = 0
    findings = []

    detected_patterns = set()

    for category, patterns in SPAM_PATTERNS.items():

        category_matches = []

        for pattern in patterns:

            if re.search(
                re.escape(pattern),
                text_lower
            ):

                category_matches.append(
                    pattern
                )

                detected_patterns.add(
                    pattern
                )

        if category_matches:

            findings.append(
                f"{category.title()} content detected: "
                + ", ".join(category_matches)
            )

            score += min(
                len(category_matches) * 10,
                25
            )

    # Email contains unsubscribe language
    # This is normally a sign of marketing email,
    # not necessarily malicious email.

    if "unsubscribe" in text_lower:

        if "Marketing or subscription email detected" not in findings:

            findings.append(
                "Marketing or subscription email detected"
            )

        score += 10

    # Excessive dollar signs
    dollar_count = text.count("$")

    if dollar_count >= 3:

        findings.append(
            "Multiple monetary references detected"
        )

        score += 10

    # Excessive exclamation marks
    exclamation_count = text.count("!")

    if exclamation_count >= 5:

        findings.append(
            "Excessive promotional punctuation detected"
        )

        score += 5

    score = min(
        score,
        100
    )

    if score >= 70:

        level = "High"

    elif score >= 40:

        level = "Medium"

    else:

        level = "Low"

    return {
        "spam_score": score,
        "spam_level": level,
        "is_spam": score >= 50,
        "findings": findings,
        "detected_patterns": sorted(
            detected_patterns
        )
    }


if __name__ == "__main__":

    test_email = """
    Subject: SPECIAL OFFER!

    Buy now and save 50%.

    Limited time offer.
    Free shipping.
    Click here to shop now.

    Unsubscribe from this newsletter.
    """

    result = detect_spam(
        test_email
    )

    print("MailGuard Spam Analysis")
    print("-----------------------")
    print(
        f"Spam Score: {result['spam_score']}"
    )
    print(
        f"Spam Level: {result['spam_level']}"
    )
    print(
        f"Spam Detected: {result['is_spam']}"
    )

    print("\nFindings:")

    for finding in result["findings"]:

        print(f"[!] {finding}")