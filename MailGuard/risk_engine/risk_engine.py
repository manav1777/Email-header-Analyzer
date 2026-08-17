def calculate_risk(header_score, url_results, phishing_score=0):
    """
    Combine header, URL, and phishing security signals
    into a normalized MailGuard risk score.
    """

    header_risk = min(
        header_score * 10,
        100
    )

    if url_results:

        url_risk = max(
            result["risk_score"]
            for result in url_results
        )

    else:

        url_risk = 0

    phishing_risk = min(
        phishing_score,
        100
    )

    final_score = (
        header_risk * 0.45
        + url_risk * 0.25
        + phishing_risk * 0.30
    )

    final_score = round(
        min(
            final_score,
            100
        )
    )

    if final_score <= 29:

        level = "Low Risk"

    elif final_score <= 59:

        level = "Medium Risk"

    elif final_score <= 79:

        level = "High Risk"

    else:

        level = "Critical Risk"

    return {
        "risk_score": final_score,
        "risk_level": level,
        "header_risk": round(header_risk),
        "url_risk": round(url_risk),
        "phishing_risk": round(phishing_risk)
    }