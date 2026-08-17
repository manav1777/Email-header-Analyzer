from risk_engine import calculate_risk


test_urls = [
    {
        "url": "http://192.168.1.50/login",
        "risk_score": 50,
        "findings": [
            "URL does not use HTTPS",
            "URL uses an IP address instead of a domain",
            "Suspicious keywords detected: login"
        ]
    }
]


result = calculate_risk(
    header_score=6,
    url_results=test_urls,
    phishing_score=80
)


print("MailGuard Risk Report")
print("---------------------")
print("Overall Risk:", result["risk_score"])
print("Risk Level:", result["risk_level"])
print("Header Risk:", result["header_risk"])
print("URL Risk:", result["url_risk"])
print("Phishing Risk:", result["phishing_risk"])