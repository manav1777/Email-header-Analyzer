from url_analyzer import analyze_url


test_urls = [
    "https://www.google.com",
    "http://192.168.1.50/login",
    "https://example.com/account/verify"
]


for url in test_urls:
    result = analyze_url(url)

    print("\nURL:", result["url"])
    print("Risk Score:", result["risk_score"])

    for finding in result["findings"]:
        print("[!]", finding)