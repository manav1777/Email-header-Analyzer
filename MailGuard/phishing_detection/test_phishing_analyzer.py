from phishing_analyzer import detect_phishing


test_email = """
URGENT SECURITY ALERT

Your account has been flagged for unusual activity.

Your account will be suspended if you do not verify your account
within 2 hours.

Please click here to login and confirm your identity.

Enter your password to verify your credentials.
"""


result = detect_phishing(test_email)


print("MailGuard Phishing Analysis")
print("---------------------------")
print("Phishing Score:", result["phishing_score"])
print("Phishing Level:", result["phishing_level"])

print("\nFindings:")

for finding in result["findings"]:
    print("[!]", finding)