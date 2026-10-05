def analyze_authorization(test_case, response):
    expected = test_case["expected_access"]
    status_code = response["status_code"]

    if expected == "DENY":

        if status_code in [401, 403]:
            return {
                "result": "PASS",
                "vulnerable": False,
                "reason": "Access correctly denied."
            }

        if status_code == 200:
            return {
                "result": "FAIL",
                "vulnerable": True,
                "reason": (
                    "The API returned a successful response where "
                    "access was expected to be denied."
                )
            }

    return {
        "result": "PASS",
        "vulnerable": False,
        "reason": "No authorization issue detected."
    }