from datetime import datetime


def get_severity(test_type, vulnerable):
    if not vulnerable:
        return "INFO"

    if test_type == "BOLA":
        return "HIGH"

    if test_type == "BFLA":
        return "HIGH"

    return "MEDIUM"


def get_cwe(test_type):
    if test_type == "BOLA":
        return "CWE-639"

    if test_type == "BFLA":
        return "CWE-862"

    return "CWE-285"


def get_owasp_category(test_type):
    if test_type == "BOLA":
        return "API1:2023 - Broken Object Level Authorization"

    if test_type == "BFLA":
        return "API5:2023 - Broken Function Level Authorization"

    return "Authorization Failure"


def create_evidence(test_case, response, analysis):

    test_type = test_case["type"]
    vulnerable = analysis["vulnerable"]

    evidence = {
        "timestamp": datetime.now().isoformat(),

        "finding": {
            "type": test_type,
            "result": analysis["result"],
            "vulnerable": vulnerable,
            "severity": get_severity(
                test_type,
                vulnerable
            )
        },

        "authorization": {
            "attacker": test_case.get("attacker"),
            "resource_owner": test_case.get(
                "resource_owner"
            ),
            "expected_access": test_case[
                "expected_access"
            ],
            "actual_access": (
                "ALLOWED"
                if response["status_code"] == 200
                else "DENIED"
            )
        },

        "request": {
            "method": test_case["method"],
            "endpoint": test_case["endpoint"]
        },

        "response": {
            "status_code": response["status_code"],
            "body": response.get("body", ""),
            "headers": response.get("headers", {})
        },

        "classification": {
            "cwe": get_cwe(test_type),
            "owasp": get_owasp_category(test_type)
        },

        "explanation": analysis["reason"]
    }

    return evidence