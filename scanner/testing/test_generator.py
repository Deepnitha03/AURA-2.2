def generate_tests(endpoints):
    tests = []

    for endpoint in endpoints:
        path = endpoint["path"]
        method = endpoint["method"]

        # BOLA test: endpoints containing an object ID
        if "{" in path and "}" in path:
            tests.append({
                "type": "BOLA",
                "method": method,
                "endpoint": path,
                "expected_access": "DENY"
            })

        # BFLA test: admin-related endpoints
        if (
            "/admin" in path.lower()
            or "admin" in endpoint.get("summary", "").lower()
        ):
            tests.append({
                "type": "BFLA",
                "method": method,
                "endpoint": path,
                "expected_access": "DENY"
            })

    return tests