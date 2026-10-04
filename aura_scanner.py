import json

from scanner.discovery.openapi_parser import (
    discover_openapi,
    extract_endpoints
)

from scanner.testing.test_generator import generate_tests
from scanner.executor.request_executor import RequestExecutor
from scanner.analysis.authorization_analyzer import analyze_authorization
from scanner.evidence.evidence_engine import create_evidence


OPENAPI_URL = "http://localhost:8000/openapi.json"
BASE_URL = "http://localhost:8000"

# Safe test identities for our local demo API
ATTACKER_NAME = "Alice"
ATTACKER_TOKEN = "alice-token"

RESOURCE_OWNER = "Bob"
RESOURCE_ID = 2


def main():

    print("=" * 60)
    print("             AURA SECURITY SCANNER")
    print("=" * 60)

    # ---------------------------------------------------------
    # 1. DISCOVER
    # ---------------------------------------------------------
    print("\n[1] DISCOVERING API")

    try:
        specification = discover_openapi(OPENAPI_URL)
        endpoints = extract_endpoints(specification)

        print(f"Discovered {len(endpoints)} endpoints.")

        for endpoint in endpoints:
            print(
                f"  {endpoint['method']:6} "
                f"{endpoint['path']}"
            )

    except Exception as error:
        print(f"Discovery failed: {error}")
        return

    # ---------------------------------------------------------
    # 2. GENERATE TESTS
    # ---------------------------------------------------------
    print("\n[2] GENERATING SECURITY TESTS")

    tests = generate_tests(endpoints)

    print(f"Generated {len(tests)} tests.")

    for test in tests:
        print(
            f"  [{test['type']}] "
            f"{test['method']} "
            f"{test['endpoint']}"
        )

    # ---------------------------------------------------------
    # 3. EXECUTE TESTS
    # ---------------------------------------------------------
    print("\n[3] EXECUTING SECURITY TESTS")

    executor = RequestExecutor(BASE_URL)

    evidence_results = []

    for test in tests:

        endpoint = test["endpoint"]
        token = ATTACKER_TOKEN

        # -----------------------------------------------------
        # BOLA
        # -----------------------------------------------------
        if test["type"] == "BOLA":

            endpoint = endpoint.replace(
                "{user_id}",
                str(RESOURCE_ID)
            )

            test["attacker"] = ATTACKER_NAME
            test["resource_owner"] = RESOURCE_OWNER

        # -----------------------------------------------------
        # BFLA
        # -----------------------------------------------------
        elif test["type"] == "BFLA":

            test["attacker"] = ATTACKER_NAME

        print(
            f"\nTesting [{test['type']}] "
            f"{test['method']} {endpoint}"
        )

        response = executor.execute(
            method=test["method"],
            endpoint=endpoint,
            token=token
        )

        print(
            f"  HTTP Status: "
            f"{response['status_code']}"
        )

        # -----------------------------------------------------
        # 4. ANALYZE
        # -----------------------------------------------------
        analysis = analyze_authorization(
            test,
            response
        )

        print(
            f"  Result: "
            f"{analysis['result']}"
        )

        if analysis["vulnerable"]:
            print("  ⚠ VULNERABILITY DETECTED")
        else:
            print("  ✓ Access correctly controlled")

        # -----------------------------------------------------
        # 5. CREATE EVIDENCE
        # -----------------------------------------------------
        evidence = create_evidence(
            test,
            response,
            analysis
        )

        # Store actual tested endpoint
        evidence["tested_endpoint"] = endpoint

        evidence_results.append(evidence)

    # ---------------------------------------------------------
    # 6. SAVE EVIDENCE
    # ---------------------------------------------------------
    output_file = "scan_results.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(
            evidence_results,
            file,
            indent=4
        )

    print(
        f"\nEvidence saved to: "
        f"{output_file}"
    )

    # ---------------------------------------------------------
    # 7. SUMMARY
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("                 SCAN SUMMARY")
    print("=" * 60)

    vulnerabilities = [
        evidence
        for evidence in evidence_results
        if evidence["finding"]["vulnerable"]
    ]

    print(
        f"Tests executed: "
        f"{len(evidence_results)}"
    )

    print(
        f"Vulnerabilities found: "
        f"{len(vulnerabilities)}"
    )

    for evidence in vulnerabilities:

        finding = evidence["finding"]
        request = evidence["request"]
        response = evidence["response"]

        print(
            f"\n  [{finding['type']}] "
            f"{request['method']} "
            f"{request['endpoint']}"
        )

        print(
            f"  Severity: "
            f"{finding['severity']}"
        )

        print(
            f"  Status: "
            f"{response['status_code']}"
        )

        print(
            f"  CWE: "
            f"{evidence['classification']['cwe']}"
        )

        print(
            f"  OWASP: "
            f"{evidence['classification']['owasp']}"
        )

        print(
            f"  Reason: "
            f"{evidence['explanation']}"
        )


if __name__ == "__main__":
    main()