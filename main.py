from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import httpx
import time
import uuid
import re
from urllib.parse import urljoin

app = FastAPI(title="AURA-2.2", version="2.2.0", description="Continuous API Authorization Security")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Controlled demo identities only. Do not use these credentials in production.
DEMO_USERS = {
    "alice": {"id": 1, "name": "Alice", "role": "user", "token": "alice-token"},
    "bob": {"id": 2, "name": "Bob", "role": "user", "token": "bob-token"},
    "admin": {"id": 3, "name": "Admin", "role": "admin", "token": "admin-token"},
}
ORDERS = {
    101: {"id": 101, "user_id": 1, "product": "Laptop", "amount": 55000},
    201: {"id": 201, "user_id": 2, "product": "Phone", "amount": 30000},
}
demo_fixed = False

# Redaction helpers. These protect scanner output, not the legitimate login response.
SECRET_KEY = re.compile(r"(?i)(token|authorization|api[_-]?key|password|secret|cookie)")
BEARER_PATTERN = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
ASSIGNMENT_PATTERN = re.compile(
    r"""(?i)((?:access_token|refresh_token|api[_-]?key|token|password|secret)\s*["']?\s*[:=]\s*["']?)[^"'\s,}&]+"""
)


def redact_secrets(value):
    """Redact common credentials recursively in scanner output and evidence."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if SECRET_KEY.search(str(key)):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact_secrets(item)
        return result
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        result = BEARER_PATTERN.sub(r"\1[REDACTED]", value)
        result = ASSIGNMENT_PATTERN.sub(r"\1[REDACTED]", result)
        for demo_user in DEMO_USERS.values():
            token = demo_user.get("token", "")
            if token:
                result = result.replace(token, "[REDACTED]")
        return result
    return value


def public_test(test):
    """Never return the scanner's internal token in a test record."""
    return {
        key: redact_secrets(value)
        for key, value in test.items()
        if key.lower() not in {"token", "access_token", "authorization", "api_key"}
    }


def demo_identity(request: Request):
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None, None
    for name, user in DEMO_USERS.items():
        if token.strip() == user["token"]:
            return name, user
    return None, None


@app.get("/target/health", tags=["Demo Target"])
def target_health():
    return {"status": "online", "target": "AURA Demo Target API"}


@app.post("/target/login", tags=["Demo Target"])
async def target_login(payload: dict):
    # Returning an access token to the client that supplied valid credentials is
    # normal login behavior. Never copy this response into scan evidence/reports.
    username = payload.get("username")
    user = DEMO_USERS.get(username)
    if not user or payload.get("password") != f"{username}123":
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {
        "access_token": user["token"],
        "token_type": "bearer",
        "user": user["name"],
        "role": user["role"],
    }


@app.get("/target/orders/{order_id}", tags=["Demo Target"])
async def target_order(order_id: int, request: Request):
    _, user = demo_identity(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    # Enforce object-level authorization on every request.
    if user["id"] != order["user_id"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return order


@app.get("/target/secure/orders/{order_id}", tags=["Demo Target"])
async def target_secure_order(order_id: int, request: Request):
    _, user = demo_identity(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if user["id"] != order["user_id"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return order


@app.get("/target/admin/reports", tags=["Demo Target"])
async def target_admin_reports(request: Request):
    _, user = demo_identity(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"report": "Confidential admin report", "total_orders": len(ORDERS)}


@app.get("/target/profiles/{user_id}", tags=["Demo Target"])
async def target_profile(user_id: int, request: Request):
    _, user = demo_identity(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    for candidate in DEMO_USERS.values():
        if candidate["id"] == user_id:
            return {"id": candidate["id"], "name": candidate["name"], "role": candidate["role"]}
    raise HTTPException(status_code=404, detail="User not found")


@app.post("/target/fix", tags=["Demo Target"])
def fix_demo_target():
    global demo_fixed
    demo_fixed = True
    return {"status": "fixed", "message": "Demo target authorization checks enabled"}


@app.post("/target/reset", tags=["Demo Target"])
def reset_demo_target():
    global demo_fixed
    demo_fixed = False
    return {"status": "reset", "message": "Demo target returned to vulnerable demonstration mode"}


# ---------------- AURA scanner state ----------------
class TargetIn(BaseModel):
    name: str
    base_url: str
    openapi_url: str
    token_a: str
    token_b: str
    authorized: bool


state = {
    "target": None,
    "endpoints": [],
    "tests": [],
    "findings": [],
    "evidence": [],
    "last_run": None,
}


@app.get("/", response_class=HTMLResponse)
def home():
    with open("static/index.html", encoding="utf-8") as file:
        return file.read()


async def fetch_json(url: str):
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


@app.post("/api/targets")
async def add_target(target: TargetIn):
    if not target.authorized:
        raise HTTPException(status_code=400, detail="Confirm that you are authorized to test this API.")
    state["target"] = target.model_dump()
    state["endpoints"] = []
    state["tests"] = []
    state["findings"] = []
    state["evidence"] = []
    # Never return target credentials to the browser.
    return {
        "status": "connected",
        "target": {
            "name": target.name,
            "base_url": target.base_url,
            "openapi_url": target.openapi_url,
            "authorized": target.authorized,
        },
    }


@app.get("/api/targets")
def targets():
    target = state["target"]
    if not target:
        return {"target": None}
    return {
        "target": {
            "name": target["name"],
            "base_url": target["base_url"],
            "openapi_url": target["openapi_url"],
            "authorized": target["authorized"],
        }
    }


@app.post("/api/targets/discover")
async def discover():
    if not state["target"]:
        raise HTTPException(status_code=400, detail="Connect a target first.")
    spec = await fetch_json(state["target"]["openapi_url"])
    endpoints = []
    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            # An operation-level security declaration overrides global security.
            security_declared = details.get("security") if "security" in details else spec.get("security")
            if security_declared == []:
                classification = "Public (explicitly declared in OpenAPI)"
                security_required = False
            elif security_declared:
                classification = "Authentication declared in OpenAPI"
                security_required = True
            else:
                classification = "Unknown (OpenAPI does not specify security)"
                security_required = None
            endpoints.append({
                "method": method.upper(),
                "path": path,
                "summary": details.get("summary", ""),
                "security": security_required,
                "auth_classification": classification,
                "parameters": [parameter.get("name") for parameter in details.get("parameters", [])],
            })
    state["endpoints"] = endpoints
    return {"status": "discovered", "count": len(endpoints), "endpoints": endpoints}


@app.get("/api/endpoints")
def endpoints():
    return {"endpoints": state["endpoints"]}


@app.get("/api/authorization-graph")
def auth_graph():
    return {
        "nodes": [
            {"id": "alice", "type": "USER", "label": "Alice"},
            {"id": "bob", "type": "USER", "label": "Bob"},
            {"id": "user-role", "type": "ROLE", "label": "Customer"},
            {"id": "admin-role", "type": "ROLE", "label": "Admin"},
            {"id": "read", "type": "PERMISSION", "label": "READ"},
            {"id": "orders", "type": "ENDPOINT", "label": "/target/orders/{order_id}"},
            {"id": "admin-reports", "type": "ENDPOINT", "label": "/target/admin/reports"},
            {"id": "order101", "type": "RESOURCE", "label": "Order 101"},
            {"id": "order201", "type": "RESOURCE", "label": "Order 201"},
        ],
        "edges": [
            ["alice", "user-role"], ["bob", "user-role"], ["admin", "admin-role"],
            ["user-role", "read"], ["read", "orders"], ["orders", "order101"], ["orders", "order201"],
        ],
    }


@app.post("/api/tests/generate")
def generate_tests():
    if not state["target"]:
        raise HTTPException(status_code=400, detail="Connect a target first.")
    paths = {endpoint["path"] for endpoint in state["endpoints"]}
    tests = []
    if "/target/orders/{order_id}" in paths or any("/orders/{order_id}" in path for path in paths):
        path = next(
            (endpoint["path"] for endpoint in state["endpoints"]
             if "orders/{order_id}" in endpoint["path"] and "secure" not in endpoint["path"]),
            "/target/orders/{order_id}",
        )
        tests.append({
            "id": "BOLA-001", "type": "BOLA", "identity": "Alice",
            "endpoint": path.replace("{order_id}", "201").replace("/target/", "/"),
            "expected": 403, "description": "Alice must not access Bob's Order 201",
            "token": state["target"]["token_a"],
        })
    if "/target/admin/reports" in paths or any("/admin/reports" in path for path in paths):
        path = next((endpoint["path"] for endpoint in state["endpoints"] if "/admin/reports" in endpoint["path"]),
                    "/target/admin/reports")
        tests.append({
            "id": "BFLA-001", "type": "BFLA", "identity": "Alice (normal user)",
            "endpoint": path.replace("/target/", "/"), "expected": 403,
            "description": "Normal user must not access admin reports",
            "token": state["target"]["token_a"],
        })
    state["tests"] = tests
    return {"tests": [public_test(test) for test in tests], "count": len(tests)}


@app.get("/api/tests")
def get_tests():
    return {"tests": [public_test(test) for test in state["tests"]]}


@app.post("/api/tests/run")
async def run_tests():
    if not state["target"]:
        raise HTTPException(status_code=400, detail="Connect a target first.")
    if not state["tests"]:
        generate_tests()
    base = state["target"]["base_url"].rstrip("/")
    findings = []
    evidence = []
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        for test in state["tests"]:
            url = urljoin(base + "/", test["endpoint"].lstrip("/"))
            started = time.perf_counter()
            try:
                response = await client.get(url, headers={"Authorization": f"Bearer {test['token']}"})
                elapsed = round((time.perf_counter() - started) * 1000, 2)
                actual = response.status_code
                body = redact_secrets(response.text[:1000])
                vulnerable = actual != test["expected"] and actual < 300
                item = {
                    **public_test(test),
                    "actual": actual,
                    "status": "VULNERABLE" if vulnerable else "SECURE",
                    "response_time_ms": elapsed,
                }
                evidence_item = {
                    "id": str(uuid.uuid4())[:8],
                    "test_id": test["id"],
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "request": f"GET {test['endpoint']}",
                    "expected": test["expected"],
                    "actual": actual,
                    "response_body": body,
                    "response_time_ms": elapsed,
                }
                evidence.append(redact_secrets(evidence_item))
                if vulnerable:
                    findings.append({
                        **item, "severity": "HIGH", "evidence_id": evidence_item["id"],
                        "evidence": "Unauthorized resource/function returned by target API.",
                    })
            except Exception as exc:
                evidence.append({
                    "id": str(uuid.uuid4())[:8], "test_id": test["id"],
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "request": f"GET {test['endpoint']}",
                    "error": "Target request failed; sensitive exception details withheld.",
                })
    state["findings"] = redact_secrets(findings)
    state["evidence"] = redact_secrets(evidence)
    state["last_run"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return {"status": "completed", "findings": state["findings"], "evidence": state["evidence"]}


@app.get("/api/findings")
def findings():
    return {"findings": redact_secrets(state["findings"])}


@app.get("/api/evidence")
def evidence():
    return {"evidence": redact_secrets(state["evidence"])}


@app.post("/api/fix-and-retest")
async def fix_and_retest():
    base = (state["target"] or {}).get("base_url", "")
    if not base.endswith("/target") and "/target" not in base:
        raise HTTPException(status_code=400, detail="Fix demo is available only for the controlled AURA demo target.")
    fix_url = urljoin(base.rstrip("/") + "/", "fix")
    async with httpx.AsyncClient(timeout=8.0) as client:
        response = await client.post(fix_url)
        response.raise_for_status()
    result = await run_tests()
    return {"status": "retested", "result": result, "verified": len(result["findings"]) == 0}


@app.get("/api/dashboard")
def dashboard():
    target = state["target"]
    safe_target = None
    if target:
        safe_target = {
            "name": target["name"], "base_url": target["base_url"],
            "openapi_url": target["openapi_url"], "authorized": target["authorized"],
        }
    return {
        "api_connected": 1 if target else 0,
        "endpoints": len(state["endpoints"]),
        "tests": len(state["tests"]),
        "findings": len(state["findings"]),
        "last_run": state["last_run"],
        "target": safe_target,
    }


@app.get("/api/verification/checklist")
async def verification_checklist():
    """Run authorization checks against the built-in demo API and report observed results."""
    checks = []
    async with httpx.AsyncClient(
        base_url="http://testserver",
        transport=httpx.ASGITransport(app=app),
        timeout=5.0,
    ) as client:
        async def check(label, path, token, expected):
            try:
                response = await client.get(
                    path, headers={"Authorization": f"Bearer {token}"}
                )
                passed = response.status_code in expected
                checks.append({
                    "test": label,
                    "expected_status": expected,
                    "actual_status": response.status_code,
                    "passed": passed,
                    "response_body": redact_secrets(response.text[:300]),
                })
            except Exception:
                checks.append({
                    "test": label,
                    "expected_status": expected,
                    "actual_status": None,
                    "passed": False,
                    "response_body": "Verification request failed; details withheld.",
                })

        await check("Alice accesses her own order", "/target/orders/101", "alice-token", [200])
        await check("Alice cannot access Bob's order", "/target/orders/201", "alice-token", [403, 404])
        await check("Normal user cannot access admin report", "/target/admin/reports", "alice-token", [403])
    redaction_sample = redact_secrets({
        "token": "alice-token",
        "message": "Authorization: Bearer bob-token",
    })
    redaction_passed = (
        redaction_sample.get("token") == "[REDACTED]"
        and "[REDACTED]" in redaction_sample.get("message", "")
        and "alice-token" not in str(redaction_sample)
        and "bob-token" not in str(redaction_sample)
    )
    checks.insert(0, {
        "test": "Token masking in scanner output",
        "expected_status": "[REDACTED]",
        "actual_status": "passed" if redaction_passed else "failed",
        "passed": redaction_passed,
        "response_body": redaction_sample,
    })
    return {
        "status": "passed" if all(item["passed"] for item in checks) else "failed",
        "checks": checks,
        "note": "This verifies the built-in demo target and redaction helper only; it does not certify arbitrary APIs.",
    }
