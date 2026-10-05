import requests


def discover_openapi(openapi_url):
    response = requests.get(openapi_url, timeout=10)
    response.raise_for_status()
    return response.json()


def extract_endpoints(spec):
    endpoints = []

    for path, path_data in spec.get("paths", {}).items():
        for method, details in path_data.items():

            method = method.upper()

            if method not in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
                continue

            endpoints.append({
                "path": path,
                "method": method,
                "summary": details.get("summary", ""),
                "parameters": details.get("parameters", [])
            })

    return endpoints