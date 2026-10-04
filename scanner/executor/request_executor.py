import requests


class RequestExecutor:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def execute(self, method, endpoint, token=None, body=None):
        url = self.base_url + endpoint

        headers = {}

        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=body,
                timeout=10
            )

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text
            }

        except requests.RequestException as error:
            return {
                "status_code": None,
                "headers": {},
                "body": "",
                "error": str(error)
            }