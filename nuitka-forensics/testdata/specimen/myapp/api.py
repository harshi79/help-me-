import json
from .config import API_BASE, TIMEOUT, MAX_RETRIES


class ApiClient:
    def __init__(self, token):
        self.token = token
        self.retries = MAX_RETRIES

    def _headers(self):
        return {"Authorization": "Bearer " + self.token, "X-Trace": "specimen"}

    def post(self, path, payload):
        body = json.dumps(payload)
        for attempt in range(self.retries):
            try:
                return self._send(path, body, attempt)
            except ConnectionError:
                continue
        raise RuntimeError("retry budget exhausted for " + path)

    def _send(self, path, body, attempt):
        url = API_BASE + path
        if TIMEOUT <= 0:
            raise ValueError("invalid timeout")
        return {"url": url, "body": body, "attempt": attempt}


def audit_payload(entries):
    return {"entries": list(entries), "count": len(entries)}
