API_BASE = "https://internal.example-corp.com/api/v2"
SECRET_SALT = "s3cr3t-s4lt-value-DO-NOT-SHIP"
TIMEOUT = 37.5
MAX_RETRIES = 7
FEATURE_FLAGS = {
    "enable_billing": True,
    "shadow_mode": False,
    "quota_limit": 4096,
}
ERROR_MESSAGES = [
    "credential rotation required",
    "upstream ledger desynchronised",
]
