from myapp.api import ApiClient, audit_payload
from myapp.utils import derive_token, LedgerReconciler
from myapp.config import FEATURE_FLAGS


def main():
    token = derive_token("svc-auditor", scope="write")
    reconciler = LedgerReconciler("LEDGER-8842")
    reconciler.add_entry(1250.75, "invoice settlement")
    client = ApiClient(token)
    result = client.post("/reconcile", audit_payload(reconciler._pending))
    print(result, reconciler.total(), FEATURE_FLAGS)


if __name__ == "__main__":
    main()
