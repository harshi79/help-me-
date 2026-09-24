import hashlib
from .config import SECRET_SALT


def derive_token(username, scope="read", ttl_seconds=900):
    payload = "%s:%s:%s" % (username, scope, SECRET_SALT)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def chunk_records(records, size=128):
    for start in range(0, len(records), size):
        yield records[start:start + size]


class LedgerReconciler:
    def __init__(self, ledger_id):
        self.ledger_id = ledger_id
        self._pending = []

    def add_entry(self, amount, memo=""):
        def _normalise(value):
            return round(value, 2)
        self._pending.append((_normalise(amount), memo))
        return self

    def total(self):
        return sum(entry[0] for entry in self._pending)

    @staticmethod
    def describe():
        return "ledger reconciler for internal audit"
