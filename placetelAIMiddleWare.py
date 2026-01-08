from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from threading import Lock
import uuid


class PlacetelAIMiddleware:
    """O(1) clustered storage for V2 transcripts."""

    def __init__(self, ttl_minutes: int = 30) -> None:
        self._ttl = timedelta(minutes=ttl_minutes)
        self._lock = Lock()
        self._by_forward: dict[str, OrderedDict[str, dict]] = {}

    def _purge_expired(self) -> None:
        now = datetime.now(timezone.utc)
        expired_keys = []
        for forward_number, entries in self._by_forward.items():
            expired_call_ids = [
                call_id
                for call_id, entry in entries.items()
                if entry["expires_at"] <= now
            ]
            for call_id in expired_call_ids:
                entries.pop(call_id, None)
            if not entries:
                expired_keys.append(forward_number)
        for forward_number in expired_keys:
            self._by_forward.pop(forward_number, None)

    def add(self, payload: dict, forward_number: str, admin_tenant: str) -> str:
        call_id = payload.get("call_id") or str(uuid.uuid4())
        entry = {
            "call_id": call_id,
            "payload": payload,
            "forward_number": forward_number,
            "admin_tenant": admin_tenant,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + self._ttl,
        }
        with self._lock:
            self._purge_expired()
            bucket = self._by_forward.setdefault(forward_number, OrderedDict())
            bucket[call_id] = entry
        return call_id

    def pop_for_forward(self, forward_number: str, call_id: str | None = None) -> dict | None:
        with self._lock:
            self._purge_expired()
            bucket = self._by_forward.get(forward_number)
            if not bucket:
                return None
            if call_id and call_id in bucket:
                return bucket.pop(call_id)
            if bucket:
                _, entry = bucket.popitem(last=False)
                return entry
            return None

    def purge(self) -> None:
        with self._lock:
            self._purge_expired()
