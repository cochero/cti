"""Content-addressed object storage (Architecture v2 §5.2 evidence preservation).

Raw collected artifacts are stored under their own SHA-256, so:
- storage is idempotent (same bytes -> same key -> one object)
- retrieval is self-verifying (fetched bytes must hash to the key)
- the raw evidence behind every extraction is permanently auditable

Backed by any S3-compatible store (MinIO in dev/Full-Mesh, MinIO in
Compact). Bucket is created on first put.
"""

import hashlib
import io
import os
from typing import Optional, Tuple

__all__ = ["ObjectStore", "ContentHashMismatch"]


class ContentHashMismatch(ValueError):
    """Fetched bytes do not hash to the requested key — corruption or
    tampering in the object store. Never return such bytes to a caller."""


class ObjectStore:
    def __init__(self, bucket: str = "truvo-raw", endpoint: Optional[str] = None,
                 access_key: Optional[str] = None, secret_key: Optional[str] = None,
                 secure: Optional[bool] = None):
        from minio import Minio

        self.bucket = bucket
        self._client = Minio(
            endpoint or os.environ["TRUVO_OBJSTORE_ENDPOINT"],
            access_key=access_key or os.environ.get("TRUVO_OBJSTORE_ACCESS_KEY", "truvo"),
            secret_key=secret_key or os.environ.get("TRUVO_OBJSTORE_SECRET_KEY", "truvo-dev-only"),
            secure=(os.environ.get("TRUVO_OBJSTORE_SECURE", "0") == "1")
            if secure is None else secure,
        )

    def _ensure_bucket(self) -> None:
        if not self._client.bucket_exists(self.bucket):
            self._client.make_bucket(self.bucket)

    def put(self, data: bytes, content_type: str = "application/octet-stream") -> Tuple[str, int]:
        """Store bytes under their SHA-256. Returns (key, size). Idempotent."""
        self._ensure_bucket()
        digest = hashlib.sha256(data).hexdigest()
        # skip re-upload if the object already exists (content-addressed)
        try:
            self._client.stat_object(self.bucket, digest)
        except Exception:
            self._client.put_object(
                self.bucket, digest, io.BytesIO(data), len(data),
                content_type=content_type,
            )
        return digest, len(data)

    def get(self, key: str) -> bytes:
        """Fetch and verify. Raises ContentHashMismatch if bytes are wrong."""
        resp = self._client.get_object(self.bucket, key)
        try:
            data = resp.read()
        finally:
            resp.close()
            resp.release_conn()
        if hashlib.sha256(data).hexdigest() != key:
            raise ContentHashMismatch(
                "object %s failed content verification" % key
            )
        return data

    def delete(self, key: str) -> None:
        """Delete one object (retention/GC path — see ops/retention.py).
        Content-addressing means the evidence pointer in claims remains
        truthful about what WAS there; deletion is the retention policy
        executing, never a silent loss."""
        self._client.remove_object(self.bucket, key)

    def iter_objects(self, older_than_days: int = 0):
        """Yield (key, last_modified) for objects older than the given
        days. Retention GC drives this; 0 days = everything."""
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        for obj in self._client.list_objects(self.bucket, recursive=True):
            if obj.last_modified.replace(tzinfo=timezone.utc) < cutoff:
                yield obj.object_name, obj.last_modified
