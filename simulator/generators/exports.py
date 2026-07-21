"""
Export job "store" for /assets/export and /vulns/export.

DESIGN NOTE - stateless on purpose:
  Gunicorn runs 4 worker processes by default, and Cloud Run also autoscales
  across container instances. Anything we put in a Python dict is per-worker,
  so a POST /export followed by a GET /export/<uuid>/status routed to a
  different worker would 404 with "unknown export UUID".

  Rather than plug in Redis for a demo, we simply:
    - accept any well-formed UUIDv4 (or any 36-char hyphenated string) on
      /status and /chunks
    - always return status = FINISHED with chunks_available = [1] on /status
    - always serve the same static chunk data on /chunks/<id>

  Downside: no QUEUED / PROCESSING transitions. The demo runs faster in
  return - the pack polls once, gets FINISHED, downloads chunks.
"""
import re
import uuid as _uuid

from .base import new_uuid


_UUID_RE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)


def create_export_uuid() -> str:
    """Return a fresh export UUID to hand back on POST /export."""
    return new_uuid()


def is_valid_export_uuid(uuid_str: str) -> bool:
    """Accept any UUIDv4-shaped string as a valid export identifier."""
    return bool(uuid_str) and bool(_UUID_RE.match(str(uuid_str)))
