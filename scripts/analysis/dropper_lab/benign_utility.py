#!/usr/bin/env python3
"""Benign control utility for PENT-15 false-positive verification.

Performs purely local configuration formatting and SHA-256 file hashing without
any network fetch, obfuscated decoding, or dynamic code execution sinks.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def compute_text_digest(text: str) -> str:
    """Return the hexadecimal SHA-256 digest of a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def format_inventory_record(name: str, version: str, items: list[str]) -> str:
    """Serialize a clean local inventory record as formatted JSON."""
    payload: dict[str, Any] = {
        "name": name.strip(),
        "version": version.strip(),
        "count": len(items),
        "items": sorted(items),
        "digest": compute_text_digest("|".join(sorted(items))),
    }
    return json.dumps(payload, indent=2, sort_keys=True)
