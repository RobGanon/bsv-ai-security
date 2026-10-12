from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix platforms
    fcntl = None  # type: ignore[assignment]

HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")

# Limits for the local audit journal (Phase 1 DoS hardening).
MAX_EVENT_DETAIL_BYTES = 4096
MAX_JOURNAL_EVENTS = 1_000_000

# O_NOFOLLOW makes open(2) fail on a trailing symlink instead of following it.
# It is Unix-only; where unavailable the per-component symlink walk in
# _validated_entries() and the fstat() regular-file check in _open_verified_fd()
# still apply.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class VerificationError(ValueError):
    """Raised when a manifest or artifact fails verification."""
