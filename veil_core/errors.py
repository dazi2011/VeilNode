class VeilError(Exception):
    """User-facing error. Receive paths intentionally keep this vague."""


class VeilDecryptError(VeilError):
    """Generic decrypt failure for password/keypart/private/auth/data mismatch."""
