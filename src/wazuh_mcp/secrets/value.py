"""SecretValue — wraps sensitive strings so they cannot leak via
repr/str/json/logging. Callers must call .expose() to access plaintext,
which makes every plaintext read site grep-able.
"""

from __future__ import annotations

import hashlib
from typing import Final

_REDACTED: Final[str] = "<redacted>"


class SecretValue:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("SecretValue requires a str")
        object.__setattr__(self, "_value", value)

    def expose(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"SecretValue({_REDACTED})"

    def __str__(self) -> str:
        return _REDACTED

    def __format__(self, spec: str) -> str:
        return _REDACTED

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretValue):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        # Hash the sha256, not the plaintext — prevents accidental
        # plaintext leak via hash-collision dictionaries or debuggers.
        return int.from_bytes(
            hashlib.sha256(self._value.encode()).digest()[:8], "big"
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SecretValue is immutable")
