"""SecretValue — wraps sensitive strings so they cannot leak via
repr/str/json/logging/pickle/copy. Callers must call .expose() to access
plaintext, which makes every plaintext read site grep-able.
"""

from __future__ import annotations

import hashlib
from typing import Final, final

_REDACTED: Final[str] = "<redacted>"


@final
class SecretValue:
    __slots__ = ("_value",)
    _value: str

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
        return int.from_bytes(hashlib.sha256(self._value.encode()).digest()[:8], "big")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SecretValue is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("SecretValue is immutable")

    def __copy__(self) -> SecretValue:
        return SecretValue(self._value)

    def __deepcopy__(self, memo: dict) -> SecretValue:
        return SecretValue(self._value)

    def __reduce__(self) -> tuple:
        # Refuse pickle — pickling a SecretValue would emit plaintext in the
        # serialized blob. Callers must re-fetch from the SecretStore.
        raise TypeError("SecretValue is not picklable; fetch from SecretStore")
