from __future__ import annotations

def add_cert(pem: str) -> None: ...
def remove_cert() -> None: ...

__all__ = [
    "add_cert",
    "remove_cert",
]
