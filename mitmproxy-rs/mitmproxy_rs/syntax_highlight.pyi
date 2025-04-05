from __future__ import annotations

from typing import Literal


def highlight(text: str, language: Literal["xml", "yaml", "error", "none"]) -> list[tuple[str, str]]:
    pass

def tags() -> list[str]:
    pass

__all__ = [
    "highlight",
    "tags",
]
