from __future__ import annotations

from typing import Literal


def highlight(text: str, language: Literal["css", "javascript", "xml", "yaml", "none", "error"]) -> list[tuple[str, str]]:
    pass

def languages() -> list[str]:
    pass

def tags() -> list[str]:
    pass

__all__ = [
    "highlight",
    "languages",
    "tags",
]
