from __future__ import annotations
from pathlib import Path
from typing import final

def active_executables() -> list[Process]: ...
def executable_icon(path: Path | str) -> bytes: ...
@final
class Process:
    @property
    def executable(self) -> Path: ...
    @property
    def display_name(self) -> str: ...
    @property
    def is_visible(self) -> bool: ...
    @property
    def is_system(self) -> bool: ...

__all__ = [
    "active_executables",
    "executable_icon",
    "Process",
]
