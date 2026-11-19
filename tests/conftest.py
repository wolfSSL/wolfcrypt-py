# conftest.py
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

"""Shared pytest fixtures."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from wolfcrypt._ffi import lib as _lib

if TYPE_CHECKING:
    from collections.abc import Iterator


class LibPatch:
    """Override wolfcrypt._ffi.lib attributes and restore them on undo().

    pytest's monkeypatch restores values from Lib.__dict__, which holds cffi
    internals that cannot be assigned back to a Lib.
    """

    def __init__(self) -> None:
        self._saved: list[tuple[str, Any]] = []

    def setattr(self, name: str, value: Any) -> None:
        self._saved.append((name, getattr(_lib, name)))
        setattr(_lib, name, value)

    def undo(self) -> None:
        while self._saved:
            name, value = self._saved.pop()
            setattr(_lib, name, value)

    @contextlib.contextmanager
    def context(self) -> Iterator[LibPatch]:
        patch = LibPatch()
        try:
            yield patch
        finally:
            patch.undo()


@pytest.fixture
def lib_patch() -> Iterator[LibPatch]:
    patch = LibPatch()
    yield patch
    patch.undo()
