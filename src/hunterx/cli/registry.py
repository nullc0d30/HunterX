# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Command registry."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

CommandHandler = Callable[[list[str]], int]


@dataclass(frozen=True, slots=True)
class Command:
    """A registered CLI command.

    Attributes:
        name: command name (e.g. ``"mission start"``).
        handler: callable receiving the remaining argv and returning an exit code.
        help_text: one-line description.

    """

    name: str
    handler: CommandHandler
    help_text: str = ""


class CommandRegistry:
    """Register and look up CLI commands."""

    def __init__(self) -> None:
        self._commands: dict[str, Command] = {}

    def register(self, name: str, handler: CommandHandler, *, help_text: str = "") -> None:
        """Register a command by name."""
        self._commands[name] = Command(name=name, handler=handler, help_text=help_text)

    def get(self, name: str) -> Command | None:
        """Return a command by name or ``None``."""
        return self._commands.get(name)

    def names(self) -> list[str]:
        """Return all registered command names."""
        return sorted(self._commands)

    def resolve(self, argv: list[str]) -> tuple[Command, list[str]] | None:
        """Resolve ``argv`` to the deepest registered command prefix.

        The longest matching command name wins; the remainder of ``argv`` is
        passed to the handler.
        """
        candidate = " ".join(argv)
        while candidate:
            command = self._commands.get(candidate)
            if command is not None:
                consumed = len(candidate.split(" "))
                return command, argv[consumed:]
            candidate = " ".join(candidate.split(" ")[:-1])
        return None
