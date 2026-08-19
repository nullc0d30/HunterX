# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""CLI application.

A minimal command dispatcher. Built on ``hunterx.cli.registry`` and
``hunterx.cli.render``, with no third-party argument-parsing dependency so the
foundation stays lean.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

import hunterx

from hunterx.cli.registry import CommandRegistry
from hunterx.cli.render import OutputRenderer


#: HunterX CLI startup banner (presentation only). The ASCII logo and the
#: branding lines are literal and deterministic; only the version line is
#: interpolated from the canonical package version.
_STARTUP_BANNER = """\
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ██╗  ██╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗╚██╗██╔╝
███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝ ╚███╔╝
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗ ██╔██╗
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║██╔╝ ██╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝

       AI-POWERED SECURITY ORCHESTRATION & INTELLIGENCE PLATFORM
                            HunterX v{version}

       Observe → Hypothesize → Probe → Verify

       Developed & Engineered by
       Ahmed Awad (AKA NullC0d3)

[INFO] HunterX Environment Bootstrapper
[INFO] System Mode · Profile: Full"""


class CliApplication:
    """Wire a registry and a renderer into a runnable CLI.

    Usage::

        app = CliApplication()
        app.registry.register("hello", handler, help_text="Say hello")
        exit(app.run(["hello"]))
    """

    def __init__(self, *, program_name: str = "hunterx") -> None:
        self.registry = CommandRegistry()
        self.renderer = OutputRenderer()
        self.program_name = program_name

    def banner(self) -> str:
        """Return the startup banner with the canonical version interpolated."""
        return _STARTUP_BANNER.format(version=hunterx.__version__)

    def run(self, argv: Sequence[str]) -> int:
        """Dispatch ``argv`` to a command and return its exit code."""
        args = list(argv)
        resolved = self.registry.resolve(args)
        if resolved is None:
            print(self.help_text(), file=sys.stderr)
            return 2
        command, remaining = resolved
        try:
            return command.handler(remaining)
        except KeyboardInterrupt:
            print()
            print("[WARN] Operation interrupted by user.")
            print()
            print("Completed work has been preserved.")
            print("HunterX can resume safely with:")
            print("  sudo ./install.sh")
            return 130

    def help_text(self) -> str:
        """Render the startup banner followed by the command list."""
        lines = [f"Usage: {self.program_name} <command> [args...]", ""]
        for name in self.registry.names():
            command = self.registry.get(name)
            assert command is not None  # nosec B101  # guarded by registry contract
            lines.append(f"  {name:<24} {command.help_text}")
        lines.append("")
        lines.append("HunterX is an authorized cybersecurity testing and research platform.")
        lines.append("Obtain appropriate authorization before testing any system.")
        return f"{self.banner()}\n\n{chr(10).join(lines)}"


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``hunterx.cli:main`` (console script)."""
    from hunterx.cli import CliApplication

    app = CliApplication()
    from hunterx.cli.commands import register_default_commands

    register_default_commands(app)
    return app.run(sys.argv[1:] if argv is None else argv)
