# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin lifecycle hooks.

A plugin instance may implement these lifecycle hooks; the manager calls them
at the appropriate times. Hooks are optional — a plugin may implement only
``activate``. This is a plain mixin: every hook defaults to a no-op so that
subclasses can override the subset they need.
"""

from __future__ import annotations

from typing import Any


class LifecycleHooks:
    """Optional lifecycle contract for plugin instances."""

    def on_load(self, context: Any) -> None:
        """Perform setup after the plugin is loaded, before activation."""

    def on_activate(self, context: Any) -> None:
        """Begin serving when the plugin is activated."""

    def on_deactivate(self, context: Any) -> None:
        """Stop serving when the plugin is deactivated."""

    def on_unload(self) -> None:
        """Release resources before the plugin is removed."""
