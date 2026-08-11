# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Vulture dead-code allowlist.
#
# Vulture flags symbols that appear unused within src/. Some of those are
# deliberate: public API entry points, plugin-registration hooks, package
# re-exports and duck-typed contracts referenced by name (not imported) from
# outside the package. This file whitelists exactly those symbols by defining
# them (vulture marks every name defined here as "used"). Adding a name here
# WITHOUT justification is a code smell — prefer removing dead code.
#
# See docs/v7-quality-gates.md ("Dead Code Detection") for the policy.

# --- console entry points (declared in pyproject.toml [project.scripts]) ---
def main():
    """Whitelist: console-script entry points ``main``."""


# --- package public surface re-exported through __init__ modules ---
__version__
__title__


# --- plugin SDK extension points (discovered by import, not direct call) ---
def register():
    """Whitelist: plugin/tool SDK registration hooks named ``register``."""


def create_adapter():
    """Whitelist: tool adapter factory entry points named ``create_adapter``."""


# --- dependency-injection / composition-root wiring ---
def build_container():
    """Whitelist: DI container builders invoked by the composition root."""


# --- reporting templates consumed by name at runtime ---
def render_template():
    """Whitelist: Jinja template render entry points."""


# --- shared keyword parameters in public port contracts ---
temperature
"""Whitelist: ``temperature`` is a keyword parameter of the ``AIPort.complete``
contract, shared by every adapter; vulture flags it as unused in ports that do
not forward it."""


# --- stdlib interface overrides with mandated unused parameters ---
fp
msg
"""Whitelist: ``fp``/``msg`` are required parameters of the urllib
``HTTPRedirectHandler.redirect_request`` override (``httpclient.py``); the
signature must match the base class even though this handler does not read
them."""
