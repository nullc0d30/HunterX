# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""JavaScript intelligence collection strategy.

Maps an execution mode and target kind onto the concrete set of analyzers the
capability should run. The strategy is a pure function of (mode, target,
requested features) so the same inputs always yield the same collection plan.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.javascript.models import JSMode


@dataclass(frozen=True, slots=True)
class JSStrategy:
    """A concrete collection plan for a target.

    Attributes:
        target: the target value (host, domain or URL).
        target_kind: canonical target kind (``host``, ``domain``, ``url``).
        mode: the execution mode.
        analyzers: the analyzer names to run (module-level names).
        with_secrets: whether to run secret scanning.
        with_technology: whether to run technology/dependency detection.
        with_routes: whether to run route analysis.
        with_history: whether to compare with historical data.
        with_source_maps: whether to probe for source maps.
        max_assets: ceiling on the number of assets analysed per run.

    """

    target: str
    target_kind: str = "host"
    mode: JSMode = JSMode.HYBRID
    analyzers: frozenset[str] = frozenset()
    with_secrets: bool = True
    with_technology: bool = True
    with_routes: bool = True
    with_history: bool = False
    with_source_maps: bool = False
    max_assets: int = 200


#: Analyzers always available regardless of mode/target.
_BASE_ANALYZERS = frozenset(
    {"endpoint", "configuration", "storage", "authentication", "worker", "wasm", "security", "dynamic_import", "service", "domain"}
)

#: Analyzers that add cost and are enabled per-strategy.
_OPTIONAL_ANALYZERS = frozenset({"route", "technology", "secret"})


class JSStrategyBuilder:
    """Build a :class:`JSStrategy` for a target and mode."""

    def build(
        self,
        target: str,
        *,
        mode: JSMode | str = JSMode.HYBRID,
        target_kind: str = "",
        with_secrets: bool = True,
        with_technology: bool = True,
        with_routes: bool = True,
        with_history: bool = False,
        with_source_maps: bool = False,
        max_assets: int = 200,
    ) -> JSStrategy:
        """Build the strategy for ``target``."""
        mode = self.mode_for(mode)
        if not target_kind:
            target_kind = _infer_target_kind(target)
        analyzers = set(_BASE_ANALYZERS)
        if with_routes:
            analyzers.add("route")
        if with_technology:
            analyzers.add("technology")
        if with_secrets:
            analyzers.add("secret")
        return JSStrategy(
            target=str(target).strip(),
            target_kind=target_kind,
            mode=mode,
            analyzers=frozenset(analyzers),
            with_secrets=with_secrets,
            with_technology=with_technology,
            with_routes=with_routes,
            with_history=with_history,
            with_source_maps=with_source_maps,
            max_assets=max_assets,
        )

    def mode_for(self, mode: JSMode | str) -> JSMode:
        """Coerce a mode value into a :class:`JSMode`."""
        if isinstance(mode, JSMode):
            return mode
        try:
            return JSMode(str(mode).lower())
        except ValueError:
            return JSMode.HYBRID

    def analyzer_names(self, strategy: JSStrategy) -> tuple[str, ...]:
        """Return the analyzer names to run for ``strategy`` (stable order)."""
        return tuple(sorted(strategy.analyzers))


def _infer_target_kind(value: str) -> str:
    """Infer the canonical target kind from a string value."""
    import ipaddress

    stripped = str(value or "").strip()
    lowered = stripped.lower()
    if lowered.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(stripped)
        return "host"
    except ValueError:
        pass
    return "host"
