# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology resolution.

Resolves free-form raw technology names — whatever a tool calls them — onto the
canonical taxonomy. ``Apache``, ``apache``, ``Apache httpd`` and
``Apache/2.4.57`` all resolve to the ``Apache HTTP Server`` definition while the
original observation is preserved on the record. Resolution is deterministic:
the same raw name always resolves to the same definition, and names with no
catalogue entry resolve to an unknown-but-preserved canonical name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from hunterx.domain.technology.models import (
    TechnologyCategory,
    TechnologyFamily,
)
from hunterx.domain.technology.normalizer import TechnologyNormalizer
from hunterx.domain.technology.taxonomy import TECHNOLOGY_CATALOG, TechDefinition

#: Version-looking suffix separators between a product name and its version.
_VERSION_SPLIT = re.compile(r"[/\s:-](v?\d+(?:\.\d+){0,3})$")

#: Fallback category/family applied to unknown technologies.
_UNKNOWN_CATEGORY = TechnologyCategory.OTHER
_UNKNOWN_FAMILY = TechnologyFamily.OTHER


@dataclass(frozen=True, slots=True)
class Resolution:
    """The result of resolving one raw technology name.

    Attributes:
        raw_name: the name exactly as observed.
        canonical_name: the canonical technology name (preserved when unknown).
        definition: the matched :class:`TechDefinition` (``None`` when unknown).
        is_known: whether the name resolved to a catalogue entry.
        alias: the alias that matched (``None`` when the canonical name matched).
        base_version: a version extracted from the raw name (``None`` when none).

    """

    raw_name: str
    canonical_name: str
    definition: TechDefinition | None = None
    is_known: bool = False
    alias: str = ""
    base_version: str = ""

    @property
    def category(self) -> TechnologyCategory:
        """Return the resolved category (``other`` when unknown)."""
        return self.definition.category if self.definition is not None else _UNKNOWN_CATEGORY

    @property
    def family(self) -> TechnologyFamily:
        """Return the resolved family (``other`` when unknown)."""
        return self.definition.family if self.definition is not None else _UNKNOWN_FAMILY

    @property
    def vendor(self) -> str:
        """Return the resolved vendor (``""`` when unknown)."""
        return self.definition.vendor if self.definition is not None else ""

    @property
    def product(self) -> str:
        """Return the resolved product (the canonical name when unknown)."""
        return self.definition.product if self.definition is not None else self.canonical_name


class TechnologyResolver:
    """Resolve raw technology names against the canonical taxonomy.

    Usage::

        resolver = TechnologyResolver()
        resolution = resolver.resolve("Apache/2.4.57")
    """

    def __init__(
        self,
        normalizer: TechnologyNormalizer | None = None,
        catalog: tuple[TechDefinition, ...] | None = None,
    ) -> None:
        self._normalizer = normalizer or TechnologyNormalizer()
        self._catalog = tuple(catalog) if catalog is not None else TECHNOLOGY_CATALOG
        self._by_canonical: dict[str, TechDefinition] = {}
        self._by_alias: dict[str, TechDefinition] = {}
        self._build_index()

    def resolve(self, raw_name: str, *, canonical_hint: str = "") -> Resolution:
        """Resolve ``raw_name`` (or ``canonical_hint``) to a definition."""
        raw = str(raw_name).strip()
        if canonical_hint and canonical_hint.strip():
            definition = self._by_canonical.get(self._normalizer.alias_key(canonical_hint))
            if definition is not None:
                return Resolution(
                    raw_name=raw,
                    canonical_name=definition.canonical_name,
                    definition=definition,
                    is_known=True,
                    base_version=_extract_base_version(raw),
                )
        normalized = self._normalizer.normalize_name(raw)
        base_version = _extract_base_version(raw)
        candidate = normalized.token
        definition = self._by_alias.get(candidate)
        if definition is not None:
            return Resolution(
                raw_name=raw,
                canonical_name=definition.canonical_name,
                definition=definition,
                is_known=True,
                alias=_matching_alias(definition, normalized.normalized),
                base_version=base_version,
            )
        # A name may carry an inline version suffix (``nginx/1.24.0``); retry
        # with the product-only prefix so the identity still resolves.
        prefix = _strip_version_suffix(normalized.normalized)
        if prefix and prefix != normalized.normalized:
            definition = self._by_alias.get(self._normalizer.alias_key(prefix))
            if definition is not None:
                return Resolution(
                    raw_name=raw,
                    canonical_name=definition.canonical_name,
                    definition=definition,
                    is_known=True,
                    alias=_matching_alias(definition, prefix),
                    base_version=base_version,
                )
        return Resolution(
            raw_name=raw,
            canonical_name=_title_case_canonical(_strip_version_suffix(normalized.normalized)) or raw,
            is_known=False,
            base_version=base_version,
        )

    def resolve_all(self, raw_names: list[str]) -> list[Resolution]:
        """Resolve a list of raw names, preserving order."""
        return [self.resolve(name) for name in raw_names]

    def catalog(self) -> tuple[TechDefinition, ...]:
        """Return the active catalogue."""
        return self._catalog

    def known_names(self) -> tuple[str, ...]:
        """Return every canonical name in the catalogue (sorted)."""
        return tuple(sorted(self._by_canonical))

    # -- internals ----------------------------------------------------------

    def _build_index(self) -> None:
        for definition in self._catalog:
            self._by_canonical[self._normalizer.alias_key(definition.canonical_name)] = definition
            for alias in definition.aliases:
                self._by_alias[self._normalizer.alias_key(alias)] = definition


def _extract_base_version(raw: str) -> str:
    """Extract a version embedded in a raw name (``nginx/1.24.0`` -> ``1.24.0``)."""
    match = _VERSION_SPLIT.search(raw.strip())
    return match.group(1) if match is not None else ""


def _strip_version_suffix(normalized: str) -> str:
    """Return the product-only prefix of a normalized name with a version."""
    return _VERSION_SPLIT.sub("", normalized).strip()


def _matching_alias(definition: TechDefinition, normalized: str) -> str:
    """Return the alias that equals ``normalized`` (empty when canonical)."""
    for alias in definition.aliases:
        if alias.lower().strip() == normalized:
            return alias
    return ""


def _title_case_canonical(normalized: str) -> str:
    """Render an unknown normalized name as a title-cased canonical name."""
    if not normalized:
        return ""
    return " ".join(part[:1].upper() + part[1:] for part in normalized.split())
