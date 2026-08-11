# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Dependency policy (the machine-readable dependency matrix).

The policy is the single source of truth for the architecture rules. It is
declared as YAML in ``config/architecture.yaml`` and parsed into typed
dataclasses here. A built-in default policy keeps the linter functional even
when the YAML file is missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from hunterx.architecture.layers import ROOT_LAYER, Layer

#: The special marker for the ``hunterx`` package itself in the matrix.
HUNTERX_ROOT = ROOT_LAYER


@dataclass(frozen=True, slots=True)
class ConditionalImport:
    """A fine-grained, module-level import exception.

    Attributes:
        source: dotted source module (or ``"*"`` for any module in a layer).
        source_layer: layer name the rule applies to.
        target: dotted target module (or a glob ending in ``.*``).
        reason: why the exception exists.

    """

    source: str
    source_layer: str
    target: str
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ForbiddenImport:
    """An explicitly forbidden import pattern.

    Attributes:
        source_pattern: regex or dotted prefix matched against the source module.
        target_pattern: regex or dotted prefix matched against the target module.
        reason: why it is forbidden.

    """

    source_pattern: str
    target_pattern: str
    reason: str = ""


@dataclass(frozen=True, slots=True)
class Waiver:
    """A documented, time-boxed exception to the architecture rules.

    Waivers surface in reports as known issues. They never fail CI, but an
    expired waiver is an error.

    Attributes:
        id: unique waiver identifier (e.g. ``"ARCH-W-001"``).
        module: the offending module.
        target: the offending import target.
        code: the violation code the waiver applies to.
        reason: justification recorded for the Architecture Council.
        expires: optional ISO date after which the waiver becomes an error.

    """

    id: str
    module: str
    target: str
    code: str
    reason: str = ""
    expires: str = ""


@dataclass(frozen=True, slots=True)
class KnownCycle:
    """A known, documented module wiring cycle that is allowed to remain.

    Attributes:
        id: unique identifier.
        modules: the cycle members (module names).
        reason: why the wiring cycle is acceptable.

    """

    id: str
    modules: tuple[str, ...]
    reason: str = ""


@dataclass(frozen=True, slots=True)
class Contract:
    """A shared contract or extension point exposed across layers.

    Attributes:
        module: dotted module path.
        kind: ``"contract"`` or ``"extension"``.
        purpose: what the contract provides.
        consumers: layers allowed to import it (empty = all).

    """

    module: str
    kind: str = "contract"
    purpose: str = ""
    consumers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DocRequirement:
    """Documentation validation settings.

    Attributes:
        required: section names that are mandatory (always the purpose /
            docstring presence).
        recommended: section names that are recommended (warnings).
        section_keywords: markers used to detect a section in a docstring.

    """

    required: tuple[str, ...] = ("docstring",)
    recommended: tuple[str, ...] = (
        "responsibilities",
        "dependencies",
        "extension points",
    )
    section_keywords: dict[str, tuple[str, ...]] = field(
        default_factory=lambda: {
            "responsibilities": ("responsibilities", "responsible for"),
            "dependencies": ("dependencies", "depends on"),
            "extension points": ("extension", "extend", "plugin", "adapter"),
        }
    )


@dataclass(slots=True)
class Policy:
    """The complete, machine-readable architecture policy.

    Attributes:
        version: policy schema version.
        package_root: relative path to the package root (e.g. ``src``).
        layers: catalogue of layers (defaults from :mod:`hunterx.architecture.layers`).
        allowed: dependency matrix mapping source layer to allowed target layers.
        conditional_imports: fine-grained module-level exceptions.
        forbidden_imports: explicitly forbidden import patterns.
        blocked_prefixes: target prefixes that are always forbidden.
        waivers: documented known issues.
        known_cycles: documented known wiring cycles.
        shared_contracts: contracts importable across layers.
        extension_points: extension surfaces.
        doc_requirements: documentation rules.
        plugin_boundary: layers/modules plugins may import.
        tool_boundary: layers/modules tools may import.
        api_baseline: path to the committed API baseline JSON.

    """

    version: str = "1.0.0"
    package_root: str = "src"
    layers: dict[str, Layer] = field(default_factory=dict)
    allowed: dict[str, tuple[str, ...]] = field(default_factory=dict)
    conditional_imports: list[ConditionalImport] = field(default_factory=list)
    forbidden_imports: list[ForbiddenImport] = field(default_factory=list)
    blocked_prefixes: tuple[str, ...] = ()
    waivers: list[Waiver] = field(default_factory=list)
    known_cycles: list[KnownCycle] = field(default_factory=list)
    shared_contracts: list[Contract] = field(default_factory=list)
    extension_points: list[Contract] = field(default_factory=list)
    doc_requirements: DocRequirement = field(default_factory=DocRequirement)
    plugin_boundary: tuple[str, ...] = (
        "hunterx.plugins.sdk",
        "hunterx.domain",
        "hunterx.shared",
    )
    tool_boundary: tuple[str, ...] = (
        "hunterx.tools.sdk",
        "hunterx.domain",
        "hunterx.shared",
        "hunterx.plugins.sdk",
    )
    api_baseline: str = "config/api_baseline.json"

    def is_allowed(self, source_layer: str, target_layer: str) -> bool:
        """Return ``True`` when ``target_layer`` is in the source layer's set."""
        allowed = self.allowed.get(source_layer, ())
        return target_layer in allowed

    def is_conditional(self, source: str, target: str) -> ConditionalImport | None:
        """Return a matching conditional import rule, if any."""
        for rule in self.conditional_imports:
            if rule.source != "*" and rule.source != source:
                continue
            if self._match_pattern(rule.target, target):
                return rule
        return None

    @staticmethod
    def _match_pattern(pattern: str, value: str) -> bool:
        """Match a dotted prefix/glob pattern against a module name."""
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return value == prefix or value.startswith(f"{prefix}.")
        return value == pattern or value.startswith(f"{pattern}.")

    def find_waiver(self, module: str, target: str, code: str) -> Waiver | None:
        """Return a waiver matching a violation, if any."""
        for waiver in self.waivers:
            if waiver.code != code:
                continue
            if waiver.module != "*" and waiver.module != module:
                continue
            if waiver.target and not self._match_pattern(waiver.target, target):
                continue
            return waiver
        return None

    def find_known_cycle(self, modules: tuple[str, ...]) -> KnownCycle | None:
        """Return a known cycle whose members match ``modules``."""
        members = set(modules)
        for known in self.known_cycles:
            if set(known.modules) == members:
                return known
        return None


def default_policy() -> Policy:
    """Return the built-in dependency matrix.

    The matrix reflects the ratified rules in ``docs/bible/03 - Folder
    Structure.md`` §7 and the actual v7 package composition.
    """
    from hunterx.architecture.layers import DEFAULT_LAYERS

    layers = {layer.name: layer for layer in DEFAULT_LAYERS}
    allowed: dict[str, tuple[str, ...]] = {
        "shared": ("shared",),
        "domain": ("domain", "shared"),
        "config": ("config", "domain", "shared"),
        "security": ("security", "domain", "shared", "infrastructure"),
        "infrastructure": ("infrastructure", "domain", "shared", "config"),
        "application": ("application", "domain", "shared", "engines", "tools"),
        "knowledge": ("knowledge", "domain", "shared"),
        "reporting": ("reporting", "domain", "shared"),
        "scheduler": ("scheduler", "domain", "shared"),
        "engines": ("engines", "domain", "shared", "tools", "reporting", "infrastructure", "application"),
        "tools": ("tools", "domain", "shared", "plugins"),
        "plugins": ("plugins", "domain", "shared"),
        "agents": ("agents", "domain", "shared"),
        "api": ("api", "domain", "shared", "config", "platform", "application", "engines"),
        "cli": ("cli", "domain", "shared", "config", "platform", "application", "engines"),
        "platform": (
            "platform",
            "domain",
            "shared",
            "config",
            "security",
            "infrastructure",
            "application",
            "knowledge",
            "reporting",
            "scheduler",
            "engines",
            "tools",
            "plugins",
            "agents",
            "api",
            "cli",
            "facade",
        ),
        "facade": ("facade", "domain", "shared", "infrastructure", "managers", "config", "application"),
        "architecture": ("architecture",),
        HUNTERX_ROOT: (HUNTERX_ROOT,),
    }
    for layer in layers.values():
        allowed.setdefault(layer.name, (layer.name,))
    allowed[HUNTERX_ROOT] = (HUNTERX_ROOT,)

    return Policy(
        layers=layers,
        allowed=allowed,
        conditional_imports=[
            ConditionalImport(
                source="hunterx.shared.di",
                source_layer="shared",
                target="hunterx.domain.exceptions",
                reason=(
                    "The DI container raises domain exceptions for registration "
                    "errors; exceptions are the one shared contract the foundation "
                    "may reference."
                ),
            ),
        ],
        forbidden_imports=[
            ForbiddenImport(
                source_pattern="hunterx.",
                target_pattern="core.",
                reason="The legacy v6 'core' package must not be imported by v7 code.",
            ),
            ForbiddenImport(
                source_pattern="hunterx.",
                target_pattern="scripts",
                reason="'scripts/' content must never be imported by shipping code (Bible §10).",
            ),
        ],
        blocked_prefixes=("core.", "scripts.", "temp_cli_apps."),
        waivers=[
            Waiver(
                id="ARCH-W-001",
                module="hunterx.domain.execution",
                target="hunterx.plugins.sdk.results",
                code="ARCH-001",
                reason=(
                    "The domain execution model references the SDK result types "
                    "FindingResult/EvidenceResult. The result contracts should move "
                    "into the domain layer; tracked as architectural debt for a "
                    "dedicated refactor sprint."
                ),
            ),
        ],
        known_cycles=[
            KnownCycle(
                id="ARCH-W-002",
                modules=("hunterx.tools.sdk", "hunterx.tools.sdk.engine", "hunterx.tools.sdk.pipeline"),
                reason=(
                    "SDK package __init__ re-export wiring cycle. Harmless at runtime "
                    "(imports complete lazily) and internal to the SDK package."
                ),
            ),
            KnownCycle(
                id="ARCH-W-003",
                modules=("hunterx.cli", "hunterx.cli.app", "hunterx.cli.commands"),
                reason=(
                    "CLI package wiring cycle: __init__ re-exports app/main and "
                    "commands import the app. Resolve by moving main() into a leaf "
                    "module in a later sprint."
                ),
            ),
        ],
        shared_contracts=[
            Contract(
                module="hunterx.domain.ports",
                purpose="Abstract ports implemented by infrastructure adapters.",
                consumers=("application", "engines", "infrastructure", "tools", "plugins", "platform"),
            ),
            Contract(
                module="hunterx.domain.exceptions",
                purpose="Exception hierarchy and error codes shared across all layers.",
            ),
            Contract(
                module="hunterx.shared",
                purpose="Cross-cutting helpers (ids, masking, time, result, di).",
            ),
        ],
        extension_points=[
            Contract(module="hunterx.plugins.sdk", kind="extension", purpose="Public SDK for plugin authors."),
            Contract(module="hunterx.tools.sdk", kind="extension", purpose="Public SDK for tool adapter authors."),
        ],
    )


def _parse_contracts(raw: object, kind: str) -> list[Contract]:
    contracts: list[Contract] = []
    if not isinstance(raw, list):
        return contracts
    for item in raw:
        if isinstance(item, str):
            contracts.append(Contract(module=item, kind=kind))
        elif isinstance(item, dict):
            contracts.append(
                Contract(
                    module=str(item.get("module", "")),
                    kind=str(item.get("kind", kind)),
                    purpose=str(item.get("purpose", "")),
                    consumers=tuple(str(c) for c in item.get("consumers", ())),
                )
            )
    return contracts


def load_policy(path: Path | None = None) -> Policy:
    """Load the policy from YAML, falling back to the built-in default.

    Args:
        path: optional path to ``architecture.yaml``. When omitted the default
            policy is returned.

    Returns:
        A populated :class:`Policy`.

    """
    policy = default_policy()
    if path is None or not path.is_file():
        return policy
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return policy
    if not isinstance(raw, dict):
        return policy

    if isinstance(raw.get("package_root"), str):
        policy.package_root = raw["package_root"]
    if isinstance(raw.get("version"), str):
        policy.version = raw["version"]
    if isinstance(raw.get("api_baseline"), str):
        policy.api_baseline = raw["api_baseline"]

    layers_raw = raw.get("layers")
    if isinstance(layers_raw, list):
        for item in layers_raw:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", ""))
            if name in policy.layers:
                existing = policy.layers[name]
                policy.layers[name] = Layer(
                    name=name,
                    packages=existing.packages,
                    description=str(item.get("description", existing.description)),
                    owner=str(item.get("owner", existing.owner)),
                    rank=int(item.get("rank", existing.rank)),
                )

    rules_raw = raw.get("rules")
    if isinstance(rules_raw, dict):
        for source, targets in rules_raw.items():
            if isinstance(source, str) and isinstance(targets, list):
                policy.allowed[source] = tuple(str(t) for t in targets if isinstance(t, str))

    conditionals_raw = raw.get("conditional_imports")
    if isinstance(conditionals_raw, list):
        policy.conditional_imports = []
        for item in conditionals_raw:
            if isinstance(item, dict):
                policy.conditional_imports.append(
                    ConditionalImport(
                        source=str(item.get("source", "*")),
                        source_layer=str(item.get("source_layer", "")),
                        target=str(item.get("target", "")),
                        reason=str(item.get("reason", "")),
                    )
                )

    forbidden_raw = raw.get("forbidden_imports")
    if isinstance(forbidden_raw, list):
        policy.forbidden_imports = []
        for item in forbidden_raw:
            if isinstance(item, dict):
                policy.forbidden_imports.append(
                    ForbiddenImport(
                        source_pattern=str(item.get("source", "")),
                        target_pattern=str(item.get("target", "")),
                        reason=str(item.get("reason", "")),
                    )
                )

    if isinstance(raw.get("blocked_prefixes"), list):
        policy.blocked_prefixes = tuple(str(p) for p in raw["blocked_prefixes"])

    waivers_raw = raw.get("waivers")
    if isinstance(waivers_raw, list):
        policy.waivers = []
        for item in waivers_raw:
            if isinstance(item, dict):
                policy.waivers.append(
                    Waiver(
                        id=str(item.get("id", "")),
                        module=str(item.get("module", "*")),
                        target=str(item.get("target", "")),
                        code=str(item.get("code", "")),
                        reason=str(item.get("reason", "")),
                        expires=str(item.get("expires", "")),
                    )
                )

    known_raw = raw.get("known_cycles")
    if isinstance(known_raw, list):
        policy.known_cycles = []
        for item in known_raw:
            if isinstance(item, dict):
                policy.known_cycles.append(
                    KnownCycle(
                        id=str(item.get("id", "")),
                        modules=tuple(str(m) for m in item.get("modules", ())),
                        reason=str(item.get("reason", "")),
                    )
                )

    policy.shared_contracts = _parse_contracts(raw.get("shared_contracts"), "contract")
    policy.extension_points = _parse_contracts(raw.get("extension_points"), "extension")

    plugin_boundary = raw.get("plugin_boundary")
    if isinstance(plugin_boundary, list):
        policy.plugin_boundary = tuple(str(p) for p in plugin_boundary)
    tool_boundary = raw.get("tool_boundary")
    if isinstance(tool_boundary, list):
        policy.tool_boundary = tuple(str(p) for p in tool_boundary)

    docs_raw = raw.get("doc_requirements")
    if isinstance(docs_raw, dict):
        policy.doc_requirements = DocRequirement(
            required=tuple(str(s) for s in docs_raw.get("required", policy.doc_requirements.required)),
            recommended=tuple(str(s) for s in docs_raw.get("recommended", policy.doc_requirements.recommended)),
            section_keywords=docs_raw.get("section_keywords", policy.doc_requirements.section_keywords),
        )
    return policy


def find_repo_root(start: Path | None = None) -> Path:
    """Walk upward from ``start`` to the repository root (where pyproject.toml lives)."""
    current = (start or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent
    while True:
        if (current / "pyproject.toml").is_file():
            return current
        parent = current.parent
        if parent == current:
            return current
        current = parent


def resolve_policy_path(root: Path) -> Path:
    """Return the canonical policy path inside a repository root."""
    return root / "config" / "architecture.yaml"
