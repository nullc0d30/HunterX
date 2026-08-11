# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Integration Factory domain models.

The Tool Integration Factory generates standardized Tool Integration Packs —
identical, validated project structures for every future security tool. This
module defines the pack specification, the generated pack, its manifest,
validation reports, semantic versioning, the compatibility matrix and the
integration templates the generator engine renders from.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum

from hunterx.domain.exceptions import (
    InvalidToolPackSpecError,
    TemplateRenderError,
)
from hunterx.domain.tool_intelligence import ToolExecutionType
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso

#: Canonical permission flags a generated adapter may request.
PERMISSION_FLAGS = ("none", "network", "filesystem", "process", "secrets")

#: Structured output formats a generated pack can declare.
OUTPUT_FORMATS = ("json", "xml", "csv", "txt", "yaml", "html")

#: Parser strategies the generated parser skeleton can implement.
PARSER_STRATEGIES = ("json", "xml", "csv", "text", "yaml", "html")

_PACK_ID = re.compile(r"[a-z0-9][a-z0-9-]*")
_CAPABILITY_ID = re.compile(r"[a-z0-9][a-z0-9-]*")
_VENDOR_ID = re.compile(r"[a-z0-9][a-z0-9-]*")


class PackArtifactKind(Enum):
    """Classification of every file a generated pack contains."""

    MANIFEST = "manifest"
    METADATA = "metadata"
    VERSION = "version"
    COMPATIBILITY = "compatibility"
    MIGRATIONS = "migrations"
    KNOWLEDGE = "knowledge"
    CAPABILITIES = "capabilities"
    INSTALLATION = "installation"
    DEPENDENCY = "dependency"
    HEALTH = "health"
    EXECUTION_RULES = "execution-rules"
    MISSION_RULES = "mission-rules"
    WORKFLOW_RULES = "workflow-rules"
    INPUT_SCHEMA = "input-schema"
    OUTPUT_SCHEMA = "output-schema"
    ADAPTER = "adapter"
    PARSER = "parser"
    NORMALIZER = "normalizer"
    DATABASE_MAPPING = "database-mapping"
    EVIDENCE_MAPPING = "evidence-mapping"
    RISK_MAPPING = "risk-mapping"
    ERROR_HANDLING = "error-handling"
    LOGGING = "logging"
    TELEMETRY = "telemetry"
    VALIDATION = "validation"
    UNIT_TESTS = "unit-tests"
    INTEGRATION_TESTS = "integration-tests"
    PERFORMANCE_TESTS = "performance-tests"
    DOCUMENTATION = "documentation"
    EXAMPLES = "examples"
    PACKAGING = "packaging"
    BOILERPLATE = "boilerplate"


class ValidationSeverity(Enum):
    """Severity of a pack validation issue."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True, slots=True)
class SemanticVersion:
    """A semantic version (SemVer 2.0.0) value object.

    Supports parsing, ordering and constraint satisfaction (``==``, ``!=``,
    ``>=``, ``>``, ``<=``, ``<``, ``~=``, ``^`` and bare exact versions).
    """

    major: int
    minor: int
    patch: int
    prerelease: str = ""
    build: str = ""

    @classmethod
    def parse(cls, value: str) -> SemanticVersion:
        """Parse ``value`` into a :class:`SemanticVersion`.

        Raises :class:`ValueError` for malformed input.
        """
        if not isinstance(value, str) or not value:
            raise ValueError("semantic version must be a non-empty string.")
        version_part = value
        build = ""
        prerelease = ""
        if "+" in version_part:
            version_part, build = version_part.split("+", 1)
        if "-" in version_part:
            version_part, prerelease = version_part.split("-", 1)
        numbers = version_part.split(".")
        if len(numbers) != 3:
            raise ValueError(f"semantic version '{value}' must have major.minor.patch.")
        try:
            major, minor, patch = (int(part) for part in numbers)
        except ValueError as exc:
            raise ValueError(f"semantic version '{value}' has non-numeric components.") from exc
        if major < 0 or minor < 0 or patch < 0:
            raise ValueError(f"semantic version '{value}' has negative components.")
        return cls(major=major, minor=minor, patch=patch, prerelease=prerelease, build=build)

    @property
    def is_prerelease(self) -> bool:
        """Return ``True`` when the version is a pre-release."""
        return bool(self.prerelease)

    @property
    def is_stable(self) -> bool:
        """Return ``True`` for stable (non pre-release) 1.0+ versions."""
        return not self.prerelease and self.major >= 1

    @property
    def tuple(self) -> tuple[int, int, int]:
        """Return the numeric ``(major, minor, patch)`` triple."""
        return (self.major, self.minor, self.patch)

    def bump_major(self) -> SemanticVersion:
        """Return the next major version (minor/patch reset)."""
        return SemanticVersion(self.major + 1, 0, 0)

    def bump_minor(self) -> SemanticVersion:
        """Return the next minor version (patch reset)."""
        return SemanticVersion(self.major, self.minor + 1, 0)

    def bump_patch(self) -> SemanticVersion:
        """Return the next patch version."""
        return SemanticVersion(self.major, self.minor, self.patch + 1)

    def _prerelease_key(self) -> tuple[object, ...]:
        if not self.prerelease:
            return (1,)
        parts: list[object] = []
        for identifier in self.prerelease.split("."):
            if identifier.isdigit():
                parts.append((0, int(identifier)))
            else:
                parts.append((1, identifier))
        return (0, *parts)

    def _key(self) -> tuple[int, int, int, object]:
        return (self.major, self.minor, self.patch, self._prerelease_key())

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._key() < other._key()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._key() <= other._key()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._key() > other._key()

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        return self._key() >= other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def satisfies(self, constraint: str) -> bool:
        """Return ``True`` when this version satisfies ``constraint``."""
        constraint = constraint.strip()
        if not constraint or constraint == "*":
            return True
        for operator in ("!=", "~=", ">=", "<=", "^", ">", "<", "=="):
            if constraint.startswith(operator):
                return self._satisfies_operator(operator, constraint[len(operator) :].strip())
        return self == SemanticVersion.parse(constraint)

    def _satisfies_operator(self, operator: str, raw: str) -> bool:
        try:
            target = SemanticVersion.parse(raw)
        except ValueError as exc:
            raise TemplateRenderError(f"invalid version constraint '{raw}': {exc}") from exc
        if operator == "==":
            return self == target
        if operator == "!=":
            return self != target
        if operator == ">=":
            return self >= target
        if operator == ">":
            return self > target
        if operator == "<=":
            return self <= target
        if operator == "<":
            return self < target
        if operator == "~=":
            return self >= target and self < SemanticVersion(target.major, target.minor + 1, 0)
        if operator == "^":
            if target.major > 0:
                return self >= target and self.major == target.major
            if target.minor > 0:
                return self >= target and self.minor == target.minor
            return self >= target and self.patch == target.patch
        return False

    def is_compatible_with(self, other: SemanticVersion) -> bool:
        """Return ``True`` under the SemVer compatibility rule.

        ``0.x`` versions share compatibility within the same minor; ``1.0+``
        versions within the same major.
        """
        if self.major == 0 or other.major == 0:
            return self.major == other.major and self.minor == other.minor
        return self.major == other.major

    def __str__(self) -> str:
        value = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            value += f"-{self.prerelease}"
        if self.build:
            value += f"+{self.build}"
        return value

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-safe mapping."""
        return {
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch,
            "prerelease": self.prerelease,
            "build": self.build,
            "text": str(self),
        }


@dataclass(frozen=True, slots=True)
class ToolPackSpec:
    """The declaration used to generate a Tool Integration Pack.

    Validation is strict: a malformed specification raises
    :class:`InvalidToolPackSpecError` so no pack ships with a hole.
    """

    pack_id: str
    vendor: str
    tool_name: str
    display_name: str = ""
    description: str = ""
    version: str = "1.0.0"
    author: str = "HunterX Team"
    license: str = "Apache-2.0"
    execution_type: ToolExecutionType = ToolExecutionType.BINARY
    capabilities: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    parameters: dict[str, object] = field(default_factory=dict)
    output_format: str = "json"
    parser_strategy: str = "json"
    install_command: str = ""
    package_manager: str = ""
    cli_binary: str = ""
    health_command: str = ""
    mission_profiles: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    architectures: tuple[str, ...] = ()
    hunterx_versions: tuple[str, ...] = ()
    deprecated: bool = False
    deprecation_reason: str = ""
    template_id: str | None = None
    include_legacy_bridge: bool = False

    def __post_init__(self) -> None:
        if not _PACK_ID.fullmatch(self.pack_id):
            raise InvalidToolPackSpecError(
                f"pack_id '{self.pack_id}' must match [a-z0-9][a-z0-9-]*."
            )
        if not _VENDOR_ID.fullmatch(self.vendor):
            raise InvalidToolPackSpecError(
                f"vendor '{self.vendor}' must match [a-z0-9][a-z0-9-]*."
            )
        if not self.tool_name.strip():
            raise InvalidToolPackSpecError("tool_name must not be empty.")
        try:
            SemanticVersion.parse(self.version)
        except ValueError as exc:
            raise InvalidToolPackSpecError(f"invalid version '{self.version}': {exc}") from exc
        for capability in self.capabilities:
            if not _CAPABILITY_ID.fullmatch(capability):
                raise InvalidToolPackSpecError(
                    f"capability '{capability}' must match [a-z0-9][a-z0-9-]*."
                )
        for permission in self.permissions:
            if permission not in PERMISSION_FLAGS:
                raise InvalidToolPackSpecError(
                    f"permission '{permission}' is not a known flag ({', '.join(PERMISSION_FLAGS)})."
                )
        if self.output_format not in OUTPUT_FORMATS:
            raise InvalidToolPackSpecError(
                f"output_format '{self.output_format}' must be one of {OUTPUT_FORMATS}."
            )
        if self.parser_strategy not in PARSER_STRATEGIES:
            raise InvalidToolPackSpecError(
                f"parser_strategy '{self.parser_strategy}' must be one of {PARSER_STRATEGIES}."
            )
        if self.deprecated and not self.deprecation_reason.strip():
            raise InvalidToolPackSpecError("a deprecated pack must declare a deprecation_reason.")
        for value in self.hunterx_versions:
            try:
                SemanticVersion.parse(value)
            except ValueError as exc:
                raise InvalidToolPackSpecError(f"invalid hunterx version '{value}': {exc}") from exc

    @property
    def entrypoint(self) -> str:
        """Return the adapter entry point in ``module.path:ClassName`` form."""
        module = f"hunterx_tool_packs.{self.vendor}.{self.pack_id}.adapters.adapter"
        return f"{module}:{self.adapter_class_name}"

    @property
    def adapter_class_name(self) -> str:
        """Return the generated adapter class name (PascalCase)."""
        return "".join(part.capitalize() for part in self.pack_id.split("-")) + "Adapter"

    def root_path(self) -> str:
        """Return the standard pack root directory ``vendor/pack_id``."""
        return f"{self.vendor}/{self.pack_id}"


@dataclass(frozen=True, slots=True)
class GeneratedFile:
    """A single file generated for a Tool Integration Pack."""

    path: str
    content: str
    kind: PackArtifactKind = PackArtifactKind.BOILERPLATE

    def __post_init__(self) -> None:
        normalized = self.path.replace("\\", "/")
        if normalized.startswith("/") or normalized.startswith("../") or ".." in normalized.split("/"):
            raise InvalidToolPackSpecError(f"generated file path '{self.path}' is not relative.")
        object.__setattr__(self, "path", normalized)


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """A single pack validation finding."""

    severity: ValidationSeverity
    code: str
    message: str
    path: str = ""

    def to_dict(self) -> dict[str, str]:
        """Serialize to a JSON-safe mapping."""
        return {"severity": self.severity.value, "code": self.code, "message": self.message, "path": self.path}


@dataclass(slots=True)
class PackValidationReport:
    """The outcome of validating a Tool Integration Pack."""

    pack_id: str
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Return ``True`` when no error-level issue exists."""
        return not any(issue.severity is ValidationSeverity.ERROR for issue in self.issues)

    @property
    def errors(self) -> list[ValidationIssue]:
        """Return error-level issues."""
        return [issue for issue in self.issues if issue.severity is ValidationSeverity.ERROR]

    @property
    def warnings(self) -> list[ValidationIssue]:
        """Return warning-level issues."""
        return [issue for issue in self.issues if issue.severity is ValidationSeverity.WARNING]

    def add(self, issue: ValidationIssue) -> None:
        """Append a validation issue."""
        self.issues.append(issue)

    def add_error(self, code: str, message: str, path: str = "") -> None:
        """Append an error-level issue."""
        self.add(ValidationIssue(ValidationSeverity.ERROR, code, message, path))

    def add_warning(self, code: str, message: str, path: str = "") -> None:
        """Append a warning-level issue."""
        self.add(ValidationIssue(ValidationSeverity.WARNING, code, message, path))

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-safe mapping."""
        return {
            "pack_id": self.pack_id,
            "passed": self.passed,
            "issue_count": len(self.issues),
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(frozen=True, slots=True)
class CompatibilityEntry:
    """A single tool-version × HunterX-version compatibility record."""

    tool_version: str
    hunterx_version: str
    status: str = "compatible"
    notes: str = ""

    def to_dict(self) -> dict[str, str]:
        """Serialize to a JSON-safe mapping."""
        return {
            "tool_version": self.tool_version,
            "hunterx_version": self.hunterx_version,
            "status": self.status,
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class CompatibilityMatrix:
    """The version compatibility matrix of a Tool Integration Pack."""

    tool_id: str
    entries: tuple[CompatibilityEntry, ...] = ()

    def status_for(self, tool_version: str, hunterx_version: str) -> str:
        """Return the compatibility status for a version pair.

        Falls back to ``incompatible`` when the pair is not declared.
        """
        for entry in self.entries:
            if entry.tool_version == tool_version and entry.hunterx_version == hunterx_version:
                return entry.status
        return "incompatible"

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-safe mapping."""
        return {
            "tool_id": self.tool_id,
            "entries": [entry.to_dict() for entry in self.entries],
        }


@dataclass(frozen=True, slots=True)
class ToolPackManifest:
    """The generated ``pack.yaml`` manifest describing a pack."""

    pack_id: str
    vendor: str
    name: str
    version: str
    description: str = ""
    author: str = ""
    license: str = "Apache-2.0"
    entrypoint: str = ""
    structure_version: str = "1.0"
    generator_version: str = ""
    generated_at: str = field(default_factory=utcnow_iso)
    capabilities: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    quality_gates_passed: bool = True
    validation: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-safe mapping."""
        return {
            "pack_id": self.pack_id,
            "vendor": self.vendor,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "license": self.license,
            "entrypoint": self.entrypoint,
            "structure_version": self.structure_version,
            "generator_version": self.generator_version,
            "generated_at": self.generated_at,
            "capabilities": list(self.capabilities),
            "targets": list(self.targets),
            "files": list(self.files),
            "quality_gates_passed": self.quality_gates_passed,
            "validation": self.validation,
        }

    @classmethod
    def from_mapping(cls, data: dict[str, object]) -> ToolPackManifest:
        """Rebuild a manifest from a deserialized mapping."""
        return cls(
            pack_id=str(data.get("pack_id", "")),
            vendor=str(data.get("vendor", "")),
            name=str(data.get("name", "")),
            version=str(data.get("version", "")),
            description=str(data.get("description", "")),
            author=str(data.get("author", "")),
            license=str(data.get("license", "Apache-2.0")),
            entrypoint=str(data.get("entrypoint", "")),
            structure_version=str(data.get("structure_version", "1.0")),
            generator_version=str(data.get("generator_version", "")),
            generated_at=str(data.get("generated_at", utcnow_iso())),
            capabilities=tuple(str(item) for item in data.get("capabilities", [])),
            targets=tuple(str(item) for item in data.get("targets", [])),
            files=tuple(str(item) for item in data.get("files", [])),
            quality_gates_passed=bool(data.get("quality_gates_passed", True)),
            validation=dict(data.get("validation", {})),
        )


@dataclass(frozen=True, slots=True)
class ToolPack:
    """A generated Tool Integration Pack.

    An immutable collection of :class:`GeneratedFile` artifacts plus its
    manifest and validation report. Packs may be persisted through a
    repository or written to disk with :meth:`write_to`.
    """

    pack_id: str
    vendor: str
    name: str
    version: str
    files: tuple[GeneratedFile, ...]
    manifest: ToolPackManifest
    validation: PackValidationReport | None = None

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for file in self.files:
            if file.path in seen:
                raise InvalidToolPackSpecError(f"pack '{self.pack_id}' duplicates file '{file.path}'.")
            seen.add(file.path)
        if self.manifest.pack_id != self.pack_id:
            raise InvalidToolPackSpecError(
                f"pack manifest pack_id '{self.manifest.pack_id}' does not match pack_id '{self.pack_id}'."
            )

    def file(self, path: str) -> GeneratedFile | None:
        """Return the generated file at ``path``, or ``None``."""
        normalized = path.replace("\\", "/")
        return next((file for file in self.files if file.path == normalized), None)

    def has(self, path: str) -> bool:
        """Return ``True`` when the pack contains ``path``."""
        return self.file(path) is not None

    def paths(self) -> list[str]:
        """Return every generated path in stable order."""
        return [file.path for file in self.files]

    def root_path(self) -> str:
        """Return the standard pack root directory ``vendor/pack_id``."""
        return f"{self.vendor}/{self.pack_id}"

    def count(self, kind: PackArtifactKind) -> int:
        """Return how many files of ``kind`` the pack contains."""
        return sum(1 for file in self.files if file.kind is kind)

    def write_to(self, directory: str) -> list[str]:
        """Write every pack file under ``directory/vendor/pack_id``.

        Returns the absolute paths written. Parent directories are created.
        """
        root = os.path.join(directory, self.vendor, self.pack_id)
        written: list[str] = []
        for file in self.files:
            target = os.path.join(root, file.path)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(file.content)
            written.append(target)
        return written


@dataclass(frozen=True, slots=True)
class IntegrationTemplate:
    """A reusable integration template the generator engine renders from.

    Templates define the base content of every pack file; generator engines
    merge spec-derived values onto them. Built-in templates ship with the
    factory; operators may register overrides by ``template_id``.
    """

    template_id: str
    name: str
    description: str = ""
    version: str = "1.0.0"
    structure_version: str = "1.0"
    author: str = "HunterX Team"
    files: dict[str, str] = field(default_factory=dict)
    builtin: bool = False

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-safe mapping."""
        return {
            "template_id": self.template_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "structure_version": self.structure_version,
            "author": self.author,
            "files": dict(self.files),
            "builtin": self.builtin,
        }

    @classmethod
    def from_mapping(cls, data: dict[str, object]) -> IntegrationTemplate:
        """Rebuild a template from a deserialized mapping."""
        return cls(
            template_id=str(data.get("template_id", "")),
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            version=str(data.get("version", "1.0.0")),
            structure_version=str(data.get("structure_version", "1.0")),
            author=str(data.get("author", "HunterX Team")),
            files={str(key): str(value) for key, value in dict(data.get("files", {})).items()},
            builtin=bool(data.get("builtin", False)),
        )


def manifest_to_yaml(manifest: ToolPackManifest) -> str:
    """Render a manifest into a deterministic YAML document."""
    return _render_yaml(manifest.to_dict())


def render_yaml(data: dict[str, object]) -> str:
    """Render a nested mapping into a deterministic YAML document."""
    return _render_yaml(data)


def _render_yaml(data: dict[str, object], indent: int = 0) -> str:
    """Render a nested mapping as simple YAML (scalars, lists, mappings)."""
    lines: list[str] = []
    prefix = "  " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.append(_render_yaml(value, indent + 1))
        elif isinstance(value, list):
            lines.append(f"{prefix}{key}:")
            for item in value:
                if isinstance(item, dict):
                    lines.append(f"{prefix}  -")
                    lines.append(_render_yaml(item, indent + 2))
                else:
                    lines.append(f"{prefix}  - {_yaml_scalar(item)}")
        else:
            lines.append(f"{prefix}{key}: {_yaml_scalar(value)}")
    return "\n".join(lines)


def _yaml_scalar(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if text == "" or any(char in text for char in ":{}[],&*#?|-<>=!%@`") or text[0] in {" ", "'", '"'}:
        return f"'{text}'"
    return text


def new_pack_id() -> str:
    """Return a fresh ULID identifier for a generated pack."""
    return generate_id()
