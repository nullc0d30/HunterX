# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool discovery.

Reliable discovery of registered tools:

1. Check whether the executable exists (``shutil.which`` across the PATH).
2. Resolve its absolute path.
3. Verify it is executable (``os.access`` on POSIX + spawn probe).
4. Attempt version detection (``--version`` and friends), capturing stdout/stderr.
5. Normalize the detected version.
6. Classify readiness (``AVAILABLE`` / ``MISSING`` / ``BROKEN`` / ``OUTDATED`` /
   ``UNSUPPORTED``).

``tool does not exist`` (MISSING) is distinguished from ``tool exists but
cannot execute`` (BROKEN). In-process adapters (which need no external binary)
are classified from the execution engine's adapter/install state.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import sys
from typing import Any

from hunterx.tools.readiness.models import (
    ToolDefinition,
    ToolReadiness,
    ToolReadinessStatus,
)
from hunterx.tools.readiness.platform import PlatformInfo

_VERSION_FALLBACK = re.compile(r"(\d+\.\d+(?:\.\d+)?)")

#: Windows executable extensions probed in user script directories.
_WINDOWS_EXECUTABLE_EXTENSIONS = (".exe", ".cmd", ".bat")

#: Preferred search directories for security-tool executables, in order:
#: HunterX shared tool directory, Go bin directory, then the venv. The launcher
#: pins this same order into PATH; discovery uses it to detect and report
#: shadowing when a same-named binary (e.g. a Python package CLI) sits earlier
#: in the effective PATH than the expected security-tool provider.
_LAUNCHER_ORDER_HINT = "HUNTERX_TOOL_BIN"


def preferred_tool_directories() -> tuple[str, ...]:
    """Return the preferred HunterX tool directories in effective order.

    Order: shared tool directory (``<data>/tools/bin`` or ``HUNTERX_TOOL_BIN``),
    Go bin (``GOBIN``/``GOPATH/bin``), then the active venv bin. Only existing
    directories are returned.
    """
    directories: list[str] = []
    tool_bin = os.environ.get(_LAUNCHER_ORDER_HINT, "")
    if not tool_bin:
        data_dir = os.environ.get("HUNTERX_DATA_DIR", "")
        if data_dir:
            tool_bin = os.path.join(data_dir, "tools", "bin")
    if tool_bin:
        directories.append(tool_bin)
    go_bin = os.environ.get("GOBIN", "")
    if go_bin:
        directories.append(go_bin)
    gopath = os.environ.get("GOPATH", "")
    if gopath and gopath != os.path.expanduser("~"):
        directories.append(os.path.join(gopath, "bin"))
    venv = os.environ.get("VIRTUAL_ENV", "")
    if venv:
        directories.append(os.path.join(venv, "bin"))
    if sys.prefix != sys.base_prefix:
        directories.append(os.path.join(sys.prefix, "bin"))
    unique: list[str] = []
    for directory in directories:
        if not directory:
            continue
        resolved = os.path.normpath(directory)
        if resolved not in unique and os.path.isdir(resolved):
            unique.append(resolved)
    return tuple(unique)


def user_script_directories() -> tuple[str, ...]:
    """Return the user-level script directories HunterX tools install into.

    ``pip install --user`` / ``pipx`` place console scripts here; the
    directories are frequently missing from ``PATH`` on Windows. HunterX
    treats them as first-class search locations so provisioned tools are both
    discovered and runnable.
    """
    directories: list[str] = []
    if os.name == "nt":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            directories.append(
                os.path.join(
                    appdata,
                    "Python",
                    f"Python{sys.version_info.major}{sys.version_info.minor}",
                    "Scripts",
                )
            )
    else:
        directories.append(os.path.join(os.path.expanduser("~"), ".local", "bin"))
    return tuple(directory for directory in directories if os.path.isdir(directory))


def ensure_user_script_paths() -> tuple[str, ...]:
    """Append existing user script directories to ``PATH`` (idempotent).

    Returns the directories appended. Called at platform composition so
    provisioned console scripts resolve both during discovery and during real
    tool execution.
    """
    existing = os.environ.get("PATH", "").split(os.pathsep)
    added: list[str] = []
    for directory in user_script_directories():
        if directory not in existing:
            added.append(directory)
            existing.append(directory)
    if added:
        os.environ["PATH"] = os.pathsep.join(existing)
    return tuple(added)


class ToolDiscovery:
    """Probe registered tool definitions against the runtime environment.

    Args:
        engine: optional Tool Integration SDK execution engine. When present,
            in-process adapters and installed-version facts are checked so the
            readiness verdict reflects what the engine can actually run.

    """

    def __init__(self, engine: Any | None = None) -> None:
        self._engine = engine

    # -- public ------------------------------------------------------------

    def discover(self, definitions: list[ToolDefinition], platform: PlatformInfo) -> list[ToolReadiness]:
        """Probe every definition and return the readiness verdicts."""
        return [self.probe(definition, platform) for definition in definitions]

    def probe(self, definition: ToolDefinition, platform: PlatformInfo) -> ToolReadiness:
        """Probe one definition and return its readiness verdict."""
        if definition.kind == "inprocess":
            return self._probe_inprocess(definition)
        executable = self._find_executable(definition)
        if executable is None:
            return self._readiness(definition, platform, status=ToolReadinessStatus.MISSING)
        binary, path = executable[:2]
        collisions = executable[2] if len(executable) > 2 else ()
        if not self._is_executable(path):
            return self._readiness(
                definition,
                platform,
                status=ToolReadinessStatus.BROKEN,
                executable=binary,
                path=path,
                error=f"'{path}' exists but is not executable",
                collisions=collisions,
            )
        version, stdout, stderr, probe_error, command = self._detect_version(definition, binary, path)
        if probe_error:
            return self._readiness(
                definition,
                platform,
                status=ToolReadinessStatus.BROKEN,
                executable=binary,
                path=path,
                stderr=stderr,
                error=probe_error,
                detected_command=command,
                collisions=collisions,
            )
        status = ToolReadinessStatus.AVAILABLE
        if version and definition.min_version and _version_lt(version, definition.min_version):
            status = ToolReadinessStatus.OUTDATED
        return self._readiness(
            definition,
            platform,
            status=status,
            executable=binary,
            path=path,
            version=version,
            stdout=stdout,
            stderr=stderr,
            detected_command=command,
            collisions=collisions,
        )

    def mark_installed(self, tool_id: str, version: str = "") -> None:
        """Record a discovered tool as installed on the engine.

        Feeds the SDK's health checker so mission execution health checks pass
        for tools the discovery probe verified as available.
        """
        engine = self._engine
        if engine is None:
            return
        with contextlib.suppress(Exception):  # version recording is best-effort
            if version:
                engine.versions.record(tool_id, version)
        with contextlib.suppress(Exception):  # install-record sync is best-effort
            record = engine.installer.record_for(tool_id)
            if record is None or record.error is not None or record.installed_at is None:
                engine.installer.register(tool_id, _static_install_hook(tool_id, version))
                engine.installer.install(tool_id, version or "detected")

    # -- internals ---------------------------------------------------------

    def _probe_inprocess(self, definition: ToolDefinition) -> ToolReadiness:
        tool_id = definition.tool_id
        engine = self._engine
        if engine is not None:
            adapter = engine.adapter_for(tool_id)
            if adapter is not None:
                version = ""
                try:
                    version = str(engine.versions.installed(tool_id) or "")
                except Exception:  # noqa: BLE001
                    version = ""
                if not version:
                    metadata = getattr(engine, "_intelligence", None)
                    if metadata is not None:
                        meta = metadata.get_metadata(tool_id)
                        version = meta.version if meta is not None else ""
                self.mark_installed(tool_id, version or "")
                return self._readiness(
                    definition,
                    PlatformInfo(os="inprocess"),
                    status=ToolReadinessStatus.AVAILABLE,
                    version=version,
                )
            return self._readiness(
                definition,
                PlatformInfo(os="inprocess"),
                status=ToolReadinessStatus.MISSING,
                error="no execution adapter registered",
            )
        return self._readiness(
            definition,
            PlatformInfo(os="inprocess"),
            status=ToolReadinessStatus.AVAILABLE,
        )

    def _find_executable(self, definition: ToolDefinition) -> tuple[str, str, tuple[dict[str, str], ...]] | None:
        """Resolve the executable and report same-named competitors.

        Returns ``(binary, path, collisions)``. Collisions are every
        same-named executable elsewhere on the PATH or in a preferred HunterX
        directory that competes with the resolved provider — including the
        preferred location itself when the resolved binary is NOT the one
        HunterX expects (executable shadowing). The version probe then
        validates which executable is the actual security-tool provider.
        """
        candidates = [definition.executable, *definition.aliases]
        for candidate in candidates:
            candidate = (candidate or "").strip()
            if not candidate:
                continue
            path = shutil.which(candidate)
            resolved_path = os.path.realpath(path) if path else ""
            if not resolved_path:
                resolved_path = self._resolve_in_user_dirs(candidate)
            if not resolved_path:
                continue
            collisions = self._collision_report(candidate, resolved_path)
            return candidate, resolved_path, collisions
        return None

    def _resolve_in_user_dirs(self, candidate: str) -> str:
        """Resolve ``candidate`` in the user-level script directories."""
        for directory in user_script_directories():
            resolved = self._resolve_in_directory(directory, candidate)
            if resolved is not None:
                return resolved
        return ""

    def _collision_report(self, candidate: str, resolved_path: str) -> tuple[dict[str, str], ...]:
        """Return every same-named executable competing with ``resolved_path``.

        Each entry is ``{"path": ..., "preferred": "true"|"false"}`` where
        ``preferred`` marks a binary inside a preferred HunterX tool
        directory. A preferred-dir binary that differs from the resolved one
        is always reported so the operator sees exactly which executable would
        run before the probe validates the provider.
        """
        collisions: list[dict[str, str]] = []
        preferred = set(preferred_tool_directories())
        seen: set[str] = set()
        for directory in self._path_directories():
            hit = self._resolve_in_directory(directory, candidate)
            if hit is None or hit == resolved_path:
                continue
            normalized = os.path.normpath(hit)
            if normalized in seen:
                continue
            seen.add(normalized)
            collisions.append(
                {
                    "path": hit,
                    "preferred": "true" if os.path.dirname(normalized) in preferred else "false",
                }
            )
        return tuple(collisions)

    def _path_directories(self) -> list[str]:
        """Return the effective PATH directories (system then preferred)."""
        directories = [os.path.normpath(d) for d in os.environ.get("PATH", "").split(os.pathsep) if d]
        for directory in preferred_tool_directories():
            normalized = os.path.normpath(directory)
            if normalized not in directories:
                directories.append(normalized)
        return directories

    def _resolve_in_directory(self, directory: str, candidate: str) -> str | None:
        """Resolve ``candidate`` (with platform executable extensions) in ``directory``."""
        direct = os.path.join(directory, candidate)
        if os.path.isfile(direct) and self._is_executable(direct):
            return os.path.realpath(direct)
        if os.name == "nt":
            for extension in _WINDOWS_EXECUTABLE_EXTENSIONS:
                with_extension = f"{direct}{extension}"
                if os.path.isfile(with_extension) and self._is_executable(with_extension):
                    return os.path.realpath(with_extension)
        return None

    def _is_executable(self, path: str) -> bool:
        if os.name == "nt":
            return os.path.isfile(path)
        try:
            return os.access(path, os.X_OK)
        except OSError:
            return False

    def _detect_version(
        self,
        definition: ToolDefinition,
        binary: str,
        path: str,
    ) -> tuple[str, str, str, str, tuple[str, ...]]:
        """Run the version probe; return ``(version, stdout, stderr, error, command)``."""
        from hunterx.domain.exceptions import ToolExecutionError, ToolTimeoutError
        from hunterx.tools.recon.runner import BinaryRunner

        command = [path, *definition.version_command]
        runner = BinaryRunner(timeout_s=10.0)
        try:
            result = runner.run(command, timeout_s=10.0, tool_id=definition.tool_id)
        except ToolTimeoutError as exc:
            return "", "", "", f"version probe timed out: {exc}", tuple(command)
        except ToolExecutionError as exc:
            return "", "", "", f"version probe failed to start: {exc}", tuple(command)
        except Exception as exc:  # noqa: BLE001 - probe failures are verdicts
            return "", "", "", f"version probe error: {exc}", tuple(command)

        stdout = result.stdout
        stderr = result.stderr
        combined = f"{stdout}\n{stderr}"
        version = self._extract_version(combined, definition.version_regex)
        if not version and definition.version_regex and combined.strip():
            # A version pattern is declared for this tool but the probe output
            # matched nothing: the binary is very likely NOT the expected tool
            # (e.g. a same-named unrelated package) or is broken.
            return (
                "",
                "",
                "",
                f"version probe output did not match the expected pattern for '{definition.tool_id}'",
                tuple(command),
            )
        if not version and result.returncode != 0 and not combined.strip():
            # The binary exists but produced nothing at all: treat as broken
            # only when the process itself failed to produce any output.
            return "", "", "", f"version probe exited {result.returncode} with no output", tuple(command)
        return version, stdout, stderr, "", tuple(command)

    def _extract_version(self, combined: str, regex: str) -> str:
        if regex:
            match = re.search(regex, combined)
            if match:
                return _normalize_version(match.group(1))
        match = _VERSION_FALLBACK.search(combined)
        if match:
            return _normalize_version(match.group(1))
        return ""

    def _readiness(
        self,
        definition: ToolDefinition,
        platform: PlatformInfo,
        *,
        status: ToolReadinessStatus,
        executable: str = "",
        path: str = "",
        version: str = "",
        stdout: str = "",
        stderr: str = "",
        error: str = "",
        detected_command: tuple[str, ...] = (),
        collisions: tuple[dict[str, str], ...] = (),
    ) -> ToolReadiness:
        expected_version = ""
        tip = getattr(self._engine, "_intelligence", None)
        if tip is not None:
            metadata = tip.get_metadata(definition.tool_id)
            expected_version = metadata.version if metadata is not None else ""

        from hunterx.tools.readiness.manifest import install_methods_for

        install_methods = install_methods_for(definition.tool_id, platform)
        return ToolReadiness(
            tool_id=definition.tool_id,
            status=status,
            executable=executable,
            path=path,
            version=version,
            expected_version=expected_version,
            detected_command=detected_command,
            stdout=stdout,
            stderr=stderr,
            error=error,
            definition=definition,
            install_methods=install_methods,
            platform=platform.os,
            collisions=collisions,
        )


def _static_install_hook(tool_id: str, version: str) -> Any:
    """Return a hook that reports the discovered version (no-op install)."""

    def hook(_tool: str, _version: str | None) -> str:
        return version or "detected"

    return hook


def _normalize_version(raw: str) -> str:
    """Normalize a detected version string to ``x.y.z``-ish form."""
    value = (raw or "").strip()
    if value.startswith("v"):
        value = value[1:]
    return value


def _version_lt(left: str, right: str) -> bool:
    """Return ``True`` when semver-ish ``left`` < ``right``."""
    from hunterx.tools.sdk.version import _compare

    try:
        return _compare(left, right) < 0
    except Exception:  # noqa: BLE001 - version comparison is best-effort
        return False


__all__ = ["ToolDiscovery"]
