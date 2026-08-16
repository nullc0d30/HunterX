# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool provisioning.

Installs missing external tools through TRUSTED, STATIC installation methods
declared in the readiness manifest. The provisioner:

- never builds commands from user/target input — package names and module
  paths are static manifest constants;
- is idempotent — an already-available tool is never reinstalled
  (detect → verify → reuse);
- verifies every install by re-running discovery before declaring success;
- reports ``UNSUPPORTED`` clearly when no compatible method exists for the
  current platform;
- always captures the executed command and its output so provisioning is
  auditable.

Unit tests inject a fake command runner — no real package is ever installed
during normal test runs.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404  # guarded static command vector (see _run)
import sys
from typing import Any

from hunterx.tools.readiness.models import (
    InstallMethod,
    InstallOutcome,
    ToolDefinition,
    ToolReadiness,
    ToolReadinessStatus,
)
from hunterx.tools.readiness.platform import PlatformInfo

#: Prefix used when the process has no elevation rights but the method needs it.
_SUDO = ("sudo",)

#: Hard timeout (seconds) applied per install-method kind. The manifest may
#: override any of these with an explicit ``timeout_s`` on an ``InstallMethod``.
#: apt-style package managers are fast; source builds (cargo/script) are slow.
_METHOD_DEFAULT_TIMEOUTS: dict[str, float] = {
    "apt": 300.0,
    "dnf": 300.0,
    "pacman": 300.0,
    "apk": 300.0,
    "zypper": 300.0,
    "choco": 300.0,
    "brew": 600.0,
    "pip": 300.0,
    "pipx": 300.0,
    "npm": 300.0,
    "go": 600.0,
    "cargo": 1200.0,
    "prebuilt": 600.0,
    "git": 600.0,
    "script": 1800.0,
    "default": 900.0,
}


class CommandRunner:
    """Execute static install commands, capturing bounded output.

    Subclass or stub in tests to avoid real installations. The argv is always
    passed structurally (no shell) so arguments are inert data. A per-call
    timeout replaces the runner default when supplied.
    """

    def __init__(self, *, timeout_s: float = 900.0) -> None:
        self._timeout = timeout_s

    def run(self, argv: list[str], *, timeout_s: float | None = None) -> tuple[int, str, str]:
        """Run ``argv`` and return ``(returncode, stdout, stderr)``."""
        effective = timeout_s if timeout_s is not None else self._timeout
        try:
            completed = subprocess.run(  # nosec B603  # trusted static argv
                argv,
                capture_output=True,
                text=True,
                timeout=effective,
                check=False,
            )
        except FileNotFoundError as exc:
            return 127, "", f"command not found: {argv[0]}" if argv else str(exc)
        except subprocess.TimeoutExpired:
            return 124, "", f"install timed out after {effective:g}s"
        except OSError as exc:
            return 126, "", str(exc)
        return completed.returncode, completed.stdout or "", completed.stderr or ""


class ToolProvisioner:
    """Provision missing tools through trusted static install methods.

    Args:
        discovery: the discovery probe used to detect/re-verify tools.
        platform: the detected runtime platform.
        runner: the command runner (stub in tests).
        auto_elevate: when ``True`` (default) prefix elevation-requiring
            commands with ``sudo`` unless already root; when ``False`` such
            methods are reported as unsupported.

    """

    def __init__(
        self,
        discovery: Any,
        platform: PlatformInfo,
        runner: Any | None = None,
        *,
        auto_elevate: bool = True,
        command_available: Any | None = None,
        observer: Any | None = None,
    ) -> None:
        self._discovery = discovery
        self._platform = platform
        self._runner = runner or CommandRunner()
        self._auto_elevate = auto_elevate
        self._command_available = command_available or shutil.which
        self._observer = observer

    def _emit(self, event: Any) -> None:
        """Forward a progress event to the installer observer (best-effort)."""
        if self._observer is not None:
            self._observer(event)

    def install(self, definition: ToolDefinition, *, verify: bool = True) -> InstallOutcome:
        """Provision ``definition`` and return the outcome.

        Already-available tools are skipped (idempotency). Returns an
        ``UNSUPPORTED`` outcome when no compatible install method exists on
        the current platform, and a ``PROVISIONING_FAILED`` outcome when every
        trusted method ran but post-install verification did not pass.
        """
        current = self._discovery.probe(definition, self._platform)
        if current.status is ToolReadinessStatus.AVAILABLE:
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=True,
                status=ToolReadinessStatus.AVAILABLE,
                version=current.version,
                skipped=True,
            )
        if current.status is ToolReadinessStatus.OUTDATED and not self._should_upgrade(current):
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=True,
                status=current.status,
                version=current.version,
                skipped=True,
            )

        # Non-provisionable catalog classifications are reported with their
        # precise status and remediation — never retried as an install and
        # never hidden behind a generic ``missing``/``unsupported`` verdict.
        if definition.classification == ToolReadinessStatus.NOT_CLI.value:
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=False,
                status=ToolReadinessStatus.NOT_CLI,
                error=definition.classification_reason or "tool requires a GUI/UI or daemon",
            )
        if definition.classification == ToolReadinessStatus.DEPRECATED.value:
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=False,
                status=ToolReadinessStatus.DEPRECATED,
                error=definition.classification_reason or "tool is obsolete/deprecated",
            )
        if definition.classification == ToolReadinessStatus.MANUAL_ONLY.value:
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=False,
                status=ToolReadinessStatus.MANUAL_ONLY,
                error=definition.classification_reason or "installation requires manual steps",
            )

        methods = self._compatible_methods(definition)
        if not methods:
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=False,
                status=ToolReadinessStatus.UNSUPPORTED,
                version=current.version,
                error=_unsupported_reason(definition, self._platform),
            )

        # Try each trusted method in declaration order and use the first that
        # installs AND verifies. This is the manifest's documented fallback
        # strategy (e.g. pip -> pipx -> apt): a method may be unavailable at
        # runtime (PEP 668 managed interpreter, missing compiler, stale repo)
        # without the whole tool being marked unprovisionable.
        last_error = ""
        last_command: tuple[str, ...] = ()
        last_stdout = ""
        last_stderr = ""
        for method in methods:
            command = self._build_command(method)
            timeout_s = self._method_timeout(method)
            self._emit(
                {
                    "phase": "method",
                    "tool_id": definition.tool_id,
                    "method": method.kind,
                    "command": command,
                }
            )
            try:
                returncode, stdout, stderr = self._runner.run(list(command), timeout_s=timeout_s)
            except KeyboardInterrupt:
                self._emit(
                    {
                        "phase": "interrupted",
                        "tool_id": definition.tool_id,
                        "method": method.kind,
                    }
                )
                raise
            if returncode != 0:
                last_error = _install_error(method, returncode, stdout, stderr, timeout_s)
                last_command = tuple(command)
                last_stdout = stdout
                last_stderr = stderr
                continue

            if not verify:
                return InstallOutcome(
                    tool_id=definition.tool_id,
                    success=True,
                    status=ToolReadinessStatus.AVAILABLE,
                    method=method,
                    command=tuple(command),
                    stdout=stdout,
                    stderr=stderr,
                )

            after = self._discovery.probe(definition, self._platform)
            if after.status is ToolReadinessStatus.AVAILABLE or (
                after.status is ToolReadinessStatus.OUTDATED and not self._should_upgrade(after)
            ):
                self._discovery.mark_installed(definition.tool_id, after.version)
                return InstallOutcome(
                    tool_id=definition.tool_id,
                    success=True,
                    status=after.status,
                    version=after.version,
                    method=method,
                    command=tuple(command),
                    stdout=stdout,
                    stderr=stderr,
                )
            last_error = "installation finished but the tool could not be verified"
            last_command = tuple(command)
            last_stdout = stdout
            last_stderr = stderr

        return InstallOutcome(
            tool_id=definition.tool_id,
            success=False,
            status=ToolReadinessStatus.PROVISIONING_FAILED,
            version=current.version,
            command=last_command,
            stdout=last_stdout,
            stderr=last_stderr,
            error=last_error,
        )

    # -- helpers -----------------------------------------------------------

    def _method_timeout(self, method: InstallMethod) -> float:
        """Return the effective hard timeout for ``method`` (seconds)."""
        if method.timeout_s and method.timeout_s > 0:
            return method.timeout_s
        return _METHOD_DEFAULT_TIMEOUTS.get(method.kind, _METHOD_DEFAULT_TIMEOUTS["default"])

    def _compatible_methods(self, definition: ToolDefinition) -> list[InstallMethod]:
        methods: list[InstallMethod] = []
        for method in definition.installation_methods:
            if self._platform.os not in method.platforms:
                continue
            if method.requires_elevation and not self._auto_elevate:
                continue
            if method.requires_elevation and not self._elevated() and not self._can_sudo():
                continue
            if not self._method_available(method):
                continue
            methods.append(method)
        return methods

    def _method_available(self, method: InstallMethod) -> bool:
        """Return ``True`` when the runtime/package-manager for ``method`` exists.

        Prevents the provisioner from attempting commands that are unavailable
        (``go`` absent, ``cargo`` absent, ``apt-get`` absent, ...) — only tools
        and package managers actually present in the environment are used.
        """
        if method.kind == "apt":
            return self._platform.package_manager == "apt" and self._command_available("apt-get") is not None
        if method.kind == "pacman":
            return self._platform.package_manager == "pacman" and self._command_available("pacman") is not None
        if method.kind == "dnf":
            return self._platform.package_manager == "dnf" and self._command_available("dnf") is not None
        if method.kind == "brew":
            return self._command_available("brew") is not None
        if method.kind == "go":
            return self._command_available("go") is not None
        if method.kind == "cargo":
            return self._command_available("cargo") is not None
        if method.kind == "pip":
            return True  # uses sys.executable; always available
        if method.kind == "pipx":
            return self._command_available("pipx") is not None
        if method.kind == "npm":
            return self._command_available("npm") is not None
        if method.kind == "choco":
            return self._command_available("choco") is not None
        if method.kind in ("script", "prebuilt", "git"):
            return self._command_available("bash") is not None
        return False

    def _build_command(self, method: InstallMethod) -> list[str]:
        """Return the concrete argv for a trusted install method."""
        if method.kind == "apt":
            prefix = [] if self._elevated() else list(_SUDO)
            return [*prefix, "apt-get", "install", "-y", method.package]
        if method.kind == "pacman":
            prefix = [] if self._elevated() else list(_SUDO)
            return [*prefix, "pacman", "-S", "--noconfirm", method.package]
        if method.kind == "dnf":
            prefix = [] if self._elevated() else list(_SUDO)
            return [*prefix, "dnf", "install", "-y", method.package]
        if method.kind == "brew":
            return ["brew", "install", method.package]
        if method.kind == "go":
            return ["go", "install", "-v", method.name]
        if method.kind == "cargo":
            return ["cargo", "install", method.package]
        if method.kind == "pip":
            # PEP 668 distros (Ubuntu 24.04+) refuse ``--user`` installs on the
            # externally-managed system interpreter. The provisioner falls
            # through to the next trusted method (typically pipx) declared for
            # the tool, so ``pip --user`` remaining the primary contract here
            # does not strand the tool on managed interpreters.
            argv = [sys.executable, "-m", "pip", "install"]
            if not self._elevated() and method.package:
                argv.append("--user")
            argv.append(method.package)
            return argv
        if method.kind == "pipx":
            return ["pipx", "install", method.package]
        if method.kind == "npm":
            argv = ["npm", "install", "-g", method.package]
            if method.requires_elevation:
                argv = ([] if self._elevated() else list(_SUDO)) + argv
            return argv
        if method.kind == "choco":
            argv = ["choco", "install", "-y", method.package]
            if method.requires_elevation and not self._elevated():
                argv = [
                    "powershell",
                    "-Command",
                    f"Start-Process choco -ArgumentList 'install,-y,{method.package}' -Verb RunAs",
                ]
            return argv
        if method.kind == "script":
            return ["bash", "-c", _STATIC_SCRIPTS.get(method.name, "exit 1")]
        if method.kind == "prebuilt":
            # Download a trusted release binary/archive into the HunterX tool
            # directory. ``name`` is the download URL; ``package`` is the local
            # file name (or the archive member to install when ``package`` ends
            # with ``!/path``). The URL is a static manifest constant.
            return ["bash", "-c", _prebuilt_script(method)]
        if method.kind == "git":
            # Clone a trusted repository and (optionally) build its CLI.
            return ["bash", "-c", _git_script(method)]
        raise ValueError(f"unsupported install method kind: {method.kind}")

    def _elevated(self) -> bool:
        return bool(self._platform.is_root)

    def _can_sudo(self) -> bool:
        return self._platform.os in ("linux", "darwin")

    def _should_upgrade(self, readiness: ToolReadiness) -> bool:
        # Only auto-upgrade when a min version is declared and the installed
        # version is below it; otherwise keep the existing install.
        return False


def _unsupported_reason(definition: ToolDefinition, platform: PlatformInfo) -> str:
    if not definition.installation_methods:
        return f"no supported installation method declared for '{definition.tool_id}'"
    return (
        f"no compatible installation method for '{definition.tool_id}' on "
        f"{platform.os}/{platform.distro or platform.package_manager}"
    )


def _install_error(
    method: InstallMethod,
    returncode: int,
    stdout: str,
    stderr: str,
    timeout_s: float,
) -> str:
    """Build a human explanation for a failed installer run.

    Distinguishes the timeout case (which otherwise only produces a terse
    stderr) so the installer UI can explain the failure and suggest a retry.
    """
    if returncode == 124:
        return (
            f"installation timed out after {timeout_s:g}s "
            f"({method.kind} installer for '{method.package or method.name}')"
        )
    detail = (stderr or stdout or f"installer exited with code {returncode}").strip()
    return detail[:2000] or f"installer exited with code {returncode}"


#: Static, trusted shell scripts for ``script``-kind install methods. Kept
#: intentionally minimal; every entry is a static constant (never interpolated).
_STATIC_SCRIPTS: dict[str, str] = {
    "linkfinder": (
        'set -e; BIN="${HUNTERX_TOOL_BIN:-$HOME/.hunterx/tools/bin}"; '
        'mkdir -p "$BIN/src"; '
        'git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git "$BIN/src/LinkFinder" 2>/dev/null || true; '
        'PY="${PYTHON:-python3}"; "$PY" -m pip install -q -r "$BIN/src/LinkFinder/requirements.txt" 2>/dev/null || true; '
        'ln -sf "$BIN/src/LinkFinder/linkfinder.py" "$BIN/linkfinder"; chmod +x "$BIN/linkfinder"; '
        'echo "linkfinder installed to $BIN/linkfinder"'
    ),
    "secretfinder": (
        'set -e; BIN="${HUNTERX_TOOL_BIN:-$HOME/.hunterx/tools/bin}"; '
        'mkdir -p "$BIN/src"; '
        'git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git "$BIN/src/SecretFinder" 2>/dev/null || true; '
        'ln -sf "$BIN/src/SecretFinder/SecretFinder.py" "$BIN/SecretFinder"; chmod +x "$BIN/SecretFinder"; '
        'echo "secretfinder installed to $BIN/SecretFinder"'
    ),
    "xnlinkfinder": (
        'set -e; BIN="${HUNTERX_TOOL_BIN:-$HOME/.hunterx/tools/bin}"; '
        'mkdir -p "$BIN/src"; '
        'git clone --depth 1 https://github.com/xnl-h4ck3r/xnLinkFinder.git "$BIN/src/xnLinkFinder" 2>/dev/null || true; '
        'PY="${PYTHON:-python3}"; "$PY" -m pip install -q -r "$BIN/src/xnLinkFinder/requirements.txt" 2>/dev/null || true; '
        'ln -sf "$BIN/src/xnLinkFinder/xnLinkFinder.py" "$BIN/xnlinkfinder"; chmod +x "$BIN/xnlinkfinder"; '
        'echo "xnlinkfinder installed to $BIN/xnlinkfinder"'
    ),
    "jwt-tool": (
        'set -e; BIN="${HUNTERX_TOOL_BIN:-$HOME/.hunterx/tools/bin}"; '
        'mkdir -p "$BIN/src"; '
        'git clone --depth 1 https://github.com/ticarpi/jwt_tool.git "$BIN/src/jwt_tool" 2>/dev/null || true; '
        'chmod +x "$BIN/src/jwt_tool/jwt_tool.py"; '
        'ln -sf "$BIN/src/jwt_tool/jwt_tool.py" "$BIN/jwt_tool"; chmod +x "$BIN/jwt_tool"; '
        'echo "jwt-tool installed to $BIN/jwt_tool"'
    ),
}


def _tool_bin() -> str:
    """Return the HunterX managed tool directory used by prebuilt/git installs."""
    return "${HUNTERX_TOOL_BIN:-$HOME/.hunterx/tools/bin}"


def _prebuilt_script(method: InstallMethod) -> str:
    """Return a trusted static script installing a release binary/archive.

    ``method.name`` is the download URL; ``method.package`` names the local
    artifact. A ``package`` ending in ``!/relative/path`` extracts that member
    from the archive into the tool bin. The URL is a static manifest constant.
    """
    url = method.name or ""
    package = method.package or "tool"
    bin_dir = _tool_bin()
    member = ""
    if "!" in package:
        package, member = package.rsplit("!", 1)
    member_install = f'tar -xzf "$BIN/{package}" -C "$BIN" "{member}" 2>/dev/null || unzip -o -j "$BIN/{package}" "{member}" -d "$BIN" 2>/dev/null || true' if member else ""
    return (
        f'set -e; BIN={bin_dir}; mkdir -p "$BIN"; '
        f'(command -v curl >/dev/null && curl -fsSL -o "$BIN/{package}" "{url}") '
        f'|| (command -v wget >/dev/null && wget -qO "$BIN/{package}" "{url}"); '
        f'{member_install} '
        f'chmod +x "$BIN/{package}" 2>/dev/null || true; '
        f'echo "downloaded to $BIN/{package}"'
    )


def _git_script(method: InstallMethod) -> str:
    """Return a trusted static script cloning and building a Go CLI from git.

    ``method.name`` is the repository URL; ``method.package`` is the go package
    path (or the local binary name when empty). The URL is a static constant.
    """
    repo = method.name or ""
    bin_dir = _tool_bin()
    name = method.package or (repo.rstrip("/").split("/")[-1] or "tool")
    return (
        f'set -e; BIN={bin_dir}; SRC="$BIN/src/{name}"; mkdir -p "$BIN"; '
        f'git clone --depth 1 "{repo}" "$SRC" 2>/dev/null || (cd "$SRC" && git pull --ff-only) ; '
        f'(cd "$SRC" && go build -o "$BIN/{name}" .); '
        f'chmod +x "$BIN/{name}"; echo "built $BIN/{name}"'
    )


__all__ = ["CommandRunner", "ToolProvisioner"]
