# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Platform detection for the Tool Readiness subsystem.

Detects the runtime environment so the provisioner can pick a safe, supported
installation method. Supported families: Debian/Ubuntu/Kali/Parrot (apt),
Arch-based (pacman), Fedora/RHEL (dnf), macOS (brew), Windows, WSL and Docker
containers. Unsupported environments are reported clearly and never guessed.
"""

from __future__ import annotations

import os
import platform as _platform
import shutil
import sys
from dataclasses import dataclass
from typing import Any

_APT_IDS = {"ubuntu", "debian", "kali", "parrot", "linuxmint", "pop", "elementary", "raspbian", "zorin"}
_PACMAN_IDS = {"arch", "manjaro", "endeavouros", "artix", "cachyos"}
_DNF_IDS = {"fedora", "rhel", "centos", "rocky", "almalinux", "ol"}


@dataclass(frozen=True, slots=True)
class PlatformInfo:
    """Detected runtime platform.

    Attributes:
        os: base operating system (``linux``, ``darwin``, ``windows``).
        distro: Linux distribution id (``ubuntu``, ``kali``, ...) or ``""``.
        distro_version: distribution version id or ``""``.
        package_manager: canonical package-manager family (``apt``, ``pacman``,
            ``dnf``, ``brew``, ``choco``, ``none``).
        arch: machine architecture (``x86_64``, ``aarch64``, ...).
        wsl: ``True`` when running under Windows Subsystem for Linux.
        container: ``True`` when running inside a container.
        supported: ``True`` when the platform has a supported install family.
        is_root: ``True`` when running with elevated privileges.

    """

    os: str = "unknown"
    distro: str = ""
    distro_version: str = ""
    package_manager: str = "none"
    arch: str = "unknown"
    wsl: bool = False
    container: bool = False
    supported: bool = False
    is_root: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of the platform."""
        return {
            "os": self.os,
            "distro": self.distro,
            "distro_version": self.distro_version,
            "package_manager": self.package_manager,
            "arch": self.arch,
            "wsl": self.wsl,
            "container": self.container,
            "supported": self.supported,
            "is_root": self.is_root,
        }


class PlatformDetector:
    """Detect the runtime platform for the readiness/provisioning layers."""

    def __init__(
        self,
        *,
        os_name: str = "",
        machine: str = "",
        os_release: str = "",
        proc_version: str = "",
        is_root: bool | None = None,
    ) -> None:
        """Create a detector, allowing deterministic overrides for tests.

        When an override is provided it is used verbatim (the real environment
        is otherwise probed). ``os_release`` is the content of ``/etc/os-release``.
        """
        self._os_name = os_name or sys.platform
        self._machine = machine or _platform.machine()
        self._os_release = os_release if os_release is not None else ""
        self._proc_version = proc_version if proc_version is not None else ""
        self._is_root = is_root

    def detect(self) -> PlatformInfo:
        """Return the detected :class:`PlatformInfo`."""
        os_family = self._os_family()
        if os_family == "windows":
            return PlatformInfo(
                os="windows",
                package_manager="choco" if shutil.which("choco") else "none",
                arch=self._machine,
                supported=False,
                is_root=self._is_root if self._is_root is not None else _is_admin(),
            )
        if os_family == "darwin":
            return PlatformInfo(
                os="darwin",
                package_manager="brew" if shutil.which("brew") else "none",
                arch=self._machine,
                supported=shutil.which("brew") is not None,
                is_root=self._is_root if self._is_root is not None else _is_admin(),
            )
        if os_family != "linux":
            return PlatformInfo(
                os=os_family,
                arch=self._machine,
                supported=False,
                is_root=self._is_root if self._is_root is not None else _is_admin(),
            )

        distro, distro_version, release_text = self._linux_release()
        package_manager = self._package_manager(distro)
        return PlatformInfo(
            os="linux",
            distro=distro,
            distro_version=distro_version,
            package_manager=package_manager,
            arch=self._machine,
            wsl=self._is_wsl(release_text),
            container=self._is_container(),
            supported=package_manager != "none",
            is_root=self._is_root if self._is_root is not None else _is_admin(),
        )

    # -- internals ---------------------------------------------------------

    def _os_family(self) -> str:
        value = str(self._os_name).lower()
        if value.startswith("win"):
            return "windows"
        if value.startswith("darwin"):
            return "darwin"
        if value in ("linux", "linux2"):
            return "linux"
        return value

    def _linux_release(self) -> tuple[str, str, str]:
        """Return ``(distro_id, version_id, release_text)``."""
        release_text = self._os_release
        if not release_text:
            try:
                with open("/etc/os-release", encoding="utf-8") as handle:  # noqa: PTH123 - guarded POSIX path
                    release_text = handle.read()
            except OSError:
                release_text = ""
        distro: str = ""
        distro_version: str = ""
        for line in release_text.splitlines():
            line = line.strip()
            if line.startswith("ID=") and not line.startswith("ID_LIKE"):
                distro = line.split("=", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("VERSION_ID="):
                distro_version = line.split("=", 1)[1].strip().strip('"').strip("'")
        return distro, distro_version, release_text

    def _package_manager(self, distro: str) -> str:
        lowered = distro.lower()
        if lowered in _APT_IDS:
            return "apt"
        if lowered in _PACMAN_IDS:
            return "pacman"
        if lowered in _DNF_IDS:
            return "dnf"
        if lowered == "alpine":
            return "apk"
        if lowered in ("opensuse", "suse", "sles"):
            return "zypper"
        return "none"

    def _is_wsl(self, release_text: str) -> bool:
        if self._proc_version:
            return "microsoft" in self._proc_version.lower() or "wsl" in self._proc_version.lower()
        if "microsoft" in release_text.lower() or "wsl" in release_text.lower():
            return True
        try:
            with open("/proc/version", encoding="utf-8", errors="replace") as handle:  # noqa: PTH123 - POSIX
                return "microsoft" in handle.read().lower() or "wsl" in handle.read().lower()
        except OSError:
            return False

    def _is_container(self) -> bool:
        for marker in ("/.dockerenv", "/run/.containerenv"):
            try:
                if os.path.exists(marker):
                    return True
            except OSError:
                continue
        try:
            with open("/proc/1/cgroup", encoding="utf-8", errors="replace") as handle:  # noqa: PTH123 - POSIX
                return "docker" in handle.read() or "kubepods" in handle.read()
        except OSError:
            return False


def _is_admin() -> bool:
    """Return ``True`` when the process runs with elevated privileges."""
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001 - best-effort elevation probe
            return False
    return bool(os.geteuid() == 0)  # type: ignore[attr-defined]  # POSIX-only branch


__all__ = ["PlatformDetector", "PlatformInfo"]
