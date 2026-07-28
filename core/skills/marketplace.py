from __future__ import annotations

import json
import os
import shutil
import threading
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..utils import logger


class SkillMarketplace:
    def __init__(self, storage_path: str = ""):
        self._lock = threading.RLock()
        self._storage_path = storage_path or os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "skills_marketplace"
        )
        self._packages: Dict[str, Dict[str, Any]] = {}
        os.makedirs(self._storage_path, exist_ok=True)
        self._load_index()

    def install(self, package_path: str) -> Optional[str]:
        if not os.path.exists(package_path):
            logger.error(f"Package not found: {package_path}")
            return None

        if package_path.endswith(".zip"):
            return self._install_zip(package_path)

        if os.path.isdir(package_path):
            return self._install_dir(package_path)

        return None

    def uninstall(self, skill_id: str) -> bool:
        with self._lock:
            if skill_id not in self._packages:
                return False
            pkg = self._packages[skill_id]
            install_path = pkg.get("install_path", "")
            if install_path and os.path.exists(install_path):
                shutil.rmtree(install_path, ignore_errors=True)
            del self._packages[skill_id]
            self._save_index()
            logger.info(f"Marketplace: uninstalled {skill_id}")
            return True

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "skill_id": sid,
                    "name": pkg.get("name", ""),
                    "version": pkg.get("version", ""),
                    "author": pkg.get("author", ""),
                    "installed_at": pkg.get("installed_at", ""),
                    "enabled": pkg.get("enabled", True),
                }
                for sid, pkg in self._packages.items()
            ]

    def get(self, skill_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._packages.get(skill_id)

    def enable(self, skill_id: str) -> bool:
        with self._lock:
            if skill_id in self._packages:
                self._packages[skill_id]["enabled"] = True
                self._save_index()
                return True
            return False

    def disable(self, skill_id: str) -> bool:
        with self._lock:
            if skill_id in self._packages:
                self._packages[skill_id]["enabled"] = False
                self._save_index()
                return True
            return False

    def verify(self, skill_id: str) -> Dict[str, Any]:
        pkg = self.get(skill_id)
        if not pkg:
            return {"exists": False, "verified": False, "error": "Package not found"}

        install_path = pkg.get("install_path", "")
        manifest_path = os.path.join(install_path, "skill.json")
        exists = os.path.exists(manifest_path)

        return {
            "exists": exists,
            "verified": exists,
            "install_path": install_path,
            "manifest_exists": exists,
        }

    def export_package(self, skill_id: str, output_path: str) -> bool:
        pkg = self.get(skill_id)
        if not pkg:
            return False
        install_path = pkg.get("install_path", "")
        if not install_path or not os.path.exists(install_path):
            return False

        zip_path = output_path if output_path.endswith(".zip") else f"{output_path}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(install_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(install_path))
                    zf.write(file_path, arcname)
        return True

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            enabled = sum(1 for p in self._packages.values() if p.get("enabled", False))
            return {
                "total_packages": len(self._packages),
                "enabled": enabled,
                "disabled": len(self._packages) - enabled,
                "storage_path": self._storage_path,
            }

    def _install_zip(self, zip_path: str) -> Optional[str]:
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                manifest_data = None
                for name in zf.namelist():
                    if name.endswith("skill.json"):
                        manifest_data = json.loads(zf.read(name))
                        break
                if not manifest_data:
                    logger.error("No skill.json found in package")
                    return None

                skill_id = manifest_data.get("skill_id", "")
                if not skill_id:
                    logger.error("skill_id missing from manifest")
                    return None

                install_dir = os.path.join(self._storage_path, skill_id)
                os.makedirs(install_dir, exist_ok=True)
                zf.extractall(install_dir)

                with self._lock:
                    self._packages[skill_id] = {
                        "name": manifest_data.get("name", ""),
                        "version": manifest_data.get("version", ""),
                        "author": manifest_data.get("author", ""),
                        "installed_at": datetime.utcnow().isoformat(),
                        "install_path": install_dir,
                        "enabled": True,
                    }
                    self._save_index()

                logger.info(f"Marketplace: installed {skill_id} from {zip_path}")
                return skill_id
        except Exception as e:
            logger.error(f"Failed to install zip package: {e}")
            return None

    def _install_dir(self, dir_path: str) -> Optional[str]:
        manifest_path = os.path.join(dir_path, "skill.json")
        if not os.path.exists(manifest_path):
            logger.error("No skill.json found in directory")
            return None

        try:
            with open(manifest_path) as f:
                manifest_data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to read manifest: {e}")
            return None

        skill_id = manifest_data.get("skill_id", "")
        if not skill_id:
            logger.error("skill_id missing from manifest")
            return None

        install_dir = os.path.join(self._storage_path, skill_id)
        if os.path.exists(install_dir):
            shutil.rmtree(install_dir)
        shutil.copytree(dir_path, install_dir)

        with self._lock:
            self._packages[skill_id] = {
                "name": manifest_data.get("name", ""),
                "version": manifest_data.get("version", ""),
                "author": manifest_data.get("author", ""),
                "installed_at": datetime.utcnow().isoformat(),
                "install_path": install_dir,
                "enabled": True,
            }
            self._save_index()

        logger.info(f"Marketplace: installed {skill_id} from {dir_path}")
        return skill_id

    def _load_index(self) -> None:
        index_path = os.path.join(self._storage_path, "index.json")
        if os.path.exists(index_path):
            try:
                with open(index_path) as f:
                    self._packages = json.load(f)
            except Exception:
                self._packages = {}

    def _save_index(self) -> None:
        index_path = os.path.join(self._storage_path, "index.json")
        try:
            with open(index_path, "w") as f:
                json.dump(self._packages, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save marketplace index: {e}")
