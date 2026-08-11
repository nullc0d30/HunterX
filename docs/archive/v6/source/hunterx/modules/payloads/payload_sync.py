# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from ...utils.utils import logger


class SyncStatus(str, Enum):
    NOT_SYNCED = "not_synced"
    SYNCING = "syncing"
    SYNCED = "synced"
    ERROR = "error"
    OUTDATED = "outdated"


@dataclass
class RepositoryInfo:
    name: str = "PayloadsAllTheThings"
    url: str = "https://github.com/swisskyrepo/PayloadsAllTheThings"
    commit_hash: str = ""
    commit_date: Optional[datetime] = None
    version: str = ""
    release_tag: str = ""
    sync_time: Optional[datetime] = None
    checksum: str = ""
    status: SyncStatus = SyncStatus.NOT_SYNCED
    file_count: int = 0
    total_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "commit_hash": self.commit_hash,
            "commit_date": self.commit_date.isoformat() if self.commit_date else None,
            "version": self.version,
            "release_tag": self.release_tag,
            "sync_time": self.sync_time.isoformat() if self.sync_time else None,
            "checksum": self.checksum,
            "status": self.status.value,
            "file_count": self.file_count,
            "total_size": self.total_size,
        }


class PayloadSyncManager:
    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = cache_dir or os.path.join(
            os.path.dirname(__file__), "..", "data", "payloads"
        )
        self._repo_dir = os.path.join(self.cache_dir, "repo")
        self._meta_path = os.path.join(self.cache_dir, "sync_meta.json")
        self._lock_path = os.path.join(self.cache_dir, ".sync_lock")
        os.makedirs(self.cache_dir, exist_ok=True)

        self.repo_info = self._load_meta()

    def _load_meta(self) -> RepositoryInfo:
        if os.path.exists(self._meta_path):
            try:
                with open(self._meta_path) as f:
                    data = json.load(f)
                return RepositoryInfo(**data)
            except Exception as e:
                logger.debug(f"PayloadSync: failed to load meta: {e}")
        return RepositoryInfo()

    def _save_meta(self) -> None:
        try:
            with open(self._meta_path, "w") as f:
                json.dump(self.repo_info.to_dict(), f, indent=2)
        except Exception as e:
            logger.warning(f"PayloadSync: failed to save meta: {e}")

    def clone(self, target_dir: Optional[str] = None) -> bool:
        repo_dir = target_dir or self._repo_dir
        if os.path.exists(repo_dir):
            logger.info(f"PayloadSync: repository already exists at {repo_dir}")
            return True

        logger.info(f"PayloadSync: cloning {self.repo_info.url} to {repo_dir}")
        self.repo_info.status = SyncStatus.SYNCING
        self._save_meta()

        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", self.repo_info.url, repo_dir],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                logger.error(f"PayloadSync: clone failed: {result.stderr}")
                self.repo_info.status = SyncStatus.ERROR
                self._save_meta()
                return False

            self._update_repo_info(repo_dir)
            self._verify_integrity(repo_dir)
            self.repo_info.status = SyncStatus.SYNCED
            self._save_meta()
            logger.info(f"PayloadSync: cloned successfully ({self.repo_info.file_count} files)")
            return True

        except FileNotFoundError:
            logger.warning("PayloadSync: git not found. Use release download instead.")
            return self.download_release(repo_dir)
        except subprocess.TimeoutExpired:
            logger.error("PayloadSync: clone timed out. Use --depth 1 or download release.")
            self.repo_info.status = SyncStatus.ERROR
            self._save_meta()
            return False

    def pull(self) -> bool:
        if not os.path.exists(os.path.join(self._repo_dir, ".git")):
            logger.info("PayloadSync: no git repository to pull. Cloning instead.")
            return self.clone()

        logger.info("PayloadSync: pulling latest changes...")
        try:
            result = subprocess.run(
                ["git", "-C", self._repo_dir, "pull", "--ff-only"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                logger.warning(f"PayloadSync: pull failed: {result.stderr}")
                return False

            self._update_repo_info(self._repo_dir)
            self.repo_info.status = SyncStatus.SYNCED
            self._save_meta()
            logger.info(f"PayloadSync: pull complete ({self.repo_info.file_count} files)")
            return True
        except Exception as e:
            logger.warning(f"PayloadSync: pull failed ({e}), trying clone...")
            return self.clone()

    def download_release(self, target_dir: Optional[str] = None) -> bool:
        repo_dir = target_dir or self._repo_dir
        logger.info("PayloadSync: downloading release archive...")
        self.repo_info.status = SyncStatus.SYNCING
        self._save_meta()

        import urllib.request
        release_url = "https://api.github.com/repos/swisskyrepo/PayloadsAllTheThings/releases/latest"

        try:
            with urllib.request.urlopen(release_url, timeout=30) as resp:
                release_data = json.loads(resp.read().decode())

            zip_url = release_data["zipball_url"]
            tag = release_data.get("tag_name", "latest")
            self.repo_info.release_tag = tag

            zip_path = os.path.join(tempfile.gettempdir(), "hunterx_payloads.zip")
            urllib.request.urlretrieve(zip_url, zip_path)

            if os.path.exists(repo_dir):
                shutil.rmtree(repo_dir)

            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(self.cache_dir)

            extracted = [d for d in os.listdir(self.cache_dir)
                         if os.path.isdir(os.path.join(self.cache_dir, d))
                         and d.startswith("swisskyrepo-PayloadsAllTheThings")]
            if extracted:
                extracted_dir = os.path.join(self.cache_dir, extracted[0])
                if os.path.exists(repo_dir):
                    shutil.rmtree(repo_dir)
                shutil.move(extracted_dir, repo_dir)

            os.unlink(zip_path)
            self._update_repo_info(repo_dir)
            self._verify_integrity(repo_dir)
            self.repo_info.status = SyncStatus.SYNCED
            self._save_meta()
            logger.info(f"PayloadSync: release {tag} downloaded ({self.repo_info.file_count} files)")
            return True

        except Exception as e:
            logger.error(f"PayloadSync: release download failed: {e}")
            self.repo_info.status = SyncStatus.ERROR
            self._save_meta()
            return False

    def sync(self) -> bool:
        if os.path.exists(self._repo_dir):
            return self.pull()
        return self.clone()

    def status(self) -> Dict[str, Any]:
        info = self.repo_info.to_dict()
        info["repo_exists"] = os.path.exists(self._repo_dir)
        info["cache_dir"] = self.cache_dir
        info["repo_dir"] = self._repo_dir
        if info["repo_exists"]:
            info["total_size_mb"] = round(self._get_dir_size(self._repo_dir) / (1024 * 1024), 2)
        return info

    def rollback(self, version: Optional[str] = None) -> bool:
        if not os.path.exists(os.path.join(self._repo_dir, ".git")):
            logger.error("PayloadSync: rollback requires git repository")
            return False

        try:
            if version:
                subprocess.run(
                    ["git", "-C", self._repo_dir, "checkout", version],
                    capture_output=True, text=True, timeout=60,
                )
            else:
                result = subprocess.run(
                    ["git", "-C", self._repo_dir, "log", "--oneline", "-2", "--skip=1"],
                    capture_output=True, text=True, timeout=30,
                )
                prev = result.stdout.strip().split("\n")[0].split()[0] if result.stdout.strip() else ""
                if prev:
                    subprocess.run(
                        ["git", "-C", self._repo_dir, "checkout", prev],
                        capture_output=True, text=True, timeout=60,
                    )

            self._update_repo_info(self._repo_dir)
            self._save_meta()
            logger.info(f"PayloadSync: rollback to {version or 'previous commit'} complete")
            return True
        except Exception as e:
            logger.error(f"PayloadSync: rollback failed: {e}")
            return False

    def verify_integrity(self) -> Dict[str, Any]:
        if not os.path.exists(self._repo_dir):
            return {"status": "not_found", "errors": ["Repository not found"]}
        return self._verify_integrity(self._repo_dir)

    def _verify_integrity(self, repo_dir: str, sample_pct: float = 0.1) -> Dict[str, Any]:
        errors: List[str] = []
        total_files = 0
        checked_files = 0
        verified = 0

        for root, _, files in os.walk(repo_dir):
            for fname in files:
                if fname.startswith("."):
                    continue
                total_files += 1

        sample_count = max(10, int(total_files * sample_pct))
        sample_idx = 0

        for root, _, files in os.walk(repo_dir):
            for fname in files:
                if fname.startswith("."):
                    continue
                if sample_idx >= sample_count:
                    break
                sample_idx += 1
                checked_files += 1
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    if len(data) > 0:
                        verified += 1
                except Exception as e:
                    errors.append(f"Corrupt file: {fpath}: {e}")

        self.repo_info.checksum = self._compute_root_checksum(repo_dir)
        self.repo_info.file_count = total_files
        self._save_meta()

        return {
            "status": "ok" if not errors else "corrupt",
            "total_files": total_files,
            "checked_files": checked_files,
            "verified": verified,
            "errors": errors,
            "checksum": self.repo_info.checksum,
        }

    def _compute_root_checksum(self, repo_dir: str) -> str:
        hasher = hashlib.sha256()
        top_files = sorted(os.listdir(repo_dir))[:100]
        for fname in top_files:
            fpath = os.path.join(repo_dir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "rb") as f:
                        hasher.update(f.read(8192))
                except Exception:
                    pass
        return hasher.hexdigest()[:32]

    def _update_repo_info(self, repo_dir: str) -> None:
        try:
            self.repo_info.file_count = sum(
                1 for root, _, files in os.walk(repo_dir) for f in files if not f.startswith(".")
            )
            self.repo_info.total_size = self._get_dir_size(repo_dir)
            self.repo_info.sync_time = datetime.utcnow()

            if os.path.exists(os.path.join(repo_dir, ".git")):
                result = subprocess.run(
                    ["git", "-C", repo_dir, "rev-parse", "HEAD"],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    self.repo_info.commit_hash = result.stdout.strip()

                result = subprocess.run(
                    ["git", "-C", repo_dir, "log", "-1", "--format=%ci"],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        self.repo_info.commit_date = datetime.strptime(
                            result.stdout.strip(), "%Y-%m-%d %H:%M:%S %z"
                        )
                    except Exception:
                        pass

                result = subprocess.run(
                    ["git", "-C", repo_dir, "describe", "--tags", "--always"],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    self.repo_info.version = result.stdout.strip()
        except Exception as e:
            logger.debug(f"PayloadSync: update repo info failed: {e}")

    def get_repo_path(self) -> str:
        return self._repo_dir

    def list_categories(self) -> List[str]:
        if not os.path.exists(self._repo_dir):
            return []
        categories = []
        for entry in sorted(os.listdir(self._repo_dir)):
            full = os.path.join(self._repo_dir, entry)
            if os.path.isdir(full) and not entry.startswith("."):
                categories.append(entry)
        return categories

    def get_file_list(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        if not os.path.exists(self._repo_dir):
            return []
        files = []
        search_root = os.path.join(self._repo_dir, category) if category else self._repo_dir
        if not os.path.exists(search_root):
            return []

        for root, _, filenames in os.walk(search_root):
            for fname in filenames:
                if fname.startswith("."):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self._repo_dir)
                files.append({
                    "path": rel_path,
                    "filename": fname,
                    "size": os.path.getsize(fpath),
                    "category": category or os.path.basename(os.path.dirname(fpath)),
                })
        return files

    @staticmethod
    def _get_dir_size(path: str) -> int:
        total = 0
        for root, _, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except Exception:
                    pass
        return total
