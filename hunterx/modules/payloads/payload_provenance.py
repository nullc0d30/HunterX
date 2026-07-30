# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ...utils.utils import logger


@dataclass
class ProvenanceRecord:
    id: int = 0
    file_path: str = ""
    filename: str = ""
    category: str = ""
    payload_hash: str = ""
    commit_hash: str = ""
    commit_date: Optional[str] = None
    repo_url: str = ""
    repo_name: str = ""
    release_tag: str = ""
    checksum: str = ""
    size_bytes: int = 0
    indexed_at: str = ""
    source: str = "PayloadsAllTheThings"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "file_path": self.file_path,
            "filename": self.filename,
            "category": self.category,
            "payload_hash": self.payload_hash,
            "commit_hash": self.commit_hash,
            "commit_date": self.commit_date,
            "repo_url": self.repo_url,
            "repo_name": self.repo_name,
            "release_tag": self.release_tag,
            "checksum": self.checksum,
            "size_bytes": self.size_bytes,
            "indexed_at": self.indexed_at,
            "source": self.source,
        }


class PayloadProvenance:
    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or os.path.join(
            os.path.dirname(__file__), "..", "data", "payload_provenance.db"
        )
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS provenance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                filename TEXT NOT NULL,
                category TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                commit_hash TEXT DEFAULT '',
                commit_date TEXT DEFAULT '',
                repo_url TEXT DEFAULT '',
                repo_name TEXT DEFAULT '',
                release_tag TEXT DEFAULT '',
                checksum TEXT DEFAULT '',
                size_bytes INTEGER DEFAULT 0,
                indexed_at TEXT DEFAULT (datetime('now')),
                source TEXT DEFAULT 'PayloadsAllTheThings'
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_prov_hash
            ON provenance(payload_hash)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_prov_path
            ON provenance(file_path)
        """)
        self._conn.commit()

    def record_file(
        self,
        file_info: Dict[str, Any],
        payload_hash: str,
        repo_info: Any,
    ) -> Optional[int]:
        with self._lock:
            rel_path = file_info.get("path", "")
            existing = self._conn.execute(
                "SELECT id FROM provenance WHERE file_path = ? AND payload_hash = ?",
                (rel_path, payload_hash),
            ).fetchone()
            if existing:
                return existing[0]

            fpath = os.path.join(
                os.path.dirname(self._db_path), "..", "data", "payloads", "repo", rel_path
            )
            checksum = ""
            size = file_info.get("size", 0)
            if os.path.exists(fpath):
                try:
                    with open(fpath, "rb") as f:
                        checksum = hashlib.sha256(f.read(65536)).hexdigest()[:64]
                    size = os.path.getsize(fpath)
                except Exception:
                    pass

            commit_hash = getattr(repo_info, "commit_hash", "")
            commit_date = ""
            if getattr(repo_info, "commit_date", None):
                try:
                    commit_date = repo_info.commit_date.isoformat()
                except Exception:
                    commit_date = str(repo_info.commit_date)
            release_tag = getattr(repo_info, "release_tag", "")
            repo_url = getattr(repo_info, "url", "")
            repo_name = getattr(repo_info, "name", "PayloadsAllTheThings")

            try:
                cursor = self._conn.execute("""
                    INSERT INTO provenance
                    (file_path, filename, category, payload_hash, commit_hash,
                     commit_date, repo_url, repo_name, release_tag, checksum, size_bytes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rel_path,
                    file_info.get("filename", ""),
                    file_info.get("category", ""),
                    payload_hash,
                    commit_hash,
                    commit_date,
                    repo_url,
                    repo_name,
                    release_tag,
                    checksum,
                    size,
                ))
                self._conn.commit()
                return cursor.lastrowid
            except Exception as e:
                logger.debug(f"Provenance: record failed: {e}")
                return None

    def sync_from_repo(self, sync_manager: Any) -> int:
        with self._lock:
            repo_info = getattr(sync_manager, "repo_info", None)
            if not repo_info:
                return 0
            commit_hash = getattr(repo_info, "commit_hash", "")
            if not commit_hash:
                return 0

            updated = self._conn.execute(
                "UPDATE provenance SET commit_hash = ?, commit_date = ? WHERE commit_hash = ''",
                (commit_hash, getattr(repo_info, "commit_date", None)),
            ).rowcount
            self._conn.commit()
            return updated

    def get_by_hash(self, payload_hash: str) -> Optional[ProvenanceRecord]:
        row = self._conn.execute(
            "SELECT id, file_path, filename, category, payload_hash, commit_hash, "
            "commit_date, repo_url, repo_name, release_tag, checksum, size_bytes, "
            "indexed_at, source FROM provenance WHERE payload_hash = ?",
            (payload_hash,),
        ).fetchone()
        if row:
            return self._row_to_record(row)
        return None

    def get_by_file_path(self, file_path: str) -> List[ProvenanceRecord]:
        rows = self._conn.execute(
            "SELECT id, file_path, filename, category, payload_hash, commit_hash, "
            "commit_date, repo_url, repo_name, release_tag, checksum, size_bytes, "
            "indexed_at, source FROM provenance WHERE file_path = ?",
            (file_path,),
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def search(
        self,
        query: str,
        limit: int = 20,
        offset: int = 0,
    ) -> List[ProvenanceRecord]:
        like = f"%{query}%"
        rows = self._conn.execute(
            "SELECT id, file_path, filename, category, payload_hash, commit_hash, "
            "commit_date, repo_url, repo_name, release_tag, checksum, size_bytes, "
            "indexed_at, source FROM provenance WHERE file_path LIKE ? OR filename LIKE ? "
            "OR category LIKE ? OR payload_hash LIKE ? "
            "LIMIT ? OFFSET ?",
            (like, like, like, like, limit, offset),
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        total = self._conn.execute("SELECT COUNT(*) FROM provenance").fetchone()[0]
        with_commit = self._conn.execute(
            "SELECT COUNT(*) FROM provenance WHERE commit_hash != ''"
        ).fetchone()[0]
        with_checksum = self._conn.execute(
            "SELECT COUNT(*) FROM provenance WHERE checksum != ''"
        ).fetchone()[0]
        return {
            "total_records": total,
            "with_commit_hash": with_commit,
            "with_checksum": with_checksum,
            "db_path": self._db_path,
        }

    def verify_integrity(self, payload_hash: str, file_path: str) -> bool:
        record = self.get_by_hash(payload_hash)
        if not record or not record.checksum:
            return False
        fpath = os.path.join(
            os.path.dirname(self._db_path), "..", "data", "payloads", "repo", file_path
        )
        if not os.path.exists(fpath):
            return False
        try:
            with open(fpath, "rb") as f:
                current = hashlib.sha256(f.read(65536)).hexdigest()[:64]
            return current == record.checksum
        except Exception:
            return False

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def _row_to_record(self, row) -> ProvenanceRecord:
        return ProvenanceRecord(
            id=row[0],
            file_path=row[1],
            filename=row[2],
            category=row[3],
            payload_hash=row[4],
            commit_hash=row[5] or "",
            commit_date=row[6] or "",
            repo_url=row[7] or "",
            repo_name=row[8] or "",
            release_tag=row[9] or "",
            checksum=row[10] or "",
            size_bytes=row[11] or 0,
            indexed_at=row[12] or "",
            source=row[13] or "PayloadsAllTheThings",
        )

    def __del__(self):
        self.close()
