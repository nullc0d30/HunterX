# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .payload_sync import PayloadSyncManager
from .payload_metadata import PayloadMetadataEngine
from .payload_provenance import PayloadProvenance
from .utils import logger


@dataclass
class IndexedPayload:
    row_id: int = 0
    filename: str = ""
    file_path: str = ""
    category: str = ""
    payload_text: str = ""
    payload_hash: str = ""
    technology: List[str] = field(default_factory=list)
    language: List[str] = field(default_factory=list)
    framework: List[str] = field(default_factory=list)
    os_targets: List[str] = field(default_factory=list)
    file_type: str = ""
    tags: List[str] = field(default_factory=list)
    metadata_json: str = "{}"
    provenance_id: Optional[int] = None
    indexed_at: str = ""
    size_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.row_id,
            "filename": self.filename,
            "file_path": self.file_path,
            "category": self.category,
            "payload_text": self.payload_text[:200] if len(self.payload_text) > 200 else self.payload_text,
            "payload_hash": self.payload_hash,
            "technology": self.technology,
            "language": self.language,
            "framework": self.framework,
            "os_targets": self.os_targets,
            "file_type": self.file_type,
            "tags": self.tags,
            "indexed_at": self.indexed_at,
            "size_bytes": self.size_bytes,
        }


class PayloadIndexer:
    FTS_TABLE = "payload_fts"

    def __init__(
        self,
        sync_manager: Optional[PayloadSyncManager] = None,
        metadata_engine: Optional[PayloadMetadataEngine] = None,
        provenance: Optional[PayloadProvenance] = None,
        db_path: Optional[str] = None,
    ):
        self.sync_manager = sync_manager or PayloadSyncManager()
        self.metadata_engine = metadata_engine or PayloadMetadataEngine()
        self.provenance = provenance or PayloadProvenance()
        self._db_path = db_path or os.path.join(
            os.path.dirname(__file__), "..", "data", "payload_index.db"
        )
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=OFF")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                category TEXT NOT NULL,
                payload_text TEXT NOT NULL,
                payload_hash TEXT UNIQUE NOT NULL,
                technology TEXT DEFAULT '[]',
                language TEXT DEFAULT '[]',
                framework TEXT DEFAULT '[]',
                os_targets TEXT DEFAULT '[]',
                file_type TEXT DEFAULT '',
                tags TEXT DEFAULT '[]',
                metadata_json TEXT DEFAULT '{}',
                provenance_id INTEGER,
                indexed_at TEXT DEFAULT (datetime('now')),
                size_bytes INTEGER DEFAULT 0
            )
        """)
        self._conn.execute(f"""
            CREATE VIRTUAL TABLE IF NOT EXISTS {self.FTS_TABLE} USING fts5(
                filename, category, payload_text, tags, technology, framework, language,
                content='payloads',
                content_rowid='id',
                tokenize='porter unicode61'
            )
        """)
        self._conn.execute("""
            CREATE TRIGGER IF NOT EXISTS payloads_ai AFTER INSERT ON payloads BEGIN
                INSERT INTO payload_fts(rowid, filename, category, payload_text, tags, technology, framework, language)
                VALUES (new.id, new.filename, new.category, new.payload_text, new.tags, new.technology, new.framework, new.language);
            END;
        """)
        self._conn.execute("""
            CREATE TRIGGER IF NOT EXISTS payloads_ad AFTER DELETE ON payloads BEGIN
                INSERT INTO payload_fts(payload_fts, rowid, filename, category, payload_text, tags, technology, framework, language)
                VALUES ('delete', old.id, old.filename, old.category, old.payload_text, old.tags, old.technology, old.framework, old.language);
            END;
        """)
        self._conn.commit()

    def index_all(self, force: bool = False) -> Dict[str, Any]:
        if not os.path.exists(self.sync_manager.get_repo_path()):
            return {"status": "error", "message": "Repository not synced. Run 'hunterx payload update' first."}

        stats = {
            "total_found": 0,
            "indexed": 0,
            "skipped": 0,
            "errors": 0,
            "categories": {},
        }

        all_files = self.sync_manager.get_file_list()
        stats["total_found"] = len(all_files)

        if not force:
            self.provenance.sync_from_repo(self.sync_manager)

        for file_info in all_files:
            try:
                result = self._index_file(file_info, force)
                if result == "indexed":
                    stats["indexed"] += 1
                    cat = file_info.get("category", "unknown")
                    stats["categories"][cat] = stats["categories"].get(cat, 0) + 1
                elif result == "skipped":
                    stats["skipped"] += 1
                else:
                    stats["errors"] += 1
            except Exception as e:
                logger.debug(f"Indexer: error indexing {file_info.get('filename')}: {e}")
                stats["errors"] += 1

        self._conn.commit()
        logger.info(f"PayloadIndexer: indexed {stats['indexed']} payloads "
                     f"({stats['skipped']} skipped, {stats['errors']} errors)")
        return stats

    def index_categories(self, categories: List[str], force: bool = False) -> Dict[str, Any]:
        stats = {"indexed": 0, "skipped": 0, "errors": 0}
        for cat in categories:
            files = self.sync_manager.get_file_list(category=cat)
            for file_info in files:
                try:
                    result = self._index_file(file_info, force)
                    if result == "indexed":
                        stats["indexed"] += 1
                    elif result == "skipped":
                        stats["skipped"] += 1
                    else:
                        stats["errors"] += 1
                except Exception as e:
                    logger.debug(f"Indexer: error {e}")
                    stats["errors"] += 1
        self._conn.commit()
        return stats

    def _index_file(self, file_info: Dict[str, Any], force: bool = False) -> str:
        repo_path = self.sync_manager.get_repo_path()
        rel_path = file_info.get("path", "")
        fpath = os.path.join(repo_path, rel_path)

        if not os.path.exists(fpath):
            return "skipped"

        size = os.path.getsize(fpath)
        if size > 1024 * 1024:
            return "skipped"

        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return "error"

        payload_hash = hashlib.sha256(content.encode()).hexdigest()[:32]

        if not force:
            existing = self._conn.execute(
                "SELECT id FROM payloads WHERE payload_hash = ?", (payload_hash,)
            ).fetchone()
            if existing:
                return "skipped"

        # Extract individual payloads (one per line, skip comments/empty)
        lines = [line.strip() for line in content.split("\n")
                 if line.strip() and not line.strip().startswith("#") and not line.strip().startswith("//")]

        if not lines:
            return "skipped"

        metadata = self.metadata_engine.analyze(
            filename=file_info.get("filename", ""),
            content=content[:5000],
            category=file_info.get("category", ""),
            rel_path=rel_path,
        )

        provenance_id = self.provenance.record_file(
            file_info, payload_hash, self.sync_manager.repo_info,
        )

        payload_text = "\n".join(lines[:1000])

        try:
            self._conn.execute("""
                INSERT OR IGNORE INTO payloads
                (filename, file_path, category, payload_text, payload_hash,
                 technology, language, framework, os_targets, file_type,
                 tags, metadata_json, provenance_id, size_bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                file_info.get("filename", ""),
                rel_path,
                file_info.get("category", ""),
                payload_text,
                payload_hash,
                json.dumps(metadata.get("technology", [])),
                json.dumps(metadata.get("language", [])),
                json.dumps(metadata.get("framework", [])),
                json.dumps(metadata.get("os_targets", [])),
                metadata.get("file_type", ""),
                json.dumps(metadata.get("tags", [])),
                json.dumps(metadata),
                provenance_id,
                size,
            ))
            return "indexed"
        except Exception as e:
            logger.debug(f"Indexer: insert failed: {e}")
            return "error"

    def search(
        self,
        query: str,
        limit: int = 20,
        offset: int = 0,
        category_filter: Optional[str] = None,
    ) -> List[IndexedPayload]:
        if not query.strip():
            return self._get_recent(limit, offset, category_filter)

        fts_query = self._build_fts_query(query)
        params: List[Any] = [fts_query]

        sql = """
            SELECT p.id, p.filename, p.file_path, p.category, p.payload_text,
                   p.payload_hash, p.technology, p.language, p.framework,
                   p.os_targets, p.file_type, p.tags, p.metadata_json,
                   p.indexed_at, p.size_bytes,
                   rank
            FROM payload_fts
            JOIN payloads p ON payload_fts.rowid = p.id
            WHERE payload_fts MATCH ?
        """
        if category_filter:
            sql += " AND p.category = ?"
            params.append(category_filter)

        sql += " ORDER BY rank LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        try:
            rows = self._conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError as e:
            logger.debug(f"FTS search failed ({e}), falling back to LIKE search")
            return self._like_search(query, limit, offset, category_filter)

        results = []
        for row in rows:
            results.append(self._row_to_payload(row))

        return results

    def _build_fts_query(self, query: str) -> str:
        terms = re.findall(r'\w+|"[^"]+"', query)
        fts_parts = []
        for term in terms:
            clean = term.strip('"').strip()
            if clean:
                fts_parts.append(f'"{clean}"')
        return " OR ".join(fts_parts) if fts_parts else query

    def _like_search(
        self, query: str, limit: int = 20, offset: int = 0,
        category_filter: Optional[str] = None,
    ) -> List[IndexedPayload]:
        params: List[Any] = [f"%{query}%", f"%{query}%"]
        sql = """
            SELECT id, filename, file_path, category, payload_text,
                   payload_hash, technology, language, framework,
                   os_targets, file_type, tags, metadata_json,
                   indexed_at, size_bytes, 0.0 as rank
            FROM payloads
            WHERE (filename LIKE ? OR payload_text LIKE ?)
        """
        if category_filter:
            sql += " AND category = ?"
            params.append(category_filter)

        sql += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_payload(row) for row in rows]

    def _get_recent(
        self, limit: int = 20, offset: int = 0,
        category_filter: Optional[str] = None,
    ) -> List[IndexedPayload]:
        params: List[Any] = []
        sql = """
            SELECT id, filename, file_path, category, payload_text,
                   payload_hash, technology, language, framework,
                   os_targets, file_type, tags, metadata_json,
                   indexed_at, size_bytes, 0.0 as rank
            FROM payloads
        """
        if category_filter:
            sql += " WHERE category = ?"
            params.append(category_filter)
        sql += " ORDER BY indexed_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_payload(row) for row in rows]

    def _row_to_payload(self, row) -> IndexedPayload:
        return IndexedPayload(
            row_id=row[0],
            filename=row[1],
            file_path=row[2],
            category=row[3],
            payload_text=row[4],
            payload_hash=row[5],
            technology=json.loads(row[6]) if isinstance(row[6], str) else (row[6] or []),
            language=json.loads(row[7]) if isinstance(row[7], str) else (row[7] or []),
            framework=json.loads(row[8]) if isinstance(row[8], str) else (row[8] or []),
            os_targets=json.loads(row[9]) if isinstance(row[9], str) else (row[9] or []),
            file_type=row[10] or "",
            tags=json.loads(row[11]) if isinstance(row[11], str) else (row[11] or []),
            metadata_json=row[12] if isinstance(row[12], str) else "{}",
            indexed_at=row[13] or "",
            size_bytes=row[14] or 0,
        )

    def get_categories(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute("""
            SELECT category, COUNT(*) as count, MAX(indexed_at) as last_indexed
            FROM payloads GROUP BY category ORDER BY count DESC
        """).fetchall()
        return [
            {"category": r[0], "count": r[1], "last_indexed": r[2]} for r in rows
        ]

    def get_stats(self) -> Dict[str, Any]:
        total = self._conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
        categories = self._conn.execute(
            "SELECT COUNT(DISTINCT category) FROM payloads"
        ).fetchone()[0]
        return {
            "total_payloads": total,
            "categories": categories,
            "db_path": self._db_path,
            "repo_synced": os.path.exists(self.sync_manager.get_repo_path()),
        }

    def get_by_id(self, payload_id: int) -> Optional[IndexedPayload]:
        row = self._conn.execute(
            "SELECT id, filename, file_path, category, payload_text, payload_hash, "
            "technology, language, framework, os_targets, file_type, tags, metadata_json, "
            "indexed_at, size_bytes, 0.0 FROM payloads WHERE id = ?",
            (payload_id,),
        ).fetchone()
        if row:
            return self._row_to_payload(row)
        return None

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def __del__(self):
        self.close()
