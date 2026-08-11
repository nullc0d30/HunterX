# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .payload_index import IndexedPayload, PayloadIndexer
from ...utils.utils import logger


@dataclass
class PayloadGraphNode:
    id: int = 0
    node_type: str = ""
    label: str = ""
    description: str = ""
    external_id: str = ""
    source: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.node_type,
            "label": self.label,
            "description": self.description,
            "external_id": self.external_id,
            "source": self.source,
            "properties": self.properties,
        }


@dataclass
class PayloadGraphEdge:
    id: int = 0
    source_id: int = 0
    target_id: int = 0
    relationship: str = ""
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship": self.relationship,
            "weight": self.weight,
            "properties": self.properties,
        }


NODE_TYPES = {
    "TECHNOLOGY", "FRAMEWORK", "LANGUAGE", "OS", "CWE", "CVE",
    "CAPEC", "MITRE_TECHNIQUE", "OWASP_CATEGORY", "NIST_CONTROL",
    "PAYLOAD", "CATEGORY",
}

RELATIONSHIP_TYPES = {
    "TARGETS", "RELATES_TO", "EXPLOITS", "MITIGATES", "INDICATES",
    "DEPENDS_ON", "BELONGS_TO", "ASSOCIATED_WITH",
}


class PayloadKnowledgeGraph:
    def __init__(
        self,
        indexer: Optional[PayloadIndexer] = None,
        db_path: Optional[str] = None,
    ):
        self.indexer = indexer or PayloadIndexer()
        self._db_path = db_path or os.path.join(
            os.path.dirname(__file__), "..", "data", "payload_graph.db"
        )
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS graph_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_type TEXT NOT NULL,
                label TEXT NOT NULL,
                description TEXT DEFAULT '',
                external_id TEXT DEFAULT '',
                source TEXT DEFAULT 'hunterx',
                properties TEXT DEFAULT '{}'
            )
        """)
        self._conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_node_type_label
            ON graph_nodes(node_type, label)
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS graph_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER NOT NULL,
                target_id INTEGER NOT NULL,
                relationship TEXT NOT NULL,
                weight REAL DEFAULT 1.0,
                properties TEXT DEFAULT '{}',
                FOREIGN KEY (source_id) REFERENCES graph_nodes(id),
                FOREIGN KEY (target_id) REFERENCES graph_nodes(id)
            )
        """)
        self._conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_edge
            ON graph_edges(source_id, target_id, relationship)
        """)
        self._conn.commit()

    def ensure_node(
        self,
        node_type: str,
        label: str,
        description: str = "",
        external_id: str = "",
        source: str = "hunterx",
        properties: Optional[Dict[str, Any]] = None,
    ) -> int:
        with self._lock:
            node_type = node_type.upper()
            existing = self._conn.execute(
                "SELECT id FROM graph_nodes WHERE node_type = ? AND label = ?",
                (node_type, label),
            ).fetchone()
            if existing:
                return existing[0]

            cursor = self._conn.execute("""
                INSERT OR IGNORE INTO graph_nodes
                (node_type, label, description, external_id, source, properties)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                node_type,
                label,
                description,
                external_id,
                source,
                json.dumps(properties or {}),
            ))
            self._conn.commit()
            return cursor.lastrowid

    def ensure_edge(
        self,
        source_id: int,
        target_id: int,
        relationship: str,
        weight: float = 1.0,
        properties: Optional[Dict[str, Any]] = None,
    ) -> int:
        with self._lock:
            relationship = relationship.upper()
            existing = self._conn.execute(
                "SELECT id FROM graph_edges WHERE source_id = ? AND target_id = ? AND relationship = ?",
                (source_id, target_id, relationship),
            ).fetchone()
            if existing:
                self._conn.execute(
                    "UPDATE graph_edges SET weight = weight + ? WHERE id = ?",
                    (weight * 0.1, existing[0]),
                )
                self._conn.commit()
                return existing[0]

            cursor = self._conn.execute("""
                INSERT OR IGNORE INTO graph_edges
                (source_id, target_id, relationship, weight, properties)
                VALUES (?, ?, ?, ?, ?)
            """, (
                source_id,
                target_id,
                relationship,
                weight,
                json.dumps(properties or {}),
            ))
            self._conn.commit()
            return cursor.lastrowid

    def link_payload(
        self,
        payload: IndexedPayload,
    ) -> int:
        with self._lock:
            cat_id = self.ensure_node(
                node_type="CATEGORY",
                label=payload.category,
                description=f"Payload category: {payload.category}",
            )

            payload_node_id = self._get_or_create_payload_node(payload)
            self.ensure_edge(cat_id, payload_node_id, "BELONGS_TO")

            for tech in (payload.technology or []):
                tech_id = self.ensure_node(
                    node_type="TECHNOLOGY",
                    label=tech,
                    description=f"Technology: {tech}",
                )
                self.ensure_edge(tech_id, payload_node_id, "TARGETS", weight=0.8)

            for fw in (payload.framework or []):
                fw_id = self.ensure_node(
                    node_type="FRAMEWORK",
                    label=fw,
                    description=f"Framework: {fw}",
                )
                self.ensure_edge(fw_id, payload_node_id, "TARGETS", weight=0.7)

            for lang in (payload.language or []):
                lang_id = self.ensure_node(
                    node_type="LANGUAGE",
                    label=lang,
                    description=f"Language: {lang}",
                )
                self.ensure_edge(lang_id, payload_node_id, "TARGETS", weight=0.6)

            for os_target in (payload.os_targets or []):
                os_id = self.ensure_node(
                    node_type="OS",
                    label=os_target,
                    description=f"OS: {os_target}",
                )
                self.ensure_edge(os_id, payload_node_id, "TARGETS", weight=0.5)

            metadata = {}
            try:
                metadata = json.loads(payload.metadata_json) if payload.metadata_json else {}
            except Exception:
                pass

            for cwe in (metadata.get("related_cwes", []) or []):
                cwe_id = self.ensure_node(
                    node_type="CWE",
                    label=cwe,
                    description=f"Common Weakness Enumeration: {cwe}",
                    external_id=cwe,
                    source="cwe.mitre.org",
                )
                self.ensure_edge(cwe_id, payload_node_id, "RELATES_TO")

            for cve in (metadata.get("related_cves", []) or []):
                cve_id = self.ensure_node(
                    node_type="CVE",
                    label=cve,
                    description=f"Common Vulnerability and Exposure: {cve}",
                    external_id=cve,
                    source="cve.mitre.org",
                )
                self.ensure_edge(cve_id, payload_node_id, "RELATES_TO")

            for capec in (metadata.get("capec_ids", []) or []):
                capec_id = self.ensure_node(
                    node_type="CAPEC",
                    label=capec,
                    description=f"Common Attack Pattern Enumeration: {capec}",
                    external_id=capec,
                    source="capec.mitre.org",
                )
                self.ensure_edge(capec_id, payload_node_id, "INDICATES")

            for mitre in (metadata.get("mitre_techniques", []) or []):
                mitre_id = self.ensure_node(
                    node_type="MITRE_TECHNIQUE",
                    label=mitre,
                    description=f"MITRE ATT&CK Technique: {mitre}",
                    external_id=mitre,
                    source="attack.mitre.org",
                )
                self.ensure_edge(mitre_id, payload_node_id, "INDICATES")

            for owasp in (metadata.get("owasp_categories", []) or []):
                owasp_id = self.ensure_node(
                    node_type="OWASP_CATEGORY",
                    label=owasp,
                    description=f"OWASP Top 10: {owasp}",
                    external_id=owasp,
                    source="owasp.org",
                )
                self.ensure_edge(owasp_id, payload_node_id, "RELATES_TO")

            return payload_node_id

    def _get_or_create_payload_node(
        self,
        payload: IndexedPayload,
    ) -> int:
        label = f"{payload.category}: {payload.payload_text[:80]}"
        existing = self._conn.execute(
            "SELECT id FROM graph_nodes WHERE node_type = 'PAYLOAD' AND label = ?",
            (label,),
        ).fetchone()
        if existing:
            return existing[0]

        cursor = self._conn.execute("""
            INSERT INTO graph_nodes
            (node_type, label, description, external_id, source, properties)
            VALUES ('PAYLOAD', ?, ?, ?, 'hunterx', ?)
        """, (
            label,
            payload.payload_text[:500],
            payload.payload_hash,
            json.dumps({
                "id": payload.row_id,
                "filename": payload.filename,
                "file_path": payload.file_path,
                "category": payload.category,
                "payload_hash": payload.payload_hash,
                "file_type": payload.file_type,
                "tags": payload.tags,
            }),
        ))
        self._conn.commit()
        return cursor.lastrowid

    def get_payloads_for_technology(
        self,
        technology: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        rows = self._conn.execute("""
            SELECT p.id, p.filename, p.file_path, p.category, p.payload_text,
                   p.payload_hash
            FROM payloads p
            JOIN graph_edges e ON e.target_id IN (
                SELECT id FROM graph_nodes WHERE node_type = 'PAYLOAD'
            )
            JOIN graph_nodes n ON n.id = e.source_id
            WHERE n.node_type = 'TECHNOLOGY' AND n.label = ?
            LIMIT ?
        """, (technology, limit)).fetchall()
        return [
            {
                "id": r[0], "filename": r[1], "file_path": r[2],
                "category": r[3], "payload_text": r[4][:200], "payload_hash": r[5],
            }
            for r in rows
        ]

    def get_payloads_for_cwe(
        self,
        cwe_id: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        rows = self._conn.execute("""
            SELECT p.id, p.filename, p.file_path, p.category, p.payload_text,
                   p.payload_hash
            FROM payloads p
            JOIN graph_edges e ON e.target_id IN (
                SELECT id FROM graph_nodes WHERE node_type = 'PAYLOAD'
            )
            JOIN graph_nodes n ON n.id = e.source_id
            WHERE n.node_type = 'CWE' AND n.label = ?
            LIMIT ?
        """, (cwe_id, limit)).fetchall()
        return [
            {
                "id": r[0], "filename": r[1], "file_path": r[2],
                "category": r[3], "payload_text": r[4][:200], "payload_hash": r[5],
            }
            for r in rows
        ]

    def get_related_nodes(
        self,
        node_type: str,
        label: str,
        max_depth: int = 2,
    ) -> List[Dict[str, Any]]:
        node = self._conn.execute(
            "SELECT id FROM graph_nodes WHERE node_type = ? AND label = ?",
            (node_type.upper(), label),
        ).fetchone()
        if not node:
            return []

        node_id = node[0]
        visited: Set[int] = set()
        results: List[Dict[str, Any]] = []
        queue: List[Tuple[int, int]] = [(node_id, 0)]

        while queue:
            current_id, depth = queue.pop(0)
            if current_id in visited or depth > max_depth:
                continue
            visited.add(current_id)

            if depth > 0:
                row = self._conn.execute(
                    "SELECT id, node_type, label, description, external_id, source FROM graph_nodes WHERE id = ?",
                    (current_id,),
                ).fetchone()
                if row:
                    results.append({
                        "id": row[0], "type": row[1], "label": row[2],
                        "description": row[3], "external_id": row[4], "source": row[5],
                    })

            edges = self._conn.execute(
                "SELECT source_id, target_id FROM graph_edges WHERE source_id = ? OR target_id = ?",
                (current_id, current_id),
            ).fetchall()
            for src, tgt in edges:
                neighbor = tgt if src == current_id else src
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))

        return results

    def build_graph_for_index(
        self,
        max_payloads: int = 1000,
    ) -> Dict[str, Any]:
        stats = {"nodes_created": 0, "edges_created": 0}
        payloads = self.indexer.search(query="", limit=max_payloads)
        for payload in payloads:
            try:
                self.link_payload(payload)
                stats["edges_created"] += 1
            except Exception as e:
                logger.debug(f"PayloadGraph: link failed for payload {payload.row_id}: {e}")

        stats["total_nodes"] = self._conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
        stats["total_edges"] = self._conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]
        return stats

    def get_statistics(self) -> Dict[str, Any]:
        total_nodes = self._conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
        total_edges = self._conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]
        by_type = self._conn.execute(
            "SELECT node_type, COUNT(*) FROM graph_nodes GROUP BY node_type ORDER BY COUNT(*) DESC"
        ).fetchall()
        by_relationship = self._conn.execute(
            "SELECT relationship, COUNT(*) FROM graph_edges GROUP BY relationship ORDER BY COUNT(*) DESC"
        ).fetchall()
        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "nodes_by_type": {r[0]: r[1] for r in by_type},
            "edges_by_relationship": {r[0]: r[1] for r in by_relationship},
            "db_path": self._db_path,
        }

    def search_nodes(
        self,
        query: str,
        node_type: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        like = f"%{query}%"
        sql = "SELECT id, node_type, label, description, external_id, source FROM graph_nodes WHERE (label LIKE ? OR description LIKE ? OR external_id LIKE ?)"
        params: List[Any] = [like, like, like]
        if node_type:
            sql += " AND node_type = ?"
            params.append(node_type.upper())
        sql += " LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [
            {"id": r[0], "type": r[1], "label": r[2], "description": r[3],
             "external_id": r[4], "source": r[5]}
            for r in rows
        ]

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def __del__(self):
        self.close()
