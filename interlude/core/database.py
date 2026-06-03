"""
Hermes Antivirus — SQLite Database Layer.

Provides thread-safe database operations using a connection-per-call pattern.
Manages signature storage, scan history, quarantine records, per-file scan
results, and application settings.  Implemented as a singleton so every
subsystem shares the same ``Database`` instance.
"""

import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

from hermes.utils.constants import (
    DATABASE_FILE,
    EICAR_MD5,
    EICAR_SHA256,
    ThreatCategory,
    ThreatSeverity,
)
from hermes.utils.logger import get_logger

logger = get_logger("database")


class Database:
    """Thread-safe SQLite database manager (singleton).

    Every public method opens its own connection, executes the query, and
    closes the connection immediately.  This avoids all ``sqlite3`` threading
    issues without requiring ``check_same_thread=False``.
    """

    _instance: Optional["Database"] = None
    _lock: threading.Lock = threading.Lock()

    # ── Singleton ────────────────────────────────────────────────────────

    def __new__(cls) -> "Database":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialised = False
            return cls._instance

    def __init__(self) -> None:
        if self._initialised:
            return
        self._db_path: str = DATABASE_FILE
        self._create_tables()
        self.seed_signatures()
        self._initialised = True
        logger.info("Database initialised at %s", self._db_path)

    # ── Helpers ──────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        """Return a new connection with row-factory enabled."""
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _execute(
        self,
        sql: str,
        params: tuple = (),
        *,
        fetch_one: bool = False,
        fetch_all: bool = False,
    ) -> Any:
        """Execute *sql* with *params* in its own connection."""
        conn = self._connect()
        try:
            cur = conn.execute(sql, params)
            if fetch_one:
                row = cur.fetchone()
                return dict(row) if row else None
            if fetch_all:
                return [dict(r) for r in cur.fetchall()]
            conn.commit()
            return cur.lastrowid
        except sqlite3.Error:
            logger.exception("Database error executing: %s", sql)
            return None
        finally:
            conn.close()

    # ── Schema ───────────────────────────────────────────────────────────

    def _create_tables(self) -> None:
        """Create all required tables if they do not exist."""
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS signatures (
                    hash          TEXT PRIMARY KEY,
                    threat_name   TEXT NOT NULL,
                    category      TEXT NOT NULL,
                    severity      INTEGER NOT NULL,
                    date_added    REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_mode      TEXT NOT NULL,
                    start_time     REAL NOT NULL,
                    end_time       REAL,
                    files_scanned  INTEGER DEFAULT 0,
                    threats_found  INTEGER DEFAULT 0,
                    status         TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS quarantine (
                    id               TEXT PRIMARY KEY,
                    original_name    TEXT NOT NULL,
                    original_path    TEXT NOT NULL,
                    quarantine_path  TEXT NOT NULL,
                    sha256_hash      TEXT,
                    md5_hash         TEXT,
                    file_size        INTEGER,
                    threat_name      TEXT,
                    threat_severity  TEXT,
                    detection_method TEXT,
                    quarantine_time  REAL NOT NULL,
                    restored         INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key   TEXT PRIMARY KEY,
                    value TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_results (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id          INTEGER,
                    file_path        TEXT NOT NULL,
                    threat_name      TEXT,
                    threat_category  TEXT,
                    severity         INTEGER,
                    detection_method TEXT,
                    action_taken     TEXT,
                    timestamp        REAL NOT NULL
                );
                """
            )
            conn.commit()
            logger.debug("Database tables verified / created.")
        except sqlite3.Error:
            logger.exception("Failed to create database tables.")
        finally:
            conn.close()

    # ── Signatures ───────────────────────────────────────────────────────

    def add_signature(
        self,
        hash_value: str,
        threat_name: str,
        category: str,
        severity: int,
    ) -> None:
        """Insert or replace a single malware signature."""
        self._execute(
            "INSERT OR REPLACE INTO signatures (hash, threat_name, category, severity, date_added) "
            "VALUES (?, ?, ?, ?, ?)",
            (hash_value.lower(), threat_name, category, int(severity), time.time()),
        )

    def check_signature(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """Look up a hash in the signature database.

        Returns:
            A dict with signature details, or ``None`` if not found.
        """
        return self._execute(
            "SELECT * FROM signatures WHERE hash = ?",
            (hash_value.lower(),),
            fetch_one=True,
        )

    def get_all_signature_hashes(self) -> List[str]:
        """Return every known hash (used to populate the Bloom filter)."""
        rows = self._execute("SELECT hash FROM signatures", fetch_all=True)
        return [r["hash"] for r in rows] if rows else []

    def batch_add_signatures(self, signatures: List[Dict[str, Any]]) -> None:
        """Bulk-insert a list of signature dicts.

        Each dict must contain keys: ``hash``, ``threat_name``, ``category``,
        ``severity``.
        """
        conn = self._connect()
        try:
            conn.executemany(
                "INSERT OR REPLACE INTO signatures "
                "(hash, threat_name, category, severity, date_added) "
                "VALUES (:hash, :threat_name, :category, :severity, :date_added)",
                [
                    {
                        "hash": s["hash"].lower(),
                        "threat_name": s["threat_name"],
                        "category": s["category"],
                        "severity": int(s["severity"]),
                        "date_added": s.get("date_added", time.time()),
                    }
                    for s in signatures
                ],
            )
            conn.commit()
            logger.info("Batch-inserted %d signatures.", len(signatures))
        except sqlite3.Error:
            logger.exception("Batch signature insert failed.")
        finally:
            conn.close()

    def seed_signatures(self) -> None:
        """Pre-load EICAR test-file hashes so the engine can detect them."""
        for h in (EICAR_SHA256, EICAR_MD5):
            self.add_signature(
                hash_value=h,
                threat_name="EICAR-Test-File",
                category=ThreatCategory.TEST.value,
                severity=int(ThreatSeverity.LOW),
            )
        logger.debug("EICAR test signatures seeded.")

    # ── Scan History ─────────────────────────────────────────────────────

    def add_scan_history(
        self,
        scan_mode: str,
        start_time: float,
        status: str,
    ) -> Optional[int]:
        """Create a new scan-history record and return its id."""
        return self._execute(
            "INSERT INTO scan_history (scan_mode, start_time, status) VALUES (?, ?, ?)",
            (scan_mode, start_time, status),
        )

    def update_scan_history(
        self,
        scan_id: int,
        *,
        end_time: Optional[float] = None,
        files_scanned: Optional[int] = None,
        threats_found: Optional[int] = None,
        status: Optional[str] = None,
    ) -> None:
        """Update fields on an existing scan-history row."""
        parts: List[str] = []
        values: List[Any] = []
        if end_time is not None:
            parts.append("end_time = ?")
            values.append(end_time)
        if files_scanned is not None:
            parts.append("files_scanned = ?")
            values.append(files_scanned)
        if threats_found is not None:
            parts.append("threats_found = ?")
            values.append(threats_found)
        if status is not None:
            parts.append("status = ?")
            values.append(status)
        if not parts:
            return
        values.append(scan_id)
        self._execute(
            f"UPDATE scan_history SET {', '.join(parts)} WHERE id = ?",
            tuple(values),
        )

    def get_scan_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return the most recent scan-history records."""
        rows = self._execute(
            "SELECT * FROM scan_history ORDER BY start_time DESC LIMIT ?",
            (limit,),
            fetch_all=True,
        )
        return rows if rows else []

    # ── Scan Results ─────────────────────────────────────────────────────

    def add_scan_result(
        self,
        scan_id: int,
        file_path: str,
        threat_name: str,
        category: str,
        severity: int,
        method: str,
        action: str,
    ) -> Optional[int]:
        """Record an individual file-scan result."""
        return self._execute(
            "INSERT INTO scan_results "
            "(scan_id, file_path, threat_name, threat_category, severity, "
            "detection_method, action_taken, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, file_path, threat_name, category, int(severity), method, action, time.time()),
        )

    # ── Quarantine ───────────────────────────────────────────────────────

    def add_quarantine_entry(
        self,
        quarantine_id: str,
        original_name: str,
        original_path: str,
        quarantine_path: str,
        sha256_hash: str,
        md5_hash: str,
        file_size: int,
        threat_name: str,
        threat_severity: str,
        detection_method: str,
    ) -> None:
        """Insert a new quarantine record."""
        self._execute(
            "INSERT OR REPLACE INTO quarantine "
            "(id, original_name, original_path, quarantine_path, sha256_hash, "
            "md5_hash, file_size, threat_name, threat_severity, detection_method, "
            "quarantine_time, restored) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (
                quarantine_id,
                original_name,
                original_path,
                quarantine_path,
                sha256_hash,
                md5_hash,
                file_size,
                threat_name,
                threat_severity,
                detection_method,
                time.time(),
            ),
        )

    def get_quarantine_entries(self) -> List[Dict[str, Any]]:
        """Return all quarantine records (not yet permanently deleted)."""
        rows = self._execute(
            "SELECT * FROM quarantine ORDER BY quarantine_time DESC",
            fetch_all=True,
        )
        return rows if rows else []

    def remove_quarantine_entry(self, quarantine_id: str) -> None:
        """Permanently delete a quarantine record from the database."""
        self._execute("DELETE FROM quarantine WHERE id = ?", (quarantine_id,))

    def update_quarantine_restored(self, quarantine_id: str) -> None:
        """Mark a quarantine entry as restored."""
        self._execute(
            "UPDATE quarantine SET restored = 1 WHERE id = ?",
            (quarantine_id,),
        )

    # ── Statistics ───────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, int]:
        """Aggregate statistics for the dashboard.

        Returns:
            Dict with keys ``total_scans``, ``total_threats``,
            ``total_files_scanned``, ``total_quarantined``.
        """
        conn = self._connect()
        try:
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM scan_history")
            total_scans = cur.fetchone()["cnt"]

            cur = conn.execute(
                "SELECT COALESCE(SUM(threats_found), 0) AS cnt FROM scan_history"
            )
            total_threats = cur.fetchone()["cnt"]

            cur = conn.execute(
                "SELECT COALESCE(SUM(files_scanned), 0) AS cnt FROM scan_history"
            )
            total_files_scanned = cur.fetchone()["cnt"]

            cur = conn.execute(
                "SELECT COUNT(*) AS cnt FROM quarantine WHERE restored = 0"
            )
            total_quarantined = cur.fetchone()["cnt"]

            return {
                "total_scans": total_scans,
                "total_threats": total_threats,
                "total_files_scanned": total_files_scanned,
                "total_quarantined": total_quarantined,
            }
        except sqlite3.Error:
            logger.exception("Failed to gather stats.")
            return {
                "total_scans": 0,
                "total_threats": 0,
                "total_files_scanned": 0,
                "total_quarantined": 0,
            }
        finally:
            conn.close()
