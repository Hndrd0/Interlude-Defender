"""
Hermes Antivirus — Hash-Based Signature Engine.

Computes SHA-256 (and MD5) file hashes and matches them against a
database of known-bad signatures.  A Bloom filter provides a fast
negative check so that files that are *definitely* clean never hit the
database at all.

If ``pybloom_live`` is installed the engine uses a proper Bloom filter;
otherwise it falls back to a plain Python ``set`` with identical
semantics (no false positives in the fallback, but higher memory).
"""

import hashlib
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from hermes.utils.constants import (
    EICAR_MD5,
    EICAR_SHA256,
    EICAR_TEST_STRING,
    HASH_CHUNK_SIZE,
    MAX_SCAN_FILE_SIZE,
    ThreatCategory,
    ThreatSeverity,
)
from hermes.utils.logger import get_logger

logger = get_logger("signatures")

# ── Attempt to import a real Bloom filter ────────────────────────────────────
try:
    from pybloom_live import BloomFilter as _BloomFilter  # type: ignore[import-untyped]

    def _make_bloom(capacity: int = 1_000_000, error_rate: float = 0.0001) -> Any:
        return _BloomFilter(capacity=capacity, error_rate=error_rate)

    _BLOOM_AVAILABLE = True
    logger.debug("Using pybloom_live BloomFilter.")
except ImportError:
    _BLOOM_AVAILABLE = False
    logger.debug("pybloom_live not found — falling back to set-based filter.")

    class _SetBloom:
        """Drop-in replacement for ``BloomFilter`` backed by a ``set``."""

        def __init__(self) -> None:
            self._store: set[str] = set()

        def add(self, item: str) -> None:
            self._store.add(item)

        def __contains__(self, item: str) -> bool:
            return item in self._store

    def _make_bloom(**_: Any) -> _SetBloom:  # type: ignore[misc]
        return _SetBloom()


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Result of scanning a single file.

    Attributes:
        file_path:        Absolute path to the scanned file.
        is_threat:        ``True`` when the file matched a known signature or
                          exceeded the heuristic threshold.
        threat_name:      Human-readable label (e.g. ``EICAR-Test-File``).
        threat_category:  Classification enum value.
        threat_severity:  Severity enum value.
        detection_method: ``"signature"``, ``"heuristic"``, etc.
        details:          Arbitrary extra information (hashes, scores, …).
        heuristic_score:  Aggregate heuristic score (0–100).
    """

    file_path: str
    is_threat: bool
    threat_name: str = ""
    threat_category: ThreatCategory = ThreatCategory.CLEAN
    threat_severity: ThreatSeverity = ThreatSeverity.NONE
    detection_method: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    heuristic_score: int = 0


# ── Signature Engine ─────────────────────────────────────────────────────────

class SignatureEngine:
    """Hash-based malware detection with Bloom-filter acceleration.

    Parameters:
        db: An initialised :class:`hermes.core.database.Database` instance.
    """

    def __init__(self, db: Any) -> None:
        from hermes.core.database import Database  # late import to avoid cycles

        self._db: Database = db
        self._bloom: Any = _make_bloom()
        self._lock = threading.Lock()
        self._load_bloom()

    # ── Public API ───────────────────────────────────────────────────────

    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file against the signature database.

        Args:
            file_path: Absolute path to the file to scan.

        Returns:
            A :class:`ScanResult` with the detection outcome.
        """
        # Basic validation
        if not os.path.isfile(file_path):
            return ScanResult(
                file_path=file_path,
                is_threat=False,
                details={"error": "File not found or inaccessible"},
            )

        try:
            file_size = os.path.getsize(file_path)
        except OSError as exc:
            logger.warning("Cannot stat %s: %s", file_path, exc)
            return ScanResult(
                file_path=file_path,
                is_threat=False,
                details={"error": str(exc)},
            )

        if file_size > MAX_SCAN_FILE_SIZE:
            return ScanResult(
                file_path=file_path,
                is_threat=False,
                details={"skipped": "File exceeds max scan size"},
            )

        # Compute hashes
        try:
            hashes = self._compute_file_hash(file_path)
        except OSError as exc:
            logger.warning("Hash computation failed for %s: %s", file_path, exc)
            return ScanResult(
                file_path=file_path,
                is_threat=False,
                details={"error": str(exc)},
            )

        sha256 = hashes["sha256"]
        md5 = hashes["md5"]

        # Check EICAR first (always detect regardless of DB state)
        if sha256 == EICAR_SHA256 or md5 == EICAR_MD5:
            return self._eicar_result(file_path, hashes)

        # Bloom filter – fast negative check
        with self._lock:
            sha_in_bloom = sha256 in self._bloom
            md5_in_bloom = md5 in self._bloom

        if not sha_in_bloom and not md5_in_bloom:
            return ScanResult(
                file_path=file_path,
                is_threat=False,
                details={"hashes": hashes},
            )

        # Potential match – verify against the database
        sig: Optional[Dict[str, Any]] = self._db.check_signature(sha256)
        if sig is None:
            sig = self._db.check_signature(md5)

        if sig is not None:
            severity = ThreatSeverity(sig["severity"])
            try:
                category = ThreatCategory(sig["category"])
            except ValueError:
                category = ThreatCategory.MALWARE
            return ScanResult(
                file_path=file_path,
                is_threat=True,
                threat_name=sig["threat_name"],
                threat_category=category,
                threat_severity=severity,
                detection_method="signature",
                details={"hashes": hashes, "signature": dict(sig)},
            )

        # Bloom false-positive
        return ScanResult(
            file_path=file_path,
            is_threat=False,
            details={"hashes": hashes, "bloom_fp": True},
        )

    def add_signature(
        self,
        hash_value: str,
        threat_name: str,
        category: str,
        severity: int,
    ) -> None:
        """Add a signature to both the database and the live Bloom filter."""
        self._db.add_signature(hash_value, threat_name, category, severity)
        with self._lock:
            self._bloom.add(hash_value.lower())
        logger.info("Signature added: %s (%s)", threat_name, hash_value[:16])

    def reload(self) -> None:
        """Rebuild the Bloom filter from the current database contents."""
        self._load_bloom()
        logger.info("Bloom filter reloaded from database.")

    # ── Private helpers ──────────────────────────────────────────────────

    def _load_bloom(self) -> None:
        """Populate the Bloom filter with every hash in the DB."""
        hashes = self._db.get_all_signature_hashes()
        new_bloom = _make_bloom()
        for h in hashes:
            new_bloom.add(h)
        with self._lock:
            self._bloom = new_bloom
        logger.debug("Bloom filter loaded with %d hashes.", len(hashes))

    @staticmethod
    def _compute_file_hash(file_path: str) -> Dict[str, str]:
        """Compute MD5 and SHA-256 digests of a file.

        Reads the file in chunks of :data:`HASH_CHUNK_SIZE` to keep
        memory usage constant regardless of file size.

        Returns:
            Dict with keys ``md5`` and ``sha256``.
        """
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                md5.update(chunk)
                sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}

    @staticmethod
    def _eicar_result(file_path: str, hashes: Dict[str, str]) -> ScanResult:
        """Build a positive :class:`ScanResult` for the EICAR test file."""
        return ScanResult(
            file_path=file_path,
            is_threat=True,
            threat_name="EICAR-Test-File",
            threat_category=ThreatCategory.TEST,
            threat_severity=ThreatSeverity.LOW,
            detection_method="signature",
            details={"hashes": hashes, "note": "EICAR antivirus test file"},
        )
