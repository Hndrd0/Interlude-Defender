"""
Hermes Antivirus — Quarantine Manager.

Isolates suspicious files by:

1. XOR-encrypting their contents (key ``0xAA``) so they cannot be
   accidentally executed.
2. Moving them into :data:`QUARANTINE_DIR` under a UUID-based name with
   a ``.quarantine`` extension.
3. Recording full metadata in the database so they can later be restored
   or permanently deleted.
"""

import hashlib
import os
import shutil
import time
import uuid
from typing import Any, Dict, List, Optional

from hermes.utils.constants import (
    HASH_CHUNK_SIZE,
    QUARANTINE_DIR,
)
from hermes.utils.logger import get_logger

logger = get_logger("quarantine")

# XOR key used for simple obfuscation (prevents double-click execution).
_XOR_KEY: int = 0xAA


class QuarantineManager:
    """Manage quarantined (isolated) threat files.

    Parameters:
        db: An initialised :class:`hermes.core.database.Database` instance.
    """

    def __init__(self, db: Any) -> None:
        from hermes.core.database import Database  # late import avoids cycles

        self._db: Database = db
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        logger.info("QuarantineManager initialised (dir: %s).", QUARANTINE_DIR)

    # ── Public API ───────────────────────────────────────────────────────

    def quarantine_file(
        self,
        file_path: str,
        threat_name: str,
        severity: str,
        detection_method: str,
    ) -> str:
        """Move *file_path* into the quarantine vault.

        The file is XOR-encrypted in memory, written to :data:`QUARANTINE_DIR`
        with a ``.quarantine`` extension, and the original is deleted.  Full
        metadata is stored in the database.

        Args:
            file_path:        Absolute path to the file to quarantine.
            threat_name:      Name of the detected threat.
            severity:         Severity label (e.g. ``"HIGH"``).
            detection_method: How the threat was detected (``"signature"``
                              or ``"heuristic"``).

        Returns:
            The newly created quarantine ID (UUID string).

        Raises:
            FileNotFoundError: If *file_path* does not exist.
            OSError:           On read / write failures.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Cannot quarantine — file not found: {file_path}")

        quarantine_id = uuid.uuid4().hex
        original_name = os.path.basename(file_path)
        quarantine_filename = f"{quarantine_id}.quarantine"
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)

        # Compute hashes *before* encryption
        sha256 = self._compute_hash(file_path, "sha256")
        md5 = self._compute_hash(file_path, "md5")
        file_size = os.path.getsize(file_path)

        # Read → encrypt → write
        try:
            with open(file_path, "rb") as f_in:
                raw_data = f_in.read()
            encrypted = self._xor_encrypt(raw_data)
            with open(quarantine_path, "wb") as f_out:
                f_out.write(encrypted)
        except OSError:
            logger.exception("Failed to encrypt/write quarantine file for %s.", file_path)
            raise

        # Remove the original
        try:
            os.remove(file_path)
        except OSError:
            logger.exception(
                "Quarantine file written but original could not be removed: %s",
                file_path,
            )

        # Record in DB
        try:
            self._db.add_quarantine_entry(
                quarantine_id=quarantine_id,
                original_name=original_name,
                original_path=file_path,
                quarantine_path=quarantine_path,
                sha256_hash=sha256,
                md5_hash=md5,
                file_size=file_size,
                threat_name=threat_name,
                threat_severity=severity,
                detection_method=detection_method,
            )
        except Exception:
            logger.exception("Failed to write quarantine DB entry for %s.", file_path)

        logger.info(
            "Quarantined '%s' → %s (threat=%s, severity=%s)",
            original_name,
            quarantine_id,
            threat_name,
            severity,
        )
        return quarantine_id

    def restore_file(self, quarantine_id: str) -> bool:
        """Decrypt and restore a quarantined file to its original location.

        Args:
            quarantine_id: The UUID of the quarantine entry.

        Returns:
            ``True`` on success, ``False`` otherwise.
        """
        entry = self._find_entry(quarantine_id)
        if entry is None:
            logger.warning("Restore failed — quarantine entry not found: %s", quarantine_id)
            return False

        quarantine_path: str = entry["quarantine_path"]
        original_path: str = entry["original_path"]

        if not os.path.isfile(quarantine_path):
            logger.error("Quarantine file missing on disk: %s", quarantine_path)
            return False

        # Read → decrypt → write back to original location
        try:
            with open(quarantine_path, "rb") as f_in:
                encrypted = f_in.read()
            decrypted = self._xor_encrypt(encrypted)  # XOR is self-inverse

            # Ensure parent directory exists
            os.makedirs(os.path.dirname(original_path), exist_ok=True)

            with open(original_path, "wb") as f_out:
                f_out.write(decrypted)
        except OSError:
            logger.exception("Failed to restore file to %s.", original_path)
            return False

        # Remove quarantine blob
        try:
            os.remove(quarantine_path)
        except OSError:
            logger.warning("Could not delete quarantine blob: %s", quarantine_path)

        self._db.update_quarantine_restored(quarantine_id)
        logger.info("Restored %s → %s", quarantine_id, original_path)
        return True

    def delete_file(self, quarantine_id: str) -> bool:
        """Permanently delete a quarantined file and its DB record.

        Args:
            quarantine_id: The UUID of the quarantine entry.

        Returns:
            ``True`` on success, ``False`` otherwise.
        """
        entry = self._find_entry(quarantine_id)
        if entry is None:
            logger.warning("Delete failed — quarantine entry not found: %s", quarantine_id)
            return False

        quarantine_path: str = entry["quarantine_path"]

        # Remove blob from disk
        if os.path.isfile(quarantine_path):
            try:
                os.remove(quarantine_path)
            except OSError:
                logger.exception("Could not delete quarantine blob: %s", quarantine_path)
                return False

        self._db.remove_quarantine_entry(quarantine_id)
        logger.info("Permanently deleted quarantine entry: %s", quarantine_id)
        return True

    def list_quarantined(self) -> List[Dict[str, Any]]:
        """Return all current quarantine entries.

        Returns:
            A list of dicts, each representing one quarantine record.
        """
        return self._db.get_quarantine_entries()

    def cleanup_old(self, days: int = 7) -> None:
        """Remove quarantine entries older than *days* days.

        Both the encrypted blob and the database record are deleted.

        Args:
            days: Age threshold in days.
        """
        cutoff = time.time() - (days * 86400)
        entries = self._db.get_quarantine_entries()
        removed = 0

        for entry in entries:
            if entry["quarantine_time"] < cutoff:
                qid: str = entry["id"]
                qpath: str = entry["quarantine_path"]
                if os.path.isfile(qpath):
                    try:
                        os.remove(qpath)
                    except OSError:
                        logger.warning("Cleanup: could not remove blob %s", qpath)
                        continue
                self._db.remove_quarantine_entry(qid)
                removed += 1

        if removed:
            logger.info(
                "Quarantine cleanup: removed %d entries older than %d days.",
                removed,
                days,
            )

    # ── Private helpers ──────────────────────────────────────────────────

    @staticmethod
    def _xor_encrypt(data: bytes, key: int = _XOR_KEY) -> bytes:
        """XOR every byte with *key*.

        Because XOR is its own inverse, the same function encrypts and
        decrypts:

        .. code-block:: python

            assert _xor_encrypt(_xor_encrypt(b"hello")) == b"hello"

        Args:
            data: Raw bytes to transform.
            key:  Single-byte XOR key (default ``0xAA``).

        Returns:
            Transformed bytes.
        """
        return bytes(b ^ key for b in data)

    @staticmethod
    def _compute_hash(file_path: str, algorithm: str = "sha256") -> str:
        """Compute the hex-digest of *file_path* using *algorithm*.

        Args:
            file_path: Absolute path to the file.
            algorithm: Any algorithm name accepted by :func:`hashlib.new`
                       (e.g. ``"sha256"``, ``"md5"``).

        Returns:
            Lowercase hex-digest string.
        """
        h = hashlib.new(algorithm)
        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _find_entry(self, quarantine_id: str) -> Optional[Dict[str, Any]]:
        """Look up a single quarantine entry by ID.

        Returns:
            The entry dict, or ``None`` if not found.
        """
        entries = self._db.get_quarantine_entries()
        for entry in entries:
            if entry["id"] == quarantine_id:
                return entry
        return None
