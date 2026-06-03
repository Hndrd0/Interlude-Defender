"""
Hermes Antivirus — Static Heuristic Analysis Engine.

Performs deep static inspection of Portable Executable (PE) files to detect
potentially malicious behaviour *without* relying on known signatures.

Each check contributes an independent score (0 – ~25) and a human-readable
list of findings.  The aggregate score (clamped to 0-100) is mapped to a
:class:`ThreatCategory`:

* **< 25** → CLEAN
* **25 – 60** → SUSPICIOUS
* **> 60** → MALWARE

Non-PE files are returned as clean with a score of 0.
"""

import math
import os
import stat
import time
from typing import Any, Dict, List, Optional, Tuple

from hermes.utils.constants import (
    ENTROPY_HIGHLY_SUSPICIOUS,
    HEURISTIC_THRESHOLD_MALICIOUS,
    HEURISTIC_THRESHOLD_SUSPICIOUS,
    MAX_SCAN_FILE_SIZE,
    PACKER_SIGNATURES,
    SUSPICIOUS_APIS,
    SUSPICIOUS_LOCATIONS,
    ThreatCategory,
    ThreatSeverity,
)
from hermes.utils.logger import get_logger

# Import ScanResult from siblings — keep the canonical definition in one place.
from hermes.core.signatures import ScanResult

logger = get_logger("heuristics")

# ── Optional PE parser ───────────────────────────────────────────────────────
try:
    import pefile  # type: ignore[import-untyped]

    _PEFILE_AVAILABLE = True
except ImportError:
    _PEFILE_AVAILABLE = False
    logger.warning(
        "pefile library not installed — PE heuristic analysis will be disabled."
    )


class HeuristicEngine:
    """Static heuristic analyser for PE binaries.

    Instantiate once and call :meth:`analyze_file` for every file that
    should undergo deep inspection.
    """

    # Injection-chain APIs — finding all three is a strong signal
    _INJECTION_CHAIN = frozenset(
        {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
    )

    def __init__(self) -> None:
        logger.info("HeuristicEngine initialised (pefile available: %s).", _PEFILE_AVAILABLE)

    # ── Public API ───────────────────────────────────────────────────────

    def analyze_file(self, file_path: str) -> ScanResult:
        """Run all heuristic checks on *file_path* and return a verdict.

        Args:
            file_path: Absolute path to the file.

        Returns:
            A :class:`ScanResult` populated with the aggregate heuristic
            score, threat classification, and a ``details`` dict containing
            every individual finding.
        """
        # Guard: path must exist
        if not os.path.isfile(file_path):
            return self._clean_result(file_path, error="File not found")

        # Guard: skip oversized files
        try:
            file_size = os.path.getsize(file_path)
        except OSError as exc:
            return self._clean_result(file_path, error=str(exc))

        if file_size > MAX_SCAN_FILE_SIZE:
            return self._clean_result(file_path, error="Exceeds max scan size")

        total_score = 0
        all_findings: List[str] = []

        # File-attribute checks (always run, even for non-PE files)
        attr_score, attr_findings = self._analyze_file_attributes(file_path)
        total_score += attr_score
        all_findings.extend(attr_findings)

        # PE-specific analysis
        pe_obj: Optional[Any] = None
        if _PEFILE_AVAILABLE:
            pe_obj = self._try_parse_pe(file_path)

        if pe_obj is not None:
            try:
                for analysis_fn in (
                    self._analyze_pe_headers,
                    self._analyze_entropy,
                    self._analyze_imports,
                    self._detect_packing,
                ):
                    score, findings = analysis_fn(pe_obj)
                    total_score += score
                    all_findings.extend(findings)
            finally:
                pe_obj.close()

        # Clamp
        total_score = max(0, min(100, total_score))

        # Classify
        category, severity = self._classify_score(total_score)

        is_threat = category not in (ThreatCategory.CLEAN,)
        threat_name = ""
        if category == ThreatCategory.SUSPICIOUS:
            threat_name = "Heuristic.Suspicious"
        elif category == ThreatCategory.MALWARE:
            threat_name = "Heuristic.Malware.Generic"

        return ScanResult(
            file_path=file_path,
            is_threat=is_threat,
            threat_name=threat_name,
            threat_category=category,
            threat_severity=severity,
            detection_method="heuristic",
            details={
                "score": total_score,
                "findings": all_findings,
                "is_pe": pe_obj is not None,
            },
            heuristic_score=total_score,
        )

    # ── PE Header Analysis ───────────────────────────────────────────────

    def _analyze_pe_headers(self, pe: Any) -> Tuple[int, List[str]]:
        """Inspect PE optional / file headers for anomalies.

        Returns:
            ``(score, findings)`` tuple.
        """
        score = 0
        findings: List[str] = []

        # Check PE timestamp
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            # Timestamps before 1990 or in the future are suspicious
            if ts < 631152000:  # 1990-01-01
                score += 5
                findings.append(
                    f"PE timestamp is implausibly old ({ts})"
                )
            elif ts > time.time() + 86400:
                score += 5
                findings.append(
                    f"PE timestamp is in the future ({ts})"
                )
        except AttributeError:
            pass

        # Look for tiny code section
        try:
            for section in pe.sections:
                name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
                if name.lower() in (".text", "code"):
                    raw_size = section.SizeOfRawData
                    if 0 < raw_size < 512:
                        score += 10
                        findings.append(
                            f"Tiny code section '{name}' ({raw_size} bytes)"
                        )
        except (AttributeError, UnicodeDecodeError):
            pass

        return score, findings

    # ── Entropy Analysis ─────────────────────────────────────────────────

    def _analyze_entropy(self, pe: Any) -> Tuple[int, List[str]]:
        """Per-section entropy analysis.

        High entropy (> 7.2) strongly suggests encryption or compression.

        Returns:
            ``(score, findings)`` tuple.
        """
        score = 0
        findings: List[str] = []

        try:
            for section in pe.sections:
                name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
                data = section.get_data()
                if not data:
                    continue
                entropy = self._calculate_entropy(data)
                if entropy > ENTROPY_HIGHLY_SUSPICIOUS:
                    score += 15
                    findings.append(
                        f"High entropy section '{name}': {entropy:.2f}"
                    )
        except (AttributeError, Exception) as exc:
            logger.debug("Entropy analysis error: %s", exc)

        return score, findings

    # ── Import Analysis ──────────────────────────────────────────────────

    def _analyze_imports(self, pe: Any) -> Tuple[int, List[str]]:
        """Check imported API names against the suspicious-API table.

        Also awards a bonus when the classic injection chain
        (VirtualAllocEx → WriteProcessMemory → CreateRemoteThread) is
        present as a complete set.

        Returns:
            ``(score, findings)`` tuple.
        """
        score = 0
        findings: List[str] = []

        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
        except Exception:
            pass

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            # No import table at all — very suspicious for a PE
            score += 20
            findings.append("PE has no import table")
            return score, findings

        seen_apis: set[str] = set()

        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name is None:
                        continue
                    api_name = imp.name.decode("ascii", errors="replace")
                    if api_name in SUSPICIOUS_APIS:
                        info = SUSPICIOUS_APIS[api_name]
                        score += info["weight"]
                        findings.append(
                            f"Suspicious import: {api_name} "
                            f"(category={info['category']}, weight={info['weight']})"
                        )
                        seen_apis.add(api_name)
        except (AttributeError, Exception) as exc:
            logger.debug("Import analysis error: %s", exc)

        # Injection-chain bonus
        if self._INJECTION_CHAIN.issubset(seen_apis):
            score += 25
            findings.append(
                "Full injection chain detected "
                "(VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)"
            )

        return score, findings

    # ── Packer Detection ─────────────────────────────────────────────────

    def _detect_packing(self, pe: Any) -> Tuple[int, List[str]]:
        """Detect known packer section names.

        Returns:
            ``(score, findings)`` tuple.
        """
        score = 0
        findings: List[str] = []

        try:
            for section in pe.sections:
                name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
                if name in PACKER_SIGNATURES:
                    score += 15
                    findings.append(f"Known packer section detected: '{name}'")
        except (AttributeError, UnicodeDecodeError, Exception) as exc:
            logger.debug("Packer detection error: %s", exc)

        return score, findings

    # ── File Attributes ──────────────────────────────────────────────────

    def _analyze_file_attributes(self, file_path: str) -> Tuple[int, List[str]]:
        """Inspect OS-level file attributes and path for red flags.

        Checks performed:

        * Hidden / system attribute (Windows)
        * Suspicious download or temp location
        * Double extension (e.g. ``invoice.pdf.exe``)

        Returns:
            ``(score, findings)`` tuple.
        """
        score = 0
        findings: List[str] = []

        # Hidden / system attributes (Windows-specific)
        try:
            if os.name == "nt":
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)  # type: ignore[union-attr]
                FILE_ATTRIBUTE_HIDDEN = 0x2
                FILE_ATTRIBUTE_SYSTEM = 0x4
                if attrs != -1:
                    if attrs & FILE_ATTRIBUTE_HIDDEN:
                        score += 10
                        findings.append("File has HIDDEN attribute")
                    if attrs & FILE_ATTRIBUTE_SYSTEM:
                        score += 10
                        findings.append("File has SYSTEM attribute")
            else:
                # Unix: dotfile heuristic
                basename = os.path.basename(file_path)
                if basename.startswith("."):
                    score += 10
                    findings.append("File is hidden (dotfile)")
        except Exception as exc:
            logger.debug("Attribute check error: %s", exc)

        # Suspicious location
        try:
            normalised = os.path.normcase(os.path.abspath(file_path))
            for loc in SUSPICIOUS_LOCATIONS:
                if loc and os.path.normcase(loc) and normalised.startswith(
                    os.path.normcase(loc)
                ):
                    score += 10
                    findings.append(f"File in suspicious location: {loc}")
                    break  # count once
        except Exception as exc:
            logger.debug("Location check error: %s", exc)

        # Double extension
        try:
            basename = os.path.basename(file_path)
            parts = basename.split(".")
            if len(parts) >= 3:
                # e.g. report.pdf.exe → parts = ['report', 'pdf', 'exe']
                score += 15
                findings.append(
                    f"Double extension detected: '{basename}'"
                )
        except Exception as exc:
            logger.debug("Extension check error: %s", exc)

        return score, findings

    # ── Entropy Calculation ──────────────────────────────────────────────

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Compute Shannon entropy of *data* (bits per byte, 0.0–8.0).

        An entropy close to 8.0 indicates highly random / encrypted data.

        Args:
            data: Raw byte sequence.

        Returns:
            Entropy value as a float.
        """
        if not data:
            return 0.0

        length = len(data)
        freq: Dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    # ── Internal Utilities ───────────────────────────────────────────────

    @staticmethod
    def _try_parse_pe(file_path: str) -> Optional[Any]:
        """Attempt to parse *file_path* as a PE binary.

        Returns the ``pefile.PE`` object on success, or ``None`` if the
        file is not a valid PE.
        """
        try:
            return pefile.PE(file_path, fast_load=True)
        except pefile.PEFormatError:
            return None
        except Exception as exc:
            logger.debug("PE parse failed for %s: %s", file_path, exc)
            return None

    @staticmethod
    def _classify_score(score: int) -> Tuple[ThreatCategory, ThreatSeverity]:
        """Map a numeric heuristic score to a threat classification.

        Returns:
            ``(ThreatCategory, ThreatSeverity)`` tuple.
        """
        if score > HEURISTIC_THRESHOLD_MALICIOUS:
            return ThreatCategory.MALWARE, ThreatSeverity.HIGH
        if score >= HEURISTIC_THRESHOLD_SUSPICIOUS:
            return ThreatCategory.SUSPICIOUS, ThreatSeverity.MEDIUM
        return ThreatCategory.CLEAN, ThreatSeverity.NONE

    @staticmethod
    def _clean_result(file_path: str, *, error: str = "") -> ScanResult:
        """Build a benign :class:`ScanResult` for non-scannable files."""
        details: Dict[str, Any] = {"score": 0, "findings": [], "is_pe": False}
        if error:
            details["error"] = error
        return ScanResult(
            file_path=file_path,
            is_threat=False,
            threat_category=ThreatCategory.CLEAN,
            threat_severity=ThreatSeverity.NONE,
            detection_method="heuristic",
            details=details,
            heuristic_score=0,
        )
