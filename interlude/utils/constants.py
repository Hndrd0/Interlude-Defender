"""
Hermes Antivirus — Application-wide constants.
"""

import os
import enum


# ─── Application Info ────────────────────────────────────────────────────────

APP_NAME = "Interlude Defender"
APP_VERSION = "1.0.0-alpha"
APP_AUTHOR = "Interlude Security"
APP_DESCRIPTION = "Next-Generation Threat Detection"

# ─── Paths ────────────────────────────────────────────────────────────────────

APP_DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Interlude")
CONFIG_FILE = os.path.join(APP_DATA_DIR, "config.json")
DATABASE_FILE = os.path.join(APP_DATA_DIR, "interlude.db")
QUARANTINE_DIR = os.path.join(APP_DATA_DIR, "quarantine")
LOG_DIR = os.path.join(APP_DATA_DIR, "logs")
SIGNATURES_DIR = os.path.join(APP_DATA_DIR, "signatures")

# Ensure directories exist
for _dir in [APP_DATA_DIR, QUARANTINE_DIR, LOG_DIR, SIGNATURES_DIR]:
    os.makedirs(_dir, exist_ok=True)


# ─── Threat Classification ───────────────────────────────────────────────────

class ThreatSeverity(enum.IntEnum):
    """Threat severity levels (higher = more dangerous)."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ThreatCategory(enum.Enum):
    """Categories of detected threats."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALWARE = "malware"
    TROJAN = "trojan"
    RANSOMWARE = "ransomware"
    SPYWARE = "spyware"
    ADWARE = "adware"
    WORM = "worm"
    ROOTKIT = "rootkit"
    CRYPTOMINER = "cryptominer"
    PUP = "potentially_unwanted"
    PACKED = "packed"
    TEST = "test_file"


class ScanMode(enum.Enum):
    """Available scan modes."""
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"
    REALTIME = "realtime"


class ScanStatus(enum.Enum):
    """Scan job statuses."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"


# ─── Detection Thresholds ────────────────────────────────────────────────────

# Heuristic score thresholds (0-100)
HEURISTIC_THRESHOLD_SUSPICIOUS = 25
HEURISTIC_THRESHOLD_MALICIOUS = 60

# Entropy thresholds
ENTROPY_SUSPICIOUS = 6.8       # Probably packed
ENTROPY_HIGHLY_SUSPICIOUS = 7.2  # Almost certainly encrypted/packed

# Maximum file size to scan (skip huge files for performance)
MAX_SCAN_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

# ─── File Extensions ─────────────────────────────────────────────────────────

# Executable extensions that should always be scanned
EXECUTABLE_EXTENSIONS = frozenset({
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.psm1',
    '.vbs', '.vbe', '.js', '.jse', '.wsh', '.wsf', '.msi',
    '.com', '.pif', '.hta', '.cpl', '.msp', '.mst', '.sct',
    '.inf', '.reg',
})

# Archive extensions (scan contents if enabled)
ARCHIVE_EXTENSIONS = frozenset({
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
    '.cab', '.iso',
})

# All scannable extensions (quick scan focuses on executables)
ALL_SCANNABLE_EXTENSIONS = EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS

# ─── Suspicious API Imports ──────────────────────────────────────────────────

SUSPICIOUS_APIS = {
    # Process Injection
    'CreateRemoteThread':      {'category': 'injection',   'severity': ThreatSeverity.HIGH,     'weight': 15},
    'CreateRemoteThreadEx':    {'category': 'injection',   'severity': ThreatSeverity.HIGH,     'weight': 15},
    'WriteProcessMemory':      {'category': 'injection',   'severity': ThreatSeverity.HIGH,     'weight': 15},
    'VirtualAllocEx':          {'category': 'injection',   'severity': ThreatSeverity.HIGH,     'weight': 12},
    'OpenProcess':             {'category': 'injection',   'severity': ThreatSeverity.MEDIUM,   'weight': 5},
    'QueueUserAPC':            {'category': 'injection',   'severity': ThreatSeverity.HIGH,     'weight': 15},
    'SetThreadContext':        {'category': 'injection',   'severity': ThreatSeverity.HIGH,     'weight': 12},
    'NtUnmapViewOfSection':    {'category': 'injection',   'severity': ThreatSeverity.CRITICAL, 'weight': 20},
    'ResumeThread':            {'category': 'injection',   'severity': ThreatSeverity.MEDIUM,   'weight': 5},

    # Defense Evasion
    'VirtualProtect':          {'category': 'evasion',     'severity': ThreatSeverity.MEDIUM,   'weight': 8},
    'VirtualProtectEx':        {'category': 'evasion',     'severity': ThreatSeverity.HIGH,     'weight': 10},
    'IsDebuggerPresent':       {'category': 'anti_debug',  'severity': ThreatSeverity.MEDIUM,   'weight': 8},
    'CheckRemoteDebuggerPresent': {'category': 'anti_debug', 'severity': ThreatSeverity.MEDIUM, 'weight': 8},

    # Keylogging / Input Capture
    'SetWindowsHookExA':       {'category': 'keylogger',   'severity': ThreatSeverity.HIGH,     'weight': 15},
    'SetWindowsHookExW':       {'category': 'keylogger',   'severity': ThreatSeverity.HIGH,     'weight': 15},
    'GetAsyncKeyState':        {'category': 'keylogger',   'severity': ThreatSeverity.HIGH,     'weight': 12},
    'GetKeyboardState':        {'category': 'keylogger',   'severity': ThreatSeverity.HIGH,     'weight': 10},

    # Persistence
    'RegSetValueExA':          {'category': 'persistence', 'severity': ThreatSeverity.MEDIUM,   'weight': 6},
    'RegSetValueExW':          {'category': 'persistence', 'severity': ThreatSeverity.MEDIUM,   'weight': 6},
    'CreateServiceA':          {'category': 'persistence', 'severity': ThreatSeverity.HIGH,     'weight': 10},
    'CreateServiceW':          {'category': 'persistence', 'severity': ThreatSeverity.HIGH,     'weight': 10},

    # Network / Download
    'URLDownloadToFileA':      {'category': 'network',     'severity': ThreatSeverity.HIGH,     'weight': 12},
    'URLDownloadToFileW':      {'category': 'network',     'severity': ThreatSeverity.HIGH,     'weight': 12},
    'InternetOpenA':           {'category': 'network',     'severity': ThreatSeverity.MEDIUM,   'weight': 5},
    'InternetOpenW':           {'category': 'network',     'severity': ThreatSeverity.MEDIUM,   'weight': 5},
    'HttpSendRequestA':        {'category': 'network',     'severity': ThreatSeverity.MEDIUM,   'weight': 5},

    # Crypto (Ransomware indicators)
    'CryptEncrypt':            {'category': 'crypto',      'severity': ThreatSeverity.MEDIUM,   'weight': 8},
    'CryptDecrypt':            {'category': 'crypto',      'severity': ThreatSeverity.MEDIUM,   'weight': 5},
    'CryptGenKey':             {'category': 'crypto',      'severity': ThreatSeverity.MEDIUM,   'weight': 5},
    'CryptAcquireContextA':    {'category': 'crypto',      'severity': ThreatSeverity.LOW,      'weight': 3},

    # Shell Execution
    'ShellExecuteA':           {'category': 'execution',   'severity': ThreatSeverity.MEDIUM,   'weight': 5},
    'ShellExecuteW':           {'category': 'execution',   'severity': ThreatSeverity.MEDIUM,   'weight': 5},
    'WinExec':                 {'category': 'execution',   'severity': ThreatSeverity.MEDIUM,   'weight': 6},
    'CreateProcessA':          {'category': 'execution',   'severity': ThreatSeverity.LOW,      'weight': 3},
    'CreateProcessW':          {'category': 'execution',   'severity': ThreatSeverity.LOW,      'weight': 3},
}

# Known packer section names
PACKER_SIGNATURES = frozenset({
    'UPX0', 'UPX1', 'UPX2', 'UPX!',           # UPX
    '.themida', '.winlice',                     # Themida / WinLicense
    '.vmp0', '.vmp1', '.vmp2',                  # VMProtect
    '.aspack', '.adata',                        # ASPack
    '.nsp0', '.nsp1', '.nsp2',                  # NsPack
    '.petite',                                  # Petite
    '.yP', '.y0da',                             # yoda's Protector
    'MEW',                                      # MEW
    '.MPRESS1', '.MPRESS2',                     # MPRESS
    '.perplex',                                 # Perplex PE Protector
    'PECompact2',                               # PECompact
})

# Suspicious file locations (files from here are riskier)
SUSPICIOUS_LOCATIONS = [
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    os.path.join(os.environ.get("APPDATA", ""), "Local", "Temp"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
]

# Quick scan targets
QUICK_SCAN_PATHS = [
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
    os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    os.path.join(os.environ.get("PROGRAMDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
]

# ─── EICAR Test String ───────────────────────────────────────────────────────
# Standard antivirus test file (NOT malware — just a test signature)
EICAR_TEST_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"

# ─── Scan Performance ────────────────────────────────────────────────────────

DEFAULT_SCAN_THREADS = 4
HASH_CHUNK_SIZE = 65536  # 64 KB chunks for hashing
FILE_MONITOR_DEBOUNCE_SEC = 1.0  # Debounce repeated events for same file
