"""
Hermes Antivirus — Configuration management.

Reads/writes a JSON config file at %APPDATA%/Hermes/config.json.
Provides default settings with user override support.
"""

import json
import os
import threading
from hermes.utils.constants import CONFIG_FILE, APP_DATA_DIR


DEFAULT_CONFIG = {
    # Real-time protection
    "realtime_protection": True,

    # Auto-scan on startup
    "auto_scan_startup": False,

    # Auto-update signatures
    "auto_update_signatures": True,

    # Scan archive files (ZIP, RAR, etc.)
    "scan_archives": True,

    # Show desktop notifications
    "show_notifications": True,

    # Scan schedule (24h format, empty = disabled)
    "scan_schedule_time": "",

    # Excluded paths (will not be scanned)
    "excluded_paths": [],

    # Excluded file extensions
    "excluded_extensions": [],

    # Maximum scan threads
    "scan_threads": 4,

    # Quarantine auto-cleanup days (0 = never)
    "quarantine_cleanup_days": 7,

    # UI settings
    "window_width": 1100,
    "window_height": 720,
    "window_x": -1,
    "window_y": -1,
    "minimize_to_tray": True,
    "start_minimized": False,

    # Monitoring paths (empty = all fixed drives)
    "monitor_paths": [],

    # First run flag
    "first_run": True,
}


class Config:
    """Thread-safe configuration manager with JSON persistence."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern — one config instance for the entire app."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._config = dict(DEFAULT_CONFIG)
        self._config_file = CONFIG_FILE
        self._file_lock = threading.RLock()
        self.load()

    def load(self):
        """Load config from disk, merging with defaults for any missing keys."""
        with self._file_lock:
            if os.path.exists(self._config_file):
                try:
                    with open(self._config_file, 'r', encoding='utf-8') as f:
                        user_config = json.load(f)
                    # Merge: user settings override defaults, but new default keys are added
                    self._config = {**DEFAULT_CONFIG, **user_config}
                except (json.JSONDecodeError, IOError):
                    # Corrupted config — reset to defaults
                    self._config = dict(DEFAULT_CONFIG)
                    self.save()
            else:
                # First run — create config file with defaults
                self._config = dict(DEFAULT_CONFIG)
                self.save()

    def save(self):
        """Persist current config to disk."""
        with self._file_lock:
            os.makedirs(os.path.dirname(self._config_file), exist_ok=True)
            try:
                with open(self._config_file, 'w', encoding='utf-8') as f:
                    json.dump(self._config, f, indent=2, ensure_ascii=False)
            except IOError:
                pass  # Silently fail if we can't write config

    def get(self, key: str, default=None):
        """Get a config value."""
        return self._config.get(key, default)

    def set(self, key: str, value):
        """Set a config value and persist to disk."""
        self._config[key] = value
        self.save()

    def get_all(self) -> dict:
        """Get a copy of all config values."""
        return dict(self._config)

    def reset(self):
        """Reset all settings to defaults."""
        self._config = dict(DEFAULT_CONFIG)
        self.save()

    def __getitem__(self, key: str):
        return self._config[key]

    def __setitem__(self, key: str, value):
        self.set(key, value)

    def __contains__(self, key: str) -> bool:
        return key in self._config
