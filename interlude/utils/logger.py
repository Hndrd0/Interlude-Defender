"""
Hermes Antivirus — Logging setup.

Provides a configured rotating file logger + console output.
Logs are stored at %APPDATA%/Hermes/logs/hermes.log.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from hermes.utils.constants import LOG_DIR


def setup_logger(
    name: str = "hermes",
    level: int = logging.INFO,
    log_to_console: bool = True,
    log_to_file: bool = True,
    max_bytes: int = 5 * 1024 * 1024,  # 5 MB per log file
    backup_count: int = 3,
) -> logging.Logger:
    """
    Set up and return a configured logger.

    Args:
        name: Logger name (used as namespace).
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_to_console: Whether to output to stdout.
        log_to_file: Whether to write to rotating log file.
        max_bytes: Maximum log file size before rotation.
        backup_count: Number of backup log files to keep.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # Format
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler (rotating)
    if log_to_file:
        os.makedirs(LOG_DIR, exist_ok=True)
        log_file = os.path.join(LOG_DIR, f"{name}.log")
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# Pre-configured loggers for each subsystem
def get_logger(subsystem: str = "hermes") -> logging.Logger:
    """Get or create a logger for a specific subsystem."""
    return setup_logger(f"hermes.{subsystem}")
