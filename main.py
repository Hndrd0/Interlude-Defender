"""
Hermes Antivirus — Entry Point

Usage:
    python main.py              Launch GUI dashboard
    python main.py --scan       Run quick scan (CLI mode)
    python main.py --background Start in system tray only
    python main.py --help       Show help
"""

import sys
import os
import argparse
import ctypes
import threading

# Ensure the project root is in the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def is_already_running() -> bool:
    """Check if another instance of Interlude is already running (Windows mutex)."""
    try:
        mutex_name = "InterludeDefenderMutex_v1"
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexW(None, True, mutex_name)
        last_error = kernel32.GetLastError()
        if last_error == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(mutex)
            return True
        # Keep mutex alive — it's released when the process exits
        return False
    except Exception:
        return False  # Can't check — allow launch


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="interlude",
        description="Interlude Defender — Next-Generation Threat Detection",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run a quick scan in CLI mode (no GUI)",
    )
    parser.add_argument(
        "--full-scan",
        action="store_true",
        help="Run a full scan in CLI mode (no GUI)",
    )
    parser.add_argument(
        "--scan-path",
        type=str,
        default=None,
        help="Scan a specific path in CLI mode",
    )
    parser.add_argument(
        "--background",
        action="store_true",
        help="Start in system tray only (no dashboard window)",
    )
    parser.add_argument(
        "--no-monitor",
        action="store_true",
        help="Disable real-time file monitoring",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def init_engines():
    """Initialize all detection engines and managers."""
    from hermes.core.database import Database
    from hermes.core.signatures import SignatureEngine
    from hermes.core.heuristics import HeuristicEngine
    from hermes.core.quarantine import QuarantineManager
    from hermes.core.scanner import Scanner
    from hermes.utils.config import Config

    # Initialize database
    db = Database()

    # Initialize detection engines
    sig_engine = SignatureEngine(db)
    heur_engine = HeuristicEngine()
    quarantine_mgr = QuarantineManager(db)

    # Initialize scanner
    scanner = Scanner(db, sig_engine, heur_engine, quarantine_mgr)

    # Configuration
    config = Config()

    return db, scanner, quarantine_mgr, config


def run_cli_scan(args):
    """Run a scan in CLI mode (no GUI)."""
    import logging
    from hermes.utils.logger import setup_logger

    level = logging.DEBUG if args.debug else logging.INFO
    logger = setup_logger("hermes", level=level)

    logger.info("Interlude Defender — CLI Mode")
    logger.info("Initializing detection engines...")

    db, scanner, quarantine_mgr, config = init_engines()

    if args.scan_path:
        logger.info(f"Scanning path: {args.scan_path}")
        threats = scanner.custom_scan(
            paths=[args.scan_path],
            callback=lambda pct, f, t: print(f"\r  [{pct:3d}%] Scanning: {os.path.basename(f)[:50]:<50}", end=""),
        )
    elif args.full_scan:
        logger.info("Starting full system scan...")
        threats = scanner.full_scan(
            callback=lambda pct, f, t: print(f"\r  [{pct:3d}%] Scanning: {os.path.basename(f)[:50]:<50}", end=""),
        )
    else:
        logger.info("Starting quick scan...")
        threats = scanner.quick_scan(
            callback=lambda pct, f, t: print(f"\r  [{pct:3d}%] Scanning: {os.path.basename(f)[:50]:<50}", end=""),
        )

    print()  # New line after progress
    stats = scanner.get_scan_stats()

    print("\n" + "=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)
    print(f"  Files scanned:  {stats.get('files_scanned', 0):,}")
    print(f"  Threats found:  {stats.get('threats_found', 0)}")
    print(f"  Scan time:      {stats.get('elapsed_time', 0):.1f}s")
    print(f"  Scan speed:     {stats.get('scan_speed', 0):.0f} files/min")
    print("=" * 60)

    if threats:
        print("\n  ⚠️  THREATS DETECTED:\n")
        for t in threats:
            print(f"  🔴 {t.threat_name}")
            print(f"     File: {t.file_path}")
            print(f"     Severity: {t.threat_severity.name}")
            print(f"     Detection: {t.detection_method}")
            print()
    else:
        print("\n  ✅ No threats found. Your system is clean.\n")


def run_gui(args):
    """Launch the PySide6 dashboard GUI."""
    import logging
    from hermes.utils.logger import setup_logger

    level = logging.DEBUG if args.debug else logging.INFO
    logger = setup_logger("hermes", level=level)

    logger.info("Interlude Defender — Starting GUI")

    # Initialize engines
    db, scanner, quarantine_mgr, config = init_engines()

    # Initialize file monitor if enabled
    file_monitor = None
    if not args.no_monitor and config.get("realtime_protection", True):
        try:
            from hermes.monitor.file_monitor import FileMonitor
            file_monitor = FileMonitor(scanner, config)
            file_monitor.start()
            logger.info("Real-time file monitoring started")
        except Exception as e:
            logger.warning(f"Could not start file monitor: {e}")

    # Launch PySide6 UI
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont
    from hermes.ui.app import HermesApp

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("Interlude Defender")
    app.setApplicationVersion("1.0.0-alpha")

    # Set default font
    font = QFont("Segoe UI", 10)
    app.setFont(font)

    # Prevent app quit when window is closed (tray keeps running)
    app.setQuitOnLastWindowClosed(False)

    # Create main window
    window = HermesApp(
        scanner=scanner,
        db=db,
        quarantine_manager=quarantine_mgr,
        config=config,
        file_monitor=file_monitor,
    )

    if args.background:
        logger.info("Starting in background mode (system tray)")
    else:
        window.show()

    # Run event loop
    exit_code = app.exec()

    # Cleanup
    logger.info("Shutting down...")
    if file_monitor:
        file_monitor.stop()

    sys.exit(exit_code)


def main():
    """Main entry point."""
    args = parse_args()

    # Single-instance check
    if is_already_running():
        print("Interlude Defender is already running.")
        sys.exit(1)

    # CLI scan mode
    if args.scan or args.full_scan or args.scan_path:
        run_cli_scan(args)
    else:
        run_gui(args)


if __name__ == "__main__":
    main()
