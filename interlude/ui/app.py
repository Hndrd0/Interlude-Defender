"""
Hermes Antivirus — Main Application Window.

The main window shell that contains the custom title bar, sidebar navigation,
and a QStackedWidget containing the dashboard, scan, quarantine, and settings pages.
Supports a frameless window with custom title bar dragging, minimize/close,
and system tray integration.
"""

from __future__ import annotations

import os
from typing import Optional

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QStackedWidget, QMessageBox, QFileDialog, QButtonGroup, QGraphicsDropShadowEffect,
    QApplication,
)
from PySide6.QtCore import Qt, QPoint, QSize
from PySide6.QtGui import QIcon, QFont, QMouseEvent, QColor, QScreen

from hermes.ui.theme import HermesTheme
from hermes.ui.dashboard import DashboardPage
from hermes.ui.scan_page import ScanPage
from hermes.ui.quarantine_page import QuarantinePage
from hermes.ui.settings_page import SettingsPage
from hermes.ui.tray import HermesTray


class HermesApp(QMainWindow):
    """Main dashboard window shell for Hermes Antivirus."""

    def __init__(
        self,
        scanner,
        db,
        quarantine_manager,
        config,
        file_monitor=None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("mainWindow")

        self._scanner = scanner
        self._db = db
        self._qm = quarantine_manager
        self._config = config
        self._file_monitor = file_monitor

        # Dragging support for frameless window
        self._drag_position: QPoint = QPoint()
        self._drag_active = False

        # Set up window properties
        self.setWindowFlags(Qt.WindowFlags(Qt.FramelessWindowHint | Qt.WindowMinimizeButtonHint))
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setMinimumSize(900, 600)
        self.resize(1100, 720)

        # Build UI structure
        self._build_ui()

        # Set up tray
        self._tray: Optional[HermesTray] = None
        self._setup_tray()

        # Connect signals
        self._connect_signals()

        # Theme & Styling
        self.setStyleSheet(HermesTheme.get_stylesheet())

        # Center on screen and load config geometry
        self._restore_position()

    def _build_ui(self) -> None:
        # Root widget allows transparent margins/rounded corners with shadow
        self._root_widget = QWidget(self)
        self._root_widget.setObjectName("rootWidget")
        self._root_widget.setStyleSheet(
            f"""
            QWidget#rootWidget {{
                background-color: {HermesTheme.BG_PRIMARY};
                border: 1px solid {HermesTheme.BORDER};
                border-radius: {HermesTheme.RADIUS_LG}px;
            }}
            """
        )

        root_layout = QVBoxLayout(self._root_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Custom Title Bar
        self._title_bar = self._create_title_bar()
        root_layout.addWidget(self._title_bar)

        # Main content row: Sidebar + Stacked Content Area
        content_row = QWidget()
        content_layout = QHBoxLayout(content_row)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # 2. Sidebar Navigation
        self._sidebar = self._create_sidebar()
        content_layout.addWidget(self._sidebar)

        # 3. Stacked Widget Pages
        self._stacked_widget = QStackedWidget()
        
        self.dashboard_page = DashboardPage(self)
        # Override auto-refresh on dashboard
        self.dashboard_page._auto_refresh = self._refresh_dashboard_stats

        self.scan_page = ScanPage(self._scanner, self)
        self.quarantine_page = QuarantinePage(self._qm, self._db, self)
        self.settings_page = SettingsPage(self._config, self)

        self._stacked_widget.addWidget(self.dashboard_page)  # Index 0
        self._stacked_widget.addWidget(self.scan_page)       # Index 1
        self._stacked_widget.addWidget(self.quarantine_page) # Index 2
        self._stacked_widget.addWidget(self.settings_page)   # Index 3

        content_layout.addWidget(self._stacked_widget, 1)
        root_layout.addWidget(content_row, 1)

        self.setCentralWidget(self._root_widget)

        # Add window drop shadow
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setOffset(0, 4)
        shadow.setColor(QColor(0, 0, 0, 120))
        self._root_widget.setGraphicsEffect(shadow)

    def _create_title_bar(self) -> QWidget:
        tb = QWidget()
        tb.setObjectName("titleBar")
        tb.setFixedHeight(48)
        tb.setStyleSheet(
            f"""
            QWidget#titleBar {{
                background-color: {HermesTheme.BG_SECONDARY};
                border-bottom: 1px solid {HermesTheme.BORDER};
                border-top-left-radius: {HermesTheme.RADIUS_LG}px;
                border-top-right-radius: {HermesTheme.RADIUS_LG}px;
            }}
            """
        )

        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(16, 0, 16, 0)
        tbl.setSpacing(8)

        # Logo and title
        logo = QLabel("🛡️")
        logo.setFont(QFont("Segoe UI Emoji", 14))
        logo.setStyleSheet("background: transparent;")
        tbl.addWidget(logo)

        title = QLabel("INTERLUDE DEFENDER")
        title.setObjectName("appTitle")
        title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        title.setStyleSheet(f"color: {HermesTheme.TEXT_PRIMARY}; background: transparent; letter-spacing: 1px;")
        tbl.addWidget(title)

        tbl.addStretch()

        # Minimize & Maximize & Close buttons
        btn_min = QPushButton("🗕")
        btn_min.setFixedSize(32, 32)
        btn_min.setCursor(Qt.PointingHandCursor)
        btn_min.setStyleSheet(
            f"""
            QPushButton {{
                background: transparent; color: {HermesTheme.TEXT_SECONDARY};
                border: none; border-radius: 6px; font-size: 14px;
            }}
            QPushButton:hover {{ background: rgba(255,255,255,0.06); color: {HermesTheme.TEXT_PRIMARY}; }}
            """
        )
        btn_min.clicked.connect(self.showMinimized)
        tbl.addWidget(btn_min)

        self._btn_max = QPushButton("🗖")
        self._btn_max.setFixedSize(32, 32)
        self._btn_max.setCursor(Qt.PointingHandCursor)
        self._btn_max.setStyleSheet(
            f"""
            QPushButton {{
                background: transparent; color: {HermesTheme.TEXT_SECONDARY};
                border: none; border-radius: 6px; font-size: 12px;
            }}
            QPushButton:hover {{ background: rgba(255,255,255,0.06); color: {HermesTheme.TEXT_PRIMARY}; }}
            """
        )
        self._btn_max.clicked.connect(self._toggle_maximize)
        tbl.addWidget(self._btn_max)

        btn_close = QPushButton("✕")
        btn_close.setFixedSize(32, 32)
        btn_close.setCursor(Qt.PointingHandCursor)
        btn_close.setStyleSheet(
            f"""
            QPushButton {{
                background: transparent; color: {HermesTheme.TEXT_SECONDARY};
                border: none; border-radius: 6px; font-size: 14px;
            }}
            QPushButton:hover {{ background: {HermesTheme.DANGER}; color: #ffffff; }}
            """
        )
        btn_close.clicked.connect(self.close)
        tbl.addWidget(btn_close)

        return tb

    def _create_sidebar(self) -> QWidget:
        sb = QWidget()
        sb.setObjectName("sidebar")
        sb.setFixedWidth(220)
        sb.setStyleSheet(
            f"""
            QWidget#sidebar {{
                background-color: {HermesTheme.BG_SECONDARY};
                border-right: 1px solid {HermesTheme.BORDER};
                border-bottom-left-radius: {HermesTheme.RADIUS_LG}px;
            }}
            """
        )

        sbl = QVBoxLayout(sb)
        sbl.setContentsMargins(0, 16, 0, 16)
        sbl.setSpacing(0)

        # Nav Buttons Group
        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)

        self._btn_dash = self._create_nav_btn("🏠  Dashboard", 0)
        self._btn_scan = self._create_nav_btn("🔍  Scan System", 1)
        self._btn_quar = self._create_nav_btn("🛡️  Quarantine", 2)
        self._btn_sett = self._create_nav_btn("⚙️  Settings", 3)

        sbl.addWidget(self._btn_dash)
        sbl.addWidget(self._btn_scan)
        sbl.addWidget(self._btn_quar)
        sbl.addWidget(self._btn_sett)

        sbl.addStretch()

        # Bottom Version text
        ver = QLabel("v1.0.0-alpha")
        ver.setFont(QFont("Segoe UI", 9))
        ver.setAlignment(Qt.AlignCenter)
        ver.setStyleSheet(f"color: {HermesTheme.TEXT_MUTED}; background: transparent;")
        sbl.addWidget(ver)

        # Default selection
        self._btn_dash.setChecked(True)

        return sb

    def _create_nav_btn(self, text: str, page_index: int) -> QPushButton:
        btn = QPushButton(text)
        btn.setObjectName("navButton")
        btn.setCheckable(True)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setFixedHeight(50)
        self._nav_group.addButton(btn, page_index)
        btn.clicked.connect(lambda: self._switch_page(page_index))
        return btn

    def _switch_page(self, index: int) -> None:
        self._stacked_widget.setCurrentIndex(index)
        # Update checked button visually if switched programmatically
        btn = self._nav_group.button(index)
        if btn and not btn.isChecked():
            btn.setChecked(True)

        # Refresh page specifics if needed
        if index == 0:
            self.dashboard_page._auto_refresh()
        elif index == 2:
            self.quarantine_page.refresh()

    def _connect_signals(self) -> None:
        # Dashboard quick actions
        self.dashboard_page.quick_scan_requested.connect(self._on_quick_scan)
        self.dashboard_page.full_scan_requested.connect(self._on_full_scan)
        self.dashboard_page.custom_scan_requested.connect(self._on_custom_scan)

    def _setup_tray(self) -> None:
        try:
            self._tray = HermesTray(self, self)
            self._tray.quick_scan_requested.connect(self._on_quick_scan)
            self._tray.quit_requested.connect(self._force_quit)
        except Exception as e:
            print(f"Failed to load system tray: {e}")

    def _refresh_dashboard_stats(self) -> None:
        """Fetch statistics from database and update DashboardPage UI."""
        try:
            stats = {}
            if self._db:
                stats = self._db.get_stats()
            
            # Map database keys to dashboard expected dictionary format
            # Db.get_stats() returns: total_scans, total_threats, total_files_scanned, total_quarantined
            # Let's map them:
            dashboard_stats = {
                "realtime_protection": self._config.get("realtime_protection", True) if self._config else True,
                "threats_blocked": stats.get("total_threats", 0),
                "files_scanned": stats.get("total_files_scanned", 0),
            }

            # Query last scan history
            if self._db:
                history = self._db.get_scan_history(limit=1)
                if history:
                    import datetime
                    # start_time is stored as a float timestamp in scan_history
                    last_scan_ts = history[0].get("start_time")
                    if last_scan_ts:
                        dashboard_stats["last_scan"] = datetime.datetime.fromtimestamp(last_scan_ts)

                # Feed recent activity lists
                recent = self._db.get_scan_history(limit=5)
                # clear previous dashboard activity items programmatically by re-adding them
                # DashboardPage handles adding activity directly
                for item in reversed(recent):
                    mode = item.get("scan_mode", "scan").capitalize()
                    status = item.get("status", "completed")
                    threats = item.get("threats_found", 0)
                    time_float = item.get("start_time", 0)
                    import datetime
                    time_str = datetime.datetime.fromtimestamp(time_float).strftime("%H:%M:%S")
                    activity_text = f"{mode} scan {status} ({threats} threat{'s' if threats != 1 else ''} found)"
                    self.dashboard_page.add_activity(activity_text, time_str)

            self.dashboard_page.update_stats(dashboard_stats)

        except Exception as e:
            print(f"Error refreshing dashboard stats: {e}")

    # ── Scan Operations ───────────────────────────────────────────────────

    def _on_quick_scan(self) -> None:
        self._switch_page(1)
        self.scan_page.start_scan("quick")

    def _on_full_scan(self) -> None:
        self._switch_page(1)
        self.scan_page.start_scan("full")

    def _on_custom_scan(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self._switch_page(1)
            self.scan_page.start_scan("custom", [folder])

    # ── Window Dragging for Frameless Layout ──────────────────────────────

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            # Only drag from the custom title bar
            if self._title_bar.rect().contains(self._title_bar.mapFromParent(event.position().toPoint())):
                self._drag_position = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
                self._drag_active = True
                event.accept()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if Qt.LeftButton and self._drag_active:
            self.move(event.globalPosition().toPoint() - self._drag_position)
            event.accept()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        self._drag_active = False
        event.accept()

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            if self._title_bar.rect().contains(self._title_bar.mapFromParent(event.position().toPoint())):
                self._toggle_maximize()
                event.accept()

    def _toggle_maximize(self) -> None:
        if self.isMaximized():
            self.showNormal()
            self._btn_max.setText("🗖")
            self._root_widget.setStyleSheet(
                f"QWidget#rootWidget {{ background-color: {HermesTheme.BG_PRIMARY}; border: 1px solid {HermesTheme.BORDER}; border-radius: {HermesTheme.RADIUS_LG}px; }}"
            )
        else:
            self.showMaximized()
            self._btn_max.setText("🗗")
            self._root_widget.setStyleSheet(
                f"QWidget#rootWidget {{ background-color: {HermesTheme.BG_PRIMARY}; border: none; border-radius: 0px; }}"
            )

    # ── Window position save/restore ──────────────────────────────────────

    def _restore_position(self) -> None:
        # Center the window initially
        primary = QApplication.primaryScreen()
        if primary:
            screen = primary.availableGeometry()
            size = self.geometry()
            x = (screen.width() - size.width()) // 2
            y = (screen.height() - size.height()) // 2
            self.move(x, y)

        if self._config:
            geom = self._config.get("window_geometry", None)
            if geom:
                # geom expected as string format "x,y,w,h"
                try:
                    parts = [int(p) for p in geom.split(",")]
                    if len(parts) == 4:
                        self.setGeometry(parts[0], parts[1], parts[2], parts[3])
                except Exception:
                    pass

    def _save_position(self) -> None:
        if self._config:
            geom = self.geometry()
            geom_str = f"{geom.x()},{geom.y()},{geom.width()},{geom.height()}"
            self._config.set("window_geometry", geom_str)

    # ── Close Events & Lifecycle ──────────────────────────────────────────

    def closeEvent(self, event) -> None:  # noqa: N802
        # If notifications/tray mode enabled, minimize to system tray instead of closing
        if self._config and self._config.get("show_notifications", True) and self._tray:
            self.hide()
            event.ignore()
            # Show a balloon bubble notification to tell user it's minimized
            self._tray.show_threat_notification(
                "Interlude Defender",
                "Interlude is still running in the background to protect your system."
            )
        else:
            self._force_quit()

    def _force_quit(self) -> None:
        self._save_position()
        if self._tray:
            self._tray.hide()
        if self._file_monitor:
            self._file_monitor.stop()
        # Finally exit the QApplication
        from PySide6.QtWidgets import QApplication
        QApplication.quit()
