"""
Hermes Antivirus — System Tray Icon.

Provides a ``QSystemTrayIcon`` with a context menu, balloon notifications,
and a dynamically generated colored shield icon.
"""

from PySide6.QtWidgets import QSystemTrayIcon, QMenu
from PySide6.QtCore import QObject, Signal, Qt
from PySide6.QtGui import QPixmap, QPainter, QColor, QIcon, QBrush, QPen, QFont


class HermesTray(QObject):
    """System tray icon and context menu for Hermes Antivirus.

    Parameters:
        main_window: The main ``HermesApp`` window to show/hide.
        parent:      Optional ``QObject`` parent.
    """

    # Signals forwarded from menu actions
    quick_scan_requested = Signal()
    quit_requested = Signal()

    def __init__(self, main_window, parent=None) -> None:
        super().__init__(parent)
        self._main_window = main_window

        # ── Tray icon ─────────────────────────────────────────────────────
        self._tray = QSystemTrayIcon(self)
        self._tray.setIcon(self._create_icon("#00d4aa"))
        self._tray.setToolTip("Hermes Antivirus — Protected")

        # ── Context menu ──────────────────────────────────────────────────
        menu = QMenu()
        menu.setStyleSheet(
            """
            QMenu {
                background-color: #111827;
                color: #e8eaed;
                border: 1px solid rgba(255,255,255,0.08);
                border-radius: 8px;
                padding: 6px 0;
                font-size: 13px;
            }
            QMenu::item {
                padding: 8px 28px 8px 16px;
            }
            QMenu::item:selected {
                background: rgba(0, 212, 170, 0.15);
            }
            QMenu::separator {
                height: 1px;
                background: rgba(255,255,255,0.08);
                margin: 4px 12px;
            }
            """
        )

        show_action = menu.addAction("🏠  Show Dashboard")
        show_action.triggered.connect(self._show_main_window)

        menu.addSeparator()

        scan_action = menu.addAction("🔍  Quick Scan")
        scan_action.triggered.connect(self.quick_scan_requested.emit)

        menu.addSeparator()

        self._status_action = menu.addAction("✅  Status: Protected")
        self._status_action.setEnabled(False)

        menu.addSeparator()

        quit_action = menu.addAction("❌  Quit")
        quit_action.triggered.connect(self.quit_requested.emit)

        self._tray.setContextMenu(menu)

        # ── Double-click to show window ───────────────────────────────────
        self._tray.activated.connect(self._on_activated)

        self._tray.show()

    # ── Public Methods ────────────────────────────────────────────────────

    def show_threat_notification(self, title: str, message: str) -> None:
        """Display a balloon / toast notification for a detected threat."""
        if self._tray.supportsMessages():
            self._tray.showMessage(
                title,
                message,
                QSystemTrayIcon.Warning,
                8000,
            )

    def update_status(self, status_text: str, icon_color: str) -> None:
        """Update the tray icon colour and the status menu label."""
        self._tray.setIcon(self._create_icon(icon_color))
        self._status_action.setText(status_text)
        self._tray.setToolTip(f"Hermes Antivirus — {status_text}")

    def hide(self) -> None:
        """Hide the tray icon (on application exit)."""
        self._tray.hide()

    # ── Icon Generator ────────────────────────────────────────────────────

    @staticmethod
    def _create_icon(color: str) -> QIcon:
        """Generate a simple colored-circle icon programmatically.

        Args:
            color: CSS-style hex colour string, e.g. ``'#00d4aa'``.

        Returns:
            A ``QIcon`` containing a 64 × 64 coloured disc with an 'H'.
        """
        size = 64
        pixmap = QPixmap(size, size)
        pixmap.fill(QColor(0, 0, 0, 0))  # transparent background

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)

        # Filled circle
        painter.setBrush(QBrush(QColor(color)))
        painter.setPen(QPen(Qt.NoPen) if False else QPen(QColor(0, 0, 0, 0)))
        painter.setPen(QPen(QColor(0, 0, 0, 0)))
        painter.drawEllipse(4, 4, size - 8, size - 8)

        # Letter 'H'
        painter.setPen(QColor("#ffffff"))
        painter.setFont(QFont("Segoe UI", 26, QFont.Bold))
        painter.drawText(pixmap.rect(), Qt.AlignCenter, "H")

        painter.end()
        return QIcon(pixmap)

    # ── Private Slots ─────────────────────────────────────────────────────

    def _show_main_window(self) -> None:
        """Bring the main window to front."""
        self._main_window.showNormal()
        self._main_window.raise_()
        self._main_window.activateWindow()

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        """Handle tray icon double-click."""
        if reason == QSystemTrayIcon.DoubleClick:
            self._show_main_window()
