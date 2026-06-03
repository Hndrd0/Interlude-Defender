"""
Hermes Antivirus — Settings Page.

Five toggle switches (with a custom animated ``ToggleSwitch`` widget),
scan-exclusion list management, and an About section.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QFrame, QFileDialog, QSizePolicy,
)
from PySide6.QtCore import (
    Qt, Signal, Property, QPropertyAnimation, QEasingCurve, QSize, QRectF,
)
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QBrush, QPen

from hermes.utils.config import Config
from hermes.utils.constants import APP_NAME, APP_VERSION, APP_AUTHOR


# ═══════════════════════════════════════════════════════════════════════════════
#  ToggleSwitch — animated custom toggle
# ═══════════════════════════════════════════════════════════════════════════════

class ToggleSwitch(QWidget):
    """Custom animated toggle switch widget.

    Signals:
        toggled(bool): Emitted when the user toggles the switch.
    """

    toggled = Signal(bool)

    _TRACK_OFF = QColor("#5f6368")
    _TRACK_ON = QColor("#00d4aa")
    _KNOB = QColor("#ffffff")

    def __init__(self, parent: Optional[QWidget] = None, checked: bool = False) -> None:
        super().__init__(parent)
        self._checked = checked
        self._knob_x: float = 1.0 if not checked else 21.0

        self.setFixedSize(QSize(46, 26))
        self.setCursor(Qt.PointingHandCursor)

        self._anim = QPropertyAnimation(self, b"knob_x")
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.InOutCubic)

    # ── Qt property for animation ─────────────────────────────────────────

    def _get_knob_x(self) -> float:
        return self._knob_x

    def _set_knob_x(self, val: float) -> None:
        self._knob_x = val
        self.update()

    knob_x = Property(float, _get_knob_x, _set_knob_x)

    # ── Checked property ──────────────────────────────────────────────────

    @property
    def checked(self) -> bool:
        return self._checked

    @checked.setter
    def checked(self, value: bool) -> None:
        if value == self._checked:
            return
        self._checked = value
        self._animate()

    # ── Paint ─────────────────────────────────────────────────────────────

    def paintEvent(self, _event) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        radius = h / 2

        # Track
        track_color = self._TRACK_ON if self._checked else self._TRACK_OFF
        p.setBrush(QBrush(track_color))
        p.setPen(QPen(Qt.NoPen))
        p.drawRoundedRect(QRectF(0, 0, w, h), radius, radius)

        # Knob
        knob_r = h - 6
        p.setBrush(QBrush(self._KNOB))
        p.drawEllipse(QRectF(self._knob_x + 3, 3, knob_r, knob_r))

        p.end()

    # ── Interaction ───────────────────────────────────────────────────────

    def mousePressEvent(self, _event) -> None:  # noqa: N802
        self._checked = not self._checked
        self._animate()
        self.toggled.emit(self._checked)

    def _animate(self) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._knob_x)
        self._anim.setEndValue(21.0 if self._checked else 1.0)
        self._anim.start()

    # ── Programmatic set (no signal) ──────────────────────────────────────

    def set_checked_no_signal(self, val: bool) -> None:
        """Set state without emitting ``toggled``."""
        self._checked = val
        self._knob_x = 21.0 if val else 1.0
        self.update()


# ═══════════════════════════════════════════════════════════════════════════════
#  SettingsPage
# ═══════════════════════════════════════════════════════════════════════════════

class SettingsPage(QWidget):
    """Settings page with 5 toggles, exclusion-path management, and About."""

    def __init__(self, config: Config, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._config = config
        self.setObjectName("settingsPage")
        self._exclusion_widgets: list[QWidget] = []
        self._build_ui()
        self._load_from_config()

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent; border: none;")

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 24, 32, 24)
        layout.setSpacing(10)

        # Page title
        title = QLabel("Settings")
        title.setFont(QFont("Segoe UI", 22, QFont.Bold))
        title.setStyleSheet("color: #e8eaed; background: transparent;")
        layout.addWidget(title)
        layout.addSpacing(8)

        # ── Protection section ────────────────────────────────────────────
        layout.addWidget(self._section_label("Protection"))

        self._tog_rtp = self._toggle_row(
            "Real-time Protection",
            "Monitor files as they are accessed",
            layout,
        )
        self._tog_autoscan = self._toggle_row(
            "Auto-scan on Startup",
            "Run a quick scan when the app launches",
            layout,
        )
        self._tog_autoupdate = self._toggle_row(
            "Auto-update Signatures",
            "Download latest threat definitions automatically",
            layout,
        )

        layout.addSpacing(12)

        # ── Scanning section ──────────────────────────────────────────────
        layout.addWidget(self._section_label("Scanning"))

        self._tog_archives = self._toggle_row(
            "Scan Archive Files",
            "Inspect contents of ZIP, RAR, 7z etc.",
            layout,
        )
        self._tog_notif = self._toggle_row(
            "Show Notifications",
            "Desktop alerts for scan results and threats",
            layout,
        )

        layout.addSpacing(12)

        # ── Exclusions section ────────────────────────────────────────────
        layout.addWidget(self._section_label("Scan Exclusions"))

        self._exclusion_container = QVBoxLayout()
        self._exclusion_container.setSpacing(6)
        layout.addLayout(self._exclusion_container)

        add_btn = QPushButton("➕  Add Exclusion")
        add_btn.setFont(QFont("Segoe UI", 11, QFont.DemiBold))
        add_btn.setCursor(Qt.PointingHandCursor)
        add_btn.setStyleSheet(
            """
            QPushButton {
                background: rgba(255,255,255,0.06);
                color: #00d4aa;
                border: 1px dashed rgba(0,212,170,0.4);
                border-radius: 10px;
                padding: 10px 18px;
            }
            QPushButton:hover {
                background: rgba(0,212,170,0.1);
                border-color: #00d4aa;
            }
            """
        )
        add_btn.clicked.connect(self._add_exclusion_dialog)
        layout.addWidget(add_btn)

        layout.addSpacing(18)

        # ── About section ─────────────────────────────────────────────────
        layout.addWidget(self._section_label("About"))

        about_card = QWidget()
        about_card.setStyleSheet(
            "background: rgba(255,255,255,0.03); border-radius: 14px;"
        )
        ac = QVBoxLayout(about_card)
        ac.setContentsMargins(20, 18, 20, 18)
        ac.setSpacing(6)

        app_lbl = QLabel(f"🛡️  {APP_NAME}")
        app_lbl.setFont(QFont("Segoe UI", 15, QFont.Bold))
        app_lbl.setStyleSheet("color: #e8eaed; background: transparent;")
        ac.addWidget(app_lbl)

        ver_lbl = QLabel(f"Version {APP_VERSION}")
        ver_lbl.setFont(QFont("Segoe UI", 11))
        ver_lbl.setStyleSheet("color: #9aa0a6; background: transparent;")
        ac.addWidget(ver_lbl)

        author_lbl = QLabel(f"by {APP_AUTHOR}")
        author_lbl.setFont(QFont("Segoe UI", 11))
        author_lbl.setStyleSheet("color: #9aa0a6; background: transparent;")
        ac.addWidget(author_lbl)

        ac.addSpacing(6)
        motto = QLabel("No tracking. No subscriptions. No dark patterns.")
        motto_font = QFont("Segoe UI", 10)
        motto_font.setItalic(True)
        motto.setFont(motto_font)
        motto.setStyleSheet("color: #00d4aa; background: transparent;")
        ac.addWidget(motto)

        layout.addWidget(about_card)
        layout.addStretch()

        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    # ── Widget factories ──────────────────────────────────────────────────

    @staticmethod
    def _section_label(text: str) -> QLabel:
        lbl = QLabel(text.upper())
        lbl.setFont(QFont("Segoe UI", 10, QFont.Bold))
        lbl.setStyleSheet(
            "color: #9aa0a6; background: transparent; "
            "letter-spacing: 1.5px; padding-top: 8px; padding-bottom: 2px;"
        )
        return lbl

    def _toggle_row(self, title: str, subtitle: str, parent_layout: QVBoxLayout) -> ToggleSwitch:
        """Create a row with label + subtitle on the left and toggle on the right."""
        row = QWidget()
        row.setStyleSheet(
            "background: rgba(255,255,255,0.03); border-radius: 12px;"
        )
        rl = QHBoxLayout(row)
        rl.setContentsMargins(18, 12, 18, 12)
        rl.setSpacing(12)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        t = QLabel(title)
        t.setFont(QFont("Segoe UI", 13))
        t.setStyleSheet("color: #e8eaed; background: transparent;")
        text_col.addWidget(t)
        s = QLabel(subtitle)
        s.setFont(QFont("Segoe UI", 10))
        s.setStyleSheet("color: #9aa0a6; background: transparent;")
        text_col.addWidget(s)
        rl.addLayout(text_col, 1)

        toggle = ToggleSwitch()
        rl.addWidget(toggle, 0, Qt.AlignRight | Qt.AlignVCenter)
        parent_layout.addWidget(row)
        return toggle

    # ── Exclusion management ──────────────────────────────────────────────

    def _add_exclusion_row(self, path: str) -> None:
        """Add a removable exclusion-path row."""
        row = QWidget()
        row.setStyleSheet(
            "background: rgba(255,255,255,0.03); border-radius: 10px;"
        )
        rl = QHBoxLayout(row)
        rl.setContentsMargins(14, 8, 14, 8)

        path_lbl = QLabel(path)
        path_lbl.setFont(QFont("Segoe UI", 10))
        path_lbl.setStyleSheet("color: #e8eaed; background: transparent;")
        path_lbl.setWordWrap(True)
        rl.addWidget(path_lbl, 1)

        rm_btn = QPushButton("✕")
        rm_btn.setFixedSize(28, 28)
        rm_btn.setCursor(Qt.PointingHandCursor)
        rm_btn.setStyleSheet(
            """
            QPushButton {
                background: rgba(255,71,87,0.15);
                color: #ff4757; border: none; border-radius: 14px;
                font-weight: bold; font-size: 12px;
            }
            QPushButton:hover { background: rgba(255,71,87,0.3); }
            """
        )
        rm_btn.clicked.connect(lambda _=False, r=row, p=path: self._remove_exclusion(r, p))
        rl.addWidget(rm_btn)

        self._exclusion_container.addWidget(row)
        self._exclusion_widgets.append(row)

    def _add_exclusion_dialog(self) -> None:
        """Open a folder picker and add the selected path as an exclusion."""
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Exclude")
        if folder:
            exclusions: list = self._config.get("excluded_paths", [])
            if folder not in exclusions:
                exclusions.append(folder)
                self._config.set("excluded_paths", exclusions)
                self._add_exclusion_row(folder)

    def _remove_exclusion(self, row_widget: QWidget, path: str) -> None:
        exclusions: list = self._config.get("excluded_paths", [])
        if path in exclusions:
            exclusions.remove(path)
            self._config.set("excluded_paths", exclusions)
        row_widget.setParent(None)
        row_widget.deleteLater()
        if row_widget in self._exclusion_widgets:
            self._exclusion_widgets.remove(row_widget)

    # ── Config load / save ────────────────────────────────────────────────

    def _load_from_config(self) -> None:
        """Populate all controls from the current ``Config``."""
        self._tog_rtp.set_checked_no_signal(self._config.get("realtime_protection", True))
        self._tog_autoscan.set_checked_no_signal(self._config.get("auto_scan_startup", False))
        self._tog_autoupdate.set_checked_no_signal(self._config.get("auto_update_signatures", True))
        self._tog_archives.set_checked_no_signal(self._config.get("scan_archives", True))
        self._tog_notif.set_checked_no_signal(self._config.get("show_notifications", True))

        # Connect signals *after* loading to avoid unnecessary writes
        self._tog_rtp.toggled.connect(lambda v: self._config.set("realtime_protection", v))
        self._tog_autoscan.toggled.connect(lambda v: self._config.set("auto_scan_startup", v))
        self._tog_autoupdate.toggled.connect(lambda v: self._config.set("auto_update_signatures", v))
        self._tog_archives.toggled.connect(lambda v: self._config.set("scan_archives", v))
        self._tog_notif.toggled.connect(lambda v: self._config.set("show_notifications", v))

        # Exclusions
        for path in self._config.get("excluded_paths", []):
            self._add_exclusion_row(path)
