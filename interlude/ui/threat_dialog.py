"""
Hermes Antivirus — Threat Detection Dialog.

A modal popup that alerts the user when a threat is detected, displaying
file details and offering Remove / Quarantine / Ignore actions.
Auto-dismisses after 30 seconds, defaulting to quarantine.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QWidget,
    QGraphicsDropShadowEffect,
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont

from hermes.utils.constants import ThreatSeverity


# ── Severity badge helpers ────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    ThreatSeverity.NONE:     "#9aa0a6",
    ThreatSeverity.LOW:      "#ffa502",
    ThreatSeverity.MEDIUM:   "#ffa502",
    ThreatSeverity.HIGH:     "#ff4757",
    ThreatSeverity.CRITICAL: "#ff4757",
}

_SEVERITY_LABELS = {
    ThreatSeverity.NONE:     "None",
    ThreatSeverity.LOW:      "Low",
    ThreatSeverity.MEDIUM:   "Medium",
    ThreatSeverity.HIGH:     "High",
    ThreatSeverity.CRITICAL: "Critical",
}


class ThreatDialog(QDialog):
    """Frameless, dark-themed threat detection popup dialog.

    Presents file path, threat name, severity badge, optional details,
    and three action buttons.  Returns the chosen action via ``exec()``.

    Attributes:
        chosen_action: One of ``'remove'``, ``'quarantine'``, ``'ignore'``.
    """

    def __init__(
        self,
        file_path: str,
        threat_name: str,
        severity: ThreatSeverity,
        details: dict | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self.chosen_action: str = "quarantine"  # default if auto-dismissed

        # ── Window flags ──────────────────────────────────────────────────
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setModal(True)
        self.setFixedWidth(500)

        # ── Build UI ──────────────────────────────────────────────────────
        self._build_ui(file_path, threat_name, severity, details)

        # ── Auto-dismiss timer (30 s → quarantine) ───────────────────────
        self._countdown = 30
        self._countdown_label: QLabel | None = None
        self._auto_timer = QTimer(self)
        self._auto_timer.setInterval(1000)
        self._auto_timer.timeout.connect(self._tick)
        self._auto_timer.start()

        # Centre on parent
        if parent is not None:
            geo = parent.geometry()
            self.move(
                geo.x() + (geo.width() - self.width()) // 2,
                geo.y() + (geo.height() - self.height()) // 2,
            )

    # ── UI Construction ───────────────────────────────────────────────────

    def _build_ui(
        self,
        file_path: str,
        threat_name: str,
        severity: ThreatSeverity,
        details: dict | None,
    ) -> None:
        """Assemble all child widgets."""

        # Outer wrapper for drop-shadow
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)

        card = QWidget()
        card.setObjectName("threatDialogCard")
        card.setStyleSheet(
            """
            #threatDialogCard {
                background-color: #111827;
                border: 1px solid rgba(255, 75, 87, 0.35);
                border-radius: 16px;
            }
            """
        )
        shadow = QGraphicsDropShadowEffect(card)
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 4)
        shadow.setColor(QColor(255, 71, 87, 90))
        card.setGraphicsEffect(shadow)

        layout = QVBoxLayout(card)
        layout.setSpacing(14)
        layout.setContentsMargins(28, 24, 28, 24)

        # ── Header ────────────────────────────────────────────────────────
        header = QHBoxLayout()
        icon_lbl = QLabel("⚠️")
        icon_lbl.setFont(QFont("Segoe UI Emoji", 28))
        header.addWidget(icon_lbl)

        title = QLabel("THREAT DETECTED")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        title.setStyleSheet("color: #ff4757; background: transparent;")
        header.addWidget(title)
        header.addStretch()
        layout.addLayout(header)

        # ── File path ─────────────────────────────────────────────────────
        path_lbl = QLabel(file_path)
        path_lbl.setWordWrap(True)
        path_lbl.setFont(QFont("Consolas", 10))
        path_lbl.setStyleSheet(
            "color: #9aa0a6; background: rgba(255,255,255,0.04); "
            "padding: 8px 12px; border-radius: 8px;"
        )
        layout.addWidget(path_lbl)

        # ── Threat name + severity row ────────────────────────────────────
        row = QHBoxLayout()
        name_lbl = QLabel(threat_name)
        name_lbl.setFont(QFont("Segoe UI", 13, QFont.DemiBold))
        name_lbl.setStyleSheet("color: #e8eaed; background: transparent;")
        row.addWidget(name_lbl)

        sev_color = _SEVERITY_COLORS.get(severity, "#9aa0a6")
        sev_text = _SEVERITY_LABELS.get(severity, "Unknown")
        badge = QLabel(f"  {sev_text}  ")
        badge.setFont(QFont("Segoe UI", 10, QFont.Bold))
        badge.setAlignment(Qt.AlignCenter)
        badge.setStyleSheet(
            f"color: #fff; background: {sev_color}; border-radius: 10px; "
            f"padding: 3px 10px;"
        )
        row.addWidget(badge)
        row.addStretch()
        layout.addLayout(row)

        # ── Optional details ──────────────────────────────────────────────
        if details:
            for key, value in details.items():
                detail_lbl = QLabel(f"{key}:  {value}")
                detail_lbl.setFont(QFont("Segoe UI", 10))
                detail_lbl.setStyleSheet("color: #9aa0a6; background: transparent; padding-left: 4px;")
                layout.addWidget(detail_lbl)

        layout.addSpacing(8)

        # ── Buttons ───────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        btn_style_base = (
            "QPushButton {{ "
            "   color: #fff; font-weight: 600; font-size: 13px; "
            "   padding: 10px 20px; border-radius: 10px; border: none; "
            "   background: {bg}; "
            "}} "
            "QPushButton:hover {{ background: {hover}; }}"
        )

        remove_btn = QPushButton("🗑  Remove")
        remove_btn.setStyleSheet(btn_style_base.format(bg="#ff4757", hover="#ff6b7f"))
        remove_btn.clicked.connect(lambda: self._finish("remove"))
        btn_row.addWidget(remove_btn)

        quarantine_btn = QPushButton("🛡️  Quarantine")
        quarantine_btn.setStyleSheet(btn_style_base.format(bg="#00d4aa", hover="#00e6bb"))
        quarantine_btn.clicked.connect(lambda: self._finish("quarantine"))
        btn_row.addWidget(quarantine_btn)

        ignore_btn = QPushButton("Ignore")
        ignore_btn.setStyleSheet(btn_style_base.format(bg="#5f6368", hover="#80868b"))
        ignore_btn.clicked.connect(lambda: self._finish("ignore"))
        btn_row.addWidget(ignore_btn)

        layout.addLayout(btn_row)

        # ── Countdown label ───────────────────────────────────────────────
        self._countdown_label = QLabel(f"Auto-quarantine in {self._countdown}s")
        self._countdown_label.setAlignment(Qt.AlignCenter)
        self._countdown_label.setFont(QFont("Segoe UI", 9))
        self._countdown_label.setStyleSheet("color: #5f6368; background: transparent;")
        layout.addWidget(self._countdown_label)

        outer.addWidget(card)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _tick(self) -> None:
        """Advance countdown; auto-quarantine when it reaches zero."""
        self._countdown -= 1
        if self._countdown_label is not None:
            self._countdown_label.setText(
                f"Auto-quarantine in {self._countdown}s"
            )
        if self._countdown <= 0:
            self._finish("quarantine")

    def _finish(self, action: str) -> None:
        """Store chosen action and close the dialog."""
        self._auto_timer.stop()
        self.chosen_action = action
        self.accept()

    # ── Public API ────────────────────────────────────────────────────────

    def get_action(self) -> str:
        """Return the user-chosen (or auto-chosen) action string.

        Call *after* ``exec()`` returns.
        """
        return self.chosen_action
