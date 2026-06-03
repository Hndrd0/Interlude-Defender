"""
Hermes Antivirus — Threat display card widget.

A compact card that represents a single detected threat.  It shows the file
path, threat name, and severity level, along with *Quarantine*, *Remove*, and
*Ignore* action buttons.  A thin colour bar on the left edge gives an
at-a-glance severity indication.

Usage::

    card = ThreatCard(
        file_path=r"C:\\Users\\admin\\Downloads\\sketch.exe",
        threat_name="Trojan.GenericKD.46543210",
        severity="HIGH",
    )
    card.quarantine_clicked.connect(handle_quarantine)
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from hermes.ui.theme import HermesTheme

# Severity → colour mapping
_SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": HermesTheme.DANGER,
    "HIGH":     "#ff6b7a",
    "MEDIUM":   HermesTheme.WARNING,
    "LOW":      HermesTheme.SUCCESS,
}


class ThreatCard(QFrame):
    """Card that displays a single detected threat with action buttons.

    Signals:
        quarantine_clicked(str): Emitted with the *file_path* when the
            Quarantine button is pressed.
        remove_clicked(str): Emitted with the *file_path* when the Remove
            button is pressed.
        ignore_clicked(str): Emitted with the *file_path* when the Ignore
            button is pressed.

    Args:
        file_path: Absolute path to the suspicious file.
        threat_name: Name/identifier of the detected threat.
        severity: One of ``'CRITICAL'``, ``'HIGH'``, ``'MEDIUM'``, ``'LOW'``.
        parent: Optional parent widget.
    """

    quarantine_clicked = Signal(str)
    remove_clicked = Signal(str)
    ignore_clicked = Signal(str)

    def __init__(
        self,
        file_path: str,
        threat_name: str,
        severity: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._file_path = file_path
        self._threat_name = threat_name
        self._severity = severity.upper()

        self.setObjectName("glassCard")
        self.setFixedHeight(90)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        # ── Drop shadow ──────────────────────────────────────────────────
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(12)
        shadow.setOffset(0, 2)
        shadow.setColor(QColor(0, 0, 0, 60))
        self.setGraphicsEffect(shadow)

        self._build_ui()

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Assemble the card layout: colour bar | info | actions."""
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 12, 0)
        root.setSpacing(0)

        # ── Severity colour bar ──────────────────────────────────────────
        bar = QFrame(self)
        bar.setFixedWidth(4)
        bar.setStyleSheet(
            f"background-color: {self._severity_color()};"
            f"border-radius: 2px;"
        )
        root.addWidget(bar)

        # ── Info section ─────────────────────────────────────────────────
        info_layout = QVBoxLayout()
        info_layout.setContentsMargins(16, 12, 8, 12)
        info_layout.setSpacing(4)

        path_row = QHBoxLayout()
        path_row.setSpacing(6)

        path_label = QLabel(self._file_path, self)
        path_label.setFont(self._bold_font(12))
        path_label.setStyleSheet(f"color: {HermesTheme.TEXT_PRIMARY};")
        path_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        path_row.addWidget(path_label, 1)

        btn_folder = QPushButton("📂", self)
        btn_folder.setFont(QFont("Segoe UI Emoji", 10))
        btn_folder.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_folder.setFixedSize(24, 24)
        btn_folder.setStyleSheet(
            """
            QPushButton {
                background-color: transparent;
                border: none;
                padding: 0;
            }
            QPushButton:hover {
                background-color: rgba(255,255,255,0.08);
                border-radius: 4px;
            }
            """
        )
        btn_folder.setToolTip("Open containing folder")
        import os
        btn_folder.clicked.connect(lambda: os.startfile(os.path.dirname(self._file_path)) if os.path.exists(os.path.dirname(self._file_path)) else None)
        path_row.addWidget(btn_folder)

        threat_label = QLabel(self._threat_name, self)
        threat_label.setStyleSheet(f"color: {HermesTheme.TEXT_SECONDARY}; font-size: 11px;")

        badge = QLabel(self._severity, self)
        badge.setFixedHeight(20)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setStyleSheet(self._badge_style())

        severity_row = QHBoxLayout()
        severity_row.setSpacing(8)
        severity_row.addWidget(threat_label)
        severity_row.addWidget(badge)
        severity_row.addStretch()

        info_layout.addLayout(path_row)
        info_layout.addLayout(severity_row)
        root.addLayout(info_layout, stretch=1)

        # ── Action buttons ───────────────────────────────────────────────
        actions = QVBoxLayout()
        actions.setContentsMargins(0, 8, 0, 8)
        actions.setSpacing(4)

        btn_quarantine = self._action_button(
            "Quarantine", HermesTheme.ACCENT_PRIMARY
        )
        btn_remove = self._action_button("Remove", HermesTheme.DANGER)
        btn_ignore = self._action_button("Ignore", HermesTheme.TEXT_SECONDARY)

        btn_quarantine.clicked.connect(
            lambda: self.quarantine_clicked.emit(self._file_path)
        )
        btn_remove.clicked.connect(
            lambda: self.remove_clicked.emit(self._file_path)
        )
        btn_ignore.clicked.connect(
            lambda: self.ignore_clicked.emit(self._file_path)
        )

        actions.addWidget(btn_quarantine)
        actions.addWidget(btn_remove)
        actions.addWidget(btn_ignore)
        root.addLayout(actions)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _severity_color(self) -> str:
        """Return the hex colour string for the current severity level."""
        return _SEVERITY_COLOURS.get(self._severity, HermesTheme.TEXT_MUTED)

    def _badge_style(self) -> str:
        """Return QSS for the severity badge label."""
        clr = self._severity_color()
        return (
            f"background-color: rgba({QColor(clr).red()}, "
            f"{QColor(clr).green()}, {QColor(clr).blue()}, 0.15);"
            f"color: {clr};"
            f"border-radius: 4px;"
            f"padding: 2px 10px;"
            f"font-size: 10px;"
            f"font-weight: 700;"
        )

    @staticmethod
    def _action_button(text: str, accent: str) -> QPushButton:
        """Create a small, styled action button.

        Args:
            text: Button label.
            accent: Hex colour used for text and hover highlight.

        Returns:
            A configured :class:`QPushButton`.
        """
        btn = QPushButton(text)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFixedHeight(24)
        btn.setStyleSheet(
            f"QPushButton {{"
            f"  background-color: transparent;"
            f"  color: {accent};"
            f"  border: 1px solid rgba(255,255,255,0.08);"
            f"  border-radius: 4px;"
            f"  padding: 2px 12px;"
            f"  font-size: 11px;"
            f"  font-weight: 600;"
            f"}}"
            f"QPushButton:hover {{"
            f"  background-color: rgba({QColor(accent).red()}, "
            f"{QColor(accent).green()}, {QColor(accent).blue()}, 0.12);"
            f"  border-color: {accent};"
            f"}}"
        )
        return btn

    @staticmethod
    def _bold_font(size: int) -> QFont:
        """Return a bold ``QFont`` at the given point-size."""
        font = QFont(HermesTheme.FONT_FAMILY, size)
        font.setBold(True)
        return font
