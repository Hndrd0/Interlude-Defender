"""
Hermes Antivirus — Glassmorphism card widget.

A translucent, bordered card with an optional title and a subtle drop-shadow.
When *hoverable* is ``True`` the card background brightens on mouse-over via a
short opacity animation, giving the UI a premium feel.

Usage::

    card = GlassCard(title="Scan Results", hoverable=True)
    card.layout().addWidget(some_content)
"""

from __future__ import annotations

from PySide6.QtCore import (
    QEasingCurve,
    QPropertyAnimation,
    Qt,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from hermes.ui.theme import HermesTheme


class GlassCard(QFrame):
    """Translucent card with glassmorphic styling and optional hover animation.

    The card automatically receives the ``glassCard`` object-name so that the
    global QSS from :class:`HermesTheme` applies.  Child widgets can be added
    to the card's built-in :pyclass:`QVBoxLayout`.

    Args:
        parent: Optional parent widget.
        title: If non-empty, a bold title label is placed at the top.
        hoverable: If ``True``, the card brightens on mouse-over.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        title: str = "",
        hoverable: bool = True,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("glassCard")
        self._hoverable = hoverable

        # ── Shadow effect ────────────────────────────────────────────────
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(15)
        shadow.setOffset(0, 2)
        shadow.setColor(QColor(0, 0, 0, 80))
        self.setGraphicsEffect(shadow)

        # ── Layout ───────────────────────────────────────────────────────
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(20, 20, 20, 20)
        self._layout.setSpacing(12)

        # ── Optional title ───────────────────────────────────────────────
        self._title_label: QLabel | None = None
        if title:
            self._create_title_label(title)

        # ── Hover animation (background-opacity proxy via stylesheet) ───
        self._bg_opacity: float = 0.03
        if hoverable:
            self._anim = QPropertyAnimation(self, b"windowOpacity")
            self._anim.setDuration(HermesTheme.ANIM_DURATION_FAST)
            self._anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

    # ── Public API ────────────────────────────────────────────────────────

    def setTitle(self, text: str) -> None:
        """Set or update the card's title text.

        Args:
            text: The new title string.
        """
        if self._title_label is None:
            self._create_title_label(text)
        else:
            self._title_label.setText(text)

    # ── Hover events ──────────────────────────────────────────────────────

    def enterEvent(self, event: object) -> None:  # noqa: N802
        """Brighten the card background on mouse-enter."""
        if self._hoverable:
            self._set_bg_opacity(0.06)
        super().enterEvent(event)

    def leaveEvent(self, event: object) -> None:  # noqa: N802
        """Restore the card background on mouse-leave."""
        if self._hoverable:
            self._set_bg_opacity(0.03)
        super().leaveEvent(event)

    # ── Internal helpers ──────────────────────────────────────────────────

    def _create_title_label(self, text: str) -> None:
        """Create and insert the title label at index 0."""
        self._title_label = QLabel(text, self)
        self._title_label.setObjectName("sectionTitle")
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self._layout.insertWidget(0, self._title_label)

    def _set_bg_opacity(self, opacity: float) -> None:
        """Apply a translucent background via inline stylesheet.

        This updates only the ``background-color`` rule so that the
        border and other QSS properties from the global stylesheet
        remain untouched.
        """
        self._bg_opacity = opacity
        rgba = f"rgba(255, 255, 255, {opacity})"
        self.setStyleSheet(f"QFrame#glassCard {{ background-color: {rgba}; }}")
