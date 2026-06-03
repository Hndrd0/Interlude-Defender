"""
Hermes Antivirus — Circular scan-progress ring widget.

A resolution-independent, anti-aliased progress ring that can animate
smoothly between values and displays the current percentage in its centre.

Usage::

    ring = ScanProgressRing(size=200, thickness=10)
    ring.set_label("Scanning…")
    ring.animate_to(75, duration=800)
"""

from __future__ import annotations

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
)
from PySide6.QtGui import (
    QColor,
    QFont,
    QPainter,
    QPaintEvent,
    QPen,
)
from PySide6.QtWidgets import QWidget

from hermes.ui.theme import HermesTheme


class ScanProgressRing(QWidget):
    """Animated circular progress indicator.

    The ring fills clockwise from the 12-o'clock position.  Call
    :meth:`animate_to` for a smooth transition or :meth:`set_value` for an
    instant jump.

    Args:
        parent: Optional parent widget.
        size: Widget width/height in pixels (the ring is always square).
        thickness: Width of the ring stroke in pixels.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        size: int = 200,
        thickness: int = 10,
        value: int = 0,
    ) -> None:
        super().__init__(parent)
        self._size = size
        self._thickness = thickness
        self._value: float = float(value)
        self._color = QColor(HermesTheme.ACCENT_PRIMARY)
        self._label: str = ""

        self.setFixedSize(QSize(size, size))

        # ── Animation object (reused across calls) ───────────────────────
        self._anim = QPropertyAnimation(self, b"animatedValue")
        self._anim.setEasingCurve(QEasingCurve.Type.InOutCubic)

    # ── Qt property for animation ─────────────────────────────────────────

    def _get_value(self) -> float:
        """Return the current progress value (0-100)."""
        return self._value

    def _set_value_internal(self, val: float) -> None:
        """Set the progress value and repaint (used by animation)."""
        self._value = max(0.0, min(val, 100.0))
        self.update()

    animatedValue = Property(float, _get_value, _set_value_internal)

    # ── Public API ────────────────────────────────────────────────────────

    def set_value(self, val: int) -> None:
        """Instantly set the progress value.

        Args:
            val: Progress percentage in 0–100.
        """
        self._anim.stop()
        self._set_value_internal(float(val))

    def set_color(self, color: str) -> None:
        """Change the ring accent colour.

        Args:
            color: Hex colour string.
        """
        self._color = QColor(color)
        self.update()

    def animate_to(self, target: int, duration: int = 800) -> None:
        """Smoothly animate the ring to *target* percent.

        If an animation is already running it will be interrupted and
        restarted from the current value.

        Args:
            target: Target percentage (0–100).
            duration: Animation duration in milliseconds.
        """
        self._anim.stop()
        self._anim.setDuration(duration)
        self._anim.setStartValue(self._value)
        self._anim.setEndValue(float(max(0, min(target, 100))))
        self._anim.start()

    def set_label(self, text: str) -> None:
        """Set the small descriptive label shown below the percentage.

        Args:
            text: Label string (e.g. ``'Scanning…'``).
        """
        self._label = text
        self.update()

    def reset(self) -> None:
        """Stop any animation and reset the ring to 0 %."""
        self._anim.stop()
        self._value = 0.0
        self._label = ""
        self.update()

    # ── Painting ──────────────────────────────────────────────────────────

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802
        """Draw the background ring, foreground arc, and centre text."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        margin = self._thickness / 2.0 + 2.0
        rect = QRectF(margin, margin, self._size - 2 * margin, self._size - 2 * margin)

        # ── Background ring ──────────────────────────────────────────────
        bg_pen = QPen(QColor(255, 255, 255, 15))
        bg_pen.setWidthF(self._thickness)
        bg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(bg_pen)
        painter.drawArc(rect, 0, 360 * 16)

        # ── Foreground arc ───────────────────────────────────────────────
        if self._value > 0:
            fg_pen = QPen(self._color)
            fg_pen.setWidthF(self._thickness)
            fg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(fg_pen)

            # Qt arcs: start at 12-o'clock (90°), sweep clockwise (negative).
            start_angle = 90 * 16
            span_angle = -int(self._value / 100.0 * 360.0 * 16)
            painter.drawArc(rect, start_angle, span_angle)

        # ── Centre percentage text ───────────────────────────────────────
        pct_text = f"{int(self._value)}%"
        pct_font = QFont(HermesTheme.FONT_FAMILY, self._size // 6)
        pct_font.setBold(True)
        painter.setPen(QColor(HermesTheme.TEXT_PRIMARY))
        painter.setFont(pct_font)

        # Text rect: upper 55 % of the widget (gives room for the label).
        text_rect = QRectF(0, 0, self._size, self._size * 0.55)
        painter.drawText(
            text_rect,
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
            pct_text,
        )

        # ── Sub-label ────────────────────────────────────────────────────
        if self._label:
            lbl_font = QFont(HermesTheme.FONT_FAMILY, self._size // 16)
            painter.setFont(lbl_font)
            painter.setPen(QColor(HermesTheme.TEXT_SECONDARY))
            label_rect = QRectF(0, self._size * 0.55, self._size, self._size * 0.25)
            painter.drawText(
                label_rect,
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                self._label,
            )

        painter.end()
