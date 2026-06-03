"""
Hermes Antivirus — Animated status indicator widget.

A small, pulsing, colour-coded circle with a radial glow that communicates
the current protection status at a glance.

Usage::

    indicator = StatusIndicator(size=16)
    indicator.set_status("protected")   # green pulse
    indicator.start_pulse()
"""

from __future__ import annotations

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPropertyAnimation,
    QSize,
    Qt,
)
from PySide6.QtGui import (
    QColor,
    QPainter,
    QPaintEvent,
    QRadialGradient,
)
from PySide6.QtWidgets import QWidget

from hermes.ui.theme import HermesTheme


# Status-name → colour mapping
_STATUS_COLOURS: dict[str, str] = {
    "protected": HermesTheme.SUCCESS,
    "scanning":  HermesTheme.WARNING,
    "threat":    HermesTheme.DANGER,
    "paused":    HermesTheme.TEXT_MUTED,
}


class StatusIndicator(QWidget):
    """A pulsing status dot with a radial-gradient glow effect.

    The dot colour and pulse can be controlled via :meth:`set_status` or
    directly via :meth:`set_color`.

    Args:
        color: Initial hex colour string.
        size: Diameter of the indicator in pixels.
        parent: Optional parent widget.
    """

    def __init__(
        self,
        color: str = "#2ed573",
        size: int = 16,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._color = QColor(color)
        self._dot_size = size
        self._pulse_opacity: float = 1.0

        # Fixed size so layout engines don't squash the dot.
        self.setFixedSize(QSize(size * 2, size * 2))

        # Prepare the animation (not started yet).
        self._anim = QPropertyAnimation(self, b"pulseOpacity")
        self._anim.setDuration(1500)
        self._anim.setStartValue(0.3)
        self._anim.setEndValue(1.0)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutSine)
        self._anim.setLoopCount(-1)  # infinite

    # ── Qt property for animation ─────────────────────────────────────────

    def _get_pulse_opacity(self) -> float:
        """Return the current pulse opacity value."""
        return self._pulse_opacity

    def _set_pulse_opacity(self, value: float) -> None:
        """Set the pulse opacity and schedule a repaint."""
        self._pulse_opacity = value
        self.update()

    pulseOpacity = Property(
        float,
        _get_pulse_opacity,
        _set_pulse_opacity,
    )

    # ── Public API ────────────────────────────────────────────────────────

    def start_pulse(self) -> None:
        """Start the infinite pulse animation."""
        if self._anim.state() != QPropertyAnimation.State.Running:
            self._anim.start()

    def stop_pulse(self) -> None:
        """Stop pulsing and reset to full opacity."""
        self._anim.stop()
        self._pulse_opacity = 1.0
        self.update()

    def set_color(self, color_hex: str) -> None:
        """Change the dot colour.

        Args:
            color_hex: New colour as a hex string (e.g. ``'#ff4757'``).
        """
        self._color = QColor(color_hex)
        self.update()

    def set_status(self, status: str) -> None:
        """Set colour from a named status string.

        Valid statuses: ``'protected'``, ``'scanning'``, ``'threat'``,
        ``'paused'``.  Unknown values default to the *paused* colour.

        Args:
            status: A status name string.
        """
        hex_colour = _STATUS_COLOURS.get(
            status.lower(), HermesTheme.TEXT_MUTED
        )
        self.set_color(hex_colour)

    # ── Painting ──────────────────────────────────────────────────────────

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802
        """Draw the status dot with a radial glow gradient."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        centre_x = self.width() / 2.0
        centre_y = self.height() / 2.0
        radius = self._dot_size / 2.0

        # ── Outer glow ───────────────────────────────────────────────────
        glow_colour = QColor(self._color)
        glow_colour.setAlphaF(0.35 * self._pulse_opacity)

        glow_grad = QRadialGradient(centre_x, centre_y, radius * 1.8)
        glow_grad.setColorAt(0.0, glow_colour)
        glow_grad.setColorAt(1.0, QColor(0, 0, 0, 0))

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(glow_grad)
        painter.drawEllipse(
            int(centre_x - radius * 1.8),
            int(centre_y - radius * 1.8),
            int(radius * 3.6),
            int(radius * 3.6),
        )

        # ── Inner dot ────────────────────────────────────────────────────
        dot_colour = QColor(self._color)
        dot_colour.setAlphaF(self._pulse_opacity)

        dot_grad = QRadialGradient(
            centre_x - radius * 0.25,
            centre_y - radius * 0.25,
            radius,
        )
        dot_grad.setColorAt(0.0, dot_colour.lighter(130))
        dot_grad.setColorAt(1.0, dot_colour)

        painter.setBrush(dot_grad)
        painter.drawEllipse(
            int(centre_x - radius),
            int(centre_y - radius),
            int(radius * 2),
            int(radius * 2),
        )

        painter.end()
