"""
Hermes Antivirus — Theme system and stylesheet generation.

Provides a centralised colour palette, sizing tokens, and a complete QSS
stylesheet that gives the entire PySide6 dashboard its dark glassmorphic look.
All constants are class-level — no instance is needed.

Usage::

    from hermes.ui.theme import HermesTheme
    app.setStyleSheet(HermesTheme.get_stylesheet())
"""

from __future__ import annotations


class HermesTheme:
    """Centralised design-token store and QSS generator for Hermes UI."""

    # ── Background colours ───────────────────────────────────────────────
    BG_PRIMARY: str = "#0a0e17"
    BG_SECONDARY: str = "#0d1117"
    BG_SURFACE: str = "#111827"
    BG_SURFACE_HOVER: str = "#1a2332"
    BG_INPUT: str = "#0d1117"

    # ── Accent colours ───────────────────────────────────────────────────
    ACCENT_PRIMARY: str = "#00d4aa"
    ACCENT_PRIMARY_HOVER: str = "#00e6bb"
    ACCENT_PRIMARY_DIM: str = "rgba(0, 212, 170, 0.1)"
    ACCENT_PRIMARY_GLOW: str = "rgba(0, 212, 170, 0.3)"

    # ── Semantic colours ─────────────────────────────────────────────────
    DANGER: str = "#ff4757"
    DANGER_HOVER: str = "#ff6b7a"
    DANGER_DIM: str = "rgba(255, 71, 87, 0.1)"

    WARNING: str = "#ffa502"
    WARNING_DIM: str = "rgba(255, 165, 2, 0.1)"

    SUCCESS: str = "#2ed573"
    SUCCESS_DIM: str = "rgba(46, 213, 115, 0.1)"

    # ── Text colours ─────────────────────────────────────────────────────
    TEXT_PRIMARY: str = "#e8eaed"
    TEXT_SECONDARY: str = "#9aa0a6"
    TEXT_MUTED: str = "#5f6368"

    # ── Borders ──────────────────────────────────────────────────────────
    BORDER: str = "rgba(255, 255, 255, 0.08)"
    BORDER_FOCUS: str = "rgba(0, 212, 170, 0.5)"

    # ── Border radii (px) ────────────────────────────────────────────────
    RADIUS_SM: int = 8
    RADIUS_MD: int = 12
    RADIUS_LG: int = 16
    RADIUS_XL: int = 24

    # ── Animation durations (ms) ─────────────────────────────────────────
    ANIM_DURATION_FAST: int = 150
    ANIM_DURATION_NORMAL: int = 300
    ANIM_DURATION_SLOW: int = 500

    # ── Font family ──────────────────────────────────────────────────────
    FONT_FAMILY: str = "Segoe UI, Roboto, Arial, sans-serif"

    # ──────────────────────────────────────────────────────────────────────
    #  Stylesheet
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def get_stylesheet() -> str:
        """Return the complete QSS stylesheet for the Hermes Antivirus app.

        The stylesheet targets widgets by ``objectName`` (using ``#id``
        selectors) so that page code only has to call
        ``widget.setObjectName()`` to pick up the correct styles.

        Returns:
            A single multi-line string of valid Qt Style Sheet rules.
        """

        t = HermesTheme  # shortcut

        return f"""
        /* ══════════════════════════  GLOBAL  ══════════════════════════ */

        QWidget {{
            background-color: {t.BG_PRIMARY};
            color: {t.TEXT_PRIMARY};
            font-family: {t.FONT_FAMILY};
            font-size: 13px;
        }}

        /* ══════════════════════════  SIDEBAR  ═════════════════════════ */

        QWidget#sidebar {{
            background-color: {t.BG_SECONDARY};
            border-right: 1px solid {t.BORDER};
        }}

        /* ── Nav buttons ──────────────────────────────────────────────── */

        QPushButton#navButton {{
            background-color: transparent;
            color: {t.TEXT_SECONDARY};
            border: none;
            border-left: 3px solid transparent;
            text-align: left;
            padding: 12px 20px;
            font-size: 13px;
            font-weight: 500;
            border-radius: 0px;
        }}

        QPushButton#navButton:hover {{
            background-color: {t.ACCENT_PRIMARY_DIM};
            color: {t.TEXT_PRIMARY};
        }}

        QPushButton#navButton:checked,
        QPushButton#navButton:pressed {{
            background-color: {t.ACCENT_PRIMARY_DIM};
            color: {t.ACCENT_PRIMARY};
            border-left: 3px solid {t.ACCENT_PRIMARY};
            font-weight: 600;
        }}

        /* ── App title ────────────────────────────────────────────────── */

        QLabel#appTitle {{
            color: {t.TEXT_PRIMARY};
            font-size: 18px;
            font-weight: 700;
            padding: 0px;
            letter-spacing: 0.5px;
        }}

        /* ══════════════════════════  BUTTONS  ═════════════════════════ */

        QPushButton#primaryButton {{
            background-color: {t.ACCENT_PRIMARY};
            color: {t.BG_PRIMARY};
            border: none;
            border-radius: {t.RADIUS_SM}px;
            padding: 10px 24px;
            font-weight: 700;
            font-size: 13px;
            min-height: 20px;
        }}

        QPushButton#primaryButton:hover {{
            background-color: {t.ACCENT_PRIMARY_HOVER};
        }}

        QPushButton#primaryButton:pressed {{
            background-color: {t.ACCENT_PRIMARY};
        }}

        QPushButton#primaryButton:disabled {{
            background-color: {t.TEXT_MUTED};
            color: {t.BG_SURFACE};
        }}

        QPushButton#dangerButton {{
            background-color: {t.DANGER};
            color: #ffffff;
            border: none;
            border-radius: {t.RADIUS_SM}px;
            padding: 10px 24px;
            font-weight: 700;
            font-size: 13px;
            min-height: 20px;
        }}

        QPushButton#dangerButton:hover {{
            background-color: {t.DANGER_HOVER};
        }}

        QPushButton#dangerButton:pressed {{
            background-color: {t.DANGER};
        }}

        QPushButton#secondaryButton {{
            background-color: transparent;
            color: {t.TEXT_PRIMARY};
            border: 1px solid {t.BORDER};
            border-radius: {t.RADIUS_SM}px;
            padding: 10px 24px;
            font-weight: 600;
            font-size: 13px;
            min-height: 20px;
        }}

        QPushButton#secondaryButton:hover {{
            background-color: rgba(255, 255, 255, 0.05);
            border-color: {t.TEXT_SECONDARY};
        }}

        QPushButton#secondaryButton:pressed {{
            background-color: rgba(255, 255, 255, 0.08);
        }}

        /* ══════════════════════════  CARDS  ═══════════════════════════ */

        QFrame#statusCard,
        QFrame#glassCard {{
            background-color: rgba(255, 255, 255, 0.03);
            border: 1px solid {t.BORDER};
            border-radius: {t.RADIUS_MD}px;
        }}

        QFrame#statusCard:hover,
        QFrame#glassCard:hover {{
            background-color: rgba(255, 255, 255, 0.05);
            border-color: rgba(255, 255, 255, 0.12);
        }}

        /* ══════════════════════════  PROGRESS BAR  ═══════════════════ */

        QProgressBar {{
            background-color: rgba(255, 255, 255, 0.06);
            border: none;
            border-radius: 6px;
            min-height: 12px;
            max-height: 12px;
            text-align: center;
            font-size: 0px;          /* hide text */
        }}

        QProgressBar::chunk {{
            border-radius: 6px;
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0,
                stop:0 {t.ACCENT_PRIMARY},
                stop:1 {t.ACCENT_PRIMARY_HOVER}
            );
        }}

        /* ══════════════════════════  TABLE  ═══════════════════════════ */

        QTableWidget {{
            background-color: {t.BG_PRIMARY};
            alternate-background-color: rgba(255, 255, 255, 0.02);
            border: 1px solid {t.BORDER};
            border-radius: {t.RADIUS_SM}px;
            gridline-color: {t.BORDER};
            selection-background-color: {t.ACCENT_PRIMARY_DIM};
            selection-color: {t.TEXT_PRIMARY};
            font-size: 12px;
        }}

        QTableWidget::item {{
            padding: 8px 12px;
            border-bottom: 1px solid {t.BORDER};
        }}

        QTableWidget::item:selected {{
            background-color: {t.ACCENT_PRIMARY_DIM};
        }}

        QHeaderView::section {{
            background-color: {t.BG_SECONDARY};
            color: {t.TEXT_SECONDARY};
            border: none;
            border-bottom: 1px solid {t.BORDER};
            padding: 10px 12px;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
        }}

        QHeaderView::section:hover {{
            color: {t.TEXT_PRIMARY};
        }}

        /* ══════════════════════════  SCROLLBAR  ══════════════════════ */

        QScrollBar:vertical {{
            background: transparent;
            width: 8px;
            margin: 4px 2px;
        }}

        QScrollBar::handle:vertical {{
            background-color: rgba(255, 255, 255, 0.12);
            border-radius: 4px;
            min-height: 30px;
        }}

        QScrollBar::handle:vertical:hover {{
            background-color: rgba(255, 255, 255, 0.20);
        }}

        QScrollBar::add-line:vertical,
        QScrollBar::sub-line:vertical,
        QScrollBar::add-page:vertical,
        QScrollBar::sub-page:vertical {{
            background: none;
            border: none;
            height: 0px;
        }}

        QScrollBar:horizontal {{
            background: transparent;
            height: 8px;
            margin: 2px 4px;
        }}

        QScrollBar::handle:horizontal {{
            background-color: rgba(255, 255, 255, 0.12);
            border-radius: 4px;
            min-width: 30px;
        }}

        QScrollBar::handle:horizontal:hover {{
            background-color: rgba(255, 255, 255, 0.20);
        }}

        QScrollBar::add-line:horizontal,
        QScrollBar::sub-line:horizontal,
        QScrollBar::add-page:horizontal,
        QScrollBar::sub-page:horizontal {{
            background: none;
            border: none;
            width: 0px;
        }}

        /* ══════════════════════════  LINE EDIT  ═════════════════════ */

        QLineEdit {{
            background-color: {t.BG_INPUT};
            color: {t.TEXT_PRIMARY};
            border: 1px solid {t.BORDER};
            border-radius: {t.RADIUS_SM}px;
            padding: 10px 14px;
            font-size: 13px;
            selection-background-color: {t.ACCENT_PRIMARY_DIM};
        }}

        QLineEdit:focus {{
            border-color: {t.BORDER_FOCUS};
        }}

        QLineEdit:disabled {{
            color: {t.TEXT_MUTED};
            background-color: rgba(255, 255, 255, 0.02);
        }}

        QLineEdit::placeholder {{
            color: {t.TEXT_MUTED};
        }}

        /* ══════════════════════════  CHECKBOX  ══════════════════════ */

        QCheckBox {{
            color: {t.TEXT_PRIMARY};
            spacing: 10px;
            font-size: 13px;
        }}

        QCheckBox::indicator {{
            width: 20px;
            height: 20px;
            border: 2px solid {t.TEXT_MUTED};
            border-radius: 5px;
            background-color: transparent;
        }}

        QCheckBox::indicator:hover {{
            border-color: {t.ACCENT_PRIMARY};
        }}

        QCheckBox::indicator:checked {{
            background-color: {t.ACCENT_PRIMARY};
            border-color: {t.ACCENT_PRIMARY};
            image: none;
        }}

        QCheckBox::indicator:disabled {{
            border-color: rgba(255, 255, 255, 0.05);
        }}

        /* ══════════════════════════  TOOLTIP  ═══════════════════════ */

        QToolTip {{
            background-color: {t.BG_SURFACE};
            color: {t.TEXT_PRIMARY};
            border: 1px solid {t.BORDER};
            border-radius: 6px;
            padding: 8px 12px;
            font-size: 12px;
        }}

        /* ══════════════════════════  LABELS  ════════════════════════ */

        QLabel#titleLabel {{
            color: {t.TEXT_PRIMARY};
            font-size: 22px;
            font-weight: 700;
        }}

        QLabel#subtitleLabel {{
            color: {t.TEXT_SECONDARY};
            font-size: 13px;
            font-weight: 400;
        }}

        QLabel#valueLabel {{
            color: {t.TEXT_PRIMARY};
            font-size: 28px;
            font-weight: 700;
        }}

        QLabel#sectionTitle {{
            color: {t.TEXT_PRIMARY};
            font-size: 16px;
            font-weight: 600;
            padding-bottom: 4px;
        }}

        /* ══════════════════════════  TOGGLE  ════════════════════════ */

        QPushButton#toggleSwitch {{
            background-color: {t.TEXT_MUTED};
            border: none;
            border-radius: 12px;
            min-width: 44px;
            max-width: 44px;
            min-height: 24px;
            max-height: 24px;
            padding: 0px;
        }}

        QPushButton#toggleSwitch:checked {{
            background-color: {t.ACCENT_PRIMARY};
        }}

        /* ══════════════════════════  SEPARATOR  ═════════════════════ */

        QFrame#separator {{
            background-color: {t.BORDER};
            max-height: 1px;
            min-height: 1px;
            border: none;
        }}
        """
