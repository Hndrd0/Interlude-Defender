"""
Hermes Antivirus — Dashboard Page.

The hero screen of the application: protection status banner, stat cards,
quick-action buttons, and a recent-activity feed.
"""

from __future__ import annotations

import datetime
from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QSizePolicy, QGraphicsDropShadowEffect,
)
from PySide6.QtCore import Qt, Signal, QTimer, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QColor, QFont

from hermes.ui.widgets.glass_card import GlassCard
from hermes.ui.widgets.status_indicator import StatusIndicator


# ── Helpers ───────────────────────────────────────────────────────────────────

def _relative_time(dt: datetime.datetime | None) -> str:
    """Return a human-friendly relative-time string."""
    if dt is None:
        return "Never"
    now = datetime.datetime.now()
    delta = now - dt
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "Just now"
    if seconds < 60:
        return "Just now"
    if seconds < 3600:
        m = seconds // 60
        return f"{m} minute{'s' if m != 1 else ''} ago"
    if seconds < 86400:
        h = seconds // 3600
        return f"{h} hour{'s' if h != 1 else ''} ago"
    d = seconds // 86400
    return f"{d} day{'s' if d != 1 else ''} ago"


class DashboardPage(QWidget):
    """Main dashboard / hero page.

    Signals:
        quick_scan_requested: User clicked Quick Scan.
        full_scan_requested:  User clicked Full Scan.
        custom_scan_requested: User clicked Custom Scan.
    """

    quick_scan_requested = Signal()
    full_scan_requested = Signal()
    custom_scan_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("dashboardPage")
        self._protection_active = True
        self._activities: list[tuple[str, str]] = []

        self._build_ui()

        # Refresh stats from DB every 30 s
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(30_000)
        self._refresh_timer.timeout.connect(self._auto_refresh)

    # ── Build ─────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 20, 28, 20)
        root.setSpacing(20)

        # ── Protection status banner ──────────────────────────────────────
        self._banner = QWidget()
        self._banner.setMinimumHeight(130)
        self._banner.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._banner.setStyleSheet(self._banner_css(True))

        banner_layout = QHBoxLayout(self._banner)
        banner_layout.setContentsMargins(32, 20, 32, 20)
        banner_layout.setSpacing(18)

        shield_lbl = QLabel("🛡️")
        shield_lbl.setFont(QFont("Segoe UI Emoji", 48))
        shield_lbl.setStyleSheet("background: transparent;")
        banner_layout.addWidget(shield_lbl)

        text_col = QVBoxLayout()
        text_col.setSpacing(4)
        self._status_title = QLabel("Your system is protected")
        self._status_title.setFont(QFont("Segoe UI", 22, QFont.Bold))
        self._status_title.setStyleSheet("color: #fff; background: transparent;")
        text_col.addWidget(self._status_title)

        sub_row = QHBoxLayout()
        sub_row.setSpacing(8)
        self._status_indicator = StatusIndicator(color="#2ed573", size=10)
        sub_row.addWidget(self._status_indicator)
        self._status_sub = QLabel("Real-time protection is active")
        self._status_sub.setFont(QFont("Segoe UI", 12))
        self._status_sub.setStyleSheet("color: rgba(255,255,255,0.8); background: transparent;")
        sub_row.addWidget(self._status_sub)
        sub_row.addStretch()
        text_col.addLayout(sub_row)

        banner_layout.addLayout(text_col)
        banner_layout.addStretch()

        shadow = QGraphicsDropShadowEffect(self._banner)
        shadow.setBlurRadius(30)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(0, 212, 170, 60))
        self._banner.setGraphicsEffect(shadow)

        root.addWidget(self._banner)

        # ── Stat cards row ────────────────────────────────────────────────
        stats_row = QHBoxLayout()
        stats_row.setSpacing(16)

        self._card_rtp = self._make_stat_card("🟢", "Real-time Protection", "ON")
        self._card_last_scan = self._make_stat_card("🕑", "Last Scan", "Never")
        self._card_threats = self._make_stat_card("🚫", "Threats Blocked", "0")
        self._card_files = self._make_stat_card("📂", "Files Scanned", "0")

        for card in (self._card_rtp, self._card_last_scan, self._card_threats, self._card_files):
            stats_row.addWidget(card["card"])

        root.addLayout(stats_row)

        # ── Quick actions row ─────────────────────────────────────────────
        actions_row = QHBoxLayout()
        actions_row.setSpacing(14)

        quick_btn = self._action_button("⚡  Quick Scan", primary=True)
        quick_btn.clicked.connect(self.quick_scan_requested.emit)

        full_btn = self._action_button("🖥️  Full Scan", primary=False)
        full_btn.clicked.connect(self.full_scan_requested.emit)

        custom_btn = self._action_button("📁  Custom Scan", primary=False)
        custom_btn.clicked.connect(self.custom_scan_requested.emit)

        actions_row.addWidget(quick_btn)
        actions_row.addWidget(full_btn)
        actions_row.addWidget(custom_btn)
        root.addLayout(actions_row)

        # ── Recent activity ───────────────────────────────────────────────
        activity_header = QLabel("Recent Activity")
        activity_header.setFont(QFont("Segoe UI", 14, QFont.DemiBold))
        activity_header.setStyleSheet("color: #e8eaed; background: transparent;")
        root.addWidget(activity_header)

        self._activity_area = QScrollArea()
        self._activity_area.setWidgetResizable(True)
        self._activity_area.setFrameShape(QFrame.NoFrame)
        self._activity_area.setStyleSheet("background: transparent; border: none;")
        self._activity_area.setMinimumHeight(120)

        self._activity_container = QWidget()
        self._activity_layout = QVBoxLayout(self._activity_container)
        self._activity_layout.setContentsMargins(0, 0, 0, 0)
        self._activity_layout.setSpacing(6)

        # placeholder
        self._empty_label = QLabel("No recent activity — run a scan to get started!")
        self._empty_label.setFont(QFont("Segoe UI", 11))
        self._empty_label.setStyleSheet("color: #5f6368; background: transparent; padding: 16px 0;")
        self._empty_label.setAlignment(Qt.AlignCenter)
        self._activity_layout.addWidget(self._empty_label)
        self._activity_layout.addStretch()

        self._activity_area.setWidget(self._activity_container)
        root.addWidget(self._activity_area, 1)

    # ── Widget factories ──────────────────────────────────────────────────

    def _make_stat_card(self, icon: str, title: str, value: str) -> dict:
        """Create a stat GlassCard and return refs to its mutable labels."""
        card = GlassCard()
        card.setMinimumHeight(105)
        card.setMinimumWidth(160)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = card.layout()
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(6)

        top = QHBoxLayout()
        icon_lbl = QLabel(icon)
        icon_lbl.setFont(QFont("Segoe UI Emoji", 16))
        icon_lbl.setStyleSheet("background: transparent;")
        top.addWidget(icon_lbl)

        title_lbl = QLabel(title)
        title_lbl.setFont(QFont("Segoe UI", 10))
        title_lbl.setStyleSheet("color: #9aa0a6; background: transparent;")
        top.addWidget(title_lbl)
        top.addStretch()
        layout.addLayout(top)

        value_lbl = QLabel(value)
        value_lbl.setFont(QFont("Segoe UI", 20, QFont.Bold))
        value_lbl.setStyleSheet("color: #e8eaed; background: transparent;")
        layout.addWidget(value_lbl)

        return {"card": card, "value_label": value_lbl, "title_label": title_lbl}

    def _action_button(self, text: str, primary: bool = False) -> QPushButton:
        """Create a styled action button."""
        btn = QPushButton(text)
        btn.setFont(QFont("Segoe UI", 13, QFont.DemiBold))
        btn.setMinimumHeight(52)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        if primary:
            btn.setStyleSheet(
                """
                QPushButton {
                    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                        stop:0 #00d4aa, stop:1 #00b894);
                    color: #0a0e17;
                    border: none;
                    border-radius: 14px;
                    padding: 12px 24px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                        stop:0 #00e6bb, stop:1 #00d4aa);
                }
                QPushButton:pressed { background: #00b894; }
                """
            )
        else:
            btn.setStyleSheet(
                """
                QPushButton {
                    background: rgba(255,255,255,0.06);
                    color: #e8eaed;
                    border: 1px solid rgba(255,255,255,0.08);
                    border-radius: 14px;
                    padding: 12px 24px;
                }
                QPushButton:hover {
                    background: rgba(255,255,255,0.1);
                    border-color: rgba(255,255,255,0.15);
                }
                QPushButton:pressed { background: rgba(255,255,255,0.04); }
                """
            )
        return btn

    @staticmethod
    def _banner_css(protected: bool) -> str:
        if protected:
            return (
                "border-radius: 18px; "
                "background: qlineargradient(x1:0,y1:0,x2:1,y2:1, "
                "stop:0 rgba(0,212,170,0.35), stop:1 rgba(0,184,148,0.20));"
                "border: 1px solid rgba(0,212,170,0.25);"
            )
        return (
            "border-radius: 18px; "
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:1, "
            "stop:0 rgba(255,71,87,0.35), stop:1 rgba(200,40,50,0.20));"
            "border: 1px solid rgba(255,71,87,0.25);"
        )

    # ── Public API ────────────────────────────────────────────────────────

    def update_stats(self, stats: dict) -> None:
        """Update stat cards from a dictionary.

        Expected keys (all optional):
            ``realtime_protection`` (bool),
            ``last_scan`` (datetime | None),
            ``threats_blocked`` (int),
            ``files_scanned`` (int).
        """
        if "realtime_protection" in stats:
            on = stats["realtime_protection"]
            self._card_rtp["value_label"].setText("ON" if on else "OFF")
        if "last_scan" in stats:
            self._card_last_scan["value_label"].setText(
                _relative_time(stats["last_scan"])
            )
        if "threats_blocked" in stats:
            self._card_threats["value_label"].setText(
                f"{stats['threats_blocked']:,}"
            )
        if "files_scanned" in stats:
            self._card_files["value_label"].setText(
                f"{stats['files_scanned']:,}"
            )

    def set_protection_status(self, active: bool) -> None:
        """Toggle the protection banner between protected / threatened."""
        self._protection_active = active
        self._banner.setStyleSheet(self._banner_css(active))

        if active:
            self._status_title.setText("Your system is protected")
            self._status_sub.setText("Real-time protection is active")
            self._status_indicator.set_color("#2ed573")
            self._card_rtp["value_label"].setText("ON")
        else:
            self._status_title.setText("Protection is disabled")
            self._status_sub.setText("Your system may be at risk")
            self._status_indicator.set_color("#ff4757")
            self._card_rtp["value_label"].setText("OFF")

    def add_activity(self, text: str, timestamp: str | None = None) -> None:
        """Prepend an activity item to the recent-activity list.

        Keeps at most 5 items visible.
        """
        if self._empty_label.isVisible():
            self._empty_label.hide()

        ts = timestamp or datetime.datetime.now().strftime("%H:%M:%S")

        row = QWidget()
        row.setStyleSheet(
            "background: rgba(255,255,255,0.03); border-radius: 10px;"
        )
        rl = QHBoxLayout(row)
        rl.setContentsMargins(14, 10, 14, 10)
        rl.setSpacing(10)

        icon_lbl = QLabel("📋")
        icon_lbl.setFont(QFont("Segoe UI Emoji", 13))
        icon_lbl.setStyleSheet("background: transparent;")
        rl.addWidget(icon_lbl)

        desc_lbl = QLabel(text)
        desc_lbl.setFont(QFont("Segoe UI", 11))
        desc_lbl.setStyleSheet("color: #e8eaed; background: transparent;")
        desc_lbl.setWordWrap(True)
        rl.addWidget(desc_lbl, 1)

        ts_lbl = QLabel(ts)
        ts_lbl.setFont(QFont("Segoe UI", 10))
        ts_lbl.setStyleSheet("color: #5f6368; background: transparent;")
        rl.addWidget(ts_lbl)

        # Insert at top (index 0); keep max 5
        self._activity_layout.insertWidget(0, row)
        self._activities.insert(0, (text, ts))

        while self._activity_layout.count() > 6:  # 5 items + 1 stretch
            item = self._activity_layout.takeAt(5)
            if item and item.widget():
                item.widget().deleteLater()
        if len(self._activities) > 5:
            self._activities = self._activities[:5]

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._refresh_timer.start()
        self._auto_refresh()

    def hideEvent(self, event) -> None:  # noqa: N802
        super().hideEvent(event)
        self._refresh_timer.stop()

    def _auto_refresh(self) -> None:
        """Hook for parent to override or connect to DB queries."""
        pass
