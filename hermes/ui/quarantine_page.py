"""
Hermes Antivirus — Quarantine Page.

Displays quarantined files in a styled table with search/filter,
restore and delete actions, and an empty-state placeholder.
"""

from __future__ import annotations

import datetime
from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QMessageBox, QSizePolicy, QStackedWidget,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor

from hermes.utils.constants import ThreatSeverity


_SEVERITY_LABELS = {
    ThreatSeverity.NONE:     "None",
    ThreatSeverity.LOW:      "Low",
    ThreatSeverity.MEDIUM:   "Medium",
    ThreatSeverity.HIGH:     "High",
    ThreatSeverity.CRITICAL: "Critical",
}

_SEVERITY_COLORS = {
    ThreatSeverity.NONE:     "#9aa0a6",
    ThreatSeverity.LOW:      "#ffa502",
    ThreatSeverity.MEDIUM:   "#ffa502",
    ThreatSeverity.HIGH:     "#ff4757",
    ThreatSeverity.CRITICAL: "#ff4757",
}


class QuarantinePage(QWidget):
    """Quarantine file viewer with table, search, and restore/delete actions."""

    def __init__(
        self,
        quarantine_manager,
        db,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("quarantinePage")
        self._qm = quarantine_manager
        self._db = db
        self._rows: list[dict] = []
        self._build_ui()

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 20, 28, 20)
        root.setSpacing(16)

        # ── Header row ───────────────────────────────────────────────────
        header_row = QHBoxLayout()
        title = QLabel("🛡️  Quarantine")
        title.setFont(QFont("Segoe UI", 22, QFont.Bold))
        title.setStyleSheet("color: #e8eaed; background: transparent;")
        header_row.addWidget(title)

        self._count_badge = QLabel("0")
        self._count_badge.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self._count_badge.setAlignment(Qt.AlignCenter)
        self._count_badge.setFixedSize(32, 24)
        self._count_badge.setStyleSheet(
            "background: rgba(255,71,87,0.2); color: #ff4757; "
            "border-radius: 12px;"
        )
        header_row.addWidget(self._count_badge)
        header_row.addStretch()
        root.addLayout(header_row)

        # ── Search / filter ───────────────────────────────────────────────
        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍  Search quarantined files…")
        self._search.setFont(QFont("Segoe UI", 12))
        self._search.setMinimumHeight(40)
        self._search.setStyleSheet(
            """
            QLineEdit {
                background: rgba(255,255,255,0.05);
                color: #e8eaed;
                border: 1px solid rgba(255,255,255,0.08);
                border-radius: 12px;
                padding: 8px 16px;
            }
            QLineEdit:focus {
                border-color: #00d4aa;
            }
            """
        )
        self._search.textChanged.connect(self._filter_table)
        root.addWidget(self._search)

        # ── Stacked: table vs empty-state ─────────────────────────────────
        self._content_stack = QStackedWidget()

        # --- Table page ---
        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels(
            ["File Name", "Original Path", "Threat", "Severity", "Date", "Actions"]
        )
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(
            """
            QTableWidget {
                background: transparent;
                color: #e8eaed;
                border: none;
                gridline-color: transparent;
                font-size: 12px;
            }
            QTableWidget::item {
                padding: 8px 6px;
                border-bottom: 1px solid rgba(255,255,255,0.04);
            }
            QTableWidget::item:alternate {
                background: rgba(255,255,255,0.02);
            }
            QTableWidget::item:selected {
                background: rgba(0,212,170,0.12);
            }
            QHeaderView::section {
                background: rgba(255,255,255,0.04);
                color: #9aa0a6;
                font-weight: bold;
                padding: 8px 6px;
                border: none;
                border-bottom: 1px solid rgba(255,255,255,0.08);
            }
            """
        )
        self._content_stack.addWidget(self._table)  # index 0

        # --- Empty-state page ---
        empty = QWidget()
        el = QVBoxLayout(empty)
        el.setAlignment(Qt.AlignCenter)
        el.setSpacing(12)

        empty_icon = QLabel("📭")
        empty_icon.setFont(QFont("Segoe UI Emoji", 48))
        empty_icon.setAlignment(Qt.AlignCenter)
        empty_icon.setStyleSheet("background: transparent;")
        el.addWidget(empty_icon)

        empty_title = QLabel("No quarantined files")
        empty_title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        empty_title.setStyleSheet("color: #e8eaed; background: transparent;")
        empty_title.setAlignment(Qt.AlignCenter)
        el.addWidget(empty_title)

        empty_sub = QLabel("Detected threats will appear here after scanning")
        empty_sub.setFont(QFont("Segoe UI", 12))
        empty_sub.setStyleSheet("color: #5f6368; background: transparent;")
        empty_sub.setAlignment(Qt.AlignCenter)
        el.addWidget(empty_sub)

        self._content_stack.addWidget(empty)  # index 1

        root.addWidget(self._content_stack, 1)

    # ── Public API ────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Reload quarantined items from the database and rebuild the table."""
        try:
            self._rows = self._db.get_quarantined_files() if self._db else []
        except Exception:  # noqa: BLE001
            self._rows = []

        if not self._rows:
            self._content_stack.setCurrentIndex(1)
            self._count_badge.setText("0")
            return

        self._content_stack.setCurrentIndex(0)
        self._count_badge.setText(str(len(self._rows)))
        self._populate_table(self._rows)

    # ── Table population ──────────────────────────────────────────────────

    def _populate_table(self, rows: list[dict]) -> None:
        self._table.setRowCount(0)
        self._table.setRowCount(len(rows))

        for i, row in enumerate(rows):
            # File name
            import os as _os
            fname = _os.path.basename(row.get("original_path", "Unknown"))
            self._table.setItem(i, 0, self._text_item(fname))

            # Original path
            self._table.setItem(i, 1, self._text_item(row.get("original_path", "")))

            # Threat name
            self._table.setItem(i, 2, self._text_item(row.get("threat_name", "Unknown")))

            # Severity
            sev_val = row.get("severity", 0)
            try:
                sev_enum = ThreatSeverity(sev_val)
            except (ValueError, KeyError):
                sev_enum = ThreatSeverity.NONE
            sev_item = self._text_item(_SEVERITY_LABELS.get(sev_enum, "Unknown"))
            sev_color = _SEVERITY_COLORS.get(sev_enum, "#9aa0a6")
            sev_item.setForeground(QColor(sev_color))
            self._table.setItem(i, 3, sev_item)

            # Date
            date_str = row.get("quarantine_date", "")
            if isinstance(date_str, datetime.datetime):
                date_str = date_str.strftime("%Y-%m-%d %H:%M")
            self._table.setItem(i, 4, self._text_item(str(date_str)))

            # Action buttons
            actions = QWidget()
            al = QHBoxLayout(actions)
            al.setContentsMargins(4, 2, 4, 2)
            al.setSpacing(6)

            q_id = row.get("id", row.get("quarantine_id", i))

            restore_btn = self._small_button("↩ Restore", "#00d4aa", "rgba(0,212,170,0.12)")
            restore_btn.clicked.connect(lambda _=False, rid=q_id: self._restore_file(rid))
            al.addWidget(restore_btn)

            delete_btn = self._small_button("🗑 Delete", "#ff4757", "rgba(255,71,87,0.12)")
            delete_btn.clicked.connect(lambda _=False, rid=q_id: self._delete_file(rid))
            al.addWidget(delete_btn)

            self._table.setCellWidget(i, 5, actions)
            self._table.setRowHeight(i, 48)

    # ── Filter ────────────────────────────────────────────────────────────

    def _filter_table(self, text: str) -> None:
        text_lower = text.lower()
        for i in range(self._table.rowCount()):
            match = False
            for c in range(self._table.columnCount() - 1):
                item = self._table.item(i, c)
                if item and text_lower in item.text().lower():
                    match = True
                    break
            self._table.setRowHidden(i, not match)

    # ── Restore / Delete ──────────────────────────────────────────────────

    def _restore_file(self, quarantine_id) -> None:
        reply = QMessageBox.question(
            self,
            "Restore File",
            "Are you sure you want to restore this file to its original location?\n"
            "This may pose a security risk.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                if self._qm:
                    self._qm.restore(quarantine_id)
            except Exception:  # noqa: BLE001
                QMessageBox.warning(self, "Error", "Failed to restore the file.")
            self.refresh()

    def _delete_file(self, quarantine_id) -> None:
        reply = QMessageBox.question(
            self,
            "Delete Permanently",
            "This will permanently delete the quarantined file.\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                if self._qm:
                    self._qm.delete(quarantine_id)
            except Exception:  # noqa: BLE001
                QMessageBox.warning(self, "Error", "Failed to delete the file.")
            self.refresh()

    # ── Widget helpers ────────────────────────────────────────────────────

    @staticmethod
    def _text_item(text: str) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        return item

    @staticmethod
    def _small_button(text: str, color: str, bg: str) -> QPushButton:
        btn = QPushButton(text)
        btn.setFont(QFont("Segoe UI", 10))
        btn.setCursor(Qt.PointingHandCursor)
        btn.setFixedHeight(30)
        btn.setStyleSheet(
            f"""
            QPushButton {{
                background: {bg}; color: {color};
                border: none; border-radius: 8px;
                padding: 2px 10px; font-weight: 600;
            }}
            QPushButton:hover {{
                background: {color}; color: #fff;
            }}
            """
        )
        return btn

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self.refresh()
