from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, getMonospaceFont
from PySide2 import QtCore
from PySide2.QtGui import QColor, QBrush
from PySide2.QtCore import Qt, QPoint, QEvent, QSize, QThread, Signal, QTimer
from PySide2.QtWidgets import (
     QApplication,
     QHBoxLayout,
     QVBoxLayout,
     QLabel,
     QWidget,
     QTableWidget,
     QTableWidgetItem,
     QTreeWidget,
     QTreeWidgetItem,
     QMenu,
     QLineEdit,
     QDialog,
     QLabel,
     QPushButton,
     QComboBox,
     QCheckBox,
     QToolButton, QStyle,
     QProgressDialog
)
from ..data_global import SIGNALS, GLOBAL
import base64
import time
import json
import subprocess
from binaryninja import (
    core_version,
    log_info,
    highlight,
    show_message_box,
    MessageBoxButtonSet,
    MessageBoxIcon
)
import binaryninja as binja

class DialogFuncScores(QDialog):
    def __init__(self, parent=None, sid=None, data=None):
        super().__init__(parent)
        self.setWindowTitle(f"Fuzz scores({sid})")
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint
        )

        SIGNALS.binja_score_updated.connect(self.showData)

        self.setWindowModality(Qt.NonModal)
        self.font = getMonospaceFont(self)
        self.sid = sid

        self.tree_widget = QTreeWidget()
        self.tree_widget.setColumnCount(6)
        self.tree_widget.expandToDepth(1)
        self.tree_widget.setHeaderLabels([
            "Function",
            "Scores",
            "Fuzz Friendly",
            "Risky Sinks",
            "Natural Loops",
            "Coverage Depth",
            "Cyclomatic Complexity"
        ])
        self.tree_widget.setSortingEnabled(True)
        self.tree_widget.sortByColumn(1, Qt.DescendingOrder)
        self.tree_widget.sortByColumn(2, Qt.DescendingOrder)
        self.tree_widget.sortByColumn(3, Qt.DescendingOrder)
        self.tree_widget.sortByColumn(4, Qt.DescendingOrder)
        self.tree_widget.sortByColumn(5, Qt.DescendingOrder)

        self.tree_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.on_tree_context_menu)
        self.tree_widget.itemDoubleClicked.connect(self.on_item_double_clicked)

        layout = QVBoxLayout()
        layout.addWidget(self.tree_widget)

        self.setLayout(layout)
        self.showData()
        self.bv = data
        self.sw = ""

    def saveFile(self):
        myfile = self.bv.file.filename+".scores"
        with open(myfile, "w") as out:
            json.dump(GLOBAL.binja_scores, out, indent=2)
        print(f"saved to {myfile}")

    def open_data(self):
        myfile = self.bv.file.filename+".scores"

        with open(myfile) as f:
            data = json.load(f)
        GLOBAL.binja_scores = data
        self.showData()

    def showSkip(self):
        self.sw = "skip"
        self.tree_widget.clear()
        mydata = GLOBAL.binja_scores_skip

        for val in mydata:
            item = QTreeWidgetItem(self.tree_widget)
            item.setText(0, val['name'])
            item.setFont(0, self.font)
            item.setData(0, Qt.UserRole, val['addr'])

    def showData(self):
        self.sw = "analyses"
        self.tree_widget.clear()
        mydata = GLOBAL.binja_scores
        func_total = 0

        for idx, val in mydata.items():
            func_total = val["func_total"]
            item = QTreeWidgetItem(self.tree_widget)
            item.setText(0, idx)
            item.setFont(0, self.font)
            item.setData(0, Qt.UserRole, val['addr'])

            item.setText(1, str(val['scores']))
            item.setFont(1, self.font)

            item.setText(2, str(val['fuzz_friendly']))
            item.setFont(2, self.font)

            item.setText(3, str(val['risky_sinks']["skor"]))
            item.setFont(3, self.font)
            item.setToolTip(3, "".join(val['risky_sinks']['tooltip']))

            item.setText(4, str(val['natural_loops']))
            item.setFont(4, self.font)

            item.setText(5, str(val['coverage_depth']))
            item.setFont(5, self.font)

            item.setText(6, str(val['cyclomatic_complexity']))
            item.setFont(6, self.font)

        self.setWindowTitle(f"Fuzz candidate scores (Total: {len(mydata)}/{func_total})")


    def on_item_double_clicked(self, item, column):
        data = item.data(column, Qt.UserRole)
        try:
            addr = data
            print("jump to:", hex(addr))
            self.bv.offset = addr
        except Exception as e:
            print(e)

    def on_tree_context_menu(self, position: QPoint):
        item = self.tree_widget.itemAt(position)
        menu = QMenu()

        menu.addAction("Clear all")
        menu.addAction("Save to file")
        menu.addAction("Load from file")
        if self.sw == "analyses":
            menu.addAction("Show skiped")
        else:
            menu.addAction("Show analyses")

        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)

    def handle_tree_action(self, action, item):
        data = item.data(0, Qt.UserRole)

        if action == "Clear all":
            GLOBAL.binja_scores = {}
            SIGNALS.binja_score_updated.emit()
        elif action == "Load from file":
            self.open_data()
        elif action == "Save to file":
            self.saveFile()
        elif action == "Show skiped":
            self.showSkip()
        elif action == "Show analyses":
            self.showData();
