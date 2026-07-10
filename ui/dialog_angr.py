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
import claripy

class DialogAngrTree(QDialog):
    def __init__(self, parent=None, sid=None, data=None):
        super().__init__(parent)
        self.setWindowTitle(f"State Tree({sid})")
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint
        )

        SIGNALS.state_tree_updated.connect(self.showData)

        self.setWindowModality(Qt.NonModal)
        self.font = getMonospaceFont(self)

        self.tree_widget = QTreeWidget()
        self.tree_widget.setColumnCount(0)
        self.tree_widget.expandToDepth(1)

        self.tree_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.on_tree_context_menu)
        self.tree_widget.itemDoubleClicked.connect(self.on_item_double_clicked)

        layout = QVBoxLayout()
        layout.addWidget(self.tree_widget)

        self.setLayout(layout)
        self.showData()
        self.bv = data

    def showData(self):
        self.tree_widget.clear()
        mydata = GLOBAL.angr_states
        try:
            self.add_node(self.tree_widget, mydata)
        except:
            pass

        self.tree_widget.headerItem().setText(0, "Total: %s" %len(mydata) )
        self.tree_widget.expandAll()

    def add_node(self, parent_item, node):
        state = node["state"]

        item = QTreeWidgetItem(parent_item)
        item.setText(0, hex(state.addr))
        item.setFont(0, self.font)
        item.setData(0, Qt.UserRole, node)

        for child in node["children"]:
            self.add_node(item, child)

    def on_item_double_clicked(self, item, column):
        try:
            addr = int(item.text(column), 0)
            print("jump to:", hex(addr))
            self.bv.offset = addr
        except Exception as e:
            print(e)

    def on_tree_context_menu(self, position: QPoint):
        item = self.tree_widget.itemAt(position)
        menu = QMenu()

        menu.addAction("Show contraints")
        menu.addAction("Show solver input")
        menu.addAction("Explore")

        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)

    def dialog_process(self):
        # Jika dialog sudah ada, tutup
        if hasattr(self, "dlg") and self.dlg is not None:
            self.dlg.close()
            self.dlg.deleteLater()
            self.dlg = None
            return
        # Buat dialog baru
        self.dlg = QProgressDialog("Process explore...", None, 0, 0)
        self.dlg.setWindowTitle("Status")
        self.dlg.setCancelButton(None)
        self.dlg.setWindowModality(Qt.ApplicationModal)
        self.dlg.show()

    def handle_tree_action(self, action, item):
        data = item.data(0, Qt.UserRole)

        if action == "Show contraints":
            print("zz")

        elif action == "Show solver input":
            new_concrete_state = data["state"]
            sym_buf = claripy.BVS("buf", 8 * 32)
            new_concrete_state.memory.store(buf_addr, sym_buf)

            out = new_concrete_state1.solver.eval(sym_buf, cast_to=bytes)

        elif action == "Explore":
            self.dialog_process()
            new_concrete_state = data["state"]
            buf_addr = new_concrete_state.solver.eval(new_concrete_state.regs.rdi)
            sym_buf = claripy.BVS("buf", 8 * 32)
            new_concrete_state.memory.store(buf_addr, sym_buf)

            GLOBAL.angr_explore(GLOBAL.angr_project, data["state"])
            self.dialog_process()
            self.showData();


