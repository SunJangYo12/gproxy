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
from ..data_global import SIGNALS, GLOBAL, GLOBAL_ANGRSTATE
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

#class StateNode:
#    def __init__(self, state):
#        self.state = state
#        self.children = []

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

        layout = QVBoxLayout()
        layout.addWidget(self.tree_widget)

        self.setLayout(layout)
        self.showData()

    def showData(self):
        mydata = GLOBAL.angr_states

        self.tree_widget.headerItem().setText(0, "Total: %s" %len(mydata) )
        for i in mydata:
            parent = QTreeWidgetItem(self.tree_widget)
            parent.setText(0, "%s" %hex(i.addr))
            parent.setData(0, Qt.UserRole, i)
            parent.setFont(0, self.font)

    def on_tree_context_menu(self, position: QPoint):
        item = self.tree_widget.itemAt(position)
        menu = QMenu()

        menu.addAction("Show contraints")
        menu.addAction("Explore")

        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)

    def dialog_process(self):
        self.dlg = QProgressDialog("Process explore...", None, 0, 0)
        self.dlg.setWindowTitle("Status")
        self.dlg.setCancelButton(None)      # hilangkan tombol Cancel
        self.dlg.setWindowModality(Qt.ApplicationModal)
        self.dlg.show()

    def handle_tree_action(self, action, item):
        data = item.data(0, Qt.UserRole)

        if action == "Show contraints":
            print("zz")

        elif action == "Explore":
            self.dialog_process()
            new_concrete_state = data
            buf_addr = new_concrete_state.solver.eval(new_concrete_state.regs.rdi)
            sym_buf = claripy.BVS("buf", 8 * 32)
            new_concrete_state.memory.store(buf_addr, sym_buf)

            root = GLOBAL_ANGRSTATE(new_concrete_state)
            self.expand_node(GLOBAL.angr_project, root)

            print(len(root.children))

            #GLOBAL.simgr = GLOBAL.angr_project.factory.simgr(new_concrete_state)
            #while len(GLOBAL.simgr.active) == 1:
            #    GLOBAL.simgr.step()
            #    print("[+] explore..")

            #SIGNALS.state_updated.emit()

    def expand_node(self, proj, node):
        simgr = proj.factory.simgr(node.state.copy())

        # Jalan terus selama hanya ada satu state aktif
        while len(simgr.active) == 1:
            simgr.step()

        # Jika tidak ada state lagi (return/crash/deadend)
        if len(simgr.active) == 0:
            return

        # Simpan semua branch sebagai anak
        for s in simgr.active:
            node.children.append(GLOBAL_ANGRSTATE(s.copy()))

