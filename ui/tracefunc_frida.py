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
     QToolButton, QStyle
)
from ..data_global import SIGNALS, GLOBAL
import base64
import time

from binaryninja import (
    core_version,
    log_info,
    highlight,
)

import binaryninja as binja


class FridaFuncListDockWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name, data):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)


        SIGNALS.frida_updated.connect(self.refresh_from_global)
        SIGNALS.frida_updatedsym.connect(self.refresh_from_global_sym)
        SIGNALS.frida_updatedsym_trace.connect(self.refresh_from_global_sym_trace)


        tree_widget = QTreeWidget()
        self.tree_widget = tree_widget
        self.tree_widget.itemDoubleClicked.connect(self.on_item_double_clicked)

        self.tree_widget.headerItem().setText(0, "Function List" )
        tree_widget.setColumnCount(1)

        # MENGAKTIFKAN KLIK KANAN
        self.tree_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.on_tree_context_menu)


        layout = QVBoxLayout()
        layout.addWidget(tree_widget)

        self.setLayout(layout)
        self.bv = data
        self.font = getMonospaceFont(self)


    def refresh_from_global(self):
        self.tree_widget.clear()
        self.tree_widget.headerItem().setText(0, "Module List: %d" %len(GLOBAL.frida_enummodules) )

        for data in GLOBAL.frida_enummodules:
            parent = QTreeWidgetItem(self.tree_widget)

            parent.setText(0, "%s" %data.get('name'))
            parent.setFont(0, self.font)
            parent.setData(0, Qt.UserRole, data )

    def refresh_from_global_sym(self):
        self.tree_widget.clear()
        func_total = 0

        for data in GLOBAL.frida_enumsymbols:
            if data.get("type") == "function":
                func_total += 1
                parent = QTreeWidgetItem(self.tree_widget)

                func_name = data.get("name")

                #if func_name.startswith("_Z") == True:
                if False:
                    func_mangle = binja.demangle.demangle_gnu3(binja.architecture.Architecture["x86"], func_name)
                    parent.setText(0, "%s" %func_mangle[1])
                else:
                    parent.setText(0, "%s" %func_name)

                parent.setFont(0, self.font)
                parent.setData(0, Qt.UserRole, data )

        self.tree_widget.headerItem().setText(0, "Function List: [%d/%d]" %(func_total, len(GLOBAL.frida_enumsymbols)) )


    def refresh_from_global_sym_trace(self):
        self.tree_widget.clear()
        self.tree_widget.headerItem().setText(0, "Trace Function List: %d" %len(GLOBAL.frida_functions) )

        for (func_name, data) in GLOBAL.frida_functions.items():
            parent = QTreeWidgetItem(self.tree_widget)

            parent.setText(0, "%d  %s" % (data['count'], func_name) )
            parent.setFont(0, self.font)
            parent.setData(0, Qt.UserRole, func_name )

            now = time.time()

            if now < data['time']:
                parent.setForeground(0, QColor("orange"))
            else:
                parent.setForeground(0, QColor("white"))




    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


    def on_item_double_clicked(self, item, column):
        pass


    def on_tree_context_menu(self, position: QPoint):
        item = self.tree_widget.itemAt(position)
        if item is None:
            return   # klik kanan di area kosong → tidak ada menu

        menu = QMenu()


        if item.parent() is None:
            menu.addAction("Copy")
            menu.addAction("Base")
            menu.addAction("Size")
            menu.addAction("Path")


        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)


    def handle_tree_action(self, action, item):

        if action == "Copy":
            QApplication.clipboard().setText(item.text(0))

        elif action == "Base":
            base = item.data(0, Qt.UserRole)
            print(base.get("base"))

        elif action == "Size":
            base = item.data(0, Qt.UserRole)
            print(base.get("size"))

        elif action == "Path":
            base = item.data(0, Qt.UserRole)
            print(base.get("path"))

