from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, getMonospaceFont
from PySide2 import QtCore
from PySide2.QtGui import QColor
from PySide2.QtCore import Qt, QPoint, QEvent, QSize, QThread, Signal
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
     QCheckBox
)
from ..data_global import SIGNALS, GLOBAL
import base64


class FuncListDockWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name, data):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)


        SIGNALS.gdb_updated.connect(self.refresh_from_global)


        tree_widget = QTreeWidget()
        self.tree_widget = tree_widget
        self.tree_widget.itemDoubleClicked.connect(self.on_item_double_clicked)

        self.tree_widget.headerItem().setText(0, "Function List" )
        tree_widget.setColumnCount(1)

        # MENGAKTIFKAN KLIK KANAN
        self.tree_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.on_tree_context_menu)


        self.lineEdit = QLineEdit()
        self.lineEdit.setObjectName(u"lineEdit")

        layout = QVBoxLayout()
        layout.addWidget(tree_widget)
        layout.addWidget(self.lineEdit)

        self.setLayout(layout)
        self.bv = data
        self.font = getMonospaceFont(self)
        self.func_name = None
        self.func_addr = None



    def refresh_from_global(self):
        self.tree_widget.clear()
        self.tree_widget.headerItem().setText(0, "Function List  %d" %len(GLOBAL.gdb_functions) )

        for raw_func, count in GLOBAL.gdb_functions.items():
            parent = QTreeWidgetItem(self.tree_widget)

            s = base64.b64decode(raw_func).decode()
            s = s.split("|||")

            func_addr = s[0]
            try:
               func_name = s[1]
            except:
               func_name = func_addr

            self.func_name = func_name
            self.func_addr = func_addr

            parent.setText(0, "%d  %s" % (count, func_name) )
            parent.setFont(0, self.font)
            parent.setData(0, Qt.UserRole, str(func_addr) )




    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


    def on_item_double_clicked(self, item, column):
        try:
            addr = int(item.data(0, Qt.UserRole), 0)
            print("jump to:", hex(addr))

            self.bv.offset = addr
        except:
            pass


    def on_tree_context_menu(self, position: QPoint):
        item = self.tree_widget.itemAt(position)
        if item is None:
            return   # klik kanan di area kosong → tidak ada menu

        menu = QMenu()


        if item.parent() is None:
            menu.addAction("Copy")
            menu.addAction("Show registers")


        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)


    def handle_tree_action(self, action, item):

        if action == "Copy":
            QApplication.clipboard().setText(item.text(0))

        elif action == "Show registers":
            print("dellefkelfk")

