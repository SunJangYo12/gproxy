from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, getMonospaceFont
from PySide2 import QtCore
from PySide2.QtGui import QColor, QBrush, QFont
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
from ..helpers import RefreshUiTask
from ..settings import Settings
import base64
import time
import os

from binaryninja import (
    core_version,
    log_info,
    highlight,
)
import json

class DialogHeapsDprintf(QDialog):
    def __init__(self, title="", parent=None, reg_name=None):
        super().__init__(parent)

        dec_title = base64.b64decode(title).decode()

        self.setWindowTitle(f"Heap = {dec_title}")
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint
        )
        self.setWindowModality(Qt.NonModal)

        SIGNALS.gdb_updated_dprintf.connect(self.setHeap)

        self.title = title
        self.history = []
        self.history_curr = 1
        self.heap = []

        layout = QVBoxLayout()
        font = getMonospaceFont(self)

        # Set up register table
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(['Address', 'value'])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)


        self.label_his = QLabel("[0/0]")
        self.label_his.setFont(font)

        self.btnF = QToolButton()
        self.btnF.setIcon(self.style().standardIcon(QStyle.SP_ArrowForward))
        self.btnF.setIconSize(QSize(20,20))
        self.btnF.setToolTip("History forward")

        self.btnB = QToolButton()
        self.btnB.setIcon(self.style().standardIcon(QStyle.SP_ArrowBack))
        self.btnB.setIconSize(QSize(20,20))
        self.btnB.setToolTip("History backward")


        self.btnS = QToolButton()
        self.btnS.setIcon(self.style().standardIcon(QStyle.SP_ArrowBack))
        self.btnS.setIconSize(QSize(20,20))
        self.btnS.setToolTip("x/10bx $esp")

        self.lineEdit = QLineEdit()
        self.lineEdit.setObjectName(u"lineEdit")


        h_layout = QHBoxLayout()
        h_layout.addWidget(self.btnB)
        h_layout.addWidget(self.btnF)
        h_layout.addWidget(self.label_his)
        h_layout.addWidget(self.lineEdit)
        h_layout.addWidget(self.btnS)



        layout.addWidget(self.table)
        layout.addLayout(h_layout)
        self.setLayout(layout)


        self.btnF.clicked.connect(self.click_stateF)
        self.btnB.clicked.connect(self.click_stateB)
        self.btnS.clicked.connect(self.click_stateS)

        self.setHeap()

        self.reg_value = None
        self.reg_raw = None


    def click_stateS(self):
        s = Settings()
        s.set("heap_cmd", self.lineEdit.text())


    def click_stateF(self):
        if self.history_curr < len(self.history)-1:
            self.history_curr += 1
            self.setHeap(self.history_curr)

    def click_stateB(self):
        if self.history_curr > 1:
            self.history_curr -= 1
            self.setHeap(self.history_curr)



    def closeEvent(self, event):
        print("[+] close dialog")
        s = Settings()
        s.remove_from_list("show_heap", self.title)


    def show_context_menu(self, pos):
        # Dapatkan posisi global
        global_pos = self.table.viewport().mapToGlobal(pos)

        # Cek row dan column
        row = self.table.rowAt(pos.y())
        col = self.table.columnAt(pos.x())
        if row < 0 or col < 0:
            return  # klik di area kosong

        item = self.table.item(row, col)

        # Buat menu
        menu = QMenu()

        #print(col, row, item.text())
        if col == 0:
            menu.addAction("Detail", lambda: self.menu_action(item, "Detail"))
            menu.addAction("Copy", lambda: self.menu_action(item, "Copy"))
        elif col == 1:
            menu.addAction("Copy", lambda: self.menu_action(item, "Copy"))

        menu.exec_(global_pos)


    def menu_action(self, item, aksi=None, solve_reg=None):
        if aksi == "Copy":
            QApplication.clipboard().setText(item.text())

        elif aksi == "Detail":
            print("sd")


    def _makewidget(self, val, center=False, rcolor=None):
        out = QTableWidgetItem(str(val))
        out.setFlags(Qt.ItemIsEnabled)
        out.setFont(getMonospaceFont(self))

        if val == "<symbolic>":
            out.setForeground(QColor("red"))

        if rcolor:
            out.setForeground(rcolor)

        if center:
            out.setTextAlignment(Qt.AlignCenter)
        return out


    def openHeap(self, name):
        output = []
        with open(name, "r") as f:
            data = f.read()
            output = data.split("\n")

        return output

    def setHeap(self, tohistory=False):
        fullpath = "/dev/shm/heaps/"+self.title

        try:
            files = os.listdir(fullpath)
            files_urut = sorted([f for f in files if f.endswith('.txt')])
        except:
            return


        if tohistory:
            xx = self.history[self.history_curr]

            self.heap = self.openHeap(fullpath+"/"+xx)
        else:
            self.history = files_urut


        total = len(self.history) - 1
        curr = self.history_curr

        self.label_his.setText(f"[{curr}/{total}]")

        self.table.setRowCount(len(self.heap))


        for i, data in enumerate(self.heap):

            raw = data.split(":")
            try:
                addr = raw[0]
                value = raw[1].replace("\t", "  ")

                self.table.setItem(i, 0, self._makewidget(addr, rcolor=QColor("green")))
                self.table.setItem(i, 1, self._makewidget(value))
            except:
                pass

