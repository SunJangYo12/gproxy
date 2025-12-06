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




class DialogDumpStructure(QDialog):
    def __init__(self, title="", parent=None, reg_name=None):
        super().__init__(parent)
        self.setWindowTitle(f"Dump Structure: {reg_name} {title}")
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint
        )
        self.setWindowModality(Qt.NonModal)

        SIGNALS.gdb_updated_struct.connect(self.setReg)

        layout = QVBoxLayout()
        font = getMonospaceFont(self)

        # Set up register table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(['Offset', 'Addr<little', 'Type'])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        layout.addWidget(self.table)
        self.setLayout(layout)

        self.setReg()

        self.reg_value = None
        self.reg_raw = None

    def closeEvent(self, event):
        print("[+] close dialog")
        GLOBAL.gdb_hookstructname = ""


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
        elif col == 1:
            menu.addAction("Copy", lambda: self.menu_action(item, "Copy"))
            menu.addAction("Dump", lambda: self.menu_action(item, "Dump structure"))

        menu.exec_(global_pos)


    def menu_action(self, item, aksi=None, solve_reg=None):
        if aksi == "Copy":
            QApplication.clipboard().setText(item.text())

        elif aksi == "Detail":
            print("sd")

        elif aksi == "Dump":
            print("zz")



    def _makewidget(self, val, center=False):
        out = QTableWidgetItem(str(val))
        out.setFlags(Qt.ItemIsEnabled)
        out.setFont(getMonospaceFont(self))

        if val == "<symbolic>":
            out.setForeground(QColor("red"))

        if center:
            out.setTextAlignment(Qt.AlignCenter)
        return out

    def setReg(self):
        regs = GLOBAL.gdb_memstruct
        self.table.setRowCount(len(regs))

        for i, reg in enumerate(regs):
            reg = reg.split("===")
            try:
                offset = reg[0]
                addr = reg[1]
                type = reg[2]

                self.table.setItem(i, 0, self._makewidget(offset))
                self.table.setItem(i, 1, self._makewidget(addr))
                self.table.setItem(i, 2, self._makewidget(type))
            except:
                pass






class DialogRegisters(QDialog):
    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Register Hook: {title}")
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint
        )
        self.setWindowModality(Qt.NonModal)

        self.reg_value = None
        self.reg_raw = None
        self.history = []
        self.history_curr = 1


        SIGNALS.gdb_updated_regs.connect(self.setReg)

        layout = QVBoxLayout()
        font = getMonospaceFont(self)

        # Set up register table
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(['Register', 'Value'])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        self.label_his = QLabel("[0/0]")
        self.label_his.setFont(font)


        self.btn = QToolButton()
        self.btn.setCheckable(True)
        self.btn.setIcon(self.style().standardIcon(QStyle.SP_MediaPause))
        self.btn.setIconSize(QSize(20,20))
        self.btn.setToolTip("Break After hit")

        self.btnF = QToolButton()
        self.btnF.setIcon(self.style().standardIcon(QStyle.SP_ArrowForward))
        self.btnF.setIconSize(QSize(20,20))
        self.btnF.setToolTip("History forward")

        self.btnB = QToolButton()
        self.btnB.setIcon(self.style().standardIcon(QStyle.SP_ArrowBack))
        self.btnB.setIconSize(QSize(20,20))
        self.btnB.setToolTip("History backward")


        self.btn.toggled.connect(self.toggle_state)
        self.btnF.clicked.connect(self.click_stateF)
        self.btnB.clicked.connect(self.click_stateB)

        h_layout = QHBoxLayout()
        h_layout.addWidget(self.btnB)
        h_layout.addWidget(self.btn)
        h_layout.addWidget(self.btnF)


        layout.addWidget(self.table)
        layout.addWidget(self.label_his)
        layout.addLayout(h_layout)
        self.setLayout(layout)

        self.setReg()

    def click_stateF(self):
        if self.history_curr < len(self.history)-1:
            self.history_curr += 1
            self.setReg(self.history_curr)

    def click_stateB(self):
        if self.history_curr > 1:
            self.history_curr -= 1
            self.setReg(self.history_curr)




    def toggle_state(self, checked):
        if checked:
            # mode PLAY
            self.btn.setIcon(self.style().standardIcon(QStyle.SP_MediaPause))
            GLOBAL.gdb_hookstop = ""
        else:
            # mode PAUSE
            self.btn.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
            GLOBAL.gdb_hookstop = "pause"


    def closeEvent(self, event):
        print("[+] close dialog")
        GLOBAL.gdb_hookname = ""


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

        reg_name = self.table.item(row, 0).text()

        #print(col, row, item.text())
        if col == 0:
            menu.addAction("Detail", lambda: self.menu_action(item, "Detail"))
        elif col == 1:
            menu.addAction("Copy", lambda: self.menu_action(item, "Copy"))
            menu.addAction("Dump Structure: ", lambda: self.menu_action(item, "Dump", reg_name))

        menu.exec_(global_pos)


    def menu_action(self, item, aksi=None, reg_name=None):
        if aksi == "Copy":
            QApplication.clipboard().setText(item.text())

        elif aksi == "Detail":
            print("sd")

        elif aksi == "Dump":
            hname = item.text()

            self.dlg = DialogDumpStructure(title=hname, reg_name=reg_name)
            self.dlg.resize(370, 430) # w,h
            self.dlg.show()
            self.dlg.raise_()
            self.dlg.activateWindow()

            GLOBAL.gdb_hookstructname = hname



    def _makewidget(self, val, center=False):
        out = QTableWidgetItem(str(val))
        out.setFlags(Qt.ItemIsEnabled)
        out.setFont(getMonospaceFont(self))

        if val == "<symbolic>":
            out.setForeground(QColor("red"))

        if center:
            out.setTextAlignment(Qt.AlignCenter)
        return out


    def setReg(self, tohistory=False):

        regs = GLOBAL.gdb_memregs

        if tohistory:
            regs = self.history[self.history_curr]
        else:
            self.history.append(regs)


        total = len(self.history) - 1
        curr = self.history_curr

        self.label_his.setText(f"[{curr}/{total}]")


        self.table.setRowCount(len(regs))

        for i, reg in enumerate(regs):
            reg = reg.split("=")
            try:
                regname = reg[0]
                regvalue = reg[1]

                self.table.setItem(i, 0, self._makewidget(regname))
                self.table.setItem(i, 1, self._makewidget(regvalue))
            except:
                pass





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

        for (raw_func, data) in GLOBAL.gdb_functions.items():
            parent = QTreeWidgetItem(self.tree_widget)

            s = raw_func.split("|||")

            func_addr = s[0]
            try:
               func_name = s[1]
            except:
               func_name = func_addr

            self.func_name = func_name
            self.func_addr = func_addr

            parent.setText(0, "%d  %s" % (data['count'], func_name) )
            parent.setFont(0, self.font)
            parent.setData(0, Qt.UserRole, str(func_addr) )

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
            menu.addAction("Hook2dump")
            menu.addAction("Clear All")


        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)


    def handle_tree_action(self, action, item):

        if action == "Copy":
            QApplication.clipboard().setText(item.text(0))

        elif action == "Hook2dump":
            hname = item.text(0).split("  ")
            hname = hname[1]

            self.dlg = DialogRegisters(title=hname)
            self.dlg.resize(250, 470) # w,h
            self.dlg.show()
            self.dlg.raise_()
            self.dlg.activateWindow()

            GLOBAL.gdb_hookname = hname



        elif action == "Clear All":
            self.tree_widget.clear()
            GLOBAL.gdb_functions = {}

