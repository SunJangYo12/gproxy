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

class DialogAngrHook(QDialog):
    def __init__(self, parent=None, sid=None, data=None):
        super().__init__(parent)
        self.setWindowTitle(f"Angr hook({sid})")
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint
        )

        SIGNALS.angrhook_updated.connect(self.showData)

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
        mydata = GLOBAL.angr_hooks

        self.tree_widget.headerItem().setText(0, "Total: %s" %len(mydata) )

        for i in mydata:
            item = QTreeWidgetItem(self.tree_widget)
            item.setText(0, i["name"])
            item.setFont(0, self.font)
            item.setData(0, Qt.UserRole, i)

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

        menu.addAction("zzz")
        menu.addAction("Refresh data")

        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)

    def handle_tree_action(self, action, item):
        data = item.data(0, Qt.UserRole)

        if action == "zzz":
            print("sd")
        elif action == "Refresh data":
            self.showData();


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
            for i in mydata:
                self.add_node(self.tree_widget, i)
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
        menu.addAction("Show registers")
        menu.addAction("Show hooks")
        menu.addAction("Temporary state")
        menu.addAction("Step")
        menu.addAction("Explore")
        menu.addAction("Refresh data")

        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)

    def dialog_process(self):
        # Jika dialog sudah ada, tutup
        if hasattr(self, "pdlg") and self.pdlg is not None:
            self.pdlg.close()
            self.pdlg.deleteLater()
            self.pdlg = None
            return
        # Buat dialog baru
        self.pdlg = QProgressDialog("Process explore...", None, 0, 0)
        self.pdlg.setWindowTitle("Process")
        self.pdlg.setCancelButton(None)
        self.pdlg.setWindowModality(Qt.ApplicationModal)
        QApplication.processEvents()
        self.pdlg.show()

    def handle_tree_action(self, action, item):
        data = item.data(0, Qt.UserRole)

        if action == "Show contraints":
            state = data["state"]
            with open("/tmp/constraints.txt", "w") as out:
                for i in state.solver.constraints:
                    out.write(f"{i}\n\n")
            print("[+] saved to /tmp/constraints.txt")

        elif action == "Show solver input":
            solver_bytes = data["solver_bytes"]
            print(solver_bytes)
            show_message_box(
                "G-proxy",
                solver_bytes,
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.InformationIcon
            )

        elif action == "Show hooks":
            state = data["state"]
            self.hdlg = DialogAngrHook(sid="myhook", data=self.bv)
            self.hdlg.resize(300, 450) # w,h
            self.hdlg.show()
            self.hdlg.raise_()
            self.hdlg.activateWindow()

        elif action == "Show registers":
            state = data["state"]
            self.drdlg = DialogRegisters(title="Registers", state=state)
            self.drdlg.resize(300, 450) # w,h
            self.drdlg.show()
            self.drdlg.raise_()
            self.drdlg.activateWindow()

        elif action == "Temporary state":
            GLOBAL.angr_state = data["state"]
            show_message_box(
                "G-proxy",
                "Copy to global, access with GLOBAL.angr_state",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.InformationIcon
            )

        elif action == "Step":
            GLOBAL.angr_step(data["state"])
            SIGNALS.state_tree_updated.emit()


        elif action == "Explore":
            self.dialog_process()

            new_concrete_state = data["state"]
            buf_addr = new_concrete_state.solver.eval(new_concrete_state.regs.rdi)
            sym_buf = claripy.BVS("buf", 8 * 32)
            new_concrete_state.memory.store(buf_addr, sym_buf)

            GLOBAL.angr_explore(GLOBAL.angr_project, data["state"], sym_buf)
            self.dialog_process()
            self.showData();

        elif action == "Refresh data":
            self.showData();


class DialogRegisters(QDialog):
    def __init__(self, title="Input", parent=None, state=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint
        )
        self.setWindowModality(Qt.NonModal)

        self.state = state

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

        layout.addWidget(self.table)
        self.setLayout(layout)

        self.setReg()

        self.reg_value = None
        self.reg_raw = None


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
            if self.table.item(row, 1).text() == "<symbolic>":
                menu.addAction("Solving", lambda: self.menu_action(item, "Solving", self.table.item(row, 0).text() ))
                menu.addAction("Copy", lambda: self.menu_action(item, "Copy"))
            else:
                menu.addAction("Copy", lambda: self.menu_action(item, "Copy"))

        menu.exec_(global_pos)

    def menu_action(self, item, aksi=None, solve_reg=None):
        if aksi == "Copy":
            QApplication.clipboard().setText(item.text())

        elif aksi == "Detail":
            reg_name = getattr(self.state.regs, item.text())
            print(reg_name)

        elif aksi == "Solving":
            print("[+] solving...")
            # Coba evaluasi/solving symbolic jadi nilai konkret
            try:
                print("[+] register: ", solve_reg)
                reg_expr = getattr(self.state.regs, solve_reg)

                val = self.state.solver.eval(reg_expr)
                val_str = hex(val)
                print("[+] done.")
            except:
                # kalau symbolic / gagal
                val_str = "[+] except solving!"
            print(val_str)



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
        regs = self.state.arch.register_list
        self.table.setRowCount(len(regs))

        for i, reg in enumerate(regs):
            regname = reg.name
            self.table.setItem(i, 0, self._makewidget(regname))

            # ===============================
            #   AMBIL NILAI REGISTER
            # ===============================
            try:
                # akses register berdasarkan nama
                reg_expr = getattr(self.state.regs, regname)
                reg_symbolic = reg_expr.symbolic
                if reg_symbolic:
                    reg_value = "<symbolic>"
                else:
                    reg_value = hex(reg_expr.v)
            except:
                self.table.setItem(i, 1, self._makewidget("<no-attr>"))
                continue


            self.table.setItem(i, 1, self._makewidget(reg_value))



