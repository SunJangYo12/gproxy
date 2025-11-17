from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, getMonospaceFont
from PySide2 import QtCore
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


class StepThread(QThread):
    done = Signal(object)

    def __init__(self, state, branch):
        super().__init__()
        self.state = state
        self.branch = branch
        self._run = True

    def stop(self):
        self._run = False
        print("thread stop")

    def run_branch(self):
        counter = 0

        while self._run:
            succ = self.state.step()
            counter += 1
            if len(succ.successors) == self.branch:
                break
            self.state = succ.successors[0]
            print("[%d] Running..." % counter)

        self.done.emit(succ)

    def run(self):
        self.run_branch()

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



class DialogStep(QDialog):
    def __init__(self, title="Input", label="Masukkan data:", parent=None, state=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint
        )
        self.setWindowModality(Qt.NonModal)

        layout = QVBoxLayout()
        font = getMonospaceFont(self)

        self.label_pc = QLabel("Register PC: 0x0000000")
        self.label_pc.setFont(font)
        layout.addWidget(self.label_pc)

        self.btn_step = QPushButton("Step block")
        self.btn_step.clicked.connect(self.process_step)
        layout.addWidget(self.btn_step)

        self.chknav = QCheckBox("Auto navigation")
        self.chknav.setChecked(False)   # default OFF
        layout.addWidget(self.chknav)


        # LABEL
        self.label = QLabel(label)
        self.label.setFont(font)
        layout.addWidget(self.label)
        # TEXTBOX
        self.lineedit = QLineEdit()
        self.lineedit.setFont(font)
        self.lineedit.setText("2")
        layout.addWidget(self.lineedit)

        # BUTTON BAR
        btn_layout = QHBoxLayout()

        self.btn_ok = QPushButton("Branch")
        self.btn_ok.clicked.connect(self.process)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setFont(font)
        self.btn_cancel.clicked.connect(self.set_cancel)

        btn_layout.addWidget(self.btn_ok)
        btn_layout.addWidget(self.btn_cancel)
        layout.addLayout(btn_layout)

        # LABEL
        self.label = QLabel("Result by")
        self.label.setFont(font)
        layout.addWidget(self.label)
        # ComboBox
        self.combo = QComboBox()
        self.combo.setFont(font)
        self.combo.addItems([
            "successors",
            "unsat_successors",
            "flat_successors",
            "unconstrained_successors",
            "all_successors"
        ])
        self.combo.currentTextChanged.connect(self.on_combo_text)
        layout.addWidget(self.combo)

        # TEXTBOX
        self.resultedit = QLineEdit()
        self.resultedit.setFont(font)
        self.resultedit.setFixedHeight(50)
        layout.addWidget(self.resultedit)

        self.btn_move = QPushButton("Move to stashes: active")
        self.btn_move.setFont(font)
        self.btn_move.setEnabled(False)
        layout.addWidget(self.btn_move)

        btn_reg = QPushButton("Show registers")
        btn_reg.setFont(font)
        btn_reg.clicked.connect(self.show_registers)
        layout.addWidget(btn_reg)

        btn_buf = QPushButton("Show buffers")
        btn_buf.setFont(font)
        layout.addWidget(btn_buf)

        # LABEL
        self.labelrun = QLabel("Running...")
        self.labelrun.setFont(font)
        self.labelrun.hide()
        layout.addWidget(self.labelrun)

        self.setLayout(layout)

        self.state = state
        self.result_state = None


    def show_registers(self):
        self.dlg = DialogRegisters(title="Registers", state=self.state)
        self.dlg.show()
        self.dlg.raise_()
        self.dlg.activateWindow()


    # Fungsi untuk ambil teks
    def get_text(self):
        return self.lineedit.text()

    def set_cancel(self):
        if hasattr(self, "thread"):
            self.thread.stop()
            self.btn_cancel.setEnabled(False)
            self.btn_ok.setEnabled(True)

    def process(self):
        self.labelrun.show()
        self.btn_ok.setEnabled(False)
        self.btn_cancel.setEnabled(True)

        self.thread = StepThread(self.state, int(self.lineedit.text()))
        self.thread.done.connect(self.on_finish)
        self.thread.start()

    def process_step(self):
        succ = self.state.step()
        try:
            self.state = succ.successors[0]
        except:
            print("except state!")
            return

        print(succ)
        self.result_state = succ

        combo_index = self.combo.currentText()
        self.on_combo_text(combo_index)

        addr = hex(succ.successors[0].addr)
        branch = len(succ.successors)
        self.label_pc.setText("Register PC: %s [%d]" % (addr, branch))

        if self.chknav.isChecked():
            #self.view.offset = addr
            tes = self.bv.file.filename
            print(tes)


    def on_finish(self, object):
        self.labelrun.setText(f"Complete")
        self.btn_ok.setEnabled(True)
        self.btn_move.setEnabled(True)
        self.btn_cancel.setEnabled(False)

        self.result_state = object

        self.on_combo_text("successors")

    def on_combo_text(self, text):
        out = None
        try:
            if text == "successors":
                out = self.result_state.successors
            elif text == "unsat_successors":
                out = self.result_state.unsat_successors
            elif text == "flat_successors":
                out = self.result_state.flat_successors
            elif text == "unconstrained_successors":
                out = self.result_state.unconstrained_successors
            elif text == "all_successors":
                out = self.result_state.all_successors
            self.resultedit.setText(repr(out))
        except:
            pass

        self.resultedit.setText(repr(out))






class StateAngrListDockWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name, data):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)


        SIGNALS.state_updated.connect(self.refresh_from_global)


        tree_widget = QTreeWidget()
        self.tree_widget = tree_widget
        self.tree_widget.itemDoubleClicked.connect(self.on_item_double_clicked)

        tree_widget.setColumnCount(1)
        tree_widget.headerItem().setText(0, "State List")

        # contoh kategori
        #reg_group = QTreeWidgetItem(["Active (12)", ""])
        #tree_widget.addTopLevelItem(reg_group)
        #QTreeWidgetItem(reg_group, ["0x40004", ""])

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



    def refresh_from_global(self):
        self.tree_widget.clear()
        self.tree_parent = []
        self.tree_child = []

        font = getMonospaceFont(self)

        for stash_name, states in GLOBAL.simgr.stashes.items():
            parent = QTreeWidgetItem(self.tree_widget)
            self.tree_parent.append(parent)

            parent.setText(0, "%s %s" % (stash_name, str(len(states)) ) )
            parent.setFont(0, font)

            # Tambahkan child setiap state
            for st in states:
                child = QTreeWidgetItem(parent)
                self.tree_child.append(child)

                child.setText(0, hex(st.addr))

                child.setFont(0, font)





    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


    def on_item_double_clicked(self, item, column):
        try:
            addr = int(item.text(column), 0)
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
            print("Is parent")
        elif item.parent().parent() is None:
            menu.addAction("Copy")
            menu.addAction("State manager")
            menu.addAction("Taint to this")
            menu.addAction("Move to stashed")
            menu.addAction("History bbl_addr")
            menu.addAction("History descrip")
            menu.addAction("History jumpkind")
            menu.addAction("History events")
        elif item.parent().parent().parent() is None:
            menu.addAction("Copy")


        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)


    def handle_tree_action(self, action, item):
        font = getMonospaceFont(self)
        parent = None
        index_child = None

        if item.parent().parent() is None:
            print("Is child")
            parent = item.parent()

        elif item.parent().parent().parent() is None:
            print("Is child1")
            parent = item.parent().parent()

        index_child = item.parent().indexOfChild(item)


        #active, unsat, etc
        key_raw = parent.text(0).split(" ")
        key = key_raw[0]

        print("key:%s index:%d" % (key, index_child ))

        state = GLOBAL.simgr.stashes[key]
        history_perstate = state[index_child]


        if action == "Copy":
            QApplication.clipboard().setText(item.text(0))

        elif action == "State manager":
            self.dlg = DialogStep(title="State Manager", label="Break after any branch", state=state[index_child] )
            self.dlg.show()
            self.dlg.raise_()
            self.dlg.activateWindow()

        elif action == "Taint to this":
            print("Taint Wait...")
            input_data = state[index_child].posix.stdin.load(0, state[index_child].posix.stdin.size)

            out = state[index_child].solver.eval(input_data, cast_to=bytes)
            print(out)


        elif action == "Move to stashed":
            target_state = state[index_child]
            GLOBAL.simgr.move(from_stash=key, to_stash="stashed", filter_func=lambda s: s is target_state)

            print("state is moved, please refresh UI")


        elif action == "History bbl_addr":
            history = history_perstate.history.bbl_addrs

            for hs in history:
                child1 = QTreeWidgetItem(item)

                child1.setText(0, hex(hs))
                child1.setFont(0, font)
            self.tree_child[index_child].setText(0, "%s bbl %s" % (item.text(0), len(history) ))


        elif action == "History descrip":
            des = history_perstate.history.descriptions

            for hs in des:
                child1 = QTreeWidgetItem(item)

                child1.setText(0, hs)
                child1.setFont(0, font)
            self.tree_child[index_child].setText(0, "%s descrip %s" % (item.text(0), len(des) ))

        elif action == "History jumpkind":
            jumpk = history_perstate.history.jumpkinds

            for hs in jumpk:
                child1 = QTreeWidgetItem(item)

                child1.setText(0, hs)
                child1.setFont(0, font)
            self.tree_child[index_child].setText(0, "%s jumpkind %s" % (item.text(0), len(jumpk) ))

        elif action == "History events":
            events = history_perstate.history.events

            for hs in events:
                child1 = QTreeWidgetItem(item)

                child1.setText(0, "%s" %hs)
                child1.setFont(0, font)
            self.tree_child[index_child].setText(0, "%s events %s" % (item.text(0), len(events) ))

