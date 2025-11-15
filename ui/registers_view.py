from binaryninja.interaction import (
    show_message_box,
    get_int_input,
    get_choice_input
)
from binaryninjaui import (
    DockHandler,
    DockContextHandler,
    getMonospaceFont,
    UIActionHandler
)
from PySide2 import QtCore
from PySide2.QtCore import Qt, QMimeData
from PySide2.QtGui import QBrush, QColor
from PySide2.QtWidgets import (
    QApplication,
    QVBoxLayout,
    QWidget,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QMenu
)



def _normalize_tab_name(tab_name):
    return tab_name[:tab_name.find("(")-1]


def _makewidget(parent, val, center=False):
    """ Small helper function that builds a TableWidgetItem and sets up the font the way we want"""
    out = QTableWidgetItem(str(val))
    out.setFlags(Qt.ItemIsEnabled)
    out.setFont(getMonospaceFont(parent))
    if center:
        out.setTextAlignment(Qt.AlignCenter)
    return out


class RegisterView(QWidget, DockContextHandler):

    dirty_color = QBrush(QColor(255, 153, 51))
    symbolic_color = QBrush(QColor(245, 66, 72))
    no_color = QBrush(QColor(255, 255, 255))

    def __init__(self, parent, name, data):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.parent = parent
        self.arch = None
        self.current_state = None
        self.symb_idx = 0
        self.reg_to_index = dict()
        self.index_to_reg = dict()
        self.reg_cache = dict()
        self.data = data
        self.tab_name = None

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self._layout = QVBoxLayout()

        # Set up register table
        self._table = QTableWidget()
        self._table.setColumnCount(2)
        self._table.setHorizontalHeaderLabels(['Register', 'Value'])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)

        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(
            self.on_customContextMenuRequested)
        self._table.doubleClicked.connect(self.on_doubleClick)

        self._layout.addWidget(self._table)

        self.setLayout(self._layout)

    def reset(self):
        self.tab_name = None
        self.arch = None
        self.reg_to_index = dict()
        self.symb_idx = 0
        self._table.setRowCount(0)

    def init(self, arch, state):
        self.arch = arch
        self.tab_name = _normalize_tab_name(self.parent.getTabName())

        regs = self.arch.reg_names()

        self._table.setRowCount(len(regs))
        for i, reg in enumerate(regs):
            self.reg_to_index[reg] = i
            self.index_to_reg[i] = reg
            self._table.setItem(i, 0, _makewidget(self, reg))
            self._table.setItem(i, 1, _makewidget(self, ""))

        self.set_reg_values(state)

    def set_reg_value(self, reg, value, color=None):
        assert self.arch is not None

        idx = self.reg_to_index[reg]

        if False:
           val_str = "< symbolic expression >"
           if color is None:
                color = RegisterView.symbolic_color
        else:
            val_str = "0x{obj:0{width}x}".format(
                obj=value.value,
                width=(value.size+3) // 4
            )

        self.reg_cache[reg] = val_str
        table_item = self._table.item(idx, 1)
        table_item.setText(val_str)
        if color is not None:
            table_item.setForeground(color)
        else:
            table_item.setForeground(self.no_color)

    def set_reg_values(self, state):
        self.current_state = state
        for reg in self.reg_to_index:
            val = getattr(state.regs, reg)
            self.set_reg_value(reg, val)

    # right click menu
    def on_customContextMenuRequested(self, pos):
        item = self._table.itemAt(pos)
        if item is None:
            return
        row_idx = item.row()

        if self.index_to_reg[row_idx] == self.arch.getip_reg():
            return

        expr = getattr(self.current_state.regs, self.index_to_reg[row_idx])

        menu = QMenu()
        show_reg_expr = menu.addAction("Show reg expression")

        action = menu.exec_(self._table.viewport().mapToGlobal(pos))

        if action is None:
            return

    # double click event
    def on_doubleClick(self, item):
        row_idx = item.row()
        if self.index_to_reg[row_idx] == self.arch.getip_reg():
            return

        old_expr = getattr(self.current_state.regs, self.index_to_reg[row_idx])
        new_val = get_int_input("value for %s" %
                                self.index_to_reg[row_idx], "Set Reg")
        if new_val is None:
            return

    def notifyOffsetChanged(self, offset):
        pass

    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        elif self.tab_name is None:
            return False
        elif _normalize_tab_name(view_frame.getTabName()) != self.tab_name:
            return False
        return True

    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            pass
        else:
            pass

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)




