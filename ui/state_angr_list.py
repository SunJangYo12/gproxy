from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, getMonospaceFont
from PySide2 import QtCore
from PySide2.QtCore import Qt, QPoint, QEvent, QSize
from PySide2.QtWidgets import (
     QApplication,
     QHBoxLayout,
     QVBoxLayout,
     QLabel,
     QWidget,
     QTreeWidget,
     QTreeWidgetItem,
     QMenu,
     QLineEdit
)

from ..data_global import SIGNALS, GLOBAL


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
        tree_widget.installEventFilter(self)


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



    def eventFilter(self, source, event) -> bool:
        """Event filter to create hook management context menu"""
        if event.type() == QEvent.ContextMenu and source is self.tree_widget:
            pos = source.viewport().mapFromParent(event.pos())
            item = source.itemAt(pos)

            # Right clicked outside an item
            if not item:
                return True
        return super().eventFilter(source, event)

    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


    def on_item_double_clicked(self, item, column):
        addr = int(item.text(column), 0)
        print("jump to:", addr)

        self.bv.offset = addr


    def on_tree_context_menu(self, position: QPoint):
        item = self.tree_widget.itemAt(position)
        if item is None:
            return   # klik kanan di area kosong → tidak ada menu

        menu = QMenu()

        # contoh action umum
        menu.addAction("Copy")
        menu.addAction("History bbl_addr")
        menu.addAction("History descrip")
        menu.addAction("History jumpkind")
        menu.addAction("History events")


        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)


    def handle_tree_action(self, action, item):
        font = getMonospaceFont(self)
        parent = item.parent()
        key_raw = parent.text(0).split(" ")

        #active, unsat, etc
        key = key_raw[0]
        index_child = parent.indexOfChild(item)

        state = GLOBAL.simgr.stashes[key]

        history_perstate = state[index_child]
        print("%s %d" % (key, index_child ))


        if action == "Copy":
            QApplication.clipboard().setText(item.text(0))

        elif action == "History bbl_addr":
            history = history_perstate.history.bbl_addrs

            for hs in history:
                child1 = QTreeWidgetItem(self.tree_child[index_child])

                child1.setText(0, hex(hs))
                child1.setFont(0, font)
            self.tree_child[index_child].setText(0, "%s bbl %s" % (item.text(0), len(history) ))


        elif action == "History descrip":
            des = history_perstate.history.descriptions

            for hs in des:
                child1 = QTreeWidgetItem(self.tree_child[index_child])

                child1.setText(0, hs)
                child1.setFont(0, font)
            self.tree_child[index_child].setText(0, "%s descrip %s" % (item.text(0), len(des) ))

        elif action == "History jumpkind":
            jumpk = history_perstate.history.jumpkinds

            for hs in jumpk:
                child1 = QTreeWidgetItem(self.tree_child[index_child])

                child1.setText(0, hs)
                child1.setFont(0, font)
            self.tree_child[index_child].setText(0, "%s jumpkind %s" % (item.text(0), len(jumpk) ))

        elif action == "History events":
            events = history_perstate.history.events

            for hs in events:
                child1 = QTreeWidgetItem(self.tree_child[index_child])

                child1.setText(0, "%s" %hs)
                child1.setFont(0, font)
            self.tree_child[index_child].setText(0, "%s events %s" % (item.text(0), len(events) ))

