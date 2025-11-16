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

        font = getMonospaceFont(self)

        for stash_name, states in GLOBAL.stashes.items():
            parent = QTreeWidgetItem(self.tree_widget)
            parent.setText(0, "%s %s" % (stash_name, str(len(states)) ) )
            parent.setFont(0, font)

            #parent.setSizeHint(0, QSize(0, 26))

            # Tambahkan child setiap state
            for st in states:
                child = QTreeWidgetItem(parent)
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
        menu.addAction("Copy Name")
        menu.addAction("Copy Value")

        # contoh: jika item punya children (group)
        if item.childCount() > 0:
            menu.addSeparator()
            menu.addAction("Expand All")
            menu.addAction("Collapse All")

        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)


    def handle_tree_action(self, action, item):
        if action == "Copy Name":
            QApplication.clipboard().setText(item.text(0))

        elif action == "Copy Value":
            QApplication.clipboard().setText(item.text(1))

        elif action == "Expand All":
            item.setExpanded(True)
            for i in range(item.childCount()):
                item.child(i).setExpanded(True)

        elif action == "Collapse All":
            item.setExpanded(False)
            for i in range(item.childCount()):
                item.child(i).setExpanded(False)



