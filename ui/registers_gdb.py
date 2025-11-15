from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget

instance_id = 0
class RegGdbDockWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name, data):
        global instance_id
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)


        self._layout = QVBoxLayout()

        title = QLabel(name, self)
        title.setAlignment(QtCore.Qt.AlignCenter)
        self._layout.addWidget(title)

        # TABLE
#        self._table = QTableWidget()
#        self._table.setColumnCount(2)
#        self._table.setHorizontalHeaderLabels(['Register', 'Value'])
#        self._table.horizontalHeader().setStretchLastSection(True)
#        self._table.verticalHeader().setVisible(False)



 #       self._layout.addWidget(self._table)

        self.setLayout(self._layout)


        instance_id += 1
        self.data = data


    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True


    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

    def on_customContextMenuRequested(self, pos):
        item = self._table.itemAt(pos)
        if item is None:
            return
        return

    def on_doubleClick(self, item):
        row_idx = item.row()
        return


