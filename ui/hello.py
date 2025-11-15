from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget

instance_id = 0
class HelloDockWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		global instance_id
		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)

		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		offset_layout = QHBoxLayout()
		offset_layout.addWidget(QLabel("Offset: "))

		self.offset = QLabel(hex(0))

		offset_layout.addWidget(self.offset)
		offset_layout.setAlignment(QtCore.Qt.AlignCenter)

		datatype_layout = QHBoxLayout()
		datatype_layout.addWidget(QLabel("Data Type: "))

		self.datatype = QLabel("")

		datatype_layout.addWidget(self.datatype)
		datatype_layout.setAlignment(QtCore.Qt.AlignCenter)

		layout = QVBoxLayout()
		title = QLabel(name, self)
		title.setAlignment(QtCore.Qt.AlignCenter)
		instance = QLabel("Instance: " + str(instance_id), self)
		instance.setAlignment(QtCore.Qt.AlignCenter)

		layout.addStretch()
		layout.addWidget(title)
		layout.addWidget(instance)
		layout.addLayout(datatype_layout)
		layout.addLayout(offset_layout)
		layout.addStretch()
		self.setLayout(layout)
		instance_id += 1
		self.data = data

	def notifyOffsetChanged(self, offset):
		self.offset.setText(hex(offset))

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

	def notifyViewChanged(self, view_frame):
		if view_frame is None:
			self.datatype.setText("None")
			self.data = None
		else:
			self.datatype.setText(view_frame.getCurrentView())
			view = view_frame.getCurrentViewInterface()
			self.data = view.getData()

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


