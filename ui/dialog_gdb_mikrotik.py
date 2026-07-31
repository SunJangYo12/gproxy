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

class DialogMikrotikSniff(QDialog):
    def __init__(self, parent=None, sid=None, data=None):
        super().__init__(parent)
        self.setWindowTitle(f"Gdb mikrotik({sid})")
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint
        )

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
        SIGNALS.gdb_updated_mikrotik_sniff.connect(self.showData)

    def open_json(self, pf):
        data = []
        try:
            with open(pf) as f:
                data = json.load(f)
        except:
            pass
        return data

    def showData(self):
        self.tree_widget.clear()
        mydata = self.open_json("/tmp/mikrotik-sniff.json")

        self.tree_widget.headerItem().setText(0, "Buffer iov Total: %s" %len(mydata) )

        for i in mydata:
            title = f"{hex(i['iov'])} {i['out_m2']['packet_length']}"
            item = QTreeWidgetItem(self.tree_widget)
            item.setText(0, title)
            item.setFont(0, self.font)
            item.setData(0, Qt.UserRole, i)

            fd_item = QTreeWidgetItem(item)
            fd_item.setText(0, f"FD: {i['fd']}")
            fd_item.setFont(0, self.font)

            ma_item = QTreeWidgetItem(item)
            ma_item.setText(0, f"Message address: {hex(i['msg_addr'])}")
            ma_item.setFont(0, self.font)

            iov_item = QTreeWidgetItem(item)
            iov_item.setText(0, f"Iov address: {hex(i['iov'])}  len: {i['iovlen']}")
            iov_item.setFont(0, self.font)

            ct_item = QTreeWidgetItem(item)
            ct_item.setText(0, f"Control address: {hex(i['control'])}  len: {i['controllen']}")
            ct_item.setFont(0, self.font)

            fg_item = QTreeWidgetItem(item)
            fg_item.setText(0, f"Flags: {i['flags']}")
            fg_item.setFont(0, self.font)

            om2_item = QTreeWidgetItem(item)
            om2_item.setText(0, f"Out M2 total: {len(i['out_m2']['m2_data'])}")
            om2_item.setFont(0, self.font)

            pl_item = QTreeWidgetItem(om2_item)
            pl_item.setText(0, f"Packet length: {i['out_m2']['packet_length']}")
            pl_item.setFont(0, self.font)

            sec_item = QTreeWidgetItem(om2_item)
            sec_item.setText(0, f"Security mode: {i['out_m2']['security_mode']}")
            sec_item.setFont(0, self.font)

            msl_item = QTreeWidgetItem(om2_item)
            msl_item.setText(0, f"Message length: {i['out_m2']['msg_length']}")
            msl_item.setFont(0, self.font)

            mgc_item = QTreeWidgetItem(om2_item)
            mgc_item.setText(0, f"Magic: {i['out_m2']['magic']}")
            mgc_item.setFont(0, self.font)

            mdat_item = QTreeWidgetItem(om2_item)
            mdat_item.setText(0, f"M2 data: {len(i['out_m2']['m2_data'])}")
            mdat_item.setFont(0, self.font)
            for z in i["out_m2"]["m2_data"]:
                mid_item = QTreeWidgetItem(mdat_item)
                mid_item.setText(0, f"ID: {z['id']}")
                mid_item.setFont(0, self.font)

                mty_item = QTreeWidgetItem(mdat_item)
                mty_item.setText(0, f"Type: {z['type']}")
                mty_item.setFont(0, self.font)

                if isinstance(z['value'], list):
                    mval_item = QTreeWidgetItem(mdat_item)
                    mval_item.setText(0, f"Value: {len(z['value'])}")
                    mval_item.setFont(0, self.font)
                    for ival in z['value']:
                        mival_item = QTreeWidgetItem(mval_item)
                        mival_item.setText(0, f"{ival}")
                        mival_item.setFont(0, self.font)
                else:
                    mval_item = QTreeWidgetItem(mdat_item)
                    mval_item.setText(0, f"Value: {z['value']}")
                    mval_item.setFont(0, self.font)

            ttip = []
            for z in i["out_m2"]["m2_data"]:
                ttip.append(f'{z["id"]} ({z["type"]})\n')

            item.setToolTip(0, "".join(ttip))

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

        menu.addAction("Dump hex (print)")
        menu.addAction("Refresh data")

        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)

    def handle_tree_action(self, action, item):
        if action == "Dump hex (print)":
            data = item.data(0, Qt.UserRole)
            print(data["out_m2"]["dump"])

        elif action == "Refresh data":
            #self.showData();
            SIGNALS.gdb_updated_mikrotik_sniff.emit()
