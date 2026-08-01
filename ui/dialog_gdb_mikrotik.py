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
        self.tree_widget.itemExpanded.connect(self.click_expand)
        self.tree_widget.itemCollapsed.connect(self.click_collap)


        layout = QVBoxLayout()
        layout.addWidget(self.tree_widget)

        self.setLayout(layout)
        self.bv = data
        self.expanded_items = set()
        self.showData()
        SIGNALS.gdb_updated_mikrotik_sniff.connect(self.showData)

    def cekandset_expand(self, tree, id):
        for data in self.expanded_items:
            if data == id:
                tree.setExpanded(True)

    def click_expand(self, item):
        try:
            data = item.data(0, Qt.UserRole)
            self.expanded_items.add(data["time"])
        except:
            pass

    def click_collap(self, item):
        try:
            data = item.data(0, Qt.UserRole)
            self.expanded_items.remove(data["time"])
        except:
            pass


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
        mydata.reverse() #balik terakhir diatas (terbaru)

        self.tree_widget.headerItem().setText(0, "Buffer iov Total: %s" %len(mydata) )

        for i in mydata:
            title = f"{hex(i['iov'])} {i['out_m2']['packet_length']}"
            item = QTreeWidgetItem(self.tree_widget)
            item.setText(0, title)
            item.setFont(0, self.font)
            item.setData(0, Qt.UserRole, i)
            self.cekandset_expand(item, i['time'])

            for z in i["out_m2"]["m2_data"]:
                mid_item = QTreeWidgetItem(item)
                mid_item.setText(0, f"{z['id']} ({z['type']})")
                mid_item.setFont(0, self.font)

                if isinstance(z['value'], list):
                    mval_item = QTreeWidgetItem(mid_item)
                    mval_item.setText(0, f"Value: {len(z['value'])}")
                    mval_item.setFont(0, self.font)

                    for ival in z['value']:
                        mival_item = QTreeWidgetItem(mval_item)
                        try:
                            isi = ival.split("=>")
                            isi = int(isi[1], 0)
                        except:
                            isi = ival
                        mival_item.setText(0, f"{isi}")
                        mival_item.setFont(0, self.font)
                        mival_item.setToolTip(0, f"{ival}")
                else:
                    mval_item = QTreeWidgetItem(mid_item)
                    mval_item.setText(0, f"Value: {z['value']}")
                    mval_item.setFont(0, self.font)
                    mval_item.setToolTip(0, f"{z['value']}")

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

        menu.addAction("Info recvmsg structure")
        menu.addAction("Info header M2 data (iov buffer)")
        menu.addAction("Dump hex (print)")
        menu.addAction("Refresh data")

        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)

    def handle_tree_action(self, action, item):
        if action == "Dump hex (print)":
            try:
                data = item.data(0, Qt.UserRole)
                print(data["out_m2"]["dump"])
            except:
                pass

        elif action == "Info recvmsg structure":
            try:
                data = item.data(0, Qt.UserRole)
                fd = data["fd"]
                msg_addr = hex(data["msg_addr"])
                iov, iovlen = hex(data["iov"]), data["iovlen"]
                control, controllen = hex(data["control"]), data["controllen"]
                flags = data["flags"]
                print(f"Fd              : {fd}")
                print(f"Message address : {msg_addr}")
                print(f"Iov address     : {iov}  len: {iovlen}")
                print(f"Control address : {control}  len: {controllen}")
                print(f"Flags           : {flags}")
            except:
                pass


        elif action == "Info header M2 data (iov buffer)":
            try:
                data = item.data(0, Qt.UserRole)
                packet_length = data["out_m2"]["packet_length"]
                security_mode = data["out_m2"]["security_mode"]
                msg_length = data["out_m2"]["msg_length"]
                magic = data["out_m2"]["magic"]

                print(f"Packat length   : {packet_length}")
                print(f"Security mode   : {security_mode}")
                print(f"Message length  : {msg_length}")
                print(f"Magic           : {magic}")
            except:
                pass


        elif action == "Refresh data":
            #self.showData();
            SIGNALS.gdb_updated_mikrotik_sniff.emit()
