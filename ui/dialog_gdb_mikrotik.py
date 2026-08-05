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
import socket
import subprocess
from binaryninja import *
import binaryninja as binja

M2_OPRATION = {
    '0xff0001': 'sys_to',
    '0xff0002': 'sys_from',
    '0xff0003': 'sys_type',
    '0xff0004': 'sys_status',
    '0xff0005': 'sys_reply_expected',
    '0xff0006': 'sys_request_id',
    '0xff0007': 'sys_cmd',
    '0xff0008': 'sys_error_code',
    '0xff0009': 'sys_error',
    '0xff000A': 'sys_user',
    '0xff000B': 'sys_perm',
    '0xff000D': 'sys_ctrl',
    '0xff000F': 'sys_ctrl_arg',
    '0xff0010': 'sys_user_id',
    '0xff0011': 'sys_notifycmd',
    '0xff0012': 'sys_originator',
    '0xff0013': 'sys_addr',
    '0xff0016': 'sys_dreason',
}

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
        self.tree_widget.setExpandsOnDoubleClick(False)


        layout = QVBoxLayout()
        layout.addWidget(self.tree_widget)

        self.setLayout(layout)
        self.bv = data
        self.expanded_items = set()
        self.viz = {}
        self.recvmsg_to = None   #this tmp
        self.recvmsg_from = None #this tmp
        self.ex_vizinit = False
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

    def add_ext_window_node(self, node_name, parent_name, an_from=None, an_to=None):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", 9999))
            msg = {
                "node": node_name,
                "parent": parent_name,
                "animate": True,
                "an_from": an_from,
                "an_to": an_to
            }
            s.sendall(json.dumps(msg).encode())
            time.sleep(1)

    def updateGraphExtWindow(self, who):
        title = f"{who['sink']} {hex(who['iov'])} {who['out_m2']['packet_length']}"
        print(title)
        print(self.viz)

        if not self.ex_vizinit:
            self.ex_vizinit = True
            for x3 in GLOBAL.graph_nodes:
                isi = f'{x3["x3_id"]} {x3["binary"]}'
                self.add_ext_window_node(isi, "ROOT")
            print(f"[+] Load x3 binary done.")
        else:
            if who['sink'] == "recvmsg":
                self.recvmsg_to = self.viz['sys_to']
                self.recvmsg_from = self.viz['sys_from']

            elif who['sink'] == "sendmsg":
                sys_to = self.recvmsg_to[0]
                sys_from = self.viz['sys_from'][0]

                # Balik?
                if len(self.viz['sys_from']) > 1:
                    print("[+] sendmsg have handler")
                    handler = f"{sys_from},{self.viz['sys_from'][1]}"
                    self.add_ext_window_node(handler, sys_from, an_from=handler, an_to=sys_from)

                # send sys_from to loader
                self.add_ext_window_node(sys_from, "ROOT", an_from=sys_from, an_to="ROOT")

                # send loader to sys_to
                self.add_ext_window_node("ROOT", sys_to, an_from="ROOT", an_to=sys_to)

                # Kirim?
                if len(self.recvmsg_to) > 1:
                    print("[+] recvmsg have handler")
                    handler = f"{sys_to},{self.recvmsg_to[1]}"
                    self.add_ext_window_node(sys_to, handler, an_from=sys_to, an_to=handler)

                self.recvmsg_to = None
                self.recvmsg_from = None

    def updateGraph(self, who):
        title = f"{who['sink']} {hex(who['iov'])} {who['out_m2']['packet_length']}"
        print(title)
        print(self.viz)

        # Context: loader binary
        # TODO
        # 1). Send
        # who is send
        #   -sink     : sendmsg
        #   -opration : SYS_FROM => www(70)
        # send to
        #   -sink     : recvmsg
        #   -opration : SYS_TO => user(13) handler(1)

        # other
        # sys_to == [0xff0002, 1,2,3,] #multicast
        # sys_to == [0xff0001] #broadcast

        # add color
        #GLOBAL.graph_attr = {
        #    "n_color": HighlightStandardColor.GreenHighlightColor,
        #    "e_color": BranchType.FalseBranch,
        #    "node_color": ["loader", "www"],
        #    "edge_color": ["loader", "www"]
        #}
        #self.bv.offset = 0x401260 # change this

    def showData(self):
        self.tree_widget.clear()
        mydata = self.open_json("/tmp/mikrotik-sniff.json")
        if len(mydata) == 0:
            return
        mydata.reverse() #balik terakhir diatas (terbaru)

        self.tree_widget.headerItem().setText(0, "Buffer iov Total: %s" %len(mydata) )

        zz = 0
        self.viz = {}
        for i in mydata:
            zz += 1
            title = f"{i['sink']} {hex(i['iov'])} {i['out_m2']['packet_length']}"
            item = QTreeWidgetItem(self.tree_widget)
            item.setText(0, title)
            item.setFont(0, self.font)
            item.setData(0, Qt.UserRole, i)
            self.cekandset_expand(item, i['time'])

            for z in i["out_m2"]["m2_data"]:
                mid_item = QTreeWidgetItem(item)
                mid_item.setText(0, f"{z['id']} ({z['type']})")

                op_key = None
                for key, op in M2_OPRATION.items():
                    if z['id'] == key:
                        mid_item.setText(0, f"{z['id']} ({op.upper()})")
                        op_key = op
                        if zz == 1:
                            self.viz[op_key] = []

                mid_item.setFont(0, self.font)
                mid_item.setToolTip(0, f"Type: {z['type']}")

                if isinstance(z['value'], list):
                    mval_item = QTreeWidgetItem(mid_item)
                    mval_item.setText(0, f"Value: {len(z['value'])}")
                    mval_item.setFont(0, self.font)

                    for ival in z['value']:
                        mival_item = QTreeWidgetItem(mval_item)
                        try:
                            isi = ival.split("=>")
                            isi = int(isi[1], 0)

                            if op_key:
                                for x3 in GLOBAL.graph_nodes:
                                    if x3["x3_id"] == f"{isi}":
                                        isi = f'{isi} {x3["binary"]}'
                                if zz == 1:
                                    self.viz[op_key].append(isi)
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

        #self.updateGraph(mydata[0])
        self.updateGraphExtWindow(mydata[0]) # BUG: race data, efek saat update sink tidak tepat

    def on_item_double_clicked(self, item, column):
        try:
            i = item.data(0, Qt.UserRole)
            for z in i["out_m2"]["m2_data"]:
                op_key = None
                for key, op in M2_OPRATION.items():
                    if z['id'] == key:
                        op_key = op
                        self.viz[op_key] = []

                if isinstance(z['value'], list):
                    for ival in z['value']:
                        try:
                            isi = ival.split("=>")
                            isi = int(isi[1], 0)
                            if op_key:
                                for x3 in GLOBAL.graph_nodes:
                                    if x3["x3_id"] == f"{isi}":
                                        isi = f"{isi} {x3['binary']}"
                                self.viz[op_key].append(isi)
                        except:
                            pass
            #self.updateGraph(i)
            self.updateGraphExtWindow(i)
        except Exception as e:
            print(e)


    def on_tree_context_menu(self, position: QPoint):
        item = self.tree_widget.itemAt(position)
        menu = QMenu()

        menu.addAction("Visual in graph")
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

        elif action == "Visual in graph":
            i = item.data(0, Qt.UserRole)
            for z in i["out_m2"]["m2_data"]:
                op_key = None
                for key, op in M2_OPRATION.items():
                    if z['id'] == key:
                        op_key = op
                        self.viz[op_key] = []

                if isinstance(z['value'], list):
                    for ival in z['value']:
                        try:
                            isi = ival.split("=>")
                            isi = int(isi[1], 0)
                            if op_key:
                                for x3 in GLOBAL.graph_nodes:
                                    if x3["x3_id"] == f"{isi}":
                                        isi = f"{isi} {x3['binary']}"
                                self.viz[op_key].append(isi)
                        except:
                            pass
            #self.updateGraph(i)
            self.updateGraphExtWindow(i)

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
