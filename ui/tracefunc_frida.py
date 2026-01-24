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
     QToolButton, QStyle
)
from ..data_global import SIGNALS, GLOBAL
import base64
import time

from binaryninja import (
    core_version,
    log_info,
    highlight,
    show_message_box,
    MessageBoxButtonSet,
    MessageBoxIcon
)

import binaryninja as binja


class DialogStalker(QDialog):
    def __init__(self, parent=None, sid=None, data=None):
        super().__init__(parent)
        self.setWindowTitle(f"Stalker({sid})")
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint
        )
        self.setWindowModality(Qt.NonModal)
        self.font = getMonospaceFont(self)

        SIGNALS.frida_stalker.connect(self.setData)
        SIGNALS.frida_stalker_ct.connect(self.setDataCt)

        self.bv = data
        self.sid = sid
        self.history = []
        self.historytmp = []
        self.curr_history = 0
        self.search_clicked = False


        self.tree_widget = QTreeWidget()

        self.tree_widget.setColumnCount(7)
        self.tree_widget.headerItem().setText(0, "name/offset" )
        self.tree_widget.headerItem().setText(1, "module" )
        self.tree_widget.headerItem().setText(2, "call count" )
        self.tree_widget.headerItem().setText(3, "addr" )
        self.tree_widget.headerItem().setText(4, "module path" )
        self.tree_widget.headerItem().setText(5, "module base" )
        self.tree_widget.headerItem().setText(6, "module size" )
        self.tree_widget.headerItem().setText(7, "fileName" )
        self.tree_widget.headerItem().setText(8, "lineNumber" )
        self.tree_widget.headerItem().setText(9, "column" )
        self.tree_widget.itemDoubleClicked.connect(self.on_item_double_clicked)

        self.tree_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.on_tree_context_menu)

        #count history
        self.label_his = QLabel("")
        self.label_his.setFont(self.font)

        #forward
        self.btnF = QToolButton()
        self.btnF.setIcon(self.style().standardIcon(QStyle.SP_ArrowForward))
        self.btnF.setIconSize(QSize(20,20))
        self.btnF.setToolTip("History forward")

        #back
        self.btnB = QToolButton()
        self.btnB.setIcon(self.style().standardIcon(QStyle.SP_ArrowBack))
        self.btnB.setIconSize(QSize(20,20))
        self.btnB.setToolTip("History backward")

        #search
        self.lineEdit = QLineEdit()
        self.lineEdit.setObjectName(u"lineEdit")

        self.btnS = QToolButton()
        self.btnS.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        self.btnS.setIconSize(QSize(20,20))
        self.btnS.setToolTip("Search")

        # set layout
        h_layout = QHBoxLayout()
        h_layout.addWidget(self.btnB)
        h_layout.addWidget(self.btnF)
        h_layout.addWidget(self.label_his)
        h_layout.addWidget(self.lineEdit)
        h_layout.addWidget(self.btnS)

        layout = QVBoxLayout()
        layout.addWidget(self.tree_widget)
        layout.addLayout(h_layout)

        self.setLayout(layout)

        # action
        self.btnF.clicked.connect(self.click_stateF)
        self.btnB.clicked.connect(self.click_stateB)
        self.btnS.clicked.connect(self.click_search)

        # init
        self.label_his.setText("[%s/%s]" % (self.curr_history, len(self.history)) )


    def setDataCt(self):
        self.history.append(GLOBAL.frida_stalkers_ct)
        self.showData()


    def setData(self):
        if self.search_clicked:
            self.historytmp.append(GLOBAL.frida_stalkers)
        else:
            self.history.append(GLOBAL.frida_stalkers)

    def showData(self):
        self.tree_widget.clear()

        total = len(self.history[self.curr_history])-1

        if self.search_clicked:
            self.setWindowTitle(f"Result Search Stalker({self.sid}) {total}")
        else:
            self.setWindowTitle(f"Stalker({self.sid}) {total}")

        self.label_his.setText("[%s/%s]" % (self.curr_history, len(self.history)-1) )

        for data in self.history[self.curr_history]:
            parent = QTreeWidgetItem(self.tree_widget)

            parent.setText(0, "%s" % data["name"] )
            parent.setFont(0, self.font)
            parent.setData(0, Qt.UserRole, data["name"])

            parent.setText(1, "%s" % data["moduleName"] )
            parent.setFont(1, self.font)
            parent.setData(1, Qt.UserRole, data["moduleName"])

            parent.setText(2, "%s" % data["call_count"] )
            parent.setFont(2, self.font)
            parent.setData(2, Qt.UserRole, data["call_count"])

            parent.setText(3, "%s" % data["addr"] )
            parent.setFont(3, self.font)
            parent.setData(3, Qt.UserRole, data["addr"])

            parent.setText(4, "%s" % data["modulePath"] )
            parent.setFont(4, self.font)
            parent.setData(4, Qt.UserRole, data["modulePath"])

            parent.setText(5, "%s" % data["moduleBase"] )
            parent.setFont(5, self.font)
            parent.setData(5, Qt.UserRole, data["moduleBase"])

            parent.setText(6, "%s" % data["moduleSize"] )
            parent.setFont(6, self.font)
            parent.setData(6, Qt.UserRole, data["moduleSize"])

            parent.setText(7, "%s" % data["fileName"] )
            parent.setFont(7, self.font)
            parent.setData(7, Qt.UserRole, data["fileName"])

            parent.setText(8, "%s" % data["lineNumber"] )
            parent.setFont(8, self.font)
            parent.setData(8, Qt.UserRole, data["lineNumber"])

            parent.setText(9, "%s" % data["column"] )
            parent.setFont(9, self.font)
            parent.setData(9, Qt.UserRole, data["column"])

    def on_tree_context_menu(self, position: QPoint):
        item = self.tree_widget.itemAt(position)
        menu = QMenu()

        menu.addAction("Sort By")
        menu.addAction("Refresh")
        menu.addAction("Clean")

        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)

    def handle_tree_action(self, action, item):
        if action == "Sort By":
            print(item.text(0))

        elif action == "Refresh":
            SIGNALS.frida_stalker_ct.emit()
            self.showData()

        elif action == "Clean":
            GLOBAL.frida_stalkers_ct = []
            self.history = []
            self.curr_history = 0
            SIGNALS.frida_stalker_ct.emit()
            self.showData()



    def click_stateF(self):
        if self.curr_history < len(self.history)-1:
            self.curr_history += 1
            self.showData()

        self.label_his.setText("[%s/%s]" % (self.curr_history, len(self.history)-1) )

    def click_stateB(self):
        if self.curr_history != 0:
            self.curr_history -= 1
            self.showData()

        self.label_his.setText("[%s/%s]" % (self.curr_history, len(self.history)-1) )


    def find_obj(self, fdata, data):
        result = []

        for i in data:
            for key in i.keys():
                #print(f"{key}: {i[key]}")

                #if key == "moduleName":
                if True:
                    if str(i[key]).find(fdata) >= 0:
                        result.append(i)
            #break
        return result


    def click_search(self):
        if self.search_clicked:
            self.history = self.historytmp
            self.search_clicked = False
            self.curr_history = 0
            self.btnS.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
            self.showData()
            return

        result_index = []
        tsearch = self.lineEdit.text()

        for hdata in self.history:
            proc = self.find_obj(tsearch, hdata)

            if len(proc) > 0:
                result_index.append(proc)

        self.historytmp = self.history
        self.history = result_index
        self.search_clicked = True
        self.curr_history = 0
        self.btnS.setIcon(self.style().standardIcon(QStyle.SP_ArrowBack))

        if len(result_index) == 0:
            return

        self.showData()

        #SIGNALS.frida_stalker.emit()


    def on_item_double_clicked(self, item, column):
        data = item.data(column, Qt.UserRole)

        try:
            addr = int(data, 0)
            print("jump to:", hex(addr))

            QApplication.clipboard().setText(str(hex(addr)))

            self.bv.offset = addr
        except:
            print("Copy data:", data)
            if column == 3:
               addr = int(data, 0)
               data = hex(addr)
            QApplication.clipboard().setText(str(data))





class FridaFuncListDockWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name, data):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)


        SIGNALS.frida_updated.connect(self.refresh_from_global)
        SIGNALS.frida_updatedsym.connect(self.refresh_from_global_sym)
        SIGNALS.frida_updatedunity.connect(self.refresh_from_global_unity_asm)
        SIGNALS.frida_updatedunity_method.connect(self.refresh_from_global_unity_method)
        SIGNALS.frida_updatedthread.connect(self.refresh_from_global_thread)
        SIGNALS.frida_updatedidthread.connect(self.refresh_from_global_id_thread)
        SIGNALS.frida_updatedsym_trace.connect(self.refresh_from_global_sym_trace)
        SIGNALS.frida_updatedjava_trace.connect(self.refresh_from_global_java_trace)

        SIGNALS.window_frida_stalker.connect(self.refresh_from_global_owindow)


        tree_widget = QTreeWidget()
        self.tree_widget = tree_widget
        self.tree_widget.itemDoubleClicked.connect(self.on_item_double_clicked)
        #self.tree_widget.itemClicked.connect(self.click_tree)
        self.tree_widget.itemExpanded.connect(self.click_expand)
        self.tree_widget.itemCollapsed.connect(self.click_collap)


        self.tree_widget.headerItem().setText(0, "Function List" )
        tree_widget.setColumnCount(1)

        # MENGAKTIFKAN KLIK KANAN
        self.tree_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.on_tree_context_menu)

        #search
        self.lineEdit = QLineEdit()
        self.lineEdit.setObjectName(u"lineEdit")

        layout = QVBoxLayout()
        layout.addWidget(tree_widget)
        layout.addWidget(self.lineEdit)

        self.setLayout(layout)
        self.bv = data
        self.font = getMonospaceFont(self)
        self.expanded_items = set()


    def format_size(self, size):
        units = ['B', 'K', 'M', 'G', 'T']
        index = 0
        while size >= 1024 and index < len(units) - 1:
            size /= 1024
            index += 1
        return f'{size:.1f}{units[index]}'


    def refresh_from_global_owindow(self):
        title = GLOBAL.window_frida_stalker_title

        self.dlg = DialogStalker(sid=title, data=self.bv)
        self.dlg.resize(340, 550) # w,h
        self.dlg.show()
        self.dlg.raise_()
        self.dlg.activateWindow()



    def refresh_from_global_unity_method(self):
        self.tree_widget.clear()
        self.tree_widget.headerItem().setText(0, "Class method list: %d" %len(GLOBAL.frida_enumunitymethod) )


    def refresh_from_global_unity_asm(self):
        self.tree_widget.clear()
        self.tree_widget.headerItem().setText(0, "Assembly list: %d" %len(GLOBAL.frida_enumunityasm) )

        for data in GLOBAL.frida_enumunityasm:
            parent = QTreeWidgetItem(self.tree_widget)

            parent.setText(0, "%s" % data )
            parent.setFont(0, self.font)
            parent.setData(0, Qt.UserRole, data )



    def refresh_from_global(self):
        self.tree_widget.clear()
        self.tree_widget.headerItem().setText(0, "Module List: %d" %len(GLOBAL.frida_enummodules) )

        for data in GLOBAL.frida_enummodules:
            parent = QTreeWidgetItem(self.tree_widget)

            msize = self.format_size(int(data.get('size')) )

            parent.setText(0, "%s" %(data.get('name')) )
            parent.setFont(0, self.font)
            parent.setData(0, Qt.UserRole, data.get('name') )
            parent.setExpanded(True)

            child1 = QTreeWidgetItem(parent)
            child1.setText(0, "Size: %s" %(msize) )
            child1.setData(0, Qt.UserRole, data.get('size') )
            child1.setFont(0, self.font)

            child2 = QTreeWidgetItem(parent)
            child2.setText(0, "Base: %s" %data.get('base') )
            child2.setData(0, Qt.UserRole, data.get('base') )
            child2.setFont(0, self.font)

            child3 = QTreeWidgetItem(parent)
            child3.setText(0, "%s" %(data.get('path')) )
            child3.setData(0, Qt.UserRole, data.get('path') )
            child3.setFont(0, self.font)


    def refresh_from_global_id_thread(self):
        self.tree_widget.clear()
        self.tree_widget.headerItem().setText(0, "%s ID Thread List: %d" % (GLOBAL.refresh_view, len(GLOBAL.frida_idthreads)) )

        for data in GLOBAL.frida_idthreads:
            parent = QTreeWidgetItem(self.tree_widget)

            try:
                parent.setText(0, "%s(%s): %s" %(data["id"], data["name"], data["state"])  )
            except:
                parent.setText(0, "%s: %s" %(data["id"], data["state"])  )


            if data["state"] == "running":
                parent.setForeground(0, QColor("orange"))

            parent.setFont(0, self.font)
            parent.setData(0, Qt.UserRole, data )


    def refresh_from_global_thread(self):
        self.tree_widget.clear()
        self.tree_widget.headerItem().setText(0, "Thread List: %d" %len(GLOBAL.frida_enumthreads) )

        for data in GLOBAL.frida_enumthreads:
            parent = QTreeWidgetItem(self.tree_widget)

            try:
                parent.setText(0, "%s(%s): %s" %(data["id"], data["name"], data["state"])  )
            except:
                parent.setText(0, "%s: %s" %(data["id"], data["state"])  )

            if data["state"] == "running":
                parent.setForeground(0, QColor("orange"))

            parent.setFont(0, self.font)
            parent.setData(0, Qt.UserRole, data )


            child1 = QTreeWidgetItem(parent)
            child1.setText(0, "context")
            child1.setFont(0, self.font)
            child1.setExpanded(True)

            for key in data["context"]:
                child2 = QTreeWidgetItem(child1)
                child2.setText(0, "%s: %s"% (key, data["context"][key]) )
                child2.setFont(0, self.font)
                child2.setData(0, Qt.UserRole, "%s: %s"% (key, data["context"][key]) )




    def refresh_from_global_sym(self):
        self.tree_widget.clear()
        func_total = 0

        for data in GLOBAL.frida_enumsymbols:
            if data.get("type") == "function":
                func_total += 1
                parent = QTreeWidgetItem(self.tree_widget)

                func_name = data.get("name")

                #if func_name.startswith("_Z") == True:
                if False:
                    func_mangle = binja.demangle.demangle_gnu3(binja.architecture.Architecture["x86"], func_name)
                    parent.setText(0, "%s" %func_mangle[1])
                else:
                    parent.setText(0, "%s" %func_name)

                parent.setFont(0, self.font)
                parent.setData(0, Qt.UserRole, data )

        self.tree_widget.headerItem().setText(0, "Function List: [%d/%d]" %(func_total, len(GLOBAL.frida_enumsymbols)) )


    def cekandset_expand(self, tree, id):

        for data in self.expanded_items:
            if data == id:
                #print(data)
                tree.setExpanded(True)


    def refresh_from_global_java_trace(self):
        self.tree_widget.clear()
        self.tree_widget.headerItem().setText(0, "%s Trace Java List: %d" % (GLOBAL.refresh_view, len(GLOBAL.frida_functions_java)) )


        for (func_name, data) in GLOBAL.frida_functions_java.items():
            tsearch = self.lineEdit.text()

            if tsearch == ">1":
                if int(data['count']) <= 1:
                    continue

            parent = QTreeWidgetItem(self.tree_widget)

            parent.setText(0, "%d  %s" % (data['count'], func_name) )
            parent.setFont(0, self.font)
            parent.setData(0, Qt.UserRole, func_name )

            self.cekandset_expand(parent, func_name)


            now = time.time()

            if now < data['time']:
                parent.setForeground(0, QColor("orange"))
            else:
                parent.setForeground(0, QColor("white"))


            for key in data["raw"]:
                if key == "arg":
                    child1 = QTreeWidgetItem(parent)
                    child1.setText(0, "arguments")
                    child1.setFont(0, self.font)

                    id_expand = func_name+"|||arguments"
                    child1.setData(0, Qt.UserRole, id_expand )
                    self.cekandset_expand(child1, id_expand)


                    arguments = data["raw"].get(key)

                    for arg in arguments:
                        child2 = QTreeWidgetItem(child1)
                        child2.setText(0, "%s" % arg )
                        child2.setFont(0, self.font)
                        child2.setData(0, Qt.UserRole, "%s" % arg)

                elif key == "retval":
                    child1 = QTreeWidgetItem(parent)
                    child1.setText(0, "retval")
                    child1.setFont(0, self.font)

                    id_expand = func_name+"|||retval"
                    child1.setData(0, Qt.UserRole, id_expand )
                    self.cekandset_expand(child1, id_expand)


                    retval = data["raw"].get(key)

                    child2 = QTreeWidgetItem(child1)
                    child2.setText(0, "%s" % retval)
                    child2.setData(0, Qt.UserRole, "%s" % retval)
                    child2.setFont(0, self.font)


                elif key == "backtrace":
                    backtrace = data["raw"].get(key)
                    backtraces = backtrace.split("\n")

                    child1 = QTreeWidgetItem(parent)
                    child1.setText(0, "backtrace")
                    child1.setFont(0, self.font)

                    id_expand = func_name+"|||backtrace"
                    child1.setData(0, Qt.UserRole, id_expand )
                    self.cekandset_expand(child1, id_expand)

                    for bk in backtraces:
                        bt = "".join(bk.split("\t"))
                        child2 = QTreeWidgetItem(child1)
                        child2.setText(0, "%s" % bt )
                        child2.setFont(0, self.font)
                        child2.setData(0, Qt.UserRole, "%s" % bt )




    def refresh_from_global_sym_trace(self):
        self.tree_widget.clear()
        self.tree_widget.headerItem().setText(0, "%s Trace Function List: %d" % (GLOBAL.refresh_view, len(GLOBAL.frida_functions)) )

        ibb = 0

        for (func_name, data) in GLOBAL.frida_functions.items():

            tsearch = self.lineEdit.text()

            if tsearch == ">1":
                if int(data['count']) <= 1:
                    continue


            parent = QTreeWidgetItem(self.tree_widget)

            parent.setText(0, "%d  %s" % (data['count'], func_name) )
            parent.setFont(0, self.font)
            parent.setData(0, Qt.UserRole, func_name )
            self.cekandset_expand(parent, func_name)

            now = time.time()

            if now < data['time']:
                parent.setForeground(0, QColor("orange"))
            else:
                parent.setForeground(0, QColor("white"))



            for key in data["raw"]:

                if key == "func_addr":
                    func_addr = data["raw"].get(key)

                    child1 = QTreeWidgetItem(parent)
                    child1.setText(0, "addr")
                    child1.setFont(0, self.font)
                    id_expand = func_name+"|||func_addr"
                    child1.setData(0, Qt.UserRole, id_expand)
                    self.cekandset_expand(child1, id_expand)

                    child2 = QTreeWidgetItem(child1)
                    child2.setText(0, "%s" % func_addr)
                    child2.setData(0, Qt.UserRole, func_addr)
                    child2.setFont(0, self.font)

                elif key == "argumen":
                    child1 = QTreeWidgetItem(parent)
                    child1.setText(0, "argumen")
                    child1.setFont(0, self.font)

                    id_expand = func_name+"|||argumen"
                    child1.setData(0, Qt.UserRole, id_expand )
                    self.cekandset_expand(child1, id_expand)

                    arg = data["raw"].get(key)

                    child2 = QTreeWidgetItem(child1)
                    child2.setText(0, "%s" % arg)
                    child2.setData(0, Qt.UserRole, "%s" % arg)
                    child2.setFont(0, self.font)

                elif key == "retval":
                    child1 = QTreeWidgetItem(parent)
                    child1.setText(0, "retval")
                    child1.setFont(0, self.font)

                    id_expand = func_name+"|||retval"
                    child1.setData(0, Qt.UserRole, id_expand )
                    self.cekandset_expand(child1, id_expand)

                    retval = data["raw"].get(key)

                    child2 = QTreeWidgetItem(child1)
                    child2.setText(0, "%s" % retval)
                    child2.setData(0, Qt.UserRole, "%s" % retval)
                    child2.setFont(0, self.font)

                elif key == "backtrace":
                    backtrace = data["raw"].get(key)
                    backtraces = backtrace.split("\n")

                    child1 = QTreeWidgetItem(parent)
                    child1.setText(0, "backtrace")
                    child1.setFont(0, self.font)

                    id_expand = func_name+"|||backtrace"
                    child1.setData(0, Qt.UserRole, id_expand )
                    self.cekandset_expand(child1, id_expand)

                    for bk in backtraces:
                        child2 = QTreeWidgetItem(child1)
                        child2.setText(0, "%s" % bk )
                        child2.setFont(0, self.font)
                        child2.setData(0, Qt.UserRole, "%s" % bk )



            for bb, bb_func in GLOBAL.frida_bb_hit:
                if bb_func == func_name:

                    symname = ''
                    try:
                        symname = "("+self.bv.get_symbol_at(int(bb, 0)).name+")"
                    except:
                        pass

                    parent.setText(0, "%d/%d  %s" % (data['count'], len(GLOBAL.frida_bb_hit), func_name) )
                    child1 = QTreeWidgetItem(parent)
                    child1.setText(0, "[%d/%d] %s%s" % (ibb, len(GLOBAL.frida_bb_hit), bb, symname) )
                    child1.setFont(0, self.font)
                    child1.setData(0, Qt.UserRole, bb )
                    ibb += 1




    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


    def click_expand(self, item):
        data = item.data(0, Qt.UserRole)
        self.expanded_items.add(data)

    def click_collap(self, item):
        data = item.data(0, Qt.UserRole)
        self.expanded_items.remove(data)


    def click_tree(self, item, column):
        data = item.data(column, Qt.UserRole)
        print("sd"+data)

    def on_item_double_clicked(self, item, column):
        data = item.data(column, Qt.UserRole)

        try:
            addr = int(str(data), 0)
            self.bv.offset = addr
        except:
            pass


        QApplication.clipboard().setText(str(data))

        print("[+] copy: ", data)



    def on_tree_context_menu(self, position: QPoint):
        item = self.tree_widget.itemAt(position)
        menu = QMenu()

        menu.addAction("Copy")
        menu.addAction("Base")
        menu.addAction("Size")
        menu.addAction("Path")
        menu.addAction("Block Coloring")
        menu.addAction("Block Reset")
        menu.addAction("Block Refresh")


        action = menu.exec_(self.tree_widget.viewport().mapToGlobal(position))
        if action:
            self.handle_tree_action(action.text(), item)


    def block_color(self, reset=False):
        for bb, func in GLOBAL.frida_bb_hit:
            addr = int(bb, 0)
            bbs = self.bv.get_basic_blocks_at(addr)
            color = '0xaa00aa'

            if (bbs):
                color = int(color, 0)
                R,G,B = (color >> 16)&0xff, (color >> 8)&0xff, (color&0xff)

                if reset:
                    color = highlight.HighlightColor(None)
                else:
                    color = highlight.HighlightColor(red=R, blue=G, green=B)

                bb = bbs[0]
                bb.set_user_highlight(color)

                print(bbs)



    def handle_tree_action(self, action, item):

        if action == "Copy":
            QApplication.clipboard().setText(item.text(0))

        elif action == "Block Reset":
            self.block_color(reset=True)
            GLOBAL.frida_bb_hit = []
            SIGNALS.frida_updatedsym_trace.emit()


        elif action == "Block Refresh":
            SIGNALS.frida_updatedsym_trace.emit()

        elif action == "Block Coloring":
            SIGNALS.frida_updatedsym_trace.emit()
            self.block_color()

        elif action == "Base":
            base = item.data(0, Qt.UserRole)
            print(base.get("base"))

            show_message_box(
                "G-proxy",
                "Base: %s" %base.get("base"),
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.InformationIcon
            )

        elif action == "Size":
            base = item.data(0, Qt.UserRole)
            print(base.get("size"))

            show_message_box(
                "G-proxy",
                "Size: %s" %base.get("size"),
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.InformationIcon
            )

        elif action == "Path":
            base = item.data(0, Qt.UserRole)
            print(base.get("path"))

            show_message_box(
                "G-proxy",
                "Path: %s" %base.get("path"),
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.InformationIcon
            )

