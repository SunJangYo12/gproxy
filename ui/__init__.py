from PySide2.QtWidgets import QApplication
from binaryninjaui import DockHandler, UIAction, UIActionHandler, Menu
from PySide2.QtCore import Qt
from .registers_view import RegisterView
from .registers_gdb import RegGdbDockWidget


RW = None
HW = None


def _get_registerview_widget(name, parent, data):
    global RW
    RW = RegisterView(parent, name, data)
    RW.setEnabled(False)

    return RW

def _registerDynamicWidgets():
    dock_handler = DockHandler.getActiveDockHandler()
    dock_handler.addDockWidget(
        "Gproxy zzzzzzzzz",
        _get_registerview_widget,
        Qt.RightDockWidgetArea,
        Qt.Vertical,
        False
    )



def _get_registergdb_widget(name, parent, data):
    global HW
    HW = RegGdbDockWidget(parent, name, data)
    HW.setEnabled(False)

    return HW

def _registerGdbDynamicWidgets():
    dock_handler = DockHandler.getActiveDockHandler()
    dock_handler.addDockWidget(
        "Gproxy Gdb Registers",
        _get_registergdb_widget,
        Qt.RightDockWidgetArea,
        Qt.Vertical,
        False
    )





def enable_widgets():
    assert HW is not None

    HW.setEnabled(True)


def disable_widgets():
    assert HW is not None

    HW.setEnabled(False)


def ui_set_arch(arch, state):
    assert RW is not None

    RW.init(arch, state)


def ui_sync_view(state, delta=True):
    assert RW is not None

    if RW.isVisible():
        RW.set_reg_values(state)


def ui_reset_view():
    assert RW is not None

    RW.reset()


_registerDynamicWidgets()
_registerGdbDynamicWidgets()

