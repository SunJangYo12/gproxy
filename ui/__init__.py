from PySide2.QtWidgets import QApplication
from binaryninjaui import DockHandler, UIAction, UIActionHandler, Menu
from PySide2.QtCore import Qt
from .registers_gdb import RegGdbDockWidget
from .state_angr_list import StateAngrListDockWidget


RW = None
HW = None
ALIST = None


def _get_registergdb_widget(name, parent, data):
    global HW
    HW = RegGdbDockWidget(parent, name, data)

    return HW

def _registerGdbDynamicWidgets():
    dock_handler = DockHandler.getActiveDockHandler()
    dock_handler.addDockWidget(
        "Gproxy => gdb registers",
        _get_registergdb_widget,
        Qt.RightDockWidgetArea,
        Qt.Vertical,
        False
    )


def _get_angrstate_widget(name, parent, data):
    global ALIST
    ALIST = StateAngrListDockWidget(parent, name, data)
#    ALIST.setEnabled(False)

    return ALIST

def _registerAngrListWidgets():
    dock_handler = DockHandler.getActiveDockHandler()
    dock_handler.addDockWidget(
        "Gproxy => state list",
        _get_angrstate_widget,
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


_registerGdbDynamicWidgets()
_registerAngrListWidgets()
