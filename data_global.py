from PySide2.QtCore import QObject, Signal

class GlobalState:
    def __init__(self):
        self.stashes = {}
        self.simgr = None

class GlobalSignals(QObject):
    state_updated = Signal()

GLOBAL = GlobalState()
SIGNALS = GlobalSignals()

