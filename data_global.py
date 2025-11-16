from PySide2.QtCore import QObject, Signal

class GlobalState:
    def __init__(self):
        self.stashes = {}

class GlobalSignals(QObject):
    state_updated = Signal()

GLOBAL = GlobalState()
SIGNALS = GlobalSignals()

