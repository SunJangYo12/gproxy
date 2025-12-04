from PySide2.QtCore import QObject, Signal

class GlobalState:
    def __init__(self):
        self.simgr = None
        self.gdb_functions = {}
        self.gdb_kernelproc = []
        self.gdb_hookname = ""
        self.gdb_hookstructname = ""
        self.gdb_memregs = []
        self.gdb_memstruct = []


    def append_gdbfunc(self, s):
        if s in self.gdb_functions:
            self.gdb_functions[s] += 1
        else:
            self.gdb_functions[s] = 1



class GlobalSignals(QObject):
    state_updated = Signal()
    gdb_updated = Signal()

GLOBAL = GlobalState()
SIGNALS = GlobalSignals()
