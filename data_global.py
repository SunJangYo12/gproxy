from PySide2.QtCore import QObject, Signal
import time


class GlobalState:
    def __init__(self):
        self.simgr = None
        self.gdb_functions = {}
        self.gdb_kernelproc = []
        self.gdb_hookstop = ""
        self.gdb_hookname = ""
        self.gdb_hookstructname = ""
        self.gdb_memregs = []
        self.gdb_memstruct = []


    def append_gdbfunc(self, s):
        now = time.time()

        if s in self.gdb_functions:
            self.gdb_functions[s]["count"] += 1
            self.gdb_functions[s]["time"] = now + 3
        else:
            self.gdb_functions[s] = {
                "count": 1,
                "time": now + 3
            }



class GlobalSignals(QObject):
    state_updated = Signal()
    gdb_updated = Signal()
    gdb_updated_regs = Signal()

GLOBAL = GlobalState()
SIGNALS = GlobalSignals()
