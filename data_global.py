from PySide2.QtCore import QObject, Signal
import time


class GlobalState:
    def __init__(self):
        self.simgr = None
        self.gdb_functions = {}
        self.gdb_blocks = {}
        self.gdb_kernelproc = []
        self.gdb_hookstop = ""
        self.gdb_hookname = ""
        self.gdb_hookstructname = ""
        self.gdb_memregs = []
        self.gdb_memstruct = []
        self.gdb_rebreak = ""

        self.frida_enummodules = {}
        self.frida_enumsymbols = {}
        self.frida_enumthreads = {}
        self.frida_idthreads = {}
        self.frida_functions = {}
        self.frida_stalkers = {}
        self.frida_stalkers_ct = []
        self.frida_bb_hit = []
        self.window_frida_stalker_title = ""

        self.refresh_view = "'0'"



    def append_gdbfunc_bb(self, s, block):
        self.gdb_functions[s]["block"] = block


    def append_gdbfunc(self, s):
        now = time.time()

        if s in self.gdb_functions:
            self.gdb_functions[s]["count"] += 1
            self.gdb_functions[s]["time"] = now + 3
        else:
            self.gdb_functions[s] = {
                "count": 1,
                "time": now + 3,
                "block": []
            }

    def append_fridafunc(self, s):
        now = time.time()

        if s in self.frida_functions:
            self.frida_functions[s]["count"] += 1
            self.frida_functions[s]["time"] = now + 3
        else:
            self.frida_functions[s] = {
                "count": 1,
                "time": now + 3
            }




class GlobalSignals(QObject):
    state_updated = Signal()
    gdb_updated = Signal()
    gdb_updated_bb = Signal()
    gdb_updated_regs = Signal()
    frida_updated = Signal()
    frida_updatedsym = Signal()
    frida_updatedthread = Signal()
    frida_updatedidthread = Signal()
    frida_updatedsym_trace = Signal()
    frida_stalker = Signal()
    frida_stalker_ct = Signal()
    window_frida_stalker = Signal()

GLOBAL = GlobalState()
SIGNALS = GlobalSignals()
