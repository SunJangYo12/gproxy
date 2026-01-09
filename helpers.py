from binaryninja import (
    log_info,
    log_debug,
    log_error,
    BackgroundTaskThread,
)

from .constants import (
    DEBUG,
    HL_BP_COLOR,
    HL_NO_COLOR,
)
from .data_global import SIGNALS, GLOBAL
import time

def expose(f):
    "Decorator to set exposed flag on a function."
    f.exposed = True
    return f


def is_exposed(f):
    "Test whether another function should be publicly exposed."
    return getattr(f, 'exposed', False)


def ishex(s):
    return s.lower().startswith("0x") and map(lambda c: c in "0123456789abcdef", s[2:].lower())


def info(x):
    log_info("[+] {:s}".format(x))

def err(x):
    log_error("[-] {:s}".format(x))

def dbg(x):
    if DEBUG:
        log_debug("[*] {:s}".format(x))



class RefreshUiTask(BackgroundTaskThread):
    def __init__(self, view, sw):
        super(RefreshUiTask, self).__init__('Update Ui...', True)
        self.view = view
        self.sw = sw

    def run(self):
        while True:
            if GLOBAL.refresh_view == "'0'":
                GLOBAL.refresh_view = ",0,"
            else:
                GLOBAL.refresh_view = "'0'"

            if self.sw == "trace-func":
                SIGNALS.frida_updatedsym_trace.emit()

            elif self.sw == "stalker-ct":
                SIGNALS.frida_stalker_ct.emit()

            time.sleep(1)
            if self.cancelled:
                break



class RunInBackground(BackgroundTaskThread):
    def __init__(self, target, cancel_cb=None, *args, **kwargs):
            BackgroundTaskThread.__init__(self, '', cancel_cb is not None)
            self.target = target
            self.args = args
            self.kwargs = kwargs
            self.cancel_cb = cancel_cb
            return

    def run(self):
        self.target(self, *self.args, **self.kwargs)
        return

    def cancel(self):
        self.cancel_cb()
        return



import os
import sys
import binaryninja as binja


class Mikrotik():
    def __init__(self, mtarget=None, mtype=None):
        self.target = mtarget
        self.type = mtype

    def find_handlers(self):
        total = len(os.listdir(self.target))
        count = 0
        start = 20
        end = 40

        for filename in os.listdir(self.target):

            print(f"[{count}/{total}] {filename}")

            count += 1

            # paging skip by start, karena hang kehabisan ram
            if count <= start:
                continue

            if count > end:
                break


            bv = binja.BinaryViewType.get_view_of_file(self.target + filename)
            if bv == None:
                continue;

            addHandler_addr = 0
            for func in bv.functions:
                name = func.name
                if func.name.startswith("_ZN") == True:
                    type, name = binja.demangle.demangle_gnu3(binja.architecture.Architecture["x86"], func.name)
                    name = binja.demangle.get_qualified_name(name)
                    if name == "nv::Looper::addHandler":
                        addHandler_addr = func.start

            if addHandler_addr == 0:
                continue

            addHandler_funcs = set()
            for xref in bv.get_code_refs(addHandler_addr):
                addHandler_funcs.add(bv.get_functions_containing(xref.address)[0])

            sys.stdout.write(filename)

            last_stored_constant = 0
            for func in addHandler_funcs:
                for block in func.medium_level_il:
                    for instr in block:
                        if instr.operation == binja.MediumLevelILOperation.MLIL_STORE and instr.src.operation == binja.MediumLevelILOperation.MLIL_CONST:
                            last_stored_constant = instr.src.constant
                        if instr.operation == binja.MediumLevelILOperation.MLIL_CALL or instr.operation == binja.MediumLevelILOperation.MLIL_CALL_UNTYPED:
                            try:
                                if instr.dest.constant == addHandler_addr:
                                    try:
                                        handler = instr.params[1]
                                        if instr.params[1].operation == binja.MediumLevelILOperation.MLIL_CONST:
                                            sys.stdout.write(',')
                                            sys.stdout.write(str(handler))
                                    except:
                                        handler = last_stored_constant
                                        sys.stdout.write(',')
                                        sys.stdout.write(str(handler))
                            except:
                                continue

            sys.stdout.write('\n')
            sys.stdout.flush()


            

   

