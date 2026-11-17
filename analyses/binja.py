#
# Thanks fuzzable project
#
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, getMonospaceFont
from PySide6 import QtCore
from PySide6.QtGui import QColor, QBrush
from PySide6.QtCore import Qt, QPoint, QEvent, QSize, QThread, Signal, QTimer
from PySide6.QtWidgets import (
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
from binaryninja import *
import typing as t
from ..data_global import SIGNALS, GLOBAL
import time

INTERESTING_PATTERNS: t.List[str] = [
    # Consuming Inputs
    "parse",
    "read",
    "buf",
    "file",
    "input",
    "str",
    # Decryption Routines
    "encode",
    "decode",
    # Other stuff
    "draw",
    "image",
    "img",
    "load",
    "url",
]

RISKY_GLIBC_CALL_PATTERNS: t.List[str] = [
    "cmp",
    "cpy",
    "alloc",
    "read",
    "write",
    "open",
    "create",
]

class SkoringFuncs(BackgroundTaskThread):
    def __init__(self, bv):
        self.progress_banner = f"Running the skoring ..."
        BackgroundTaskThread.__init__(self, self.progress_banner, True)
        self.bv = bv

        # mapping of functions + locations we've chosen to skipped
        self.skipped: t.Dict[str, str] = {}

        # stores all the scores we've measured from the functions
        self.scores: t.List[t.Any] = []

        # caches names of calls we've visited already to skip repeats
        self.visited: t.List[t.Any] = []

    def run(self):
        funcs = self.bv.functions
        count = 0
        total = len(funcs)
        for func in funcs:
            if self.cancelled:
                break
            name = func.symbol.full_name

            if self.skip_analysis(func):
                print(f"[+] Skiping: {name}")
                GLOBAL.binja_scores_skip.append({
                    "name": name,
                    "addr": func.start
                })
                continue

            print(f"[+] Analyses: {count}/{total} {name}")
            score = self.analyze_call(name, func, total)
            count += 1
            #SIGNALS.binja_score_updated.emit()
            #time.sleep(1)

        #TODO
        #load from file by dialog
        #tooltip for all table

        SIGNALS.binja_score_updated.emit()
        print("[+] Done.")

    def analyze_call(self, name, func, func_total):
        addr = func.start
        stripped = "sub_" in name

        fuzz_friendly = 0
        if not stripped:
            fuzz_friendly = self.is_fuzz_friendly(name)

        #toplevel = self.is_toplevel_call(func)
        fuzz_friendly = fuzz_friendly
        risky_sinks = self.risky_sinks(func)
        natural_loops = self.natural_loops(func)
        coverage_depth = self.get_coverage_depth(func)
        cyclomatic_complexity = self.get_cyclomatic_complexity(func)
        total =  fuzz_friendly + risky_sinks["skor"] + natural_loops + coverage_depth + cyclomatic_complexity

        GLOBAL.binja_scores[name] = {
            "fuzz_friendly": fuzz_friendly,
            "risky_sinks": self.risky_sinks(func),
            "natural_loops": self.natural_loops(func),
            "coverage_depth": self.get_coverage_depth(func),
            "cyclomatic_complexity": self.get_cyclomatic_complexity(func),
            "scores": total,
            "addr": addr,
            "func_total": func_total
        }

    def risky_sinks(self, func) -> int:
        out = {
            "skor": 0,
            "tooltip": []
        }
        for block in func.mlil:
            for insn in block:
                if insn.operation != MediumLevelILOperation.MLIL_CALL:
                    continue

                target = insn.dest
                if target.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                    sym = self.bv.get_function_at(target.constant)
                    if not sym:
                        continue

                    for arg in sym.parameter_vars:
                        if str(arg.type) == "char*":
                            out["skor"] += 2
                            out["tooltip"].append("arg: char*\n")
                        elif str(arg.type) == "void*":
                            out["skor"] += 2
                            out["tooltip"].append("arg: void*\n")
                        elif str(arg.type) == "int32_t*":
                            out["skor"] += 1
                            out["tooltip"].append("arg: int32_t*\n")
                        elif str(arg.type) == "int32_t":
                            out["skor"] += 1
                            out["tooltip"].append("arg: int32_t\n")
                        elif str(arg.type) == "char**":
                            out["skor"] += 1
                            out["tooltip"].append("arg: char**\n")

                    #if any([pattern in sym.name.lower() for pattern in RISKY_GLIBC_CALL_PATTERNS]):
                    #    skor += 2
                    for pattern in RISKY_GLIBC_CALL_PATTERNS:
                        if pattern in sym.name.lower():
                            out["skor"] += 2
                            out["tooltip"].append("Sink: "+sym.name+"\n")
        return out


    def skip_analysis(self, func) -> bool:
        name = func.name
        symbol = func.symbol.type

        # ignore imported functions from other libraries, ie glibc or win32api
        if symbol in [
            SymbolType.ImportedFunctionSymbol,
            SymbolType.LibraryFunctionSymbol,
            SymbolType.ImportAddressSymbol,
            SymbolType.ImportedFunctionSymbol,
            SymbolType.ImportedDataSymbol,
        ]:
            return True
        return False


    def natural_loops(self, target) -> int:
        return len([bb in bb.dominance_frontier for bb in target.basic_blocks])

    def get_cyclomatic_complexity(self, func) -> int:
        num_blocks = len(func.basic_blocks)
        num_edges = sum([len(b.outgoing_edges) for b in func.basic_blocks])
        return num_edges - num_blocks + 2


    def get_coverage_depth(self, target) -> int:
        """
        Calculates coverage depth by doing a depth first search on function call graph,
        and return a final depth and flag denoting recursive implementation.
        """
        depth = 0

        # as we iterate over callees, add to a callstack and iterate over callees
        # for those as well, adding to the callgraph until we're done with all
        callstack = [target]
        while callstack:
            # increase depth as we finish iterating over callees for another func
            func = callstack.pop()
            depth += 1

            # add all childs to callgraph, and add those we haven't recursed into callstack
            for child in func.callees:
                # ignore recursive calls
                if child.name == target.name:
                    continue

                # if address attempt to resolve call
                if child.name not in self.visited:
                    callstack += [child]

            self.visited += [func.name]

        return depth


    def is_fuzz_friendly(self, symbol_name) -> int:
        """
        FUZZABILITY HEURISTIC

        Analyze the function's name to see if it is "fuzzer entry friendly". This denotes
        a function that can easily be called to consume a buffer filled by the fuzzer, or
        a string pointing to a filename, which can also be supplied through a file fuzzer.
        """
        return [
            pattern in symbol_name.lower() for pattern in INTERESTING_PATTERNS
        ].count(True)

    def is_toplevel_call(self, target) -> bool:
        return len(target.callers) == 0

