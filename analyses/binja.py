#
# Thanks fuzzable project
#
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
        for func in funcs:
            if self.cancelled:
                break
            name = func.symbol.full_name

            if self.skip_analysis(func):
                print(f"[+] Skiping: {name}")
                continue

            print(f"[+] Analyses: {name}")
            score = self.analyze_call(name, func, len(funcs))
            SIGNALS.binja_score_updated.emit()
            time.sleep(1)

        print("[+] Done.")

    def analyze_call(self, name, func, func_total):
        addr = hex(func.start)
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
        total =  fuzz_friendly + risky_sinks + natural_loops + coverage_depth + cyclomatic_complexity

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
        return 0


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

            #self.visited += [func.name]

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

