from binaryninja.function import DisassemblyTextRenderer, InstructionTextToken
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.enums import InstructionTextTokenType
from binaryninjaui import FlowGraphWidget, ViewType

from binaryninja import *

from ..data_global import SIGNALS, GLOBAL


class ProcessRun(FlowGraph):
    def __init__(self):
        super(ProcessRun, self).__init__()
        self.node_map = {}

    def populate_nodes(self):
        items = GLOBAL.gdb_kernelproc

        if len(items) == 0:
            return

        root_item = items[0]
        self.add_node(root_item)

        for item in items[1:]:
            self.add_node(item)

            self.connect_node(root_item, item)


    def add_node(self, name):
        node = FlowGraphNode(self)
        node.name = name
        node.lines = [
            DisassemblyTextLine([
                InstructionTextToken(
                    InstructionTextTokenType.TextToken,
                    name
                )
            ])
        ]
        self.append(node)
        self.node_map[name] = node

    def connect_node(self, src, dst):
        src = self.node_map[src]
        dst = self.node_map[dst]

        src.add_outgoing_edge(
            BranchType.UnconditionalBranch,
            dst
        )





class ProcessCreate(FlowGraphWidget):
    def __init__(self, parent, data):
        self.data = data
        self.graph = ProcessRun()

        super(ProcessCreate, self).__init__(parent, data, self.graph)

    def item_update(self):
        self.setGraph(self.graph)


    def navigate(self, addr):
        block = self.data.get_recent_basic_block_at(addr)
        if block is None:
            func = self.data.get_recent_function_at(addr)
        else:
            func = block.function
        if func is None:
            return False
        return self.navigateToFunction(func, addr)


    def navigateToFunction(self, func, addr):

        graph = ProcessRun()
        self.setGraph(graph)
        return True



# View type for the new view
class ProcessInit(ViewType):
    def __init__(self):
        super(ProcessInit, self).__init__("Kernel Process GDB", "Gproxy - Process List")

    def getPriority(self, data, filename):
        if data.executable:
            # Use low priority so that this view is not picked by default
            return 1
        return 0

    def create(self, data, view_frame):
        return ProcessCreate(view_frame, data)




