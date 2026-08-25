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
        try:
            node_color = GLOBAL.graph_attr["node_color"] #this array, node pembeda (bergerak)
            edge_color = GLOBAL.graph_attr["edge_color"] #this array, edge pembeda (bergerak)
            items = GLOBAL.graph_attr["node_members"]
        except:
            node_color = []
            edge_color = []
            items = []

        if len(items) == 0:
            return

        root_item = GLOBAL.graph_attr["node_root"] #this string

        #root_item = items[0]
        if root_item in node_color:
            self.add_node(root_item, True)
        else:
            self.add_node(root_item, False)

        for item in items[1:]:
            if item in node_color:
                self.add_node(item, True)
            else:
                self.add_node(item, False)

            if item in edge_color:
                self.connect_node(root_item, item, True)
            else:
                self.connect_node(root_item, item, False)

    def add_node(self, name, is_color):
        node = FlowGraphNode(self)
        if is_color:
            node.highlight = GLOBAL.graph_attr["n_color"]

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

    def connect_node(self, src, dst, is_color):
        src = self.node_map[src]
        dst = self.node_map[dst]

        if is_color:
            src.add_outgoing_edge(
                GLOBAL.graph_attr['e_color'],
                dst
            )
        else:
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
        super(ProcessInit, self).__init__("Gproxy Graph", "Gproxy - Graph")

    def getPriority(self, data, filename):
        if data.executable:
            # Use low priority so that this view is not picked by default
            return 1
        return 0

    def create(self, data, view_frame):
        return ProcessCreate(view_frame, data)




