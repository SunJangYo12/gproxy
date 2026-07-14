from PySide2.QtCore import QObject, Signal
import time


class GlobalState:
    def __init__(self):
        self.simgr = None
        self.angr_project = None
        self.angr_states = []     #all states here
        self.angr_state = None    #temporary state for console
        self.angr_hooks = []      #hook with {name.., metadata}
        self.gdb_functions = {}
        self.gdb_blocks = {}
        self.gdb_kernelproc = []
        self.gdb_hookstop = ""
        self.gdb_hookname = ""
        self.gdb_hookstructname = ""
        self.gdb_memregs = []
        self.gdb_memstruct = []
        self.gdb_memstack = []
        self.gdb_rebreak = ""

        self.frida_enummodules = {}
        self.frida_enumsymbols = {}
        self.frida_enumthreads = {}
        self.frida_enumunityasm = {}
        self.frida_enumunitymethod = {}
        self.frida_idthreads = {}
        self.frida_functions = {}
        self.frida_functions_hook = {}
        self.frida_functions_java = {}
        self.frida_stalkers = {}
        self.frida_stalkers_ct = []
        self.frida_stalkers_ct_module = []
        self.frida_bb_hit = []
        self.window_frida_stalker_title = ""
        self.window_frida_tracer_title = ""
        self.window_angr_title = ""
        self.refresh_view = "'0'"

    def angr_find_node(self, node, target_state):
        if node["state"] is target_state:
            return node

        for child in node["children"]:
            result = self.angr_find_node(child, target_state)
            if result is not None:
                return result
        return None

    def angr_explore(self, proj, target_state, sym_buf, nav=None):
        for angr_states in self.angr_states:
            node = self.angr_find_node(angr_states, target_state)
            if node is None:
                print("State tidak ditemukan")
                return

        simgr = proj.factory.simgr(node["state"].copy())

        while len(simgr.active) == 1:
            simgr.step()
            if nav:
                try:
                    print(hex(simgr.active[0].addr))
                    time.sleep(1)
                    nav.offset = simgr.active[0].addr
                except:
                    pass

        self.simgr = simgr
        if not simgr.active:
            return

        # Kalau ingin replace child lama
        # node["children"].clear()
        for s in simgr.active:
            node["children"].append({
                "state": s.copy(),
                "solver_bytes": s.solver.eval(sym_buf, cast_to=bytes),
                "children": []
            })
            print("[+] got branch ", hex(s.addr))

    def angr_step(self, state):
        simgr = self.angr_project.factory.simgr(state)
        simgr.step()
        new_state = simgr.active

        for s in new_state:
            root = {
                "isroot": True,
                "state": s.copy(),
                "children": []
            }
            self.angr_states.append(root)

    def angr_addstates(self, state):
        root = {
            "isroot": True,
            "state": state.copy(),
            "children": []
        }
        self.angr_states.append(root)


    def config_dynamic(self, sw, func_name):
        config = "/dev/shm/gproxy.config"
        print(f"set config: {sw} {func_name}")

        all = []
        try:
            with open(config, "r") as fd:
                for line in fd:
                    key = line.split(":")

                    if key[0] == sw:
                        if func_name != "":
                            new = key[0]+":"+func_name+"\n"
                            all.append(new)
                    else:
                        all.append(line)

                if fd.readlines() <= 1:
                    print("new")
                    all.append(f"{sw}:{func_name}\n")
        except:
            print("new")
            all.append(f"{sw}:{func_name}\n")

        with open(config, "w") as fd:
            for i in all:
                fd.write(i)


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

    def append_fridafunc(self, s, raw):
        now = time.time()

        if s in self.frida_functions:
            self.frida_functions[s]["count"] += 1
            self.frida_functions[s]["time"] = now + 3
            self.frida_functions[s]["raw"] = raw
        else:
            self.frida_functions[s] = {
                "count": 1,
                "time": now + 3,
                "raw": raw
            }


    def append_fridajavafunc(self, s, raw):
        now = time.time()

        if s in self.frida_functions_java:
            self.frida_functions_java[s]["count"] += 1
            self.frida_functions_java[s]["time"] = now + 3
            self.frida_functions_java[s]["raw"] = raw
        else:
            self.frida_functions_java[s] = {
                "count": 1,
                "time": now + 3,
                "raw": raw
            }




class GlobalSignals(QObject):
    angrhistory_updated = Signal()
    angrhook_updated = Signal()
    state_updated = Signal()
    state_tree_updated = Signal()
    gdb_updated = Signal()
    gdb_updated_dprintf = Signal()
    gdb_updated_bb = Signal()
    gdb_updated_regs = Signal()
    gdb_updated_stacks = Signal()
    frida_updated = Signal()
    frida_updatedhook = Signal()
    frida_updatedsym = Signal()
    frida_updatedthread = Signal()
    frida_updatedidthread = Signal()
    frida_updatedunity = Signal()
    frida_updatedunity_method = Signal()
    frida_updatedsym_trace = Signal()
    frida_updatedjava_trace = Signal()
    frida_stalker = Signal()
    frida_stalker_ct = Signal()
    frida_stalker_ct_module = Signal()
    window_frida_stalker = Signal()
    window_frida_tracer = Signal()
    window_frida_tracer_allocator = Signal()
    window_angrstate_tree = Signal()
    window_angrhook = Signal()

GLOBAL = GlobalState()
SIGNALS = GlobalSignals()
