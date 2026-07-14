#/usr/lib/x86_64-linux-gnu/libexif.so.12.3.3
#exif_loader_write_file+0x76
#    => 0x69
#    => base offset: 0x174a0
#    => pas call fread: 0x71


import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
import angr
import claripy


#binary_64 = '/media/jin/4abb279b-6d65-4663-97c2-26987f64673a/home/yuna/Tools/Python-env/frizzer/tests/simple_binary/test'
#p = angr.Project(binary_64, concrete_target=avatar_gdb, use_sim_procedures=True)

avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.X86_64, "127.0.0.1", 1234)

p = angr.Project(
    "/usr/lib/x86_64-linux-gnu/libexif.so.12.3.3",
    concrete_target=avatar_gdb,
    use_sim_procedures=True,
    main_opts={
        'base_addr': 0x7f6b73ba0000
    },
)
#p.loader.dynamic_load("/usr/lib/x86_64-linux-gnu/libc-2.31.so")

entry_state = p.factory.entry_state()
entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

print("[+] now triger breakpoint")
simgr = p.factory.simgr(entry_state)
simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x7f6b73bb7511]))

exploration = simgr.run()
new_concrete_state = exploration.stashes['found'][0]

print("[+] starting...")

from gproxy.data_global import GLOBAL, SIGNALS
def UPD():
    GLOBAL.simgr = simgr
    SIGNALS.state_updated.emit()

GLOBAL.angr_project = p





buf_addr = new_concrete_state.solver.eval(new_concrete_state.regs.rdi)
sym_buf = claripy.BVS("buf", 8*32)
new_concrete_state.memory.store(buf_addr, sym_buf)

simgr = p.factory.simgr(new_concrete_state)

all_states = []
visited = set()
while simgr.active:
    for s in simgr.active:
        key = (id(s), s.addr)
        if key not in visited:
            visited.add(key)
            all_states.append(s.copy())
    simgr.step()


#sample hook
class MyFread(angr.SimProcedure):
    def run(self, ptr, size, nmemb, fp):
        total = self.state.solver.eval(size * nmemb)

        sym = claripy.BVS("file", total * 8)
        self.state.memory.store(ptr, sym)

        return nmemb

p.hook_symbol("fread", MyFread())


#hook plt@GOT
p.hook(0x7fac48627e60, angr.SIM_PROCEDURES["libc"]["fread"]())



#sample step
state = GLOBAL.angr_state
buf = state.solver.eval(state.regs.rdi)
size = state.solver.eval(state.regs.rdx)
sym = claripy.BVS("input", size * 8)

state.memory.store(buf, sym)
state.regs.rip = 0x7fc58a812516 #after fread

xsimgr = p.factory.simgr(state)
xsimgr.step()


#dump bufferto file
addr = 0x404000
size = 0x100

data = state.memory.load(addr, size)
data = state.solver.eval(data, cast_to=bytes)

with open("dump.bin", "wb") as f:
    f.write(data)



#buffer tracking
buf = 0x602000
size = 0x100
def check_mem(state):
    if state.inspect.mem_read_address is None:
        return
    addr = state.solver.eval(state.inspect.mem_read_address)
    if buf <= addr < buf + size:
        print(f"Instruction {state.addr:#x} membaca buffer {addr:#x}")

state.inspect.b(
    "mem_read",
    when=angr.BP_BEFORE,
    action=check_mem,
)

while simgr.active:
    simgr.step()

state.inspect.b("mem_write", when=angr.BP_BEFORE, action=check_mem)


#cek eksekusi di concrete atau simbolik, concrenet hook dan inspect tidak berfungsi
state.project.concrete_target
<angr_targets.targets.avatar_gdb.AvatarGDBConcreteTarget object at 0x7f982ee9be50>

