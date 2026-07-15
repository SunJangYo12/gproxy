# Tips
Start server setelah address di binaryninja di rebase.<br>

Menyamakan binaryninja dan angr:
```python

hex(state.project.loader.main_object.mapped_base)


```
ANGR baseaddress misal mengikuti GDB:
```python

proj = angr.Project(bv.file.filename, main_opts={'base_addr': 0x555555554000})
state = proj.factory.entry_state(stdin=angr.SimFile)

```

Test step state for branch
```python
import angr
proj = angr.Project(bv.file.filename)
state = proj.factory.entry_state(stdin=angr.SimFile)
simgr = proj.factory.simgr(state)
while len(simgr.active) == 1:
	simgr.step()
```
After import Angr and generate state in console paste this for UI consumer
```python
from gproxy.data_global import GLOBAL, SIGNALS
GLOBAL.simgr = simgr
SIGNALS.state_updated.emit()
```

Update realtime in UI
```python
import angr
from gproxy.data_global import GLOBAL, SIGNALS

proj = angr.Project(bv.file.filename)
state = proj.factory.entry_state(stdin=angr.SimFile)
simgr = proj.factory.simgr(state)
while len(simgr.active) == 1:
    simgr.step()
    GLOBAL.simgr = simgr
    SIGNALS.state_updated.emit()
```

Explore, this pararel step for active stash
```python
simgr.explore(find=0x123)
simgr.explore(find=0x123, avoid=0x777) #menghindari 0x777

// Mencari ketika input stdin menghasilkan password benar
simgr.epxpore(find=lambda s: b"Access granted" in s.posix.dumps(0) )

// Menghindari pesan kesalahan di stdout
simgr.explore(avoid=lambda s: b"Wrong password" in s.posix.dumps(1) )

// Brute force password
simgr.explore(find=lambda s: b"Success" in s.posix.dumps(1), avoid=lambda s: b"Fail" in s.posix.dumps(1) )
```

Show status explore
```python
import logging
logging.getLogger('angr').setLevel('INFO')
Note: dump(fd) 0=stdin 1=stdout 2=stderr
```

Symbion mode, sample packed_elf64 malware
```python
import subprocess
import os
import nose
import avatar2 as avatar2
import angr
import claripy
from angr_targets import AvatarGDBConcreteTarget
from gproxy.data_global import GLOBAL, SIGNALS

avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.X86_64, "127.0.0.1", 1234) #other terminal $ gdbserver :1234 ./packed_elf64
p = angr.Project(bv.file.filename, concrete_target=avatar_gdb, use_sim_procedures=True)

entry_state = p.factory.entry_state()
entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
simgr = p.factory.simgr(entry_state)

def UPD():
    GLOBAL.simgr = simgr
    SIGNALS.state_updated.emit()

simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x85b853]))
exploration = simgr.run()

GLOBAL.simgr = simgr
SIGNALS.state_updated.emit()

new_concrete_state = exploration.stashes['found'][0]

for i in range(0,4):
     simgr = p.factory.simgr(new_concrete_state)
     simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x85b853]))
     exploration = simgr.run()
     new_concrete_state = exploration.stashes['found'][0]

GLOBAL.simgr = simgr
SIGNALS.state_updated.emit()

simgr = p.factory.simgr(new_concrete_state)
simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x400cd6]) )

exploration = simgr.run()
GLOBAL.simgr = simgr
SIGNALS.state_updated.emit()
```

Symbion test server
```
>>> import angr
>>> bv.file.filename
'/media/jin/4abb279b-6d65-4663-97c2-26987f64673a/home/yuna/Tools/Python-env/frizzer/tests/simple_binary/test'
>>> import avatar2 as avatar2
>>> from angr_targets import AvatarGDBConcreteTarget
>>> 
>>> binary_x64 = bv.file.filename
>>> binary_x64
'/media/jin/4abb279b-6d65-4663-97c2-26987f64673a/home/yuna/Tools/Python-env/frizzer/tests/simple_binary/test'
>>> avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.X86_64, "127.0.0.1", 1234) #gdbserver --attach :1234 297795
>>> 
>>> p = angr.Project(binary_x64, concrete_target=avatar_gdb, use_sim_procedures=True)
>>> 
>>> entry_state = p.factory.entry_state()
>>> 
>>> entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
>>> entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
>>> 
>>> p.entry
4198832
>>> hex(p.entry)
'0x4011b0'
>>> simgr = p.factory.simgr(entry_state)
>>> 
>>> simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x40131a])) #addr handleState
>>> 
>>> exploration = simgr.run()
>>> 
>>> new_concrete_state = exploration.stashes['found'][0]
>>> 
>>> buf_addr = new_concrete_state.solver.eval(new_concrete_state.regs.rdi)
>>> sym_buf = claripy.BVS("buf", 8 * 32)
>>> 
>>> new_concrete_state.memory.store(buf_addr, sym_buf)
>>> 
>>> simgr = p.factory.simgr(new_concrete_state)
>>> 
>>> while len(simgr.active) == 1:
...    simgr.step()

>>> exe = simgr.explore(find=0x4013ec)
>>> new_concrete_state1 = exe.found[0]
>>> data = new_concrete_state1.solver.eval(sym_buf, cast_to=bytes)

#update data
SIGNALS.state_tree_updated.emit()

#open window hook BUG reopen with state tree, Alternatif in righ click state tree
GLOBAL.window_angr_title = "myhook"
SIGNALS.window_angrhook.emit()
SIGNALS.angrhook_updated.emit()


#angr symbion step concrete di fread, untuk lanjut step
1. di dialog tree klik kanan state> temprary state
========
GLOBAL.angr_state.options.add(angr.options.SYMBION_SYNC_CLE)
GLOBAL.angr_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
simgr = p.factory.simgr(GLOBAL.angr_state)
simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x7f51f24e5516])) #alamat setelah fread
exploration = simgr.run()
z = exploration
GLOBAL.simgr = simgr

solusi:
p.hook(0x7fac4870b0b0, angr.SIM_PROCEDURES["libc"]["memcpy"]())
========

#Explore dari console
1. klik kanan state > temporary state
========
buf_addr = GLOBAL.angr_state.solver.eval(GLOBAL.angr_state.regs.rdi) #pass fread mau di call
buf_size = GLOBAL.angr_state.solver.eval(GLOBAL.angr_state.regs.rax) #setelah fread di call
sym_buf = claripy.BVS("buf", 8*buf_size)
GLOBAL.angr_state.memory.store(buf_addr, sym_buf)

seed_ast = GLOBAL.angr_state.memory.load(buf_addr, buf_size)
seed = GLOBAL.angr_state.solver.eval(seed_ast, cast_to=bytes)
GLOBAL.angr_state.preconstrainer.preconstrain(seed, sym_buf) #init symbolic real data buffer

GLOBAL.angr_explore(GLOBAL.angr_project, GLOBAL.angr_state, sym_buf, bv) #param terakhir opsional untuk auto navigasi dari binja bv
SIGNALS.state_tree_updated.emit()
=========
NOTE: buffer symbolik diwarisi ke child tree, dengan hanya copy ke temporary state
di child tree lalu GLOBAL.angr_explore(GLOBAL.angr_project, GLOBAL.angr_state, sym_buf)



# Add GLOBAL.angr_states
saat GLOBAL.simgr berisi stash errored alias
<SimulationManager with all stashes empty (1 errored)>
===========
GLOBAL.angr_addstates(GLOBAL.simgr.errored[0].state)
SIGNALS.state_tree_updated.emit()
===========


# Add message in state
1. Klik kanan state > temporary state
=========
GLOBAL.angr_state.info = "my message"
=========
2. akan tampil di tooltip alias sorot mouse
NOTE: ini tidak ikut tercopy jika state.copy()

# Tips
untuk explore state custom di console python
lihat di dialog_angr.py bagian explore sebagai contoh
lalu pilih refresh untuk menampilkan hasil explore.
1. state list
2. click kanan di state
3. dialog state tree
4. copy to tree
disitu state menarik untuk diexplore

Jika pakai program target besar misal apache2 saat pakai AvatarGDBConcreteTarget
dan error, coba hardcoded timeout di lib/python3.8/site-packages/avatar2/protocols/gdb.py
response = self._communicator.get_sync_response(token, timeout=100)


# History berisi data bermanfaat dan recent_events dll akan berisi data
GLOBAL.angr_state.options.add(angr.options.TRACK_MEMORY_ACTIONS)
GLOBAL.angr_state.options.add(angr.options.TRACK_REGISTER_ACTIONS)
GLOBAL.angr_state.options.add(angr.options.TRACK_JMP_ACTIONS)

ChatGPT:
1. History
history.bbl_addrs → jalur yang dilewati.
history.jump_guard → kondisi branch.
    a.) guard:
--------
"guard": <Bool buf_0 == 0xff>
--------
Artinya kondisi yang harus benar agar transisi yang diambil state saat ini terjadi.

Secara logika:
--------
buf[0] == 0xFF
--------
Kalau branch yang diambil adalah else, guard bisa menjadi bentuk kebalikannya
atau representasi ekuivalennya, tergantung bagaimana VEX mengangkat instruksi
tersebut.
Ini adalah informasi yang sangat penting untuk concolic execution, karena untuk
mengeksplorasi jalur lain Anda sering kali ingin mencoba memenuhi kondisi yang berlawanan.

    b.) target
Misalnya:
---------
"target": 0x401050
---------
Artinya:
> Setelah kondisi dipenuhi, state melompat ke alamat 0x401050.

    c.) kind
Contoh:
---------
"kind": "Ijk_Boring"
---------
jumpkind menjelaskan jenis perpindahan kontrol, bukan apakah branch
diambil atau tidak.

Beberapa nilai yang umum:
Ijk_Boring:   Perpindahan biasa (fall-through atau branch normal)
Ijk_Call:     Pemanggilan fungsi
Ijk_Ret:      Return dari fungsi
Ijk_Syscall:  System call
Ijk_NoDecode: Instruksi tidak dapat didekode
Ijk_Exit:     Program keluar

Untuk percabangan if, biasanya Anda akan melihat Ijk_Boring.
Contoh lengkap

Misalnya program:
=====================
if (buf[0] == 'A')
    foo();
else
    bar();

State yang menuju foo() mungkin memiliki:
{
    "addr": 0x401000,
    "guard": <Bool buf_0 == 0x41>,
    "target": 0x401030,
    "kind": "Ijk_Boring"
}
======================
Artinya:
berada di branch pada 0x401000, kondisi yang dipenuhi adalah buf[0] == 'A',
berpindah ke 0x401030, perpindahannya adalah branch biasa.



2. State.history.events adalah daftar event yang terjadi selama eksekusi state. Berbeda denga
n bbl_addrs yang hanya menyimpan alamat basic block, events menyimpan informasi tentang ap
a yang terjadi.
Contohnya:
    - memory read
    - memory write
    - register read/write
    - constraint baru
    - SimProcedure dipanggil
    - syscall
    - symbolic variable dibuat
    - dll.

3. recent_events biasanya lebih berguna saat dipanggil setiap simgr.step(), karena
hanya berisi event pada langkah terakhir.
Contoh event:
Misalnya program melakukan:
========
x = *(buf+4);
========
Anda mungkin melihat event seperti:
    - SimActionData READ
yang berisi informasi:
    - alamat yang dibaca
    - ukuran
    - nilai
    - apakah symbolic

Misalnya:
========
memcpy(dst, src, len);
========
Jika memakai SimProcedure, bisa muncul event yang menunjukkan penulisan memori.


4. state.history.recent_actions
Anda akan mendapatkan informasi seperti:
--------------------
READ
address = 0x404000
size = 1

WRITE
address = 0x404100
size = 4
---------------------
Ini jauh lebih berguna untuk analisis data flow.

5. Perbedaan events dan actions
events = kejadian tingkat tinggi selama eksekusi (berbagai jenis event).
actions = operasi konkret yang dilakukan state (read, write, register,
constraint, jump, dll.).
```

kode yang dikaburkan
```python
state1 = simgr.found[0]
addr = state1.addr
data = state1.memory.load(addr, 0x100)
raw = state1.solver.eval(data, cast_to=bytes)

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)

for i in md.disasm(raw, addr):
    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

# atau load ke binaryninja hasil raw
bv.add_user_segment(addr, len(raw), 0, len(raw), SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
bv.write(addr, raw)
bv.add_function(addr)
```
