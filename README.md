Bridge gdb, binaryninja and angr for binary analyses

![](Screenshot_2025-12-04_08-46-50.png)

Youtube Demo 1
[![Demo 1](https://img.youtube.com/vi/GSqoDsAwt-Y/maxresdefault.jpg)](https://m.youtube.com/watch?v=GSqoDsAwt-Y)

Youtube Demo 2 (real target)
[![Demo 2](https://img.youtube.com/vi/qLTcykEyN0I/maxresdefault.jpg)](https://m.youtube.com/watch?v=qLTcykEyN0I)


# Requirenment
```
binaryninja 2.0...
gdb 9
angr 9.2.102
```

# Usage
```
1). copy this directory in binaryninja plugin path
2). gdb ./a.out
    (gdb) source /gproxy/gdbinit.py
3). start server in binaryninja: Tools > gproxy > start server

mencocokan alamat gdb ke binaryninja
(gdb) b main
(gdb) run
(gdb) info proc mappings 
          Start Addr           End Addr       Size     Offset objfile
      0x555555554000 

4). binaryninja: file > rebase > 0x555555554000
```

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

# Cheatshet
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

#Mencari ketika input stdin menghasilkan password benar
simgr.epxpore(find=lambda s: b"Access granted" in s.posix.dumps(0) )

#Menghindari pesan kesalahan di stdout
simgr.explore(avoid=lambda s: b"Wrong password" in s.posix.dumps(1) )

#Brute force password
simgr.explore(find=lambda s: b"Success" in s.posix.dumps(1), avoid=lambda s: b"Fail" in s.posix.dumps(1) )

#show status explore
import logging
logging.getLogger('angr').setLevel('INFO')

#Note: dump(fd) 0=stdin 1=stdout 2=stderr

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

# kode yang dikaburkan

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

# Tips visualisasi semua proses linux
Untuk refresh visual proses linux, klik simbol di sidebar dan
lihat juga di sidebar function list berapa kali hook load_elf_binary di HIT
yang menandakan jumlah proses baru saat os baru boot.


# Tips dynamic hook (monitoring data) analysis
Jika alamat target misal lokasi struktur ada di tengah fungsi
anda bisa set alamat di /tmp/funcs.txt alias merubah offset symbol addr.
otomatis jika klik kanan di function list dia pakai alamat ini.

Saat pakai tombol pause lalu play, harus manual alias continue di gdb langsung
untuk melanjutkan.
NOTE: Untuk dump structure hanya update saat ini bukan berasal dari history register.

# dump value variable local
1). dump seluruh frame:
x/64gx $rsp
x/64gx $rbp-0x100


# Utilitis for mikrotik helper
Open console binaryninja and paste this, this script by https://github.com/tenable/routeros

1). find handlers
```python
from gproxy.helpers import Mikrotik
aa = Mikrotik()
aa.target = "/media/jin/4abb279b-6d65-4663-97c2-26987f64673a/home/yuna/Lab/DockerImage-mikrotik/modif/npk-routeros/bak/6.42.11/nova/bin/"
aa.find_handlers()

```
output, copy all to csv file filter with [1/79] user... etc
NOTE: this is very slow because bn analysis all. and fix it hex result from int
```
[0/79] kidcontrol
kidcontrol,0,0,0
[1/79] user
user,0,0,0,0,0,0,0,0
[2/79] ping
[3/79] convertbr
[4/79] keyman
[5/79] modprobed
modprobed,1
[6/79] telser
[7/79] licupgr

```

# Trace function basic block
```
1. open bn > view > block list

2. (gdb) cmdtracefunc generate
   (gdb) cmdtracefunc run-bn
   (gdb) c

3. right click in function list > generate block
         wait breakpoint
   (gdb) cmdtracefunc run-bn-block
   (gdb) c

NOTE: for update view, double click in function list

View desc:
[4/18] sub_xxx
    3 0x123 => start-block
    7 0x777 => end-block

[hit/count_hit]
    3 => berapa kali dipanggil   
```

# Trace function ringan 
```
(gdb) cmdtracefunc generate
(gdb) cmdtracefunc dprintf
(gdb) c

ui binja: klik kanan di function list dprintf> gen registers
NOTE: untuk awalan window register belum muncul, solusinya klik kanan lagi
di fungsi yang sama.
```


# Frida function trace
```
$ python fridainit.py
>> Select target? Linux/Android (l/a): a
>> remote ip: 192.168.43.1
>> Chose pid? (1234): 9144
>> em
>> et
```

Cheatshet frida patch
```
# enumerate JNI function (ident with "Java_")
$ frida-trace -i "Java_*" com.android.tes

# enumerate all function by module
$ frida-trace -I "openssl_mybank.so" com.android.tes
```

example case:
```
	=====================
	 Fuzzer proxy v2.0.0
	=====================

>> Select target? Linux/Android (l/a): a
>> Chose pid? (1234): 5843

[+] Inject Agent successfully

==============
 List Command:
==============
1. shell/reverse_shell_java (s/js)
2. enum_module/enum_symbol/enum_thread (em/es/et)
3. trace (tr)> (all/<symbol>/back)> (all/mnemonic(ret,jne)/<enter-none>)
4. stalker (stl)> (back/<id>/window/intruksi/stoplivethread/startlivethread)
           (intruksi)> <func_addr>
5. exit

>> tr
[+] Getting modules...
[+] Send to binja...
[+] Done.

>> Module> png_read
[+] Getting symbols to hook...

>> png_read> symbol> parse_png_file

>> png_read> parse_png_file> Stalking filter> ret
[+] hook: parse_png_file intruction filter: ret
[+] Setup hook: parse_png_file with stalking: ret
[+] Done.

>> exit
NOTE: >1 filter di pencarian hanya fungsi ter hit

```

# Tips hook addr dengan base dan offset dari binja (striped binary)
```
$ python
>> 0x7ff2232323 + 0x510 #base_module+offset

$ python fridainit.py
>> png_read> symbol> 0x630f5d4db0

>> png_read> 0x630f5d4db0> Stalking filter> 
[+] Agent @ Setup hook: unkown 

NOTE: jika addr HIT akan ada fungsi baru yaitu: unkwon
```

# Trace with basic block color in binaryninja
NOTE: set filter modules with edited in rpc_scrips.js: var whitelist = ["all"];
```
>> tr
[+] Agent @ Getting modules...
[+] Send to binja...
[+] Done.

# first rebase in binaryninja with:
# 1). double click in module> base> auto copy
# 2). file > rebase> paste
# 3). wait function is hit
# 4). righ click function> color block
# NOTE: using color reset for reload block color orig

>> Module> png_read
[+] Agent @ Getting symbols to hook...

>> png_read> symbol> parse_png_file
>> png_read> parse_png_file> Stalking filter> block

```


# Contoh penggunaan stalker
```
>> stl
>> by thread/module? t/m: t

>> Stalker(0)> 30405
>> call-count/call-tree (cc/ct)> cc
[+] Agent @ Setup Stalker...

>> Stalker(30405)> 

NOTE: isi edit text dengan field data untuk filter
```

# Contoh penggunaan stalker call-tree
```
1.) saat window stalker muncul kilk kanan> Clean
2.) jalanakan program target
3.) di window stalker klik kanan> Refresh
4.) ulangi

NOTE: perbedaan call-count dan call-tree, call-count urutuan panggilan acak tapi dengan
informasi call count, sedangkan call-tree urutan panggilan original dan tidak disertai call count.
```
# New fitur stalker call-tree(ct)
Lebih ringan karena semua hasil stalker masuk ke file alih-alih memori ram sekaligus
menampilkan hanya 20 baris terbaru dari file /tmp/stalker-ct.json.
```
	=====================
	 Fuzzer proxy v2.0.0
	=====================

>> Select target? Linux/HostIP/USB (l/h/u): h
>> Chose pid? (1234): 2803
>> Script type package? y/n: 

[+] Inject Agent successfully

==============
 List Command:
==============
1. shell/reverse_shell_java (s/sj)
2. enum_module/enum_symbol/enum_thread (em/es/et)
3. trace (tr)> (all/all-tree/<symbol>/0x11,0x22.../back)> (block/back/mnemonic(all,ret,jne)/<enter=none-fast)
4. trace-java (tr-java)> (all/package-class/back) (full-info)> (className)
6. stalker (stl)> (back/<id-thread>/window/intruksi/stoplivethread/startlivethread)> 
           (intruksi)> (func_addr/back)> (filter)> (mnemonic:ret,jne,enter:all/back)
exit

>> stl
>> by thread/module? t/m: t

>> Stalker(0)> 2803
>> call-count/call-tree (cc/ct)> ct
[+] Agent @ Setup Stalker...

>> Stalker(2803)>
```
```
NOTE:
1. di window stalker klik kanan > refresh dan ini akan update ui berisi data trace
2. di window stalker > isi input text > klik kanan > refresh ini akan mencari 
   string di semua field json /tmp/stalker-ct.json
```


# trace java class android
```
>> tr-java
>> Class> com.facebook
atau
>> Class> com.
```


# Unity game trace
```
1). view > Gproxy show frida list
2). extrack template in fridautils/frida-zombeast-old.tar.gz to /home/ or set code in line Script type package "path"
3). patch target with path-gadget.py or frida-server
4). python fridainit.py
>> Select target? Linux/Android (l/a): a
>> Chose pid? (1234): 27362
>> Script type package? y/n: y

[+] Inject Agent successfully

==============
 List Command:
==============
1. trace-unity (tr-unity)> (<assembly-name>/dump-asm)>
exit

>> tr-unity

>> Assembly> Assembly-CSharp
>> Tracking with param? y/n: y #rawan crash dan lambat
[+] Agent: start hooking... #tunggu sampai hook complete
...
[+] Agent: hook complete. 

```
# frida stalker by module and all thread
```
>> stl
>> by thread/module? t/m: m
[+] Agent @ Getting modules...
[+] Send to binja...
[+] Done.
>> module name (png_read,libc.so): thread_sim
[+] Agent @ stalking => thread_sim

NOTE: in frida window stalker double click in thread id to show function call tree
dan jika di frida target cpu 100% click kanan dan clean fridaserver.
```

# trace tree

```

	=====================
	 Fuzzer proxy v2.0.0
	=====================

>> Select target? Linux/HostIP/USB (l/h/u): u
>> Chose package? (com.abc): com.whatsapp
>> Script type package? y/n: 

[+] Inject Agent successfully

==============
 List Command:
==============
1. shell/reverse_shell_java (s/sj)
2. enum_module/enum_symbol/enum_thread (em/es/et)
3. trace (tr)> (all/all-tree/<symbol>/0x11,0x22.../back)> (block/back/mnemonic(all,ret,jne)/<enter=none-fast)
4. trace-java (tr-java)> (all/package-class/back) (full-info)> (className)
6. stalker (stl)> (back/<id-thread>/window/intruksi/stoplivethread/startlivethread)> 
           (intruksi)> (func_addr/back)> (filter)> (mnemonic:ret,jne,enter:all/back)
exit

>> tr
[+] Agent @ Getting modules...
[+] Send to binja...
[+] Done.

>> Module> libcurve25519.so

>> Dump symbol address? frida/bn/r2: > r2
[+] Using radare2 symbol.
[+] r2 -e scr.color=0 -A -q -c 'afl' lib.so | awk '{print $1, $4}' > funcs.txt

>> Path funcs.txt default: (/tmp/funcs.txt) 
>> Base lib: 0x7f5e6fa000

>> libcurve25519.so> symbol> all-tree
[+] Agent @ Setup hook-tree UI: sym.imp.memset
Error: unable to intercept function at 0x7f5e710a30; please file a bug
[+] Agent @ Setup hook-tree UI: entry0
[+] Agent @ Setup hook-tree UI: sym.Java_org_whispersystems_curve25519_NativeCurve25519Provider_generatePublicKey
[+] Agent @ Setup hook-tree UI: fcn.00007cd8
[+] Agent @ Setup hook-tree UI: fcn.00008d68
[+] Agent @ Setup hook-tree UI: fcn.00008f28
[+] Agent @ Setup hook-tree UI: fcn.00008fb8
[+] Agent @ Setup hook-tree UI: fcn.00009048
[+] Agent @ Setup hook-tree UI: fcn.00009644
[+] Agent @ Setup hook-tree UI: fcn.000096e4
[+] Agent @ Setup hook-tree UI: fcn.0000986c
[+] Agent @ Setup hook-tree UI: fcn.00008cd8
[+] Agent @ Setup hook-tree UI: fcn.00009aa8

...
Thread 18847
└─sym.Java_org_whispersystems_curve25519_NativeCurve25519Provider_smokeCheck
└─sym.Java_org_whispersystems_curve25519_NativeCurve25519Provider_verifySignature
   └─fcn.00009be4
      └─fcn.0000d760
      └─fcn.0000a0f8
         └─fcn.0000ea88
         └─fcn.0000d6f4
         └─fcn.0000d908
            └─fcn.0000e5cc
            └─fcn.0000dddc
         └─fcn.0000dddc
      └─fcn.0000eab0
      └─fcn.0000cf6c
         └─fcn.0000f274
            └─fcn.0000d760
            └─fcn.0000e5cc
            └─fcn.0000dddc
            └─fcn.0000ea88
            └─fcn.0000d6f4
            └─fcn.0000e1e4
               └─fcn.0000e5cc
               └─fcn.0000dddc

```
**TIPS
update trace tree in ui binja
```
1. buka apk saat idle
2. lalu trace
3. klik kanan> Coloring All
4. buka fitur apknya, misal di tab message
5. amati yang tidak berwarna berarti itu fungsi yang menangani message
```
trace lebih dari satu module di dalam folder
```
$ ls /tes/lib
libwhatsapp.so
libabc.so
...
$ bash r2-generate.sh
$ cp -R /tes/lib/zout /tmp

>> tr
[+] Agent @ Getting modules...
[+] Send to binja...
[+] Done.

>> Module> zzzzz

>> Dump symbol address? frida/bn/r2: > r2
[+] Using radare2 symbol.
[+] r2 -e scr.color=0 -A -q -c 'afl' libname.so | awk '{print $1, libname.so!$4}' > funcs.txt

>> Single/path-recursive? s/<path>: /tmp/zout
[+] Processing: 0x7f5e36b000 (libar-bundle3.so.txt)
[+] Processing: -1 (libar-bundle4.so.txt)
[+] Fail
[+] Processing: 0x7f57e7e000 (libaom.so.txt)
[+] Processing: 0x7f5dfe1000 (libar-bundle2.so.txt)
[+] Processing: -1 (libandroidx.graphics.path.so.txt)
[+] Fail
[!] big Symbol, nothing for show.

>> zzzzz> symbol> all-tree
```
# monitor thread
```
>> et
TIPS: untuk mengetahui thread baru yang muncul klik kanan> coloring Al, lalu (et)
dan list yang tidak terwarnai adalah thread baru
```
