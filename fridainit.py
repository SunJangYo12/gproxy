#!/usr/bin/env python3

import frida
import sys
import os
import time
import datetime
from ctypes import *
import xmlrpc.client
import threading
import json
from collections import Counter
import subprocess
import hashlib

proxy = xmlrpc.client.ServerProxy("http://127.0.0.1:1337", allow_none=True)

pwd = None
ALL_ALLOC = {}

def get_taint_subtree(data, root):
    tree = {}
    for item in data:
        node = tree
        for entry in item:
            addr = entry["ptr"]
            if addr not in node:
                node[addr] = {
                    "__meta__": entry,
                    "__children__": {}
                }
            node = node[addr]["__children__"]
    return tree.get(root)


def on_message(message, data):
    if message['type'] == 'send':
        if message['payload']['type'] == 'enum_modules':
           #print(message)
           print("[+] Send to binja...")
           modules = message['payload']['log']

           proxy.settofrida_enum(modules, "modules")
           print("[+] Done.")

        elif message['payload']['type'] == 'enum_symbols':
           print("[+] Send to binja...")
           sym = message['payload']['log']

           proxy.settofrida_enum(sym, "symbols")
           print("[+] Done.")


        elif message['payload']['type'] == 'enumunity_assembly':
           asm = message['payload']['log']

           #for i in asm:
           #    print(f"[+] {i}")
           #print("\n\n")

           #proxy.settofrida_enum(asm, "unity_assembly")

        elif message['payload']['type'] == 'enumunity_method':
           method = message['payload']['log']
           print(method)

           #proxy.settofrida_enum(method, "unity_method")



        elif message['payload']['type'] == 'enum_threads':
           print("[+] Send to binja...")
           threads = message['payload']['log']

           proxy.settofrida_enum(threads, "threads")
           print("[+] Done.")

        elif message['payload']['type'] == 'id_threads':
           threads = message['payload']['log']
           proxy.settofrida_enum(threads, "id_threads")

        elif message['payload']['type'] == 'bb_hit':
           bbs = message['payload']['log']

           proxy.settofrida_enum(bbs, "bb_hit")



        elif message['payload']['type'] == 'stalker':
           sdata = message['payload']['log']

           with open("/tmp/stalker-cc.json", "w") as fd:
               fd.write(json.dumps(sdata))

           proxy.settofrida_enum("zz", "stalker")


        elif message['payload']['type'] == 'stalker-ct':
           sdata = message['payload']['log']

           with open("/tmp/stalker-ct.json", "a") as fd:
               fd.write(json.dumps(sdata[0]) + "\n")

           #proxy.settofrida_enum(sdata[0], "stalker-ct")



        elif message['payload']['type'] == 'bnlog':
           bnlog = message['payload']['log']
           #proxy.settofrida_enum(str(bnlog), "bnlog")
           print(str(bnlog))

        elif message['payload']['type'] == 'info':
           info = message['payload']['log']
           print(f"[+] {info}")


        elif message['payload']['type'] == 'zhook_hit':
           data = message['payload']['log']
           go = message['payload']['go']
           all_chain = message['payload']['chain']

           tchain = []
           for i in all_chain:
               tchain.append(i["chain"])

           for dat in data:
               id = dat["key"]
               key = id.split("_")[1]

               subtree = get_taint_subtree(tchain, key)
               dat["tainted"] = subtree

               if id not in ALL_ALLOC:
                   ALL_ALLOC[id] = dat

           if go == "l":
               print("\n[+] Load .txt from saved")
           else:
               with open("/tmp/trace-buffinput.json", "w") as fd:
                   fd.write(json.dumps(ALL_ALLOC))

           proxy.settofrida_func("0", "hooktree_hit_all")


        elif message['payload']['type'] == 'hook_hit':
           info = message['payload']['log']
           #proxy.settofrida_func(info, "")

           if "heap_area" in info:
               if info["heap_area"]:
                   heap_area = info["heap_area"].split("-> ")
                   ptr  = heap_area[1]
                   func = heap_area[0].split("] ")

                   try:
                       if func[1] not in ALL_ALLOC[ptr]["member"]:
                           ALL_ALLOC[ptr]["member"].append(func[1])
                   except:
                       pass

           elif "buff_area" in info:
               if info["buff_area"]:
                   raw = info["buff_area"]
                   func_name = raw["name"]
                   sink_args = str(raw["sink_args"])
                   sink_name = raw["sink"]
                   sink_ptr  = raw["sink_ptr"]
                   thread    = raw["thread"]
                   context   = raw["context"]

                   id = sink_name+"_"+sink_ptr

                   #pakai try jika belum di ENTER atau update
                   try:
                       if True: #func_name not in ALL_ALLOC[id]["member"]:
                           ALL_ALLOC[id]["member"][func_name] = {
                               "func_name": func_name,
                               "sink_args": sink_args,
                               "sink_name": sink_name,
                               "sink_ptr":  sink_ptr,
                               "skor":      info["skor"],
                               "thread":    thread,
                               "context":   context,
                           }
                   except:
                       pass

        elif message['payload']['type'] == 'hookmalloc_hit':
           info = message['payload']['log']
           proxy.settofrida_func(info, "malloc")


        elif message['payload']['type'] == 'fail_hook_tree':
           info = message['payload']['log']

           print("[+] Write fail.")

           with open("/tmp/fail-hook.json", "a") as fd:
               fd.write(json.dumps(info) + "\n")


        elif message['payload']['type'] == 'java_hit':
           java_hit = message['payload']['log']
           proxy.settofrida_func(java_hit, "java_hit")


    elif message['type'] == 'error':
        print(message['stack'])

def exiting():
    print("Exiting!")


def inject_module(script, target):
    triggerAddr = None
    while True:
       if target == "a":
          triggerAddr = script.exports_sync.injectmodule("android", None);
       elif target == "l":
          pathmodule = "{}/ccode/afl_proxy/module/libmodule.so".format(os.getcwd())
          triggerAddr = script.exports_sync.injectmodule("linux", pathmodule);
       else:
          print("[!] PY error target inject module")
          exit(1)

       if triggerAddr == "0x0":
          print("[+] PY inject libmodule.so")
          time.sleep(1)
       else:
          print("[+] PY inject libmodule.so successfully")
          print("[*] PY libmodule.so trigger addr: {}".format(triggerAddr))
          break
    if triggerAddr == None:
       print("[!] error inject module")
       exit()
    return triggerAddr

def setup_hook(script, dick_sym, func_target, fstalking):
    for data in dick_sym:
        if data.get("type") == "function":
            func_name = data.get("name")
            func_addr = data.get("address")

            if func_addr == "0x0":
                continue

            try:
                # single
                if func_name == func_target:
                    if fstalking != None:
                        script.exports_sync.setuphook(data, fstalking)
                    else:
                        script.exports_sync.setuphook(data, -1)

                elif func_target == "zzall-tree": #all-tree
                    name = data.get("name")

                    if name.startswith("_Z"):
                        result = subprocess.check_output(["c++filt", name])
                        name = result.decode().strip()
                    zdata = {
                       "type": data.get("type"),
                       "name": name,
                       "address": data.get("address")
                    }
                    script.exports_sync.setuphook(zdata, -2)

                else: #all
                    if not func_target:
                        script.exports_sync.setuphook(data, -1)

            except Exception as e:
                print(f"{func_name} >>>>>>> {e}")

def setup_hooktree_r2(pfuncs, pbase):
    result = []
    with open(pfuncs) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            addr = hex(pbase + int(parts[0], 0) )
            name = parts[1] if len(parts) > 1 else None

            out = {
                "address": addr,
                "name": name,
                "type": "function"
            }
            result.append(out)

    return result


class TraceColorizer:
    def __init__(self, xdata):
        self.xdata = xdata
        self.data = None
        self.names = []
        self.dup_names = set()

    def load(self):
        self.data = self.xdata

    def _collect(self, node):
        self.names.append(node["name"])
        for child in node.get("children", {}).values():
            self._collect(child)

    def find_duplicates(self):
        for pid in self.data:
            self._collect(self.data[pid]["root"])

        counter = Counter(self.names)
        self.dup_names = {k for k, v in counter.items() if v > 1}

    def _mark(self, node):
        if node["name"] in self.dup_names:
            node["color"] = 1

        for child in node.get("children", {}).values():
            self._mark(child)

    def apply_color(self):
        for pid in self.data:
            self._mark(self.data[pid]["root"])

    def save(self, outfile):
        with open(outfile, "w") as f:
            json.dump(self.data, f, indent=2)


class MyThreadGetHookCount(threading.Thread):
    def __init__(self, script):
        super().__init__()
        self.stop_event = threading.Event()
        self.script = script

    def run(self):
        while not self.stop_event.is_set():
            data = self.script.exports_sync.gethooknodes()

            trace = TraceColorizer(data)
            trace.load()
            trace.find_duplicates()
            trace.apply_color()
            trace.save("/tmp/hooktree_hit.json")


            proxy.settofrida_func("0", "hooktree_hit_all")

            time.sleep(4)


    def stop(self):
        self.stop_event.set()


class MyThread(threading.Thread):
    def __init__(self, script):
        super().__init__()
        self.stop_event = threading.Event()
        self.script = script

    def run(self):
        while not self.stop_event.is_set():
            self.script.exports_sync.idthreads()
            time.sleep(0.3)

    def stop(self):
        self.stop_event.set()

class MyUtils:
    def read_dynamic_config(sw):
        out = ""
        try:
            with open("/dev/shm/gproxy.config", "r") as fd:
                for line in fd:
                    key = line.split(":")

                    if key[0] == sw:
                        out = key[1].split("\n")[0]
                        break
        except:
            pass
        return out

    def config_dynamic(sw, func_name):
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




def main():
    print("\n\t=====================")
    print("\t Fuzzer proxy v3.0.1")
    print("\t=====================\n")
    target = input(">> Select target? Linux/HostIP/USB/TcpADB (l/h/u/t): ")

    DEBUG = False

    if target == "h":
       #ahost = input(">> Android host: ")
       #device = frida.get_device_manager().add_remote_device(ahost)
       device = frida.get_device_manager().add_remote_device("192.168.0.101")
       pid_raw = input(">> Chose pid? (1234): ")
       pid = int(pid_raw)
       device.resume(pid)


    elif target == "t":
       # this like: adb -s 192.168.0.100:5555
       manager = frida.get_device_manager()

       # get all service
       #for device in manager.enumerate_devices():
       #    print(device.id, device.name, device.type)

       #tcpip = input(">> ADB tcpip: ")
       tcpip = "192.168.0.101:5555"
       device = manager.get_device(tcpip)

       package = input(">> Chose package/process? (com.abc.df/mediaserver): ")
       #package = "ru.zdevs.zarchiver"
       ispaket = len(package.split(".")) > 1

       if ispaket:
           pid = device.spawn([package])
           device.resume(pid)
       else:
           pid = package

       #for p in device.enumerate_processes():
       #    print(f"{p.pid:6} {p.name}")

    elif target == "u":
       manager = frida.get_device_manager()

       device = frida.get_usb_device()
       package = input(">> Chose package? (com.abc): ")
       pid = device.spawn([package])
       device.resume(pid)

    elif target == "l":
       device = frida.get_local_device() #local linux

       if DEBUG:
           pid_raw = subprocess.run(["pidof", "apache2"], capture_output=True, text=True)
           pid_raw = pid_raw.stdout.split("\n")[0]
       else:
           pid_raw = input(">> Chose pid? (1234): ")

       pid = int(pid_raw)

    else:
       print("[!] PY target not found")
       exit(1)

    session = device.attach(pid)

    is_script_package = input(">> Script type package? y/n: ")

    if is_script_package == "y":
        fscript = "/media/jin/6a76baf7-5d55-4bae-ac03-6cb70d5d180d/Tools/frida-zombeast-old/dist/agent.js"
    else:
        fscript = "fridautils/rpc_script.js"

    with open(fscript, "r") as file:
        data = file.read()
        script = session.create_script(data)

    script.on("message", on_message)
    script.load()

    print(f"\n[+] Inject Agent successfully")

    print("\n==============")
    print(" List Command:")
    print("==============")
    if is_script_package == "y":
        print("1. trace-unity (tr-unity)> (<assembly-name>/dump-asm)")
    else:
        print("1. shell/reverse_shell_java (s/sj)")
        print("2. enum_module/enum_symbol/enum_thread/enum_thread_live (em/es/et/etl)")
        print("3. trace (tr)> (all/all-tree/all-alloc/<symbol>/0x11,0x22.../back)> (block/back/mnemonic(all,ret,jne)/<enter=none-fast)")
        print("      all = hook all symbol, symbol generate by frida,r2 and binja you chose this")
        print("      all-tree = hook all symbol with tree")
        print("      all-alloc = hook all symbol, while all function touch it buffer by allocation")
        print("                   malloc, calloc, realloc")
        print("      all-binput = hook all symbol, while all function touch it buffer by allocation")
        print("                   read, fread, fgets, recv, recvfrom")
        print("      <symbol> = single hook with symbol name")
        print("      0x11,0x22.. = custom count hook with address")
        print("")
        print("4. trace-java (tr-java)> (all/package-class/back) (full-info)> (className)")
        print("6. stalker (stl)> (back/<id-thread>/window/intruksi/stoplivethread/startlivethread)> ")
        print("           (intruksi)> (func_addr/back)> (filter)> (mnemonic:ret,jne,enter:all/back)")
        print("7. fuzzing (fuzz)> (sym/addr)")
    print("exit")

    loop_menu = True

    while loop_menu:
        if DEBUG:
            pshell = "tr"
        else:
            pshell = input("\n>> ")

        if pshell == "em":
            script.exports_sync.enummodules()

        elif pshell == "es":
            module = input("\n>> Module> ")
            script.exports_sync.enumsymbols(module)

        elif pshell == "et":
            script.exports_sync.enumthreads()

        elif pshell == "etl":
            proxy.settofrida_func("id_threads", "refresh")

            thread = MyThread(script)
            thread.start()

        elif pshell == "bn_func":
            proxy.setgeneratesymbol()
            print("[+] Generate done.")


        elif pshell == "stl":
            in_sw = input(f">> by thread/module? t/m: ")

            if in_sw == "m":
                script.exports_sync.enummodules()
                in_mod = input(f">> module name (png_read,libc.so): ")

                proxy.settofrida_func("id_threads", "refresh")
                proxy.settofrida_openwindow("stalker", "by module")

                script.exports_sync.setstalker("module", in_mod, "")

                while True:
                    script.exports_sync.idthreads()


                    tid_func = MyUtils.read_dynamic_config("stalker-ct-module")
                    try:
                        tid_func = int(tid_func)
                    except:
                        tid_func = -1

                    req_clean = MyUtils.read_dynamic_config("stalker-ct-module-clean-fridaserver")
                    if req_clean == "oke":
                        script.exports_sync.getstalkerdata("req_clean")
                        MyUtils.config_dynamic("stalker-ct-module-clean-fridaserver", "")

                    sdata = script.exports_sync.getstalkerdata(tid_func)

                    noroot = []
                    yesroot = []
                    for i in sdata:
                        nout = {
                           "tid": i["tid"],
                           "root": None,
                           "root_len": i["root_len"]
                        }
                        out = {
                           "tid": i["tid"],
                           "root": i["root"],
                           "root_len": i["root_len"]
                        }
                        noroot.append(nout)
                        yesroot.append(out)

                    proxy.settofrida_enum(noroot, "stalker-ct-module")

                    if len(yesroot) != 0:
                        with open("/dev/shm/gproxy.stalker-ct-module", "w") as fd:
                            json.dump(yesroot, fd, indent=4)
                    #print(sdata)
                    time.sleep(1)

                continue
                #end module

            proxy.settofrida_func("id_threads", "refresh")

            thread = MyThread(script)
            thread.start()

            tmpid = 0
            xin_sintr = ""
            xin_sintr_filter = ""

            while True:
                in_id = input(f"\n>> Stalker({tmpid})> ")

                if in_id == "back":
                    print(f"[+] Exit stalker: {tmpid}")
                    thread.stop()
                    script.exports_sync.setstalker("exit", tmpid, "")
                    break

                elif in_id == "stoplivethread":
                    print(f"[+] Stop Live thread view")
                    thread.stop()

                elif in_id == "startlivethread":
                    print(f"[+] Start Live thread view")
                    thread.start()

                elif in_id == "intruksi":
                    while True:
                        in_sintr = input(f"\n>> Stalker({tmpid})> intruksi({xin_sintr})> ")
                        xin_sintr = in_sintr

                        if in_sintr == "back":
                            break
                        else:
                            in_sintr_filter = input(f"\n>> Stalker({tmpid})> intruksi({xin_sintr})> filter({xin_sintr_filter})> ")
                            xin_sintr_filter = in_sintr_filter

                            if in_sintr_filter == "back":
                                break
                            script.exports_sync.setstalker("intruksi", in_sintr, in_sintr_filter)


                elif in_id == "window":
                    proxy.settofrida_openwindow("stalker")
                else:
                    in_ct = input(">> call-count/call-tree (cc/ct)> ")

                    #os.remove("/tmp/stalker-ct.json")

                    tmpid = int(in_id)
                    proxy.settofrida_openwindow("stalker", in_id)
                    script.exports_sync.setstalker(in_ct, int(in_id), "")



        elif pshell == "fuzz":
            print("==========================================")
            print("  Harcoded in rpc_script.js in setfuzz()")
            print("  1). set function addr NativeFunction")
            print("  2). copy radamse binary to target device")
            print("==========================================")
            offset = "0x458c0" #input("\n>> Offset addr> ")
            base = "0x559213aa8000" #input("\n>> Base lib> ")

            offset = int(offset, 0)
            base = int(base, 0)
            zz = int("0x1f4", 0)

            addr = hex(base + offset + zz)

            script.exports_sync.setfuzz(addr)
            print("[+] Waiting hook...")


        elif pshell == "tr":
            script.exports_sync.enummodules()
            if DEBUG:
                in_module = "apache2"
            else:
                in_module = input("\n>> Module> ")

            if in_module == "back":
                continue

            if DEBUG:
                in_swsym = "frida"
            else:
                in_swsym = input("\n>> Dump symbol address? frida/bn/r2:> ")

            while True:
                isbn = 0

                dick_sym = []

                if in_swsym == "frida":
                    print("[+] Using frida symbol.")
                    if DEBUG:
                        sw_frida = "s"
                    else:
                        sw_frida = input(">> Symbol/Import/Export? s/i/e: ")

                    dick_sym = script.exports_sync.enumsymbolstrace(in_module, sw_frida)

                elif in_swsym == "r2":
                    print("[+] Using radare2 symbol.")
                    # read -p "libname: " libname
                    # r2 -e scr.color=0 -A -q -c 'afl' $libname | awk '{print $1, "$libname!"$4}' > funcs.txt

                    p_rec = input(">> Single/path-recursive? s/<path>: ")

                    if p_rec != "s":
                        for f in os.listdir(p_rec):
                            pbase = script.exports_sync.getbase(f)
                            print(f"[+] Processing: {pbase} ({f})")

                            if pbase == -1:
                                print(f"[+] Fail")
                                continue
                            proc = setup_hooktree_r2(f"{p_rec}/{f}", int(pbase, 0))
                            dick_sym.extend(proc) #tidak nested list
                    else:
                        pfuncs = input(">> Path funcs.txt default: (/tmp/funcs.txt) ")
                        pbase = input(">> Base lib: ")
                        pbase = int(pbase, 0)
                        if pfuncs == "":
                            pfuncs = "/tmp/funcs.txt"
                        dick_sym = setup_hooktree_r2(pfuncs, pbase)

                elif in_swsym == "bn":
                    print("\n[+] Using binaryninja symbol.")
                    proxy.setgeneratesymbol()
                    print("[+] Generate done.")
                    pbase = input(">> Base target lib: ")
                    pbase = int(pbase, 0)

                    isbn = 1

                    with open("/tmp/funcs.txt") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            parts = line.split()
                            addr = parts[0]
                            name = parts[1] if len(parts) > 1 else None
                            addr = int(addr, 0)

                            out = {
                                "address": hex(pbase + addr),
                                "name": name,
                                "type": "function"
                            }
                            dick_sym.append(out)

                #init for total symbol
                if len(dick_sym) >= 300:
                    print("[!] big Symbol, nothing for show.")
                else:
                    proxy.settofrida_func(dick_sym, "init")

                if DEBUG:
                    in_symbol = "all-binput"
                else:
                    in_symbol = input(f"\n>> {in_module}> symbol> ")

                if in_symbol == "back":
                    script.exports_sync.setuphook("", "detach-all")
                    break

                elif in_symbol == "all":
                    setup_hook(script, dick_sym, None, None)

                    proxy.settofrida_func("trace-func", "refresh")
                    break

                elif in_symbol == "all-binput":
                    script.exports_sync.setuphook("", "buffinput")
                    time.sleep(1)

                    setup_hook(script, dick_sym, None, None)

                    proxy.settofrida_openwindow("tracer_allocator", "Trace buffer input")
                    #proxy.settofrida_func("trace-func", "refresh")
                    while True:
                        go = input("\nENTER for update/load: ENTER/l? \n")
                        data = script.exports_sync.getbuffertrace(go)

                elif in_symbol == "all-alloc":
                    script.exports_sync.setuphook("", "allocator")
                    time.sleep(1)

                    setup_hook(script, dick_sym, None, None)

                    proxy.settofrida_openwindow("tracer_allocator", "Trace Allocator")
                    #proxy.settofrida_func("trace-func", "refresh")
                    while True:
                        go = input("\nENTER for update..\n")

                        data = script.exports_sync.getalloctrace()

                        for dat in data:
                            mykey = dat["key"]
                            if mykey not in ALL_ALLOC:
                                ALL_ALLOC[mykey] = dat

                        with open("/tmp/trace-allocator.json", "w") as fd:
                            fd.write(json.dumps(ALL_ALLOC))

                        proxy.settofrida_func("0", "hooktree_hit_all")

                elif in_symbol == "all-tree":
                    setup_hook(script, dick_sym, "zzall-tree", None)

                    proxy.settofrida_func("trace-func", "refresh")
                    print("==============")
                    print("[+] Trace ready.")

                    thnode = MyThreadGetHookCount(script)
                    thnode.start()

                    proxy.settofrida_openwindow("tracer", "by module")
                    break


                else:
                    while True:
                        in_fstalking = input(f"\n>> {in_module}> {in_symbol}> Stalking filter> ")

                        if in_fstalking == "back":
                            break

                        elif in_fstalking == "block":

                            if in_symbol.startswith("0x"):
                                dick_sym = []
                                dick = {
                                    "name": "unkown_"+in_symbol,
                                    "address": in_symbol,
                                    "type": "function"
                                }
                                dick_sym.append(dick)

                                script.exports_sync.setuphook(dick, "zsetup_block")
                            else:
                                setup_hook(script, dick_sym, in_symbol, "zsetup_block")

                        #jarang berguna, karena alamat hasil dari generate binaryninja
                        elif in_symbol.startswith("0x"):
                            arr_in = in_symbol.split(",")
                            dick_sym = []

                            for uaddr in arr_in:
                                dick = {
                                    "name": "unkown_"+uaddr,
                                    "address": uaddr,
                                    "type": "function"
                                }
                                dick_sym.append(dick)

                            setup_hook(script, dick_sym, None, None)
                        else:
                            setup_hook(script, dick_sym, in_symbol, in_fstalking)


        elif pshell == "tr-unity":
            while True:
                script.exports_sync.assemblylist();

                in_asm = input("\n>> tr-unity> Assembly> ")
                in_sw = input(f"\n>> build-in-trace/build-in-trace-param/custom-trace? bt/btp/ct: ")

                in_asm = "Assembly-CSharp" #DEBUG

                if in_asm == "dump-asm":
                    script.exports_sync.assemblydump();
                else:
                    script.exports_sync.assemblytrace(in_asm, in_sw);



        elif pshell == "tr-java":
            while True:
                in_class = input("\n>> Class> ")

                proxy.settofrida_func("refresh-java", "refresh")

                if in_class == "back":
                    break
                elif in_class == "all":
                    script.exports_sync.enumjavaclass("") #rawan crash

                elif in_class == "full-info":
                    in_info_class = input("\n>> Class> full-info>  ")

                else:
                    script.exports_sync.enumjavaclass(in_class)



        elif pshell == "sj":
            rsip = input(">> listen ip: ")
            rsport = input(">> listen port: ")
            script.exports_sync.reshelljava(rsip, rsport)

        elif pshell == "s":
            shell_cmd = input(">> Command shell (ls): ")
            script.exports_sync.shell(shell_cmd)

        elif pshell == "exit":
            loop_menu = False
            break
        else:
            print("[!] Unkown command.")

    session.on('detached', exiting)


if __name__ == "__main__":
    main()
