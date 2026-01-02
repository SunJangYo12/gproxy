#!/usr/bin/env python3

import frida
import sys
import os
import time
import datetime
from ctypes import *
import xmlrpc.client
import threading



proxy = xmlrpc.client.ServerProxy("http://127.0.0.1:1337", allow_none=True)

pwd = None

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

        elif message['payload']['type'] == 'enum_threads':
           print("[+] Send to binja...")
           threads = message['payload']['log']

           proxy.settofrida_enum(threads, "threads")
           print("[+] Done.")

        elif message['payload']['type'] == 'id_threads':
           threads = message['payload']['log']
           proxy.settofrida_enum(threads, "id_threads")


        elif message['payload']['type'] == 'stalker':
           sdata = message['payload']['log']
           proxy.settofrida_enum(sdata, "stalker")


        elif message['payload']['type'] == 'info':
           info = message['payload']['log']
           print(f"[+] {info}")


        elif message['payload']['type'] == 'hook_hit':
           info = message['payload']['log']
           #print(f"[+] Hit {info}")
           proxy.settofrida_func(info, False)


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

def setup_hook(script, dick_sym, func_target):
    #print(dick_sym)

    for data in dick_sym:
        if data.get("type") == "function":
            func_name = data.get("name")
            func_addr = data.get("address")

            if func_addr == "0x0":
                print(f"[!] warning: {func_name} is {func_addr}")
                continue

            print(f"[+] hook: {func_name} is {func_addr}")
            try:
                script.exports_sync.setuphook(func_name)
            except Exception as e:
                print(f"{func_name} >>>>>>> {e}")


class MyThread(threading.Thread):
    def __init__(self, script):
        super().__init__()
        self.stop_event = threading.Event()
        self.script = script

    def run(self):
        while not self.stop_event.is_set():
            self.script.exports_sync.idthreads()
            time.sleep(1)

    def stop(self):
        self.stop_event.set()


def main():
    print("\n\t=====================")
    print("\t Fuzzer proxy v2.0.0")
    print("\t=====================\n")
    target = input(">> Select target? Linux/Android (l/a): ")

    if target == "a":
       #ahost = input(">> Android host: ")
       #device = frida.get_device_manager().add_remote_device(ahost)
       device = frida.get_device_manager().add_remote_device("192.168.43.1")
    elif target == "l":
       device = frida.get_local_device() #local linux
    else:
       print("[!] PY target not found")
       exit(1)

    pid_raw = input(">> Chose pid? (1234): ")

    pid = int(pid_raw)
    session = device.attach(pid)

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
    print("1. shell/reverse_shell_java (s/js)")
    print("2. enum_module/enum_symbol/enum_thread (em/es/et)")
    print("3. trace (tr)> (back/all/<sym/addr>)")
    print("4. stalker (stl)> (back/<id>/window)")
    print("5. exit")

    loop_menu = True

    while loop_menu:
        pshell = input("\n>> ")

        if pshell == "em":
            script.exports_sync.enummodules()

        elif pshell == "es":
            module = input("\n>> Module> ")
            script.exports_sync.enumsymbols(module)

        elif pshell == "et":
            script.exports_sync.enumthreads()


        elif pshell == "stl":

            thread = MyThread(script)
            thread.start()

            tmpid = 0


            while True:
                in_id = input("\n>> Stalker> ")

                if in_id == "back":
                    print(f"[+] Exit stalker: {tmpid}")
                    thread.stop()
                    script.exports_sync.setstalker("exit", tmpid)
                    break
                elif in_id == "window":
                    proxy.settofrida_openwindow("stalker")

                else:
                    tmpid = int(in_id)
                    proxy.settofrida_openwindow("stalker", in_id)
                    script.exports_sync.setstalker("run", int(in_id))


        elif pshell == "tr":
            script.exports_sync.enummodules()
            in_module = input("\n>> Module> ")

            if in_module == "back":
                continue

            dick_sym = script.exports_sync.enumsymbolstrace(in_module)

            #init total symbol
            proxy.settofrida_func(dick_sym, True)

            in_symbol = input(f"\n>> Module> {in_module}> ")

            if in_symbol == "back":
                continue
            elif in_symbol == "all":
                setup_hook(script, dick_sym, None)
            #else:
            #    setup_hook(script, dick_sym, in_symbol)



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
