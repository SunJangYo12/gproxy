import gdb
import xmlrpc.client
import base64
import re

import sys,os

MYFILE = os.path.abspath(os.path.expanduser(__file__))
if os.path.islink(MYFILE):
    MYFILE = os.readlink(MYFILE)
sys.path.insert(0, os.path.dirname(MYFILE) + "/gdbutils")


import trace_memory
import kernel_cmd
import detect_struct

proxy = xmlrpc.client.ServerProxy("http://127.0.0.1:1337", allow_none=True)


class RegsCommand(gdb.Command):
    """Menampilkan register dan alamat instruksi."""

    def __init__(self):
        super(RegsCommand, self).__init__("regs", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        rip = gdb.parse_and_eval("$rip")
        rsp = gdb.parse_and_eval("$rsp")
        print(f"RIP = {rip}, RSP = {rsp}")


class CommandVersion(gdb.Command):
    """Menampilkan versi binaryninja."""

    def __init__(self):
        super(CommandVersion, self).__init__("cmdversion", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        versi = proxy.version()
        print(versi)

class CommandJump(gdb.Command):
    """Jump to address"""

    def __init__(self):
        super(CommandJump, self).__init__("cmdjump", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        print("jump to: %s" % arg)
        proxy.jump("%s" % arg)


class CommandComment(gdb.Command):
    """ makecomm(int addr, string comment) => None
        Add a comment at the location `address`.
        Example: cmdcomment 0x40000 "Important call here!"
    """
    def __init__(self):
        super(CommandComment, self).__init__("cmdcomment", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        #BUG
        try:
            raw_arg = arg.split(" ")
            addr = raw_arg[0]
            comm = raw_arg[1]

            proxy.makecomm(addr, comm)
            print("Comment in: %s" % arg)
        except:
            print("ERR Usage: cmdcomment 0x1234 zzz")


class CommandColor(gdb.Command):
    """ setcolor(int addr [, int color]) => None
        Set the location pointed by `address` with `color`.
        Example:  cmdcolor 0x40000 0xff0000
    """
    def __init__(self):
        super(CommandColor, self).__init__("cmdcolor", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):

        try:
            raw_arg = arg.split(" ")
            addr = raw_arg[0]
            color = raw_arg[1]

            result = proxy.setcolor(addr, color)
            print(result)
            print("Color in: %s" % arg)
        except:
            print(proxy.setcolor(arg))


class CommandColorBlock(gdb.Command):
    def __init__(self):
        super(CommandColorBlock, self).__init__("cmdcolorblock", gdb.COMMAND_USER)

        # def color: cmdcolorblock
        # custom : cmdcolorblock $pc 0xffaa00aa => blue

    def invoke(self, arg, from_tty):

        try:
            raw_arg = arg.split(" ")
            addr = raw_arg[0]
            color = raw_arg[1]

            result = proxy.setcolorblock(addr, color)
            print(result)
        except:
            #rip = int(gdb.parse_and_eval("$rip"))
            rip = int(gdb.parse_and_eval("$eip"))
            rip = str(hex(rip))

            print(proxy.setcolorblock(rip))




class StepSync:
    """Plugin GDB: kirim 'hello' setiap kali RIP berubah (tiap instruksi step)."""

    def __init__(self):
        self.last_rip = None
        gdb.events.stop.connect(self.on_stop)
        print("\n")
        print("    G-proxy v.0.1")
        print("\n")

    def on_stop(self, event):
        try:
            rip = int(gdb.parse_and_eval("$pc"))
        except gdb.error:
            return

        if self.last_rip is None:
            self.last_rip = rip
            return

        if rip != self.last_rip:

            self.last_rip = rip
            print("current_pc=%#x" % self.last_rip)

            proxy.jump("%#x" % self.last_rip)


class TraceBreakpoint(gdb.Breakpoint):
    def __init__(self, addr, func_name=None, bn=None, hook=None, bb=False):
        super(TraceBreakpoint, self).__init__("*{}".format(addr),
                                              gdb.BP_BREAKPOINT,
                                              internal=False)
        self.silent = True            # tidak menampilkan pesan GDB default
        self.func_name = func_name
        self.addr = addr
        self.bn = bn
        self.hook = hook

        if bb:
            proxy.set_global("")


    def get_registers(self):
        out = gdb.execute("info registers", to_string=True)
        regs = []

        # regex ambil nama reg di awal baris
        for line in out.splitlines():
            m = re.match(r"^([a-zA-Z0-9]+)\s+", line)
            if m:
                regs.append(m.group(1))
        return regs

    def collect_registers(self):
        result = []
        for r in self.get_registers():
            val = gdb.parse_and_eval("$" + r)
            result.append(f"{r}={val}\n")

        return "".join(result)

    def collect_structure(self, arg):
        aa =  detect_struct.runn(arg, in_gdb=False)
        return aa


    def stop(self):
        gdb_memregs = ""
        gdb_memstruct = ""
        gdb_stop = False

        # Comment ini jika ingin lebih cepat
        cek_global = proxy.cekgdb_global().split("T_T")

        # update breakpoint with basicblock func
        try:
            if cek_global[3] == "pause":
                gdb_stop = True
        except:
            pass

        # Dynamic hook for monitoring data
        if cek_global[0] == self.func_name or cek_global[0] == self.addr:
            gdb_memregs = self.collect_registers()

            try:
                gdb_memstruct = self.collect_structure(cek_global[1])
            except:
                pass

            try:
                if cek_global[2] == "pause":
                    gdb_stop = True
            except:
                pass


        if self.func_name:
            print(f"[TRACE] Hit {self.func_name}  => {self.addr}")

            if self.bn:
                output = f"{self.addr}|||{self.func_name}T_T{gdb_memregs}T_T{gdb_memstruct}"
                output = base64.b64encode(output.encode()).decode()
                proxy.settogdb(output)

            # Custom hook
            if self.hook:
                kernel_cmd.hook(self.func_name, proxy)

        else:
            print(f"[TRACE] Hit {self.addr}")

            if self.bn:
                proxy.settogdb(self.addr)

            if self.hook:
                kernel_cmd.hook(self.addr)


        # False lanjutkan jalannya program
        return gdb_stop


class LoadTrace(gdb.Command):
    def __init__(self):
        super(LoadTrace, self).__init__("cmdtracefunc", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        #path = arg.strip()
        bn = False
        hook = False
        bblock = False

        if arg == "run":
            print("[+] starting traces..")

        elif arg == "run-bn":
            print("[+] starting traces..")
            bn = True

        elif arg == "run-bn-block":
            print("[+] starting traces..")
            bn = True
            bblock = True

        elif arg == "run-bn-hookIPC":
            print("[+] starting traces..")
            bn = True
            hook = True

        elif arg == "generate":
            proc = proxy.setgeneratesymbol()
            if proc:
                print("[+] success generate symbol in /tmp/funcs.txt")
            else:
                print("[+] failed!")
            return

        else:
            print("\nImportant: binaryninja harus di rebase mengikuti base address gdb")
            print("Usage: cmdtracefunc generate <= generate function addr from binja")
            print("Usage: cmdtracefunc run <= setup breakpoint, continue for start")
            print("Usage: cmdtracefunc run-bn")
            print("          setup breakpoint, continue for start, with send to binaryninja")

            print("Usage: cmdtracefunc run-bn-block")
            print("          setup breakpoint, continue for start, with send to binaryninja")
            print("          this tracing basic block form func by generate in bn block view")

            print("Usage: cmdtracefunc run-bn-hookIPC")
            print("          setup breakpoint, continue for start, with send to binaryninja")
            print("          Trace function with custom hook by custom /tmp/funcs.txt")
            print("          Hook ini melakukan trace fungsi IPC dan list proses di awal kernel boot")
            print("\n")
            return

        path = "/tmp/funcs.txt"
        if bblock:
            path = "/tmp/blocks.txt"


        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split()
                    addr = parts[0]
                    name = parts[1] if len(parts) > 1 else None

                    # Pasang trace-breakpoint
                    if bblock:
                        TraceBreakpoint(addr, name, bn, hook, bb=True)
                    else:
                        TraceBreakpoint(addr, name, bn, hook)

                    if name:
                        print(f"[+] Tracepoint at {addr} ({name})")
                    else:
                        print(f"[+] Tracepoint at {addr}")

        except Exception as e:
            print(f"Error: {e}")


class LoadTraceMemory(gdb.Command):
    def __init__(self):
        super(LoadTraceMemory, self).__init__("cmdtracememory", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if arg == "run":
            trace_memory.detect_arch()
            trace_memory.log("[*] Detected arch: %s" % trace_memory.arch)
            trace_memory.install_all()
        else:
            print("usage: cmdtracememory run")


class KernelProcList(gdb.Command):
    def __init__(self):
        super(KernelProcList, self).__init__("cmdkernelproclist", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if arg == "run":
            kernel_cmd.getListProcess()
        else:
            print("\nusage: cmdkernelproclist run\n")


RegsCommand()
CommandVersion()
CommandJump()
CommandComment()
CommandColor()
CommandColorBlock()
StepSync()
LoadTrace()
LoadTraceMemory()
KernelProcList()
detect_struct.install_all()
