import gdb
import xmlrpc.client


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
            #rip = int(gdb.parse_and_eval("$rip"))
            rip = int(gdb.parse_and_eval("$eip"))
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
    def __init__(self, addr, func_name=None):
        super(TraceBreakpoint, self).__init__("*{}".format(addr),
                                              gdb.BP_BREAKPOINT,
                                              internal=False)
        self.silent = True            # tidak menampilkan pesan GDB default
        self.func_name = func_name

    def stop(self):

        # Print informasi
        if self.func_name:
            print(f"[TRACE] Hit {self.func_name}  => {self.location}")
        else:
            print(f"[TRACE] Hit {self.location}")

        # lanjutkan jalannya program
        return False     # False = auto-continue


class LoadTrace(gdb.Command):
    def __init__(self):
        super(LoadTrace, self).__init__("cmdbreaktrace", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        #path = arg.strip()
        if arg == "run":
            print("[+] starting traces..")

        elif arg == "generate":
            proc = proxy.setgeneratesymbol()
            if proc:
                print("[+] success generate symbol in /tmp/funcs.txt")
            else:
                print("[+] failed!")
            return

        else:
            print("Important: binaryninja harus di rebase mengikuti base address gdb")
            print("Usage: cmdbreaktrace generate <= generate function addr from binja")
            print("Usage: cmdbreaktrace run <= set breakpoint, then continue")
            return

        path = "/tmp/funcs.txt"

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
                    TraceBreakpoint(addr, name)

                    if name:
                        print(f"[+] Tracepoint at {addr} ({name})")
                    else:
                        print(f"[+] Tracepoint at {addr}")

        except Exception as e:
            print(f"Error: {e}")



RegsCommand()
CommandVersion()
CommandJump()
CommandComment()
CommandColor()
CommandColorBlock()
StepSync()
LoadTrace()
