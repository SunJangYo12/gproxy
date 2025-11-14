import gdb
import xmlrpc.client


proxy = xmlrpc.client.ServerProxy("http://192.168.43.53:1337", allow_none=True)


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
            print("Color in: %s" % arg)
        except:
            print(proxy.setcolorblock(arg))




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
            rip = int(gdb.parse_and_eval("$rip"))
        except gdb.error:
            return

        if self.last_rip is None:
            self.last_rip = rip
            return

        if rip != self.last_rip:

            self.last_rip = rip
            print("current_pc=%#x" % self.last_rip)

            proxy.jump("%#x" % self.last_rip)


RegsCommand()
CommandVersion()
CommandJump()
CommandComment()
CommandColor()
CommandColorBlock()
StepSync()
