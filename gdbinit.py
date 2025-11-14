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



class StepHello:
    """Plugin GDB: kirim 'hello' setiap kali RIP berubah (tiap instruksi step)."""

    def __init__(self):
        self.last_rip = None
        gdb.events.stop.connect(self.on_stop)
        print("[+] StepHello terpasang: akan kirim 'hello' tiap RIP berubah.")

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
StepHello()
