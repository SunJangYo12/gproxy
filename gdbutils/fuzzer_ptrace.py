import gdb
import re

def get_registers():
    print("\n[+] Get snapshot register")
    out = gdb.execute("info registers", to_string=True)
    regs = []
    #regex ambil nama reg di awal baris
    for line in out.splitlines():
       m = re.match(r"^([a-zA-Z0-9]+)\s+", line)
       if m:
           val = gdb.parse_and_eval("$" + m.group(1))
           xx = {
               "key": m.group(1),
               "value": hex(val)
           }
           regs.append(xx)
    return regs



def set_dynamic_breakpoints():
    print("\n[+] Set dynamic breakpoints")
    gdb.execute("break check_two", to_string=False)
    gdb.execute("break check_three", to_string=False)



def create_snapshot():
    print("\n[+] Create snapshot")
    create_snapshot = gdb.execute("x create_snapshot", to_string=True).split(" ")[0]

    gdb.execute("set $snapshot = (int*(*)())%s" % create_snapshot, to_string=True)

    gdb.execute("call $snapshot()")



def restore_snapshot(pid, buffer):
    print("\n[+] Restore snapshot")
    restore = gdb.execute("x restore_snapshot", to_string=True).split(" ")[0]

    gdb.execute("set $restore = (long*(*)(int, unsigned char *))%s" %restore)
    gdb.execute("call $restore(%s, %s)"% (pid, buffer))


def start_fuzz(arg):

    #set_dynamic_breakpoints()

    #snapshot_buf = create_snapshot()

    #snapshot_registers = get_registers()

    arg = arg.split(" ")

    if arg[0] == "snapshot":
        create_snapshot()

    elif arg[0] == "restore":
        restore_snapshot(arg[1], arg[2])
    else:
        print(gdb.execute("break check_one", to_string=True))
        print(gdb.execute("run", to_string=True))










