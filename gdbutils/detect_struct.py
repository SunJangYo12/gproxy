
import gdb
import struct
import string

KERN_MIN = 0xffffffff80000000   # kernel mapping range
KERN_MAX = 0xffffffffffffffff
TEXT_MIN = 0xffffffff81000000   # approximate kernel .text
TEXT_MAX = 0xffffffffa2000000   # approx end of .text
MAX_LEN = 0x300

PRINTABLE = set(bytes(string.printable, 'ascii'))

def read(addr, size):
    inf = gdb.selected_inferior()
    return inf.read_memory(addr, size).tobytes()

def looks_ascii(buf):
    if not buf:
        return False
    return all(b in PRINTABLE for b in buf if b != 0)

def safe_read_cstring(addr, limit=256):
    try:
        data = read(addr, limit)
        s = data.split(b"\x00")[0]
        if 2 <= len(s) <= limit and looks_ascii(s):
            return s.decode("ascii", "ignore")
    except:
        pass
    return None

def looks_possible_refcount(v):
    return 0 < v < 0x1000

def looks_small_int(v):
    return 0 <= v < 4096

def looks_size_t_like(v):
    return (v > 4096) and not (KERN_MIN <= v <= KERN_MAX)

def looks_kernel_ptr(v):
    return KERN_MIN <= v <= KERN_MAX

def looks_func_ptr(v):
    return TEXT_MIN <= v <= TEXT_MAX

def looks_ops_table(v):
    return looks_kernel_ptr(v)


def runn(arg, in_gdb=True):
    #addr = int(gdb.parse_and_eval(arg))
    addr = gdb.parse_and_eval(arg).cast(gdb.lookup_type("unsigned long"))
    raw = read(addr, MAX_LEN)

    zzz = []

    if in_gdb:
        print(f"\n[+] Dumping unknown struct at {hex(addr)}")
        print("-" * 70)

    for off in range(0, MAX_LEN, 8):
        chunk = raw[off:off+8]
        if len(chunk) < 8:
            break

        val = struct.unpack("<Q", chunk)[0]

        tags = []

        # --- pointer heuristics ---
        if looks_kernel_ptr(val):
            tags.append("PTR(kernel)")
        if looks_func_ptr(val):
            tags.append("FUNC?")
        if looks_ops_table(val):
            tags.append("OPS?")

        # --- cstring heuristics ---
        if looks_kernel_ptr(val):
            s = safe_read_cstring(val)
            if s:
                tags.append(f"STR=\"{s}\"")

        # --- numeric heuristics ---
        if looks_small_int(val):
            tags.append("small-int")
        if looks_possible_refcount(val):
            tags.append("refcount?")
        if looks_size_t_like(val):
            tags.append("size_t?")

        tag_str = ""
        if tags:
            tag_str = "   <" + ", ".join(tags) + ">"

        if in_gdb:
            print(f"+0x{off:03x}: 0x{val:016x}{tag_str}")
        else:
            zzz.append(f"+0x{off:03x}===0x{val:016x}==={tag_str}\n")

    return "".join(zzz)


class DumpStruct(gdb.Command):
    def __init__(self):
        super(DumpStruct, self).__init__("cmd_dumpstruct", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        #print("cmd_dumpstruct <addr> — heuristik otomatis isi struktur kernel. ex cmd_dumpstruct $rdi")
        runn(arg)

def install_all():
    DumpStruct()


