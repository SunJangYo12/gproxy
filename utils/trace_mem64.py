import gdb

# ============================================================
# GLOBAL DATA. only 64bit program
# ============================================================

allocs = {}  # address -> size


# ============================================================
# LIST OF FUNCTIONS TO MONITOR
# ============================================================

ALLOC_FUNCS = {
    # glibc allocators
    "malloc": ("$rdi", "return"),
    "calloc": ("$rsi", "return"),     # calloc(n, size) → total size = n*size (langsung kita hitung)
    "realloc": ("$rsi", "return"),
    "posix_memalign": ("$rdx", "return"),
    "aligned_alloc": ("$rsi", "return"),

    # jemalloc / tcmalloc
    "je_malloc": ("$rdi", "return"),
    "tc_malloc": ("$rdi", "return"),
    "tc_calloc": ("$rsi", "return"),
    "tc_realloc": ("$rsi", "return"),

    # strdup family (allocates)
    "strdup": ("unknown", "return"),
    "strndup": ("$rsi", "return"),

    # asprintf (allocates)
    "asprintf": ("unknown", "return"),
    "vasprintf": ("unknown", "return"),

    # getline (may allocate)
    "getline": ("unknown", "return"),
    "getdelim": ("unknown", "return"),

    # mmap allocator
    "mmap": ("$rdx", "return"),     # size is 3rd arg
}

WRITE_FUNCS = {
    "read": ("$rsi", "$rdx"),            # buf, count
    "recv": ("$rsi", "$rdx"),
    "recvfrom": ("$rsi", "$rdx"),
    "recvmsg": ("$rdi", "unknown"),      # more complex struct
    "fread": ("$rdi", "$rdx"),           # ptr, size
    "readv": ("$rsi", "unknown"),

    # memory ops
    "memcpy": ("$rdi", "$rdx"),          # dest, n
    "memmove": ("$rdi", "$rdx"),
    "memset": ("$rdi", "$rdx"),
    "strcpy": ("$rdi", "unknown"),
    "strncpy": ("$rdi", "$rdx"),
    "strcat": ("$rdi", "unknown"),
    "strncat": ("$rdi", "$rdx"),

    # formatted output
    "sprintf": ("$rdi", "unknown"),
    "snprintf": ("$rdi", "$rdx"),

    # parsing → write to buffer
    "scanf": ("unknown", "unknown"),
    "sscanf": ("$rdi", "unknown"),
}

# ============================================================
# HELPERS
# ============================================================

def in_heap(buf):
    buf = int(buf)
    for addr, size in allocs.items():
        if addr <= buf < addr + size:
            return addr, size
    return None


# ============================================================
# ALLOC HANDLER
# ============================================================
class ReturnHandler(gdb.FinishBreakpoint):
    def __init__(self, size, funcname):
        super().__init__(gdb.newest_frame(), internal=True)
        self.size = size
        self.funcname = funcname
        self.silent = True

    def stop(self):
        addr = int(self.return_value)
        allocs[addr] = self.size

        #print(f"[ALLOC] {self.location} → addr={hex(addr)}, size={hex(self.size)}")
        print(f"[ALLOC] {self.funcname} → addr={hex(addr)}, size={hex(self.size)}")

        return False

class AllocBreakpoint(gdb.Breakpoint):
    def __init__(self, name, size_expr, ret):
        super().__init__(name, gdb.BP_BREAKPOINT, internal=False)
        self.size_expr = size_expr
        self.ret = ret
        self.funcname = name
        self.silent = True

    def stop(self):
        # evaluate size
        if self.size_expr == "unknown":
            return False

        size = int(gdb.parse_and_eval(self.size_expr))

        # execute until return to get address
        #gdb.execute("finish", to_string=True)
        ReturnHandler(size, self.funcname) #pengganti baris atas

        return False


# ============================================================
# WRITE HANDLER
# ============================================================

class WriteBreakpoint(gdb.Breakpoint):
    def __init__(self, name, buf_expr, size_expr):
        super().__init__(name, gdb.BP_BREAKPOINT, internal=False)
        self.buf_expr = buf_expr
        self.size_expr = size_expr
        self.silent = True

    def stop(self):
        try:
            buf = int(gdb.parse_and_eval(self.buf_expr))
        except:
            return False

        if self.size_expr == "unknown":
            size = -1
        else:
            size = int(gdb.parse_and_eval(self.size_expr))

        hit = in_heap(buf)
        if hit:
            addr, alloc_size = hit
            print(f"[HEAP WRITE] {self.location} → buf={hex(buf)}, write={size} bytes, heap={hex(addr)}(+{hex(alloc_size)})")

        return False


# ============================================================
# INSTALL BREAKPOINTS
# ============================================================

def install():
    print("[*] Installing allocator breakpoints...")
    for func, (size_expr, ret) in ALLOC_FUNCS.items():
        try:
            AllocBreakpoint(func, size_expr, ret)
            print("  +", func)
        except:
            print("  - failed to install %s" % func)
            pass

    print("\n\n[*] Installing write breakpoints...")
    for func, (buf_expr, size_expr) in WRITE_FUNCS.items():
        try:
            WriteBreakpoint(func, buf_expr, size_expr)
            print("  +", func)
        except:
            print("  - failed to install %s" % func)
            pass

    print("\n\n[+] Heap tracing ready.\n")


install()

