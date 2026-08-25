
# heap_trace.py
# GDB Python heap tracer: supports x86_64 and x86 (i386)
# Add/remove functions in ALLOC_FUNCS / WRITE_FUNCS as needed.

import gdb
import traceback
import re

# -------------------------
# Configuration
# -------------------------
LOG_TO_FILE = None   # e.g. "/tmp/heap_trace.log" or None
DETECT_OVERFLOW = False

# -------------------------
# Globals
# -------------------------
allocs = {}   # addr -> {"size": int or None, "caller": str, "alloc_fn": name}
arch = None   # "x86_64" or "i386"




# -------------------------
# Module range filter (optional)
# -------------------------
MODULE_FILTER = {
    "enabled": False,
    "start": 0x7743d000,      # explicit start address (hex or int) or None
    "end": 0x77449000,        # explicit end address or None
}

def in_module_range(addr):
    if not MODULE_FILTER.get("enabled"):
        return True
    if addr is None:
        return False
    s = MODULE_FILTER.get("start")
    e = MODULE_FILTER.get("end")
    if s is None or e is None:
        return False
    return (s <= addr < e)

def get_caller_pc():
    """Return caller return address (PC) from stack for current frame.
       Works for x86_64 and i386 based on `arch` global.
    """
    try:
        if arch == "x86_64":
            # return address is at ($rsp)
            return int(gdb.parse_and_eval("*(unsigned long*)($rsp)"))
        else:
            # i386: return address at ($esp)
            return int(gdb.parse_and_eval("*(unsigned int*)($esp)"))
    except Exception:
        # fallback: try $pc of previous frame
        try:
            f = gdb.newest_frame().older()
            if f:
                return int(f.pc())
        except Exception:
            pass
    return None

def get_module_from_addr(addr):
    """Return (module_name, base_addr) where addr resides, or (None, None)."""
    try:
       out = gdb.execute("info files", to_string=True)
       pat = re.compile(r'0x([0-9a-fA-F]+)\s*-\s*0x([0-9a-fA-F]+)\s+is\s+(.+)')

       for m in pat.finditer(out):
           start = int(m.group(1), 16)
           end   = int(m.group(2), 16)
           name  = m.group(3).strip()
           #print("%s: %s - %s (size: %d)" % (name, hex(start), hex(end), end-start))

           if start <= addr < end:
               # Nama file modul (misalnya "/usr/lib/libhello.so")
               #mod = obj.filename.split("/")[-1]
               try:
                   mod = name.split("target:")
                   mod = mod[1]
               except:
                   mod = "zzz"
               return mod, start

    except Exception:
        pass
    return None, None



# -------------------------
# Helper IO
# -------------------------
def log(msg):
    line = msg + "\n"
    print(msg)
    if LOG_TO_FILE:
        with open(LOG_TO_FILE, "a") as f:
            f.write(line)

# -------------------------
# Detect arch
# -------------------------
def detect_arch():
    global arch
    try:
        # Jika ada frame yang terpilih, ini biasanya mengembalikan string seperti "i386:x86-64"
        arch_name = None
        try:
            arch_name = gdb.selected_frame().architecture().name()
        except Exception:
            # fallback ke show architecture
            arch_name = gdb.execute("show architecture", to_string=True)

        s = arch_name.lower()
        if "x86-64" in s or "x86_64" in s or "amd64" in s:
            arch = "x86_64"
        elif "i386" in s or "ia32" in s or "elf32" in s:
            arch = "i386"
        else:
            arch = "x86_64"
    except Exception:
        arch = "x86_64"

# -------------------------
# Arg extraction helpers
# -------------------------
def reg_arg_x64(idx):
    regs = ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"]
    if idx < len(regs):
        return regs[idx]
    return None

def get_arg_value(func_arg_pos):
    """
    func_arg_pos: either a register name string like '$rsi'
                  or integer index (0-based) meaning nth argument
                  or expression string like '*(unsigned int*)($esp+8)'
    """
    try:
        # explicit expression
        if isinstance(func_arg_pos, str) and func_arg_pos.startswith("$"):
            return int(gdb.parse_and_eval(func_arg_pos))

        if isinstance(func_arg_pos, str):
            # treat as expression
            return int(gdb.parse_and_eval(func_arg_pos))

        if isinstance(func_arg_pos, int):
            # interpret as 0-based arg index
            idx = func_arg_pos
            if arch == "x86_64":
                reg = reg_arg_x64(idx)
                if reg:
                    return int(gdb.parse_and_eval(reg))
                else:
                    # arguments beyond 6 in x86_64 are on stack; access via $rsp + offset
                    # compute offset: return address on stack is at ($rsp), first stack arg at $rsp+8
                    # arg n (0-based) beyond regs -> offset = 8 + 8*(n-6)
                    offset = 8 + 8 * (idx - 6)
                    expr = "*(unsigned long*)($rsp + %d)" % offset
                    return int(gdb.parse_and_eval(expr))
            else:  # i386
                # stack: first arg at [esp+4]
                offset = 4 + 4 * idx
                expr = "*(unsigned int*)($esp + %d)" % offset
                return int(gdb.parse_and_eval(expr))
    except Exception as e:
        # can't evaluate arg (e.g., complex struct). Return None
        return None

# -------------------------
# in_heap check
# -------------------------
def in_heap(buf):
    if buf is None:
        return None
    for a, meta in allocs.items():
        sz = meta.get("size")
        if sz is None:
            # if size unknown: check exact pointer equality or treat as hit if same start
            if buf == a:
                return (a, sz, meta)
            continue
        if a <= buf < a + sz:
            return (a, sz, meta)
    return None

# -------------------------
# Utility to read return value after function finishes
# -------------------------
def get_return_reg():
    try:
        if arch == "x86_64":
            return int(gdb.parse_and_eval("$rax"))
        else:
            return int(gdb.parse_and_eval("$eax"))
    except Exception:
        return None

# -------------------------
# Define functions to monitor
# Format for each function:
#  ALLOC_FUNCS: name -> {"args": [arg_positions...], "compute_size": callable or None}
#  WRITE_FUNCS: name -> {"args": [buf_arg_index, size_arg_index], ...}
# arg positions: int (0-based) or explicit expression string (e.g. "*(unsigned int*)($esp+8)")
# compute_size: a function which given the evaluated args returns the allocation size
# -------------------------

def mul_args(args):
    try:
        return args[0] * args[1]
    except Exception:
        return None

ALLOC_FUNCS = {
    # glibc
    "malloc": {"args":[0], "compute_size": lambda args: args[0]},
    "calloc": {"args":[0,1], "compute_size": lambda args: (args[0] * args[1]) if args[0] is not None and args[1] is not None else None},
    "realloc": {"args":[0,1], "compute_size": lambda args: args[1]},
    "posix_memalign": {"args":[0,1,2], "compute_size": lambda args: args[2] if len(args)>2 else None},
    "aligned_alloc": {"args":[0,1], "compute_size": lambda args: args[1] if len(args)>1 else None},
    "memalign": {"args":[0,1], "compute_size": lambda args: args[1] if len(args)>1 else None},

    # common libc-like helpers that allocate (size unknown easily)
    "strdup": {"args":[0], "compute_size": None},
    "strndup": {"args":[0,1], "compute_size": None},
    "asprintf": {"args":[0,1], "compute_size": None},
    "vasprintf": {"args":[0,1], "compute_size": None},

    # getline - may allocate if *lineptr == NULL; we can't easily read that here reliably
    "getline": {"args":[0,1,2], "compute_size": None},

    # mmap: size is arg 2 in x86_64 (0-based idx=2), in i386 also index 2
    "mmap": {"args":[0,1,2,3,4,5], "compute_size": lambda args: args[2] if len(args)>2 else None},
    "mmap64": {"args":[0,1,2,3,4,5], "compute_size": lambda args: args[2] if len(args)>2 else None},
}

WRITE_FUNCS = {
    # read(fd, buf, count)
    "read": {"args":[0,1,2]},
    "recv": {"args":[0,1,2]},
    "recvfrom": {"args":[0,1,2,3,4]},
    "fread": {"args":[0,1,2,3]},  # ptr, size, nmemb, stream -> total bytes = size*nmemb
    "readv": {"args":[0,1,2]},
    # mem ops: memcpy(dest, src, n)
    "memcpy": {"args":[0,1,2]},
    "memmove": {"args":[0,1,2]},
    "memset": {"args":[0,1,2]},
    "strcpy": {"args":[0,1]},
    "strncpy": {"args":[0,1,2]},
    "strcat": {"args":[0,1]},
    "strncat": {"args":[0,1,2]},
    "sprintf": {"args":[0,1]},  # dest, fmt, ... size unknown
    "snprintf": {"args":[0,1,2]}, # dest, size, fmt, ...
    "sscanf": {"args":[0,1]}, # buffer read by sscanf? often parsing source -> less common to write to buffer
}

# -------------------------
# Breakpoint classes
# -------------------------
class ReturnHandler(gdb.FinishBreakpoint):
    def __init__(self, arg_vals, meta, funcname, caller_mod):
        super().__init__(gdb.newest_frame(), internal=True)
        self.arg_vals = arg_vals
        self.meta = meta
        self.funcname = funcname
        self.caller_mod = caller_mod
        self.silent = True

    def stop(self):
        #ret = int(self.return_value)
        #print(f"[RET] malloc({self.size}) = {hex(ret)}")

        ret = get_return_reg()
        size = None
        compute_fn = self.meta.get("compute_size")
        if compute_fn:
            try:
                size = compute_fn(self.arg_vals)
            except Exception:
                size = None
        # If we don't have size and function is strdup-like, try to compute via strlen on returned pointer
        if size is None and self.funcname in ("strdup", "strndup"):
            try:
                # attempt to compute strlen at runtime
                if ret:
                    s = int(gdb.parse_and_eval("strlen((char*)%d)" % ret))
                    # strdup size = strlen+1
                    size = s + 1
            except Exception:
                size = None

        # store allocation
        if ret and ret != 0:
            allocs[ret] = {"size": size, "caller": None, "alloc_fn": self.funcname}
            log("[ALLOC] %s -> addr=%s size=%s   caller=%s" % (self.funcname, hex(ret), (hex(size) if size else "unknown"), self.caller_mod ))

        return False

class AllocBreakpoint(gdb.Breakpoint):
    def __init__(self, funcname, meta):
        super().__init__(funcname, gdb.BP_BREAKPOINT, internal=False)
        self.funcname = funcname
        self.meta = meta
        self.silent = True

    def stop(self):
        try:
            caller = get_caller_pc()
            if not in_module_range(caller):
                return False

            caller_mod, caller_base = get_module_from_addr(caller)
            if caller_mod is None:
                caller_mod = "??"

            #log(f"[ALLOC] {self.funcname} called from {hex(caller)} in {caller_mod}")


            # read args before calling finish
            arg_vals = []
            for i, a in enumerate(self.meta.get("args", [])):
                if isinstance(a, str) and a.startswith("$"):
                    arg_vals.append(get_arg_value(a))
                else:
                    arg_vals.append(get_arg_value(i))
            # run until function returns to get return value
            # use "finish" to run the function and return to caller
            #gdb.execute("finish", to_string=True) # ERROR

            ReturnHandler(arg_vals, self.meta, self.funcname, caller_mod) #pengganti baris atas


        except Exception:
            # don't crash tracer
            log("[!] alloc handler error for %s\n%s" % (self.funcname, traceback.format_exc()))
        return False

class WriteBreakpoint(gdb.Breakpoint):
    def __init__(self, funcname, meta):
        super().__init__(funcname, gdb.BP_BREAKPOINT, internal=False)
        self.funcname = funcname
        self.meta = meta
        self.silent = True

    def stop(self):
        try:
            args_spec = self.meta.get("args", [])
            # get buffer arg (we assume first arg is destination for many functions)
            buf = get_arg_value(1) if self.funcname in ("memcpy","memmove") else None
            # generic attempt: choose arg 1 as buffer for typical functions (read: arg index 1)
            if buf is None:
                # default mapping: for read-like functions, buffer is arg index 1
                if len(args_spec) >= 2:
                    buf = get_arg_value(1)
                elif len(args_spec) >= 1:
                    buf = get_arg_value(0)

            # get size / count attempt
            size = None
            # heuristics for specific functions
            if self.funcname in ("read", "recv", "recvfrom"):
                size = get_arg_value(2)
            elif self.funcname == "fread":
                # fread(ptr, size, nmemb, stream)
                s = get_arg_value(1)
                nm = get_arg_value(2)
                if s is not None and nm is not None:
                    size = s * nm
            elif self.funcname in ("memcpy", "memmove"):
                size = get_arg_value(2)
            elif self.funcname == "memset":
                size = get_arg_value(2)
            elif self.funcname in ("strncpy", "strncat"):
                size = get_arg_value(2)
            elif self.funcname == "snprintf":
                size = get_arg_value(1)
            elif self.funcname == "sprintf":
                size = None  # unknown
            else:
                # fallback: try arg index 2 (third arg)
                if len(args_spec) > 2:
                    size = get_arg_value(2)

            hit = in_heap(buf)
            if hit:
                a, alloc_size, meta = hit
                # compute offset
                offset = buf - a
                # overflow detection
                overflow = False
                if alloc_size is not None and size is not None:
                    if offset + size > alloc_size:
                        overflow = True
                if DETECT_OVERFLOW and overflow:
                    log("[HEAP WRITE][OVERFLOW] %s -> buf=%s size=%s heap=%s(+%s) offset=%s" %
                        (self.funcname, hex(buf), str(size), hex(a), hex(alloc_size), hex(offset)))
                else:
                    log("[HEAP WRITE] %s -> buf=%s size=%s heap=%s(+%s) offset=%s" %
                        (self.funcname, hex(buf), (str(size) if size is not None else "unknown"), hex(a), (hex(alloc_size) if alloc_size else "unknown"), hex(offset)))
        except Exception:
            log("[!] write handler error for %s\n%s" % (self.funcname, traceback.format_exc()))
        return False

# -------------------------
# Install breakpoints
# -------------------------
def install_all():
    log("\n\n[*] Installing allocator breakpoints...")
    for fn, meta in ALLOC_FUNCS.items():
        try:
            AllocBreakpoint(fn, meta)
            log("  + %s" % fn)
        except Exception:
            log("  - failed to install %s" % fn)

    log("\n\n[*] Installing writer breakpoints...")
    for fn, meta in WRITE_FUNCS.items():
        try:
            WriteBreakpoint(fn, meta)
            log("  + %s" % fn)
        except Exception:
            log("  - failed to install %s" % fn)

    log("\n\n[+] Installation done. Tracing ready.")

#detect_arch()
#log("[*] Detected arch: %s" % arch)
#install_all()


