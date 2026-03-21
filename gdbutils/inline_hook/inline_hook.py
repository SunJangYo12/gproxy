import gdb
import struct
import re

def parse_addr(line):
    m = re.match(r'\s*(0x[0-9a-fA-F]+)', line)
    if not m:
        raise Exception(f"Parse error: {line}")
    return int(m.group(1), 16)

class InlineHook(gdb.Command):
    def __init__(self):
        super(InlineHook, self).__init__("hooka", gdb.COMMAND_USER)

    def calc_size(self, a, min_size=12):
        total = 0
        cur = a

        print("[+] calculating instruction size...")

        while total < min_size:
            out = gdb.execute(f"x/2i {cur}", to_string=True)
            lines = out.strip().split("\n")

            if "rip+" in lines[0]:
                print("[!] ERROR: rip-relative detected, stop copy")
                total = -1
                break

            cur_addr = parse_addr(lines[0])
            next_addr = parse_addr(lines[1])

            size = next_addr - cur_addr
            print(f"  {lines[0].strip()} (size={size})")
            total += size
            cur = next_addr

        print(f"[+] total size = {total}")
        return total

    def make_handler(self):
        inferior = gdb.selected_inferior()

        # ====== malloc ======
        size = 0x100
        addr = int(gdb.parse_and_eval(f"(void*)malloc({size})"))
        gdb.execute(f"call (int)mprotect((void*)({addr} & ~0xfff), 0x1000, 7)")
        print(f"[+] shellcode @ {hex(addr)}")

        # ====== SHELLCODE ======
        sc = b""
        # rdi = meta (dipass dari hook)
        sc += b"\x48\x8B\x77\x10"              # mov rsi, [rdi+0x10]  ; string_ptr
        sc += b"\x48\x8B\x57\x18"              # mov rdx, [rdi+0x18]  ; string_len
        sc += b"\x48\xC7\xC0\x01\x00\x00\x00"  # mov rax, 1 (write)
        sc += b"\x48\xC7\xC7\x01\x00\x00\x00"  # mov rdi, 1 (stdout)
        sc += b"\x0F\x05"                      # syscall
        sc += b"\xC3"                          # ret

        # write shellcode
        inferior.write_memory(addr, sc)

        print("[+] ready to call")

        # expose ke gdb
        gdb.execute(f"set $my_handler = (void*){addr}")



    def mydata(self, inferior, id, a, func_name):
        meta = int(gdb.parse_and_eval("(void*)malloc(0x20)"))
        gdb.execute(f"call (int)mprotect((void*)({meta} & ~0xfff), 0x1000, 7)")

        print(f"[+] mydata @ {hex(meta)}")

        # alloc string
        str_addr = int(gdb.parse_and_eval(f"(void*)malloc({len(func_name)})"))
        inferior.write_memory(str_addr, func_name)

        print(f"[+] string @ {hex(str_addr)}")

        # isi struct
        inferior.write_memory(meta + 0x00, struct.pack("<Q", id))
        inferior.write_memory(meta + 0x08, struct.pack("<Q", a))
        inferior.write_memory(meta + 0x10, struct.pack("<Q", str_addr))  # pointer
        inferior.write_memory(meta + 0x18, struct.pack("<Q", len(func_name)))  # length

        return meta


    def processing(self, arg, name):
        inferior = gdb.selected_inferior()

        # ambil alamat fungsi
        a = int(f"{arg}", 0)
        print(f"\n[+] target @ {name}")

        # hitung size instruksi
        size = self.calc_size(a)
        if size == -1:
            return

        # malloc tramp
        tramp = int(gdb.parse_and_eval("(void*)malloc(0x100)"))
        gdb.execute(f"call (int)mprotect((void*)({tramp} & ~0xfff), 0x1000, 7)")
        print(f"[+] tramp @ {hex(tramp)}")

        # COPY INSTRUKSI ASLI
        original = inferior.read_memory(a, size)
        inferior.write_memory(tramp, original)

        # tambah jmp balik ke a+size
        ret = a + size
        jmp_back = b"\x48\xB8" + struct.pack("<Q", ret) + b"\xFF\xE0"
        inferior.write_memory(tramp + size, jmp_back)
        print(f"[+] trampoline ready → {hex(ret)}")



        # malloc hook
        hook = int(gdb.parse_and_eval("(void*)malloc(0x100)"))
        gdb.execute(f"call (int)mprotect((void*)({hook} & ~0xfff), 0x1000, 7)")
        print(f"[+] hook @ {hex(hook)}")

        name = "[+] HIT "+name+"\n"
        mydata = self.mydata(inferior, 1, a, name.encode())

        self.make_handler()
        handler = int(gdb.parse_and_eval("$my_handler"))

        hook_code = (
            b"\x48\xBF" + struct.pack("<Q", mydata) +   # mov rdi, mydata
            b"\x48\xB8" + struct.pack("<Q", handler) +  # mov rax, handler
            b"\xFF\xD0" +                               # call rax
            b"\x48\xB8" + struct.pack("<Q", tramp) +    # mov rax, tramp
            b"\xFF\xE0"                                 # jmp rax
        )


        jmp_tramp = b"\x48\xB8" + struct.pack("<Q", tramp) + b"\xFF\xE0"

        # tulis shellcode + string + jmp_tramp
        inferior.write_memory(hook, hook_code)
        inferior.write_memory(hook + len(hook_code), jmp_tramp)

        print(f"[+] hook ready")



        # =========================
        # patch fungsi a
        # =========================
        patch = b"\x48\xB8" + struct.pack("<Q", hook) + b"\xFF\xE0"
        inferior.write_memory(a, patch)

        print("[+] patched a → hook")


    def invoke(self, arg, from_tty):
        base = int(arg, 0)

        with open("/tmp/funcs.txt") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                parts = line.split()
                addr = hex(base + int(parts[0], 0) )
                #addr = parts[0]
                name = parts[1] if len(parts) > 1 else None

                #print(f"{name} : {addr}")
                self.processing(addr, name)




# register
InlineHook()
