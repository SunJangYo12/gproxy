


#1. Copy instruksi awal fungsi a sampai minimal 12 byte ke trampoline (tanpa memotong instruksi)
#2. Patch awal fungsi a dengan jump ke hook
#3. Saat fungsi a dipanggil:
#   → eksekusi dialihkan ke hook
#   → hook menjalankan shellcode (misalnya print)
#   → lalu lompat ke trampoline
#4. Trampoline:
#   → menjalankan instruksi asli yang tadi dicopy
#   → lalu lompat ke a + size
#   → sehingga fungsi a lanjut normal


#=============
# USAGE:
#(gdb) source ~/.binaryninja/plugins/gproxy/gdbutils/inline_hook/inline_hook.py
#(gdb) scgen
#[+] shellcode @ 0x7ffff7fc9000
#[+] buffer @ 0x7ffff7fc9080
#[+] ready to call
#(gdb) set $sc = 0x7ffff7fc9000
#(gdb) call (void(*)())$sc()
#HELLO
#$4 = (void (*)()) 0x7
#(gdb) set $my_handler = $sc
#(gdb) hooka
#(gdb) c
#Continuing.
#HELLO
#Function A
#HELLO


import gdb
import struct
import re

def parse_addr(line):
    m = re.match(r'\s*(0x[0-9a-fA-F]+)', line)
    if not m:
        raise Exception(f"Parse error: {line}")
    return int(m.group(1), 16)


class ShellcodeGen(gdb.Command):
    def __init__(self):
        super(ShellcodeGen, self).__init__("scgen", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        inferior = gdb.selected_inferior()

        # ====== STRING ======
        msg = b"HELLO\n\x00"

        # ====== malloc ======
        size = 0x100
        addr = int(gdb.parse_and_eval(f"(void*)malloc({size})"))

        # RWX
        gdb.execute(f"call (int)mprotect((void*)({addr} & ~0xfff), 0x1000, 7)")

        print(f"[+] shellcode @ {hex(addr)}")

        # buffer string
        buf_addr = addr + 0x80
        inferior.write_memory(buf_addr, msg)

        # ====== SHELLCODE ======
        sc = b""

        # write(1, buf, len)
        sc += b"\x48\xC7\xC0\x01\x00\x00\x00"          # mov rax, 1
        sc += b"\x48\xC7\xC7\x01\x00\x00\x00"          # mov rdi, 1
        sc += b"\x48\xBE" + struct.pack("<Q", buf_addr)  # mov rsi, buf
        sc += b"\x48\xC7\xC2" + struct.pack("<I", len(msg))  # mov rdx, len
        sc += b"\x0F\x05"                              # syscall
        sc += b"\xC3"                                  # ret

        # write shellcode
        inferior.write_memory(addr, sc)

        print(f"[+] buffer @ {hex(buf_addr)}")
        print("[+] ready to call")

        # expose ke gdb
        gdb.execute(f"set $sc = (void*){addr}")




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

            cur_addr = parse_addr(lines[0])
            next_addr = parse_addr(lines[1])

            size = next_addr - cur_addr
            #print(f"  {lines[0].strip()} (size={size})")
            total += size
            cur = next_addr

        print(f"[+] total size = {total}")
        return total


    def invoke(self, arg, from_tty):
        inferior = gdb.selected_inferior()

        # ambil alamat fungsi a
        a = int(gdb.parse_and_eval("&a"))
        print(f"[+] a @ {hex(a)}")

        # hitung size instruksi
        size = self.calc_size(a)

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

        handler = int(gdb.parse_and_eval("$my_handler"))

        hook_code = (
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

# register
InlineHook()
ShellcodeGen()
