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



    def make_handler(self, tramp, mydata):
        inferior = gdb.selected_inferior()

        # ====== malloc handler ======
        size = 0x200
        addr = int(gdb.parse_and_eval(f"(void*)malloc({size})"))
        gdb.execute(f"call (int)mprotect((void*)({addr} & ~0xfff), 0x1000, 7)")
        print(f"[+] handler @ {hex(addr)}")

        # ====== malloc logic (onEnter) ======
        logic = int(gdb.parse_and_eval("(void*)malloc(0x100)"))
        gdb.execute(f"call (int)mprotect((void*)({logic} & ~0xfff), 0x1000, 7)")
        print(f"[+] logic @ {hex(logic)}")

        # == write HOOK HIT==
        #sc = b""
        #sc += b"\x48\xC7\xC0\x01\x00\x00\x00"  # mov rax, 1 (write)
        #sc += b"\x48\xC7\xC7\x01\x00\x00\x00"  # mov rdi, 1 (stdout)
        #sc += b"\x48\x8D\x35\x0A\x00\x00\x00"  # lea rsi, [rip+0xa]
        #sc += b"\x48\xC7\xC2\x0E\x00\x00\x00"  # mov rdx, len
        #sc += b"\x0F\x05"                      # syscall
        #sc += b"\xC3"                          # ret
        #sc += b"HOOK HIT!\n"


        sc = b""
        sc += b"\x48\x8B\x77\x10"  # mov rsi, [rdi+0x10]
        sc += b"\x48\x8B\x57\x18"  # mov rdx, [rdi+0x18]
        sc += b"\x48\xC7\xC0\x01\x00\x00\x00" # mov rax, 1 (sys_write)
        sc += b"\x48\xC7\xC7\x01\x00\x00\x00" # mov rdi, 1 (stdout)
        sc += b"\x0F\x05" # syscall
        sc += b"\xC3" # ret
        inferior.write_memory(logic, sc)




        # ====== HANDLER ======
        handler = b""

        # --- SAVE ---
        handler += b"\x9C"                      # pushfq
        handler += b"\x50"                      # push rax
        handler += b"\x53"                      # push rbx
        handler += b"\x51"                      # push rcx
        handler += b"\x52"                      # push rdx
        handler += b"\x56"                      # push rsi
        handler += b"\x57"                      # push rdi
        handler += b"\x55"                      # push rbp
        handler += b"\x41\x50"                  # push r8
        handler += b"\x41\x51"                  # push r9
        handler += b"\x41\x52"                  # push r10
        handler += b"\x41\x53"                  # push r11

        handler += b"\x48\x83\xEC\x08"          # sub rsp, 8 (align)



        # --- CALL LOGIC ---
        handler += b"\x48\xBF" + struct.pack("<Q", mydata) # mov rdi, mydata
        handler += b"\x48\xB8" + struct.pack("<Q", logic)
        handler += b"\xFF\xD0"                  # call rax

        handler += b"\x48\x83\xC4\x08"          # add rsp, 8

        # --- RESTORE ---
        handler += b"\x41\x5B"                  # pop r11
        handler += b"\x41\x5A"                  # pop r10
        handler += b"\x41\x59"                  # pop r9
        handler += b"\x41\x58"                  # pop r8
        handler += b"\x5D"                      # pop rbp
        handler += b"\x5F"                      # pop rdi
        handler += b"\x5E"                      # pop rsi
        handler += b"\x5A"                      # pop rdx
        handler += b"\x59"                      # pop rcx
        handler += b"\x5B"                      # pop rbx
        handler += b"\x58"                      # pop rax
        handler += b"\x9D"                      # popfq

        # --- JMP TRAMPOLINE ---
        handler += b"\x48\xB8" + struct.pack("<Q", tramp)
        handler += b"\xFF\xE0"

        # write handler
        inferior.write_memory(addr, handler)

        print("[+] handler ready")

        return addr


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


        name = "[+] HIT "+name+"\n"
        mydata = self.mydata(inferior, 1, a, name.encode())


        handler = self.make_handler(tramp, mydata)

        hook_code = (
            b"\x48\xB8" + struct.pack("<Q", handler) +  # mov rax, handler
            b"\xFF\xE0"                                 # jmp rax
        )

        # malloc hook
        hook = int(gdb.parse_and_eval("(void*)malloc(0x100)"))
        gdb.execute(f"call (int)mprotect((void*)({hook} & ~0xfff), 0x1000, 7)")
        print(f"[+] hook @ {hex(hook)}")

        # tulis shellcode + string + jmp_tramp
        inferior.write_memory(hook, hook_code)
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
