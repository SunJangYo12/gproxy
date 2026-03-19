import gdb
import struct

class InlineHook(gdb.Command):
    def __init__(self):
        super(InlineHook, self).__init__("hooka", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        # ambil alamat fungsi a
        a = int(gdb.parse_and_eval("&a"))
        print(f"[+] a @ {hex(a)}")


        # malloc
        hook = int(gdb.parse_and_eval("(void*)malloc(0x100)"))
        print(f"[+] hook @ {hex(hook)}")

        # mprotect RWX
        gdb.execute(f"call (int)mprotect((void*)({hook} & ~0xfff), 0x1000, 7)")

        # shellcode: write(1,"HOOK\n",5); ret
        shellcode = bytes([
            0x48,0xc7,0xc0,0x01,0x00,0x00,0x00,      # mov rax,1
            0x48,0xc7,0xc7,0x01,0x00,0x00,0x00,      # mov rdi,1
            0x48,0x8d,0x35,0x0a,0x00,0x00,0x00,      # lea rsi,[rip+0xa]
            0x48,0xc7,0xc2,0x05,0x00,0x00,0x00,      # mov rdx,5
            0x0f,0x05,                                # syscall
            0xc3                                       # ret
        ])
        msg = b"HOOK\n"


        # tulis shellcode
        inferior = gdb.selected_inferior()
        inferior.write_memory(hook, shellcode)
        inferior.write_memory(hook + len(shellcode), msg)
        print("[+] shellcode written")


        # patch a: mov rax, $hook; jmp rax
        patch = b"\x48\xB8" + struct.pack("<Q", hook) + b"\xFF\xE0"
        inferior.write_memory(a, patch)

        print("[+] patched a → hook")

# register command
InlineHook()

