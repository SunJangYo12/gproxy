import gdb

#(gdb) p a
#$1 = {<text variable, no debug info>} 0x401156 <a>
#(gdb) set $a = 0x401156
#(gdb) set $tramp = (void*) malloc(0x100)
#(gdb) call (int)mprotect((void*)((long)$tramp & ~0xfff), 0x1000, 7)

def build_tramp():
    a = int(gdb.parse_and_eval("$a"))
    tramp = int(gdb.parse_and_eval("$tramp"))

    total = 0
    cur = a


    while total < 12:
        out = gdb.execute(f"x/2i {cur}", to_string=True)
        lines = out.strip().split("\n")

        cur_addr = int(lines[0].split(":")[0].split()[0], 16)
        next_addr = int(lines[1].split(":")[0].split()[0], 16)

        size = next_addr - cur_addr
        total += size
        cur = next_addr

    print(f"[+] size = {total}")


    # copy
    for i in range(total):
        byte = gdb.execute(f"x/1bx {a+i}", to_string=True)
        val = int(byte.split(":")[1].strip(), 16)
        gdb.execute(f"set {{char}} ({tramp}+{i}) = {val}")

    print(f"[+] copy")


    ret = a + total

    # jmp back
    gdb.execute(f"set {{char}} ({tramp}+{total}) = 0x48")
    gdb.execute(f"set {{char}} ({tramp}+{total+1}) = 0xB8")
    gdb.execute(f"set {{long long}} ({tramp}+{total+2}) = {ret}")
    gdb.execute(f"set {{char}} ({tramp}+{total+10}) = 0xFF")
    gdb.execute(f"set {{char}} ({tramp}+{total+11}) = 0xE0")

    print(f"[+] trampoline ready → jump back to {hex(ret)}")

build_tramp()

