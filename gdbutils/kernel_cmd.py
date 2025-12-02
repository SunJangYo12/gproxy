import gdb
import struct

# load_elf_binary(struct linux_binprm *bprm)
#tips mencari struktur binprm no symbol
# b *<load_elf_binary_addr>
# c
# (gdb) x/64bx $rdi
# 0x7f 0x45... adalah ELF alias alamat awal structur awal: char buf[256]



#methology find filename struct
# b *0xffffffff810d1ff3
# cmd_dumpstruct $rdi
# reverse enginering for load_elf_binary() and source code kernel 3.3.5/include/linux/binfmts.h
# found kernel_read() pasti membaca file jadi structur *file ketemu
# lanjut mencocokan dibawahnya kalau int hasil cmd_dum.. adalah nilai kecil

def f_printLoadBinary():
    inf  = gdb.selected_inferior()

    address_load_elf_binary = "0xffffffff810d1ff3"
    gdb.execute(f"b *({address_load_elf_binary})")

    gdb.execute('c', False, True)
    #kernel 5.x with symbol
    #ret=gdb.execute('p *((struct linux_binprm*) $rdi)', False, True)
    #print(ret)
    #ret=gdb.execute('p ((struct linux_binprm*) $rdi)->filename', False, True)
    #filename = gdb.execute('p *(char**)($rdi+0x60)', False, True).split()[3]


    #kernel 3.3.5
    rdi = gdb.parse_and_eval("$rdi").cast(gdb.lookup_type("unsigned long"))
    offset_filename = 0x0c8

    try:
        filename_ptr = struct.unpack('<Q', bytes(inf.read_memory(rdi+offset_filename, 0x8) ))[0]

        # read filename string
        raw = inf.read_memory(filename_ptr, 256).tobytes()
        filename = raw.split(b"\x00", 1)[0].decode("ascii", "replace")

        print(filename)
    except:
        print("[!] error get process")

        print(gdb.execute(f"x/10bx $rdi"))




    gdb.execute("del")



def getListProcess():
    while True:
        f_printLoadBinary()

