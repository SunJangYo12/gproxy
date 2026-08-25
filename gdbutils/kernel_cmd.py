import gdb
import struct

# This IPC hook, by vmlinuz-to-elf tools, Add to /tmp/funcs.txt
#0xffffffff810d1ff3 load_elf_binary
#0xffffffff81293c9f sock_sendmsg
#0xffffffff81293e7b sock_recvmsg
#0xffffffff8130d9e3 unix_stream_sendmsg
#0xffffffff8130e51f unix_stream_recvmsg
#0xffffffff810a317e pipe_write
#0xffffffff810a2def pipe_read

def hook_load_elf_binary(proxy=None):
    print(f"\tHOOK load_elf_binary")

    inf  = gdb.selected_inferior()
    rdi = gdb.parse_and_eval("$rdi").cast(gdb.lookup_type("unsigned long"))
    offset_filename = 0x0c8

    try:
        filename_ptr = struct.unpack('<Q', bytes(inf.read_memory(rdi+offset_filename, 0x8) ))[0]

        # read filename string
        raw = inf.read_memory(filename_ptr, 256).tobytes()
        filename = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
        print(f"\t\t{filename}")

        proxy.settogdb_addprocess(filename)

    except:
        print("-"*60)
        print("ERROR parsing")

        print(gdb.execute(f"x/10bx $rdi"))


# sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t len);

#(gdb) x/gx $rsi #msghdr *msg NOTE: x/gx addr intel endian
#0xffff8801388cfed0:	0xffff8801388cfe08 #pointer msg_name=sockaddr_un
#(gdb) x/h 0xffff8801388cfe08
#0xffff8801388cfe08:	0x0010 #1=AF_UNIX,2=AF_INET, 0x10/16 adalah ipc bukan socket
#(gdb) x/h 0xffff8801388cfe08+2
#0xffff8801388cfe0a:	0x0000 #harusnya isinya path kalau unix socket, 0 berarti netlink eg. "/run/user/100/bus" tapi kernel menyimpan alias sudah null jika udah connect

def hook_sock_sendmsg():
    return
    print(f"\tHOOK sock_sendmsg")




def hook_sys_sendto():
    print(f"\tHOOK sys_sendto")



def hook(func_addr, proxy=None):
    #print(f"\thook init.")

    if func_addr == "load_elf_binary":
        hook_load_elf_binary(proxy)

    elif func_addr == "sock_sendmsg":
        hook_sock_sendmsg()

    elif func_addr == "sys_sendto":
        hook_sys_sendto()






















# load_elf_binary(struct linux_binprm *bprm)
# tips mencari struktur binprm no symbol
# b *<load_elf_binary_addr>
# c
# (gdb) x/64bx $rdi
# 0x7f 0x45... adalah ELF alias alamat awal structur awal: char buf[256]

# how find filename struct
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

