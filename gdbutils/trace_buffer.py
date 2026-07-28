import gdb
import struct

CMSG_DATA = 0
CMSG_HDR_SIZE = 12 # len, level, type = 12 di 64bit, 12 di 32bit

def parse_cmsg(inferior, cmsg_ptr, cmsg_len, is64):
    """Parse ancillary data. Yg paling penting: SCM_RIGHTS = kirim FD"""
    ptr_size = 8 if is64 else 4
    fmt_len = "<Q" if is64 else "<I"

    offset = 0
    while offset + CMSG_HDR_SIZE <= cmsg_len:
        cmsg_mem = inferior.read_memory(cmsg_ptr + offset, CMSG_HDR_SIZE).tobytes()
        cmsg_len_i, cmsg_level, cmsg_type = struct.unpack("<III", cmsg_mem[:12])

        if cmsg_len_i == 0 or cmsg_len_i > cmsg_len:
            break

        print(f"    -> level={cmsg_level} type={cmsg_type} len={cmsg_len_i}")

        # SCM_RIGHTS = 1. Artinya ada kirim File Descriptor
        if cmsg_level == 1 and cmsg_type == 1: # SOL_SOCKET, SCM_RIGHTS
            data_start = offset + CMSG_HDR_SIZE
            fd_count = (cmsg_len_i - CMSG_HDR_SIZE) // ptr_size
            fd_mem = inferior.read_memory(cmsg_ptr + data_start, fd_count * ptr_size).tobytes()
            fds = struct.unpack(f"<{fd_count}{fmt_len[1:]}", fd_mem)
            print(f" [!] DAPAT FD: {fds}") # <-- ini penting buat IPC

        offset += (cmsg_len_i + ptr_size - 1) & ~(ptr_size - 1) # align

def dump_buffer(inferior, addr, length, max_dump=256):
    """Dump buffer ke hex + ascii. Mirip x/100bx"""
    if addr == 0 or length == 0:
        print(" -> buf kosong")
        return

    length = min(length, max_dump) # batasi biar ga spam
    mem = inferior.read_memory(addr, length).tobytes()

    print(f" -> Dump {length} byte dari 0x{addr:x}:")
    for i in range(0, length, 16):
        chunk = mem[i:i+16]
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f" 0x{addr+i:08x}: {hex_part:<48} |{ascii_part}|")


def buffer_trace(func):
    if func == "recvmsg":
        inf = gdb.selected_inferior()
        frame = gdb.selected_frame()
        is64 = "x86-64" in frame.architecture().name()
        ptr_size = 8 if is64 else 4
        fmt = "<Q" if is64 else "<I"

        # Argumen
        if is64: sockfd, msg_addr = int(frame.read_register("rdi")), int(frame.read_register("rsi"))
        else:
            esp = int(frame.read_register("esp"))
            sockfd = struct.unpack("<I", inf.read_memory(esp+4,4).tobytes())[0]
            msg_addr = struct.unpack("<I", inf.read_memory(esp+8,4).tobytes())[0]

        # Baca struct msghdr 0x38 byte
        h = inf.read_memory(msg_addr, 0x38).tobytes()
        if is64:
            name, namelen = struct.unpack(fmt, h[0:8])[0], struct.unpack("<I", h[8:12])[0]
            iov, iovlen = struct.unpack(fmt, h[16:24])[0], struct.unpack(fmt, h[24:32])[0]
            control, controllen = struct.unpack(fmt, h[32:40])[0], struct.unpack(fmt, h[40:48])[0]
            flags = struct.unpack("<I", h[48:52])[0]
        else:
            name, namelen = struct.unpack(fmt, h[0:4])[0], struct.unpack(fmt, h[4:8])[0]
            iov, iovlen = struct.unpack(fmt, h[8:12])[0], struct.unpack(fmt, h[12:16])[0]
            control, controllen = struct.unpack(fmt, h[16:20])[0], struct.unpack(fmt, h[20:24])[0]
            flags = struct.unpack(fmt, h[24:28])[0]

        print(f" -> recvmsg fd={sockfd} msg=0x{msg_addr:x} iovlen={iovlen} ctrllen={controllen} flags=0x{flags:x}")

        # 1. Ekstrak buffer data dari iovec
        if iovlen > 0:
            iov0 = inf.read_memory(iov, ptr_size*2).tobytes()
            buf, length = struct.unpack(fmt, iov0[0:ptr_size])[0], struct.unpack(fmt, iov0[ptr_size:ptr_size*2])[0]
            print(f" -> iov_buf=0x{buf:x} len={length}")

            dump_buffer(inf, buf, length, max_dump=128) # dump 128 byte pertama aja

            #if length > 0:
            #    gdb.post_event(lambda: gdb.Breakpoint(f"*(char[{min(length,256)}]*){buf}", gdb.BP_WATCHPOINT))

        # 2. Ekstrak msg_control = Ancillary data
        if controllen >= 12 and control != 0:
            print(f" -> msg_control=0x{control:x} len={controllen}")
            parse_cmsg(inf, control, controllen, is64)

        # 3. Cek msg_flags penting
        flag_str = []
        if flags & 0x20: flag_str.append("MSG_TRUNC") # data kepotong
        if flags & 0x40: flag_str.append("MSG_CTRUNC") # control kepotong
        if flags & 0x01: flag_str.append("MSG_OOB")
        if flag_str:
            print(f" -> flags: {'|'.join(flag_str)}")

    elif func == "recv":
        buf_addr = None #self.inf.read_register("rsi") # arg2 recv di x64 = buffer
        length   = None #int(self.inf.read_register("rdx")) # arg3 = len
        esp = None

        for r in self.get_registers():
            val = gdb.parse_and_eval("$" + r)
            if r == "esp":
                esp = int(val)

        sockfd = self.inf.read_memory(esp + 4, 4).tobytes()
        print(sockfd)
        #sockfd = int(self.inf.read_memory(esp + 4, 4).tobytes(), 16) # arg1
        #buf_addr = int(self.inf.read_memory(esp + 8, 4).tobytes(), 16) # arg2
        #length = int(self.inf.read_memory(esp + 12, 4).tobytes(), 16) # arg3

        #print(f"[+] {self.func_name} caller. buf={buf_addr} len={length}")

        #print(f"[+] {self.func_name} called. buf=0x{int(buf_addr):x} len={length}")
        #    if r == "rdi":
        #        mem_content = self.inf.read_memory(val, 100).tobytes()
        #        print(f"trace: {r}={val}")
        #        print(mem_content)
        #        print("============")

