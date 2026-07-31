import gdb
import struct
import traceback
import json

def dump_buffer(inferior, addr, length, max_dump=256):
    """Dump buffer ke hex + ascii. Mirip x/100bx"""
    if addr == 0 or length == 0:
        print(" -> buf kosong")
        return

    length = min(length, max_dump) # batasi biar ga spam
    mem = inferior.read_memory(addr, length).tobytes()
    for i in range(0, length, 16):
        chunk = mem[i:i+16]
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"0x{addr+i:08x}: {hex_part:<48} |{ascii_part}|")

TYPE_MAP = {
    "int32-4":   0x08, # 4-byte
    "int32":     0x09, # 1-byte
    "int64":     0x10,
    "ipv6":      0x18,  # 1-byte
    "string":    0x20,  # 2-byte len
    "string-1":  0x21,  # 1-byte len
    "message":   0x28,
    "raw":       0x30,
    "bool[]":    0x80,
    "int32[]":   0x88,
    "int64[]":   0x90,
    "string[]":  0xa0,
    "ipv6[]":    0x98,
    "message[]": 0xa8,
    "raw[]":     0xb0
}

def parse_m2_attribute(data):
    out = []
    offset = 6
    while offset < len(data):
        output = None

        cek_id = data[offset:offset+2]

        if cek_id == "0xff" or cek_id == "0xfe":
            id = hex(int.from_bytes(data[offset:offset+3], "little"))
            type = data[offset+3:offset+4]
            type = int.from_bytes(type, "little")
        else:
            id = data[offset:offset+3]
            id = hex(int.from_bytes(id, "little"))
            type = data[offset+3:offset+4]
            type = int.from_bytes(type, "little")


        if type == 0x1 or type == 0x0:
            output = type
            type = f"{hex(type)} bool"
            offset += 4  # 4 = id(3) + val(1) byte

        elif type == TYPE_MAP["ipv6"]:
            type = f"{hex(type)} ipv6"
            output = data[offset+4:offset+20]
            output = f"{output} => {hex(int.from_bytes(output, 'little'))}"
            offset += 20

        elif type == TYPE_MAP["string-1"]:
            slen = data[offset+4:offset+5]
            slen = int.from_bytes(slen, "little")
            output = data[offset+5:offset+5+slen]
            output = f"{output} => {hex(int.from_bytes(output, 'little'))}"
            type = f"{hex(type)} string len(1-byte) slen: {hex(slen)}({slen})"
            offset += 5+slen  # 5 = id(3) + type(1) + size(1)

        elif type == TYPE_MAP["message[]"]:
            type = f"{hex(type)} message[]"
            key = data[offset+4:offset+7]
            output = f"{key} TODO"
            offset += 45

        elif type == TYPE_MAP["int32[]"]:
            type = f"{hex(type)} u32-ARRAY"
            arrlen = data[offset+4:offset+6]
            arrlen = int.from_bytes(arrlen, "little")

            arr_out = []
            sdata = offset + 6
            tcount = 4 * arrlen     #type count

            b = data[sdata:sdata+tcount]
            for i in range(0, len(b), 4):
                val = b[i:i+4]
                val = f"{val} => {hex(int.from_bytes(val, 'little'))}"
                arr_out.append(val)
            output = arr_out
            offset += tcount + 6  # 6 = id(3) + tipe(1) + len(2) byte

        elif type == TYPE_MAP["int32-4"]:
            type = f"{hex(type)} u32 4-byte"
            output = data[offset+4:offset+8]
            output = f"{output} => {hex(int.from_bytes(output, 'little'))}"
            offset += 8  # 8 = id(3) + tipe(1) + val(4)

        elif type == TYPE_MAP["int32"]:
            type = f"{hex(type)} u32"
            offset += 5 # 5 = id(3) + tipe(1) + val(1)
            output = data[offset-1:offset]
            output = f"{output} => {hex(int.from_bytes(output, 'little'))}"
        else:
            output = "Parse M2 failed, please cek again!"
            print("Parse M2 failed, please cek again!")
            break

        out.append({
            "id": id,
            "type": type,
            "value": output
        })
        type = None
        id = None
    return out

def parse_m2_packet(data, buf_addr):
    if len(data) < 6:
        print(" -> Data terlalu pendek < 6 byte")
        return

    attr_M2 = {}
    pkt_len = data[0]
    sec_mode = data[1]
    total_len = struct.unpack("<H", data[2:4])[0] # 2 bytes LE
    magic = data[4:6]

    attr_M2["packet_length"] = pkt_len
    attr_M2["security_mode"] = sec_mode
    attr_M2["msg_length"]    = total_len
    attr_M2["magic"]         = magic.hex()

    print(f" -> M2 PACKET HEADER => {hex(buf_addr)}")
    print(f" Packet Length    : 0x{pkt_len:02x} ({pkt_len})")
    print(f" Security Mode    : 0x{sec_mode:02x} ({sec_mode})")
    print(f" Total Msg Length : 0x{total_len:04x} ({total_len})")
    print(f" Magic            : {magic} = 0x{magic.hex()}")

    # Dump attribute
    if magic == b"M2":
        try:
            m2_data = parse_m2_attribute(data[0:pkt_len+50])
            attr_M2["m2_data"] = m2_data

            for i in m2_data:
                print(i)
        except Exception as e:
            traceback.print_exc()
    else:
        attr_M2["m2_data"] = "Not M2 packet"
        print("Not M2 packet")

    # Dump hex + ascii
    outdump = []
    for i in range(0, pkt_len+50, 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f" 0x{i:04x}: {hex_part:<48} |{ascii_part}|")
        outdump.append(f" 0x{i:04x}: {hex_part:<48} |{ascii_part}|\n")

    attr_M2["dump"] = "".join(outdump)
    return attr_M2

# Normalnya buffer terisi setelah akhir fungsi, tapi recvmsg kayanya gak
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

        print(f" -> recvmsg fd={sockfd} msg_addr=0x{msg_addr:x} iovlen={iovlen} ctrllen={controllen} flags=0x{flags:x}")

        # 1. Ekstrak buffer data dari iovec
        out_m2 = None
        if iovlen > 0:
            iov0 = inf.read_memory(iov, ptr_size*2).tobytes()
            buf_addr, length = struct.unpack(fmt, iov0[0:ptr_size])[0], struct.unpack(fmt, iov0[ptr_size:ptr_size*2])[0]
            print(f" -> iov_buf=0x{buf_addr:x} len={length}")

            length = min(length, 512)
            data = inf.read_memory(buf_addr, length).tobytes()
            out_m2 = parse_m2_packet(data, buf_addr)

        output = {
            "fd": sockfd,
            "msg_addr": msg_addr,
            "iov": iov,
            "iovlen": iovlen,
            "control": control,
            "controllen": controllen,
            "flags": flags,
            "out_m2": out_m2
        }
        return output
