import struct


data = bytes.fromhex(
"310000004d320100ff8802000d000000010000000200ff8800000500ff010100fe09010300ff09010600ff091d0700ff080200fe0000ff09000700ff09011300ff1800000000000000000000ffffc0a82b35010000210561646d696e0300002100000000000000000000000000000000"
)

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

offset = 6
z = 1
while offset < len(data):
    output = None

    cek_id = hex(data[offset+2])
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
        offset += 20

    elif type == TYPE_MAP["string-1"]:
        slen = data[offset+4:offset+5]
        slen = int.from_bytes(slen, "little")
        output = data[offset+5:offset+5+slen]
        type = f"{hex(type)} string len(1-byte) slen: {hex(slen)}({slen})"
        offset += 5+slen  # 5 = id(3) + type(1) + size(1)

    elif type == TYPE_MAP["message[]"]:
        type = f"{hex(type)} message[]"
        key = data[offset+4:offset+7]
        print(f"key: {key} TODO")
        offset += 45

    elif type == TYPE_MAP["int32[]"]:
        type = f"{hex(type)} u32-ARRAY"
        arrlen = data[offset+4:offset+6]
        arrlen = int.from_bytes(arrlen, "little")

        output = []
        sdata = offset + 6
        tcount = 4 * arrlen     #type count

        b = data[sdata:sdata+tcount]
        for i in range(0, len(b), 4):
            val = b[i:i+4]
            val = int.from_bytes(val, "little")
            output.append(val)
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
    else:
        output = "Parse failed, please cek again!"
        break

    print(f"id    : {id}")
    print(f"type  : {type}")
    print(output)
    print("==================")

    type = None
    id = None




