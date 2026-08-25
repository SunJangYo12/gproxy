data = """
 0x0000: 31 00 00 00 4d 32 01 00 ff 88 02 00 0d 00 00 00  |1...M2..........|
 0x0010: 01 00 00 00 02 00 ff 88 00 00 05 00 ff 01 01 00  |................|
 0x0020: fe 09 01 03 00 ff 09 01 06 00 ff 09 1d 07 00 ff  |................|
 0x0030: 08 02 00 fe 00 00 ff 09 00 07 00 ff 09 01 13 00  |................|
 0x0040: ff 18 00 00 00 00 00 00 00 00 00 00 ff ff c0 a8  |................|
 0x0050: 2b 35 01 00 00 21 05 61 64 6d 69 6e 03 00 00 21  |+5...!.admin...!|
 0x0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
"""

hex_str = ""
for line in data.strip().split('\n'):
    # ambil bagian sebelum |
    hex_part = line.split('|')[0]
    # buang alamat 0x0000:
    hex_part = hex_part.split(':')[1]
    # buang spasi
    hex_str += hex_part.replace(' ', '').strip()

print(hex_str)
print(len(hex_str)//2, "bytes")
