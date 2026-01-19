import gdb
import re
from permission import Permission
from typing import ByteString, Optional
import warnings
import string

GEF_MAX_STRING_LENGTH = 50
DEFAULT_PAGE_ALIGN_SHIFT = 12
DEFAULT_PAGE_SIZE = 1 << DEFAULT_PAGE_ALIGN_SHIFT

class ArchType:
    def __init__(self):
        self.ptrsize = 0

    def get_ptr(self):
        res = self.cached_lookup_type("size_t")
        if res is not None:
            self.ptrsize = res.sizeof
        else:
            try:
                self.ptrsize = gdb.parse_and_eval("$pc").type.sizeof
            except:
                print("error arch")
                pass

    def format_address(self, addr: int) -> str:
        """Format the address according to its size."""
        memalign_size = self.ptrsize
        addr = self.align_address(addr)
        return f"0x{addr:016x}" if memalign_size == 8 else f"0x{addr:08x}"


    def align_address(self, address: int) -> int:
        """Align the provided address to the process's native length."""
        return address & 0xFFFFFFFFFFFFFFFF if self.ptrsize == 8 else address & 0xFFFFFFFF


    def cached_lookup_type(self, _type: str):
        try:
            return gdb.lookup_type(_type).strip_typedefs()
        except RuntimeError:
            return None

    def dereference(self, addr: int):
        try:
            ulong_t = self.cached_lookup_type(self.use_stdtype()) or \
                      self.cached_lookup_type(self.use_default_type()) or \
                      self.cached_lookup_type(self.use_golang_type()) or \
                      self.cached_lookup_type(self.use_rust_type())
            if not ulong_t:
                raise gdb.MemoryError("Failed to determine unsigned long type")

            unsigned_long_type = ulong_t.pointer()
            res = gdb.Value(addr).cast(unsigned_long_type).dereference()
            # GDB does lazy fetch by default so we need to force access to the value
            res.fetch_lazy()
            return res
        except gdb.MemoryError as e:
            print(str(e))

        return None


    def is_64bit(self) -> bool:
        return self.ptrsize == 8

    def is_32bit(self) -> bool:
        return self.ptrsize == 4

    #def is_x86_64() -> bool:
    #    return Elf.Abi.X86_64 in gef.arch.aliases

    #def is_x86_32():
    #    return Elf.Abi.X86_32 in gef.arch.aliases

    def is_x86(self) -> bool:
        return is_x86_32() or is_x86_64()


    def use_stdtype(self) -> str:
        if self.is_32bit(): return "uint32_t"
        elif self.is_64bit(): return "uint64_t"
        return "uint16_t"

    def use_default_type(self) -> str:
        if self.is_32bit(): return "unsigned int"
        elif self.is_64bit(): return "unsigned long"
        return "unsigned short"

    def use_golang_type(self) -> str:
        if self.is_32bit(): return "uint32"
        elif self.is_64bit(): return "uint64"
        return "uint16"

    def use_rust_type(self) -> str:
        if self.is_32bit(): return "u32"
        elif self.is_64bit(): return "u64"
        return "u16"



# Thanks gef
class AddressHuman:
    def __init__(self):
        self.value = {}
        self.section = None
        self.info = None

    def get_registers(self):
        out = gdb.execute("info registers", to_string=True)
        regs = []
        # regex ambil nama reg di awal baris
        for line in out.splitlines():
            m = re.match(r"^([a-zA-Z0-9]+)\s+", line)
            if m:
                regs.append(m.group(1))
        return regs

    def collect_registers(self):
        result = []
        for r in self.get_registers():
            val = gdb.parse_and_eval("$" + r)
            val = hex(val)
            result.append(f"{r}={val}")
        return result

    def get_filepath(self):
        progspace = gdb.current_progspace()
        return progspace.filename

    def file_lookup_address(self, address: int):
        lines = (gdb.execute("info files", to_string=True) or "").splitlines()
        infos = []
        for line in lines:
            line = line.strip()
            if not line:
                break

            if not line.startswith("0x"):
                continue

            blobs = [x.strip() for x in line.split(" ")]
            addr_start = int(blobs[0], 16)
            addr_end = int(blobs[2], 16)
            section_name = blobs[4]

            if len(blobs) == 7:
                filename = blobs[6]
            else:
                filename = self.get_filepath()

            output = {
               "section_name": section_name,
               "addr_start": addr_start,
               "addr_end": addr_end,
               "filename": filename
            }
            infos.append(output)

        for info in infos:
            if info["addr_start"] <= address < info["addr_end"]:
                return info
        return None


    def parse_string_range(self, s: str):
        """Parses an address range (e.g. 0x400000-0x401000)"""
        addrs = s.split("-")
        return map(lambda x: int(x, 16), addrs)

    def process_lookup_address(self, address: int):
        pid = gdb.selected_inferior().pid
        maps = []

        with open(f"/proc/{pid}/maps", "r") as fd:
            for line in fd:
                line = line.strip()
                addr, perm, off, _, rest = line.split(" ", 4)

                rest = rest.split(" ", 1)
                if len(rest) == 1:
                    inode = rest[0]
                    pathname = ""
                else:
                    inode = rest[0]
                    pathname = rest[1].lstrip()

                addr_start, addr_end = self.parse_string_range(addr)

                off = int(off, 16)
                perm = Permission.from_process_maps(perm)
                inode = int(inode)
                output = {
                    "page_start": addr_start,
                    "page_end": addr_end,
                    "offset": off,
                    "permission": perm,
                    "inode": inode,
                    "path": pathname
                }
                maps.append(output)

        for sect in maps:
            if sect["page_start"] <= address < sect["page_end"]:
                return sect

        return None

    def lookup_address(self, address: int):
        sect = self.process_lookup_address(address) #Section(start=0x7ffffffdd000, end=0x7ffffffff>
        info = self.file_lookup_address(address) #Zone(name='.text', zone_start=93824992236000, zo>

        if sect or info:
            if sect["path"] == "[heap]":
                self.value = {
                    "addr": address,
                    "label": "[heap]"
                }

            elif sect["path"] == "[stack]":
                self.value = {
                    "addr": address,
                    "label": "[stack]"
                }

            elif info["section_name"] == ".text":
                self.value = {
                    "addr": address,
                    "label": "[code]"
                }

            elif sect["path"] == self.get_filepath() and Permission.EXECUTE:
                self.value = {
                    "addr": address,
                    "label": "[code_file]"
                }
        else:
            self.value = {
                "addr": address,
                "label": ""
            }
        self.section = sect
        self.info = info

    def dereference(self, arch):
        addr = arch.align_address(int(self.value['addr']))

        derefed = arch.dereference(addr)
        return None if derefed is None else int(derefed)

    def maps_area(self):
        if self.section and self.section["page_start"] <= self.value["addr"] < self.section["page_end"]:
            return True

        return False



class StackHuman:

    def write(self, address: int, buffer: ByteString, length: Optional[int] = None) -> None:
        """Write `buffer` at address `address`."""
        length = length or len(buffer)
        gdb.selected_inferior().write_memory(address, buffer, length)

    def read(self, addr: int, length: int = 0x10) -> bytes:
        """Return a `length` long byte array with the copy of the process memory at `addr`."""
        return gdb.selected_inferior().read_memory(addr, length).tobytes()

    def read_integer(self, addr: int) -> int:
        """Return an integer read from memory."""
        sz = gef.arch.ptrsize
        mem = self.read(addr, sz)
        unpack = u32 if sz == 4 else u64
        return unpack(mem)

    def read_cstring(self,
                     address: int,
                     max_length: int = GEF_MAX_STRING_LENGTH,
                     encoding: Optional[str] = None) -> str:
        """Return a C-string read from memory."""
        encoding = encoding or "unicode-escape"
        length = min(address | (DEFAULT_PAGE_SIZE-1), max_length+1)

        try:
            res_bytes = self.read(address, length)
        except gdb.error:
            err(f"Can't read memory at '{address}'")
            return ""
        try:
            with warnings.catch_warnings():
                # ignore DeprecationWarnings (see #735)
                warnings.simplefilter("ignore")
                res = res_bytes.decode(encoding, "strict")
        except UnicodeDecodeError:
            # latin-1 as fallback due to its single-byte to glyph mapping
            res = res_bytes.decode("latin-1", "replace")

        res = res.split("\x00", 1)[0]
        ustr = res.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        if max_length and len(res) > max_length:
            return f"{ustr[:max_length]}[...]"
        return ustr

    def read_ascii_string(self, address: int) -> Optional[str]:
        """Read an ASCII string from memory"""
        cstr = self.read_cstring(address)
        if isinstance(cstr, str) and cstr and all(x in string.printable for x in cstr):
            return cstr
        return None



    def is_ascii_string(self, address: int) -> bool:
        """Helper function to determine if the buffer pointed by `address` is an ASCII string (in GDB)"""
        try:
            return self.read_ascii_string(address) is not None
        except Exception:
            return False


    def get_value(self, addrHuman, arch, deref):
        txt = ""
        if addrHuman.section:
            if addrHuman.section["permission"][0] == "r":
                if self.is_ascii_string(deref):
                    s = self.read_cstring(deref)

                    if len(s) < arch.ptrsize:
                        txt = f'("{s}"?)'
                    elif len(s) > GEF_MAX_STRING_LENGTH:
                        txt = f'"{s[:GEF_MAX_STRING_LENGTH]}[...]"'
                    else:
                        txt = s
        return txt



    def dereference_from(self, address: int, offset: int):
        arch = ArchType()
        arch.get_ptr()

        index = 1
        output = []

        addrHuman = AddressHuman()
        addrHuman.lookup_address(address)

        deref = addrHuman.dereference(arch)

        out = {
            "index": 0,
            "address": f"{arch.format_address(address)}",
            "label": addrHuman.value['label'],
            "value": self.get_value(addrHuman, arch, address)
        }
        output.append(out)

        if deref is None:
            return


        addrHuman.lookup_address(deref)

        while 1:

            out = {
                "index": index,
                "address": f"{arch.format_address(deref)}",
                "label": addrHuman.value['label'],
                "value": self.get_value(addrHuman, arch, deref)
            }
            output.append(out)

            addrHuman.lookup_address(deref)

            if addrHuman.maps_area():
                deref = addrHuman.dereference(arch)
            else:
                break
            index += 1

        print(output)




#            print(f"{arch.format_address(address)}|{offset:+#07x} {arch.format_address(deref)}{addrHuman.value['label']} → {txt}  {zzz}")

#        else:
#            print(f"{arch.format_address(address)}|{offset:+#07x}  {arch.format_address(deref)}")






