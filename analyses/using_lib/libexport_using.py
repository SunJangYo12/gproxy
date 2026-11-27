from gproxy.data_global import GLOBAL, SIGNALS
import json
from binaryninja import SymbolType

with open("/tmp/exports.json") as f:
    libumsg_exports = json.load(f)

loader_imports = set()
for sym in bv.get_symbols():
    if sym.type == SymbolType.ImportedFunctionSymbol:

        loader_imports.add(sym.name)


matched = loader_imports & libumsg_exports.keys()

print(f"loader imports {len(loader_imports)} functions total")
print(f"{len(matched)} of them match libumsg.so exports:\n")

#GLOBAL.gdb_functions = {}
for name in sorted(matched):
    #GLOBAL.append_gdbfunc(libumsg_exports[name]["name_resolve"]) #name_resolve/address
    print(libumsg_exports[name]["name_resolve"]) #name_resolve/address
    print(libumsg_exports[name]["address"]) #name_resolve/address
    print()

#SIGNALS.gdb_updated.emit()
