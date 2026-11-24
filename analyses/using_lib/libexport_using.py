import json
from binaryninja import SymbolType

# Baca daftar export libumsg.so yang disimpan sebelumnya
with open("/tmp/exports.json") as f:
    libumsg_exports = json.load(f)

# Ambil semua fungsi yang diimpor loader
loader_imports = set()
for sym in bv.get_symbols():
    if sym.type == SymbolType.ImportedFunctionSymbol:
        loader_imports.add(sym.name)

# Cocokkan
matched = loader_imports & libumsg_exports.keys()

print(f"loader imports {len(loader_imports)} functions total")
print(f"{len(matched)} of them match libumsg.so exports:\n")
for name in sorted(matched):
    print(f"  {name} -> {libumsg_exports[name]} (in libumsg.so)")
