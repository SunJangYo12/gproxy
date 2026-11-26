import json
from binaryninja import SymbolType, SymbolBinding

exports = {}
for sym in bv.get_symbols():
    if sym.type == SymbolType.FunctionSymbol and sym.binding == SymbolBinding.GlobalBinding:
        exports[sym.name] = {
            "address": hex(sym.address),
            "name_resolve": sym.full_name
        }
with open("/tmp/exports.json", "w") as f:
    json.dump(exports, f, indent=2)

print(f"Saved {len(exports)} exported functions")
