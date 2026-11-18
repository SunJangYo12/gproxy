"""
Bandingkan fungsi antara binary lama dan baru di Binary Ninja.

Cara pakai di console Python (tab binary BARU harus aktif, jadi `bv` = versi baru):

    exec(open("/path/ke/diff_funcs.py").read())
    bandingkan("/path/ke/old.bndb")

Hasil tersimpan di variabel console:
    berubah : fungsi yang ada di kedua versi tapi signature atau panjangnya beda
    hilang  : fungsi di versi lama yang tidak ditemukan di versi baru
    baru    : fungsi di versi baru yang tidak ada padanannya di versi lama
"""
import hashlib
import binaryninja as bn


def _il_ops(f):
    """Daftar nama operasi IL (tanpa alamat/operand), MLIL dulu, fallback LLIL."""
    try:
        il = f.mlil
        if il is not None:
            return [i.operation.name for i in il.instructions]
    except Exception:
        pass
    try:
        il = f.llil
        if il is not None:
            return [i.operation.name for i in il.instructions]
    except Exception:
        pass
    return []


def catat(view):
    """Catat info tiap fungsi: nama, alamat, panjang byte, jumlah blok, jumlah IL, hash."""
    data = {}
    for f in view.functions:
        ops = _il_ops(f)
        sig = hashlib.sha1("|".join(ops).encode()).hexdigest()
        data[f.start] = {
            "name": f.name,
            "addr": f.start,
            "bytes": f.total_bytes,
            "blocks": len(f.basic_blocks),
            "il_count": len(ops),
            "sig": sig,
        }
    return data


def _auto_name(name):
    return name.startswith(("sub_", "j_sub_", "data_", "FUN_"))


def bandingkan(old_path, tampil=True):
    global berubah, hilang, baru, old_info, new_info

    old = bn.load(old_path)
    try:
        old_info = catat(old)
    finally:
        old.file.close()
    new_info = catat(bv)  # noqa: F821  (bv disediakan console Binary Ninja)

    new_by_name = {}
    new_by_sig = {}
    for d in new_info.values():
        if not _auto_name(d["name"]):
            new_by_name[d["name"]] = d
        new_by_sig.setdefault(d["sig"], []).append(d)

    berubah, hilang = [], []
    cocok_new = set()  # alamat fungsi baru yang sudah dipasangkan

    for o in old_info.values():
        n = None
        # 1) cocokkan lewat nama (hanya nama asli, bukan sub_xxx)
        if not _auto_name(o["name"]):
            n = new_by_name.get(o["name"])
        # 2) kalau tidak ada, cocokkan lewat hash signature
        if n is None:
            kandidat = [c for c in new_by_sig.get(o["sig"], []) if c["addr"] not in cocok_new]
            if kandidat:
                n = kandidat[0]

        if n is None:
            hilang.append(o)
            continue

        cocok_new.add(n["addr"])
        if o["sig"] != n["sig"] or o["bytes"] != n["bytes"]:
            berubah.append({"old": o, "new": n})

    baru = [d for a, d in new_info.items() if a not in cocok_new]

    if tampil:
        print(f"Total fungsi lama: {len(old_info)}  baru: {len(new_info)}")
        print(f"Berubah: {len(berubah)}  Hilang: {len(hilang)}  Baru: {len(baru)}\n")
        print("== BERUBAH ==")
        for p in berubah:
            o, n = p["old"], p["new"]
            print(
                f"{o['name']:<32} old {hex(o['addr'])} ({o['bytes']}B, {o['blocks']} blk)"
                f"  ->  new {hex(n['addr'])} ({n['bytes']}B, {n['blocks']} blk)"
                f"  selisih {n['bytes'] - o['bytes']:+d}B"
            )
    return berubah
