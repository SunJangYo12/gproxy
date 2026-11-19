"""
Jendela hasil perbandingan fungsi untuk Binary Ninja.
Klik satu baris -> view langsung pindah ke fungsi tersebut di binary baru.

Pakai setelah bandingkan(...) dari diff_funcs.py selesai:

    exec(open("/path/ke/tampil_hasil.py").read())
    tampil_hasil()
"""
import binaryninja as bn

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QAbstractItemView, QCheckBox, QHBoxLayout, QHeaderView, QLabel,
        QLineEdit, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    )
except ImportError:  # Binary Ninja versi lama
    from PySide2.QtCore import Qt
    from PySide2.QtWidgets import (
        QAbstractItemView, QCheckBox, QHBoxLayout, QHeaderView, QLabel,
        QLineEdit, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    )

_jendela = None  # simpan referensi supaya tidak di-garbage-collect

KOLOM = ["Kategori", "Nama", "Alamat baru", "Alamat lama", "Byte lama", "Byte baru", "Selisih"]


def _baris_data():
    rows = []
    for p in berubah:  # noqa: F821
        o, n = p["old"], p["new"]
        rows.append(("Berubah", n["name"], n["addr"], o["addr"], o["bytes"], n["bytes"], n["bytes"] - o["bytes"]))
    for n in baru:  # noqa: F821
        rows.append(("Baru", n["name"], n["addr"], None, None, n["bytes"], None))
    for o in hilang:  # noqa: F821
        rows.append(("Hilang", o["name"], None, o["addr"], o["bytes"], None, None))
    return rows


def _buat_jendela(view):
    global _jendela

    rows = _baris_data()
    w = QWidget()
    w.setWindowTitle("Hasil perbandingan fungsi")
    w.resize(900, 600)
    lay = QVBoxLayout(w)

    atas = QHBoxLayout()
    filter_box = QLineEdit()
    filter_box.setPlaceholderText("Filter nama...")
    cb = {k: QCheckBox(k) for k in ("Berubah", "Baru", "Hilang")}
    for c in cb.values():
        c.setChecked(True)
    atas.addWidget(filter_box)
    for c in cb.values():
        atas.addWidget(c)
    lay.addLayout(atas)

    info = QLabel("")
    lay.addWidget(info)

    tabel = QTableWidget(len(rows), len(KOLOM))
    tabel.setHorizontalHeaderLabels(KOLOM)
    tabel.setSelectionBehavior(QAbstractItemView.SelectRows)
    tabel.setSelectionMode(QAbstractItemView.SingleSelection)
    tabel.setEditTriggers(QAbstractItemView.NoEditTriggers)
    tabel.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    tabel.horizontalHeader().setStretchLastSection(True)

    for r, (kat, nama, a_baru, a_lama, b_lama, b_baru, selisih) in enumerate(rows):
        def teks(v):
            return QTableWidgetItem("" if v is None else v)

        def hexi(v):
            it = QTableWidgetItem("" if v is None else f"0x{v:08x}")
            it.setData(Qt.UserRole, v)
            return it

        def angka(v):
            it = QTableWidgetItem()
            if v is not None:
                it.setData(Qt.DisplayRole, int(v))  # supaya urut numerik
            return it

        tabel.setItem(r, 0, teks(kat))
        tabel.setItem(r, 1, teks(nama))
        tabel.setItem(r, 2, hexi(a_baru))
        tabel.setItem(r, 3, hexi(a_lama))
        tabel.setItem(r, 4, angka(b_lama))
        tabel.setItem(r, 5, angka(b_baru))
        tabel.setItem(r, 6, angka(selisih))

    tabel.setSortingEnabled(True)
    tabel.resizeColumnsToContents()
    lay.addWidget(tabel)

    def terapkan_filter():
        q = filter_box.text().lower()
        tampil = 0
        for r in range(tabel.rowCount()):
            kat = tabel.item(r, 0).text()
            nama = tabel.item(r, 1).text().lower()
            sembunyi = (not cb[kat].isChecked()) or (q not in nama)
            tabel.setRowHidden(r, sembunyi)
            tampil += 0 if sembunyi else 1
        info.setText(f"{tampil} dari {tabel.rowCount()} baris. Klik baris untuk pindah ke fungsinya "
                     f"(Hilang hanya ada di binary lama, jadi tidak bisa dibuka).")

    def saat_pilih():
        r = tabel.currentRow()
        if r < 0:
            return
        addr = tabel.item(r, 2).data(Qt.UserRole)  # alamat di binary baru
        if addr is None:
            return
        try:
            view.navigate(view.view, addr)
        except Exception:
            view.file.navigate(view.file.view, addr)

    filter_box.textChanged.connect(terapkan_filter)
    for c in cb.values():
        c.stateChanged.connect(terapkan_filter)
    tabel.itemSelectionChanged.connect(saat_pilih)

    terapkan_filter()
    w.show()
    _jendela = w


def tampil_hasil():
    view = bv  # noqa: F821  (tab binary baru)
    bn.execute_on_main_thread(lambda: _buat_jendela(view))
