#fixed node and animate line edge

import tkinter as tk
import networkx as nx
import socket
import threading
import json

HOST = '0.0.0.0'
PORT = 9999

# 1. Bikin graph awal
G = nx.Graph()
G.add_node("ROOT")
pos = nx.spring_layout(G, seed=42) # kasih seed biar gak goyang

# 2. Setup GUI
win = tk.Tk()
win.title("Realtime Graph + Animasi")
canvas = tk.Canvas(win, width=400, height=400, bg="#222")
canvas.pack()

def to_pixel(x, y, w=400, h=400):
    scale = 120
    cx, cy = w//2, h//2
    return x * scale + cx, y * scale + cy

def redraw():
    canvas.delete("all")
    global pos

    old_nodes = list(pos.keys())
    pos = nx.spring_layout(G, k=0.8, iterations=50, pos=pos, fixed=old_nodes )

    # gambar edge biasa
    for u, v in G.edges():
        x1, y1 = to_pixel(*pos[u])
        x2, y2 = to_pixel(*pos[v])
        canvas.create_line(x1, y1, x2, y2, width=2, fill="#999")

    r = 20
    for node, (x, y) in pos.items():
        px, py = to_pixel(x, y)
        color = "#FF5555" if node == "ROOT" else "#87CEEB"
        canvas.create_oval(px-r, py-r, px+r, py+r, fill=color, outline="white", width=2)
        canvas.create_text(px, py, text=node, font=("Arial", 9, "bold"))

# 3. Fungsi Animasi Edge Hijau
def animate_edge(u, v, steps=30):
    if u not in pos or v not in pos: return

    x1, y1 = to_pixel(*pos[u])
    x2, y2 = to_pixel(*pos[v])

    line_id = None
    def step(i):
        nonlocal line_id
        progress = i / steps
        ax = x1 + (x2 - x1) * progress
        ay = y1 + (y2 - y1) * progress

        if line_id: canvas.delete(line_id) # hapus garis lama
        line_id = canvas.create_line(x1, y1, ax, ay, width=4, fill="#00FF00", capstyle=tk.ROUND)

        if i < steps:
            win.after(20, lambda: step(i+1)) # panggil lagi 20ms kemudian
        else:
            canvas.delete(line_id)
            redraw() # gambar final

    step(0)

# 4. Thread buat listen socket
def handle_client(conn):
    with conn:
        data = conn.recv(1024).decode()
        if not data: return
        msg = json.loads(data)
        # format baru: {"node": "Dot-5", "parent": "ROOT", "animate": true}
        node = msg["node"]
        parent = msg["parent"]

        is_new = node not in G
        G.add_node(node)
        G.add_edge(parent, node)

        win.after(0, redraw)

        # kalau ada perintah animasi, jalanin
        if msg.get("animate", False) and not is_new:
            win.after(100, lambda: animate_edge(parent, node))

def server_thread():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening di {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn,)).start()

threading.Thread(target=server_thread, daemon=True).start()
redraw()
win.mainloop()

