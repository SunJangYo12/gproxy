# mouse zoom + drag

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
canvas = tk.Canvas(win, width=500, height=500, bg="#222")
#canvas.pack()
canvas.pack(fill="both", expand=True)

# Variabel global buat zoom dan pan
scale = 200 # zoom level. makin gede makin zoom in
offset_x, offset_y = 500, 500 # titik tengah canvas
drag_data = {
    "mode": None,
    "node": None,
    "x": 0,
    "y": 0
}
R_NODE = 20

def to_pixel(x, y):
    return x * scale + offset_x, y * scale + offset_y

def to_graph(px, py):
    return (px - offset_x) / scale, (py - offset_y) / scale

def redraw():
    canvas.delete("all")
    global pos

    if drag_data["mode"]!= "node":
        fixed_nodes = [n for n in pos.keys() if n!= drag_data["node"]]
        pos = nx.spring_layout(G, k=0.8, iterations=50, pos=pos, fixed=fixed_nodes, seed=42 )

    # gambar edge biasa
    for u, v in G.edges():
        x1, y1 = to_pixel(*pos[u])
        x2, y2 = to_pixel(*pos[v])
        canvas.create_line(x1, y1, x2, y2, width=2, fill="black")

    r = 20
    for node, (x, y) in pos.items():
        px, py = to_pixel(x, y)
        r_scaled = R_NODE * (scale / 200) / 2
        color = "#FF5555" if node == "ROOT" else "#aa00aa"

        if node == drag_data["node"]: color = "#FFFF00" # kuning pas di drag
        canvas.create_oval(px-r_scaled, py-r_scaled, px+r_scaled, py+r_scaled, fill=color)
        canvas.create_text(px, py, text=node, font=("Arial", 9, "bold"), fill="white")

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

# 1. MOUSE EVENT UNTUK DRAG NODE & PAN
def get_node_at(x, y):
    for node in G.nodes():
        px, py = to_pixel(*pos[node])
        r_scaled = R_NODE * (scale / 200)
        if (px - r_scaled < x < px + r_scaled) and (py - r_scaled < y < py + r_scaled):
            return node
    return None


# 1. FUNGSI ZOOM
def on_mousewheel(event):
    global scale
    # Windows: event.delta, Linux: event.num
    factor = 1.1 if event.delta > 0 else 0.9
    scale *= factor
    scale = max(50, min(scale, 800)) # batas min dan max zoom
    redraw()

def on_press(event):
    node = get_node_at(event.x, event.y)
    if node: # klik di node = drag node
        drag_data["mode"] = "node"
        drag_data["node"] = node
    else: # klik di kosong = pan
        drag_data["mode"] = "pan"
    drag_data["x"] = event.x
    drag_data["y"] = event.y

def on_drag(event):
    global offset_x, offset_y
    if drag_data["mode"] == "node":
        # update posisi node ke posisi mouse
        gx, gy = to_graph(event.x, event.y)
        pos[drag_data["node"]] = (gx, gy)
        redraw()
    elif drag_data["mode"] == "pan":
        # geser canvas
        dx = event.x - drag_data["x"]
        dy = event.y - drag_data["y"]
        offset_x += dx
        offset_y += dy
        drag_data["x"] = event.x
        drag_data["y"] = event.y
        redraw()

def on_release(event):
    drag_data["mode"] = None
    drag_data["node"] = None
    redraw() # redraw final biar warna balik


canvas.bind("<MouseWheel>", on_mousewheel) # Windows
canvas.bind("<Button-4>", lambda e: on_mousewheel(type('e', (), {'delta': 120}))) # Linux zoom in
canvas.bind("<Button-5>", lambda e: on_mousewheel(type('e', (), {'delta': -120}))) # Linux zoom out
canvas.bind("<ButtonPress-1>", on_press)
canvas.bind("<B1-Motion>", on_drag)
canvas.bind("<ButtonRelease-1>", on_release)

# 4. Thread buat listen socket
def handle_client(conn):
    with conn:
        data = conn.recv(1024).decode()
        if not data: return
        msg = json.loads(data)
        node = msg["node"]
        parent = msg["parent"]
        an_from = msg["an_from"]
        an_to = msg["an_to"]

        is_new = node not in G
        G.add_node(node)
        G.add_edge(parent, node)

        win.after(0, redraw)

        # kalau ada perintah animasi, jalanin
        if msg.get("animate", False) and not is_new:
            win.after(100, lambda: animate_edge(an_from, an_to))

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

