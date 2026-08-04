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
pos = nx.spring_layout(G)

# 2. Setup GUI
win = tk.Tk()
win.title("Realtime Graph")
canvas = tk.Canvas(win, width=400, height=400, bg="#888")
canvas.pack()

def to_pixel(x, y, w=400, h=400):
    scale = 120
    cx, cy = w//2, h//2
    return x * scale + cx, y * scale + cy

def redraw():
    canvas.delete("all") # hapus semua dulu
    # hitung ulang layout biar rapi
    global pos
    pos = nx.spring_layout(G, k=0.8, iterations=10, pos=pos, fixed=["ROOT"])

    for u, v in G.edges():
        x1, y1 = to_pixel(*pos[u])
        x2, y2 = to_pixel(*pos[v])
        canvas.create_line(x1, y1, x2, y2, width=2, fill="black")

    r = 20
    for node, (x, y) in pos.items():
        px, py = to_pixel(x, y)
        color = "#FF5555" if node == "ROOT" else "#87CEEB"
        canvas.create_oval(px-r, py-r, px+r, py+r, fill=color, outline="black")
        canvas.create_text(px, py, text=node, font=("Arial", 9, "bold"))

# 3. Thread buat listen socket
def handle_client(conn):
    with conn:
        data = conn.recv(1024).decode()
        if not data: return
        msg = json.loads(data) # {"node": "Dot-5", "parent": "ROOT"}

        node = msg["node"]
        parent = msg["parent"]

        G.add_node(node)
        G.add_edge(parent, node)

        # update GUI harus di main thread
        win.after(0, redraw)

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
