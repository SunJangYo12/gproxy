
import tkinter as tk
import networkx as nx
import socket
import threading
import json
import math

HOST = '0.0.0.0'
PORT = 9999

G = nx.Graph()
G.add_node("ROOT")
pos = nx.spring_layout(G, seed=42)

win = tk.Tk()
win.title("Realtime Graph + Zoom + Drag")
canvas = tk.Canvas(win, width=800, height=800, bg="#222")
canvas.pack(fill="both", expand=True)

scale = 200
offset_x, offset_y = 400, 400
drag_data = {"mode": None, "node": None, "x": 0, "y": 0} # mode: "pan" atau "node"
R_NODE = 20

def to_pixel(x, y):
    return x * scale + offset_x, y * scale + offset_y

def to_graph(px, py):
    return (px - offset_x) / scale, (py - offset_y) / scale

def redraw():
    canvas.delete("all")
    global pos
    # fixed = semua node KECUALI yg lagi di drag
    fixed_nodes = [n for n in pos.keys() if n!= drag_data["node"]]
    pos = nx.spring_layout(G, k=0.8, iterations=50, pos=pos, fixed=fixed_nodes, seed=42)

    for u, v in G.edges():
        x1, y1 = to_pixel(*pos[u])
        x2, y2 = to_pixel(*pos[v])
        canvas.create_line(x1, y1, x2, y2, width=2, fill="#555")

    for node, (x, y) in pos.items():
        px, py = to_pixel(x, y)
        r_scaled = R_NODE * (scale / 200)
        color = "#FF5555" if node == "ROOT" else "#87CEEB"
        if node == drag_data["node"]: color = "#FFFF00" # kuning pas di drag
        canvas.create_oval(px-r_scaled, py-r_scaled, px+r_scaled, py+r_scaled, fill=color, outline="white", width=2, tags=("node", node))
        canvas.create_text(px, py, text=node, font=("Arial", int(9 * scale/200), "bold"))

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
        if line_id: canvas.delete(line_id)
        line_id = canvas.create_line(x1, y1, ax, ay, width=4, fill="#00FF00", capstyle=tk.ROUND)
        if i < steps:
            win.after(20, lambda: step(i+1))
        else:
            canvas.delete(line_id)
            redraw()
    step(0)

# 1. MOUSE EVENT UNTUK DRAG NODE & PAN
def get_node_at(x, y):
    for node in G.nodes():
        px, py = to_pixel(*pos[node])
        r_scaled = R_NODE * (scale / 200)
        if (px - r_scaled < x < px + r_scaled) and (py - r_scaled < y < py + r_scaled):
            return node
    return None

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

def on_mousewheel(event):
    global scale
    factor = 1.1 if event.delta > 0 else 0.9
    scale *= factor
    scale = max(50, min(scale, 800))
    redraw()

canvas.bind("<ButtonPress-1>", on_press)
canvas.bind("<B1-Motion>", on_drag)
canvas.bind("<ButtonRelease-1>", on_release)
canvas.bind("<MouseWheel>", on_mousewheel)
canvas.bind("<Button-4>", lambda e: on_mousewheel(type('e', (), {'delta': 120})))
canvas.bind("<Button-5>", lambda e: on_mousewheel(type('e', (), {'delta': -120})))

def handle_client(conn):
    global pos
    with conn:
        data = conn.recv(1024).decode()
        if not data: return
        msg = json.loads(data)
        node = msg["node"]
        parent = msg["parent"]

        is_new = node not in G
        G.add_node(node)
        G.add_edge(parent, node)

        if is_new:
            angle = hash(node) % 360 * math.pi / 180
            dist = 0.5
            px = pos[parent][0] + dist * math.cos(angle)
            py = pos[parent][1] + dist * math.sin(angle)
            pos = (px, py)

        win.after(0, redraw)
        if msg.get("animate", False):
            win.after(150, lambda: animate_edge(parent, node))

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

