import socket
import json
import time

HOST = '127.0.0.1' # ganti ke IP server
PORT = 9999

def add_node(node_name, parent_name, an_from=None, an_to=None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        msg = {
            "node": node_name,
            "parent": parent_name,
            "animate": True,
            "an_from": an_from,
            "an_to": an_to
        }
        s.sendall(json.dumps(msg).encode())

# contoh: tambah 5 node realtime
for i in range(5):
    add_node(f"Dot-{i}", "ROOT")
    time.sleep(0.1) # jeda 1 detik biar keliatan update

