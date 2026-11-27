import socket
import threading
import xmlrpc.server, xmlrpc.client
import json

from binaryninja import (
    log_info,
    PluginCommand,
    show_message_box,
    MessageBoxButtonSet,
    MessageBoxIcon,
    highlight
)
from binaryninjaui import DockHandler

from .helpers import (
    info,
    err,
    dbg,
    RunInBackground,
)

from .constants import (
    HOST,
    PORT,
    DEBUG,
    HL_NO_COLOR,
    HL_BP_COLOR,
    HL_CUR_INSN_COLOR,
)

from .gproxy import (
    Gproxy,
    BinjaGefRequestHandler,
)
from gproxy.data_global import GLOBAL, SIGNALS
from .analyses.binja import SkoringFuncs


__service_thread = None
__gef_instance = None


def is_service_started():
    global __service_thread
    return __service_thread is not None





def start_service(host, port, bv):
    """ Starting the service """
    global __gef_instance
    info("Starting service on {}:{}".format(host, port))
    server = xmlrpc.server.SimpleXMLRPCServer(
        (host, port),
        requestHandler=BinjaGefRequestHandler,
        logRequests=False,
        allow_none=True
    )
    server.register_introspection_functions()
    __gef_instance = Gproxy(server, bv)
    server.register_instance(__gef_instance)
    dbg("Registered {} functions.".format( len(server.system_listMethods()) ))
    while True:
        if hasattr(server, "shutdown") and server.shutdown==True: break
        server.handle_request()
    return


def shutdown_service():
    try:
        cli = xmlrpc.client.ServerProxy("http://{:s}:{:d}".format(HOST, PORT))
        cli.shutdown()
    except socket.error:
        pass


def stop_service():
    """ Stopping the service """
    global __service_thread
    dbg("Trying to stop service thread")
    shutdown_service()
    __service_thread.join()
    __service_thread = None
    info("Server stopped")
    return


def gef_start(bv):
    global __service_thread
    dbg("Starting background service...")
    __service_thread = threading.Thread(target=start_service, args=(HOST, PORT, bv))
    __service_thread.daemon = True
    __service_thread.start()
    show_message_box(
        "G-proxy",
        "Service successfully started, you can now have gef connect to it",
        MessageBoxButtonSet.OKButtonSet,
        MessageBoxIcon.InformationIcon
    )
    return


def gef_stop(bv):
    "Stopping background service... "
    stop_service()
    show_message_box(
        "G-proxy",
        "Service successfully stopped",
        MessageBoxButtonSet.OKButtonSet,
        MessageBoxIcon.InformationIcon
    )
    return



PluginCommand.register(
    "Gproxy\\Start service",
    "Start the service for communicating with gproxy",
    gef_start,
    is_valid = lambda view: not is_service_started()
)


PluginCommand.register(
    "Gproxy\\Stop service",
    "Stop the service for communicating with gproxy",
    gef_stop,
    is_valid = lambda view: is_service_started()
)


def analysesSkor(bv):
    SIGNALS.window_binja_score.emit()
    scanner = SkoringFuncs(bv)
    scanner.start()

PluginCommand.register(
    "Gproxy\\Start analyses",
    "untuk mengumpulkan skor", analysesSkor)



def warnaJejak(bv, addr, count):
    color = '0xaa00aa'
    addr = int(addr, 0)
    bbs = bv.get_basic_blocks_at(addr)

    if (bbs):
        color = int(color, 0)
        R,G,B = (color >> 16)&0xff, (color >> 8)&0xff, (color&0xff)
        color = highlight.HighlightColor(red=R, blue=G, green=B)

        bb = bbs[0]
        bb.highlight = color

def tampilkanJejak(bv):
    with open("/dev/shm/gdb-hit-cc.jsonl") as f:
        func_hit = json.load(f)

    for f in func_hit:
        print(f"[+] block color: {f['name']} => {f['addr']}")
        warnaJejak(bv, f['addr'], f['count'])


PluginCommand.register(
    "Gproxy\\Color blocks",
    "hasil jejak eksekusi gdb", tampilkanJejak)

