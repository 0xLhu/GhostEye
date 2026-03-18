import ctypes
import sys
from list_proc import list_processes
from mapping import open_process, query_memory
import socket
import struct


TCP_STATES = {
    1:  "CLOSED",
    2:  "LISTENING",
    3:  "SYN_SENT",
    4:  "SYN_RECEIVED",
    5:  "ESTABLISHED",
    6:  "FIN_WAIT1",
    7:  "FIN_WAIT2",
    8:  "CLOSE_WAIT",
    9:  "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState",      ctypes.c_ulong),
        ("dwLocalAddr",  ctypes.c_ulong),
        ("dwLocalPort",  ctypes.c_ulong),
        ("dwRemoteAddr", ctypes.c_ulong),
        ("dwRemotePort", ctypes.c_ulong),
        ("dwOwningPid",  ctypes.c_ulong),
    ]

iphlpapi = ctypes.WinDLL("iphlpapi.dll")

def get_tcp_connections():
    GetExtendedTcpTable = iphlpapi.GetExtendedTcpTable
    GetExtendedTcpTable.restype = ctypes.c_ulong

    TCP_TABLE_OWNER_PID_ALL = 5
    AF_INET = 2

    size = ctypes.c_ulong(0)
    GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

    buffer = ctypes.create_string_buffer(size.value)
    result = GetExtendedTcpTable(buffer, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if result != 0:
        raise ctypes.WinError(result)

    count = struct.unpack_from("I", buffer)[0]
    rows = (MIB_TCPROW_OWNER_PID * count).from_buffer_copy(buffer[4:])
    
    connections = []
    for row in rows:
        local_ip = socket.inet_ntoa(struct.pack("<L", row.dwLocalAddr))
        local_port = socket.ntohs(row.dwLocalPort)
        remote_ip = socket.inet_ntoa(struct.pack("<L", row.dwRemoteAddr))
        remote_port = socket.ntohs(row.dwRemotePort)
        connections.append({
            "pid": row.dwOwningPid,
            "local": f"{local_ip}:{local_port}",
            "remote": f"{remote_ip}:{remote_port}",
            "state": TCP_STATES.get(row.dwState, f"UNKNOWN({row.dwState})"),
        })
    
    return connections

if __name__ == "__main__":
    connections = get_tcp_connections()
    proc_map = {p["pid"]: p["name"] for p in list_processes()}
    for conn in connections:
        print(f"PID: {conn['pid']}, Local: {conn['local']}, Remote: {conn['remote']}, State: {conn['state']}")
        if conn['pid'] in proc_map:
            print(f"  Process: {proc_map[conn['pid']]}")
