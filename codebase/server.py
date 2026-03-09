import sys
import socket
import selectors
import time
import csv
import select
from protocol_fsm import ProtocolFSM_Server, ProtocolFSM_Client
from Crypto.Random import get_random_bytes

sel = selectors.DefaultSelector()
host = "127.0.0.1"
port = 65432

round_storage = {}
last_aggregation_time = time.time()
AGGREGATION_INTERVAL = 10.0 

class ConnectionData:
    def __init__(self, addr):
        self.addr = addr

clientClasses = {}

def get_key(clientID):
    search_id = str(clientID)
    with open("MasterKeys.csv", newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if row and row[0] == search_id:
                return row[1].encode('utf-8')
    return None

def accept_wrapper(sock):
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = ConnectionData(addr)
    events = selectors.EVENT_READ
    sel.register(conn, events, data=data)
    clientClasses[conn] = ProtocolFSM_Server()

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        try:
            recv_data = sock.recv(1024)
        except (ConnectionResetError, BrokenPipeError):
            recv_data = None

        if recv_data:
            opcode = recv_data[0]
            if opcode == 10:
                clientID = recv_data[1]
                masterkey = get_key(clientID)
                if masterkey is None:
                    cleanup_connection(sock)
                    return
                clientClasses[sock].initialize_keys(masterkey, clientID)

            try:
                packet_opcode, packet_iv, packet_ciphertext, plaintext = clientClasses[sock].process_incoming_packet(recv_data)
            except ValueError as e:
                print(f"Error with client {clientClasses[sock].clientID}: {e}")
                try:
                    err_iv = get_random_bytes(16)
                    err_packet = clientClasses[sock].prepare_error_packet(60, str(e).encode('utf-8'), err_iv)
                    sock.sendall(err_packet)
                except Exception:
                    pass
                cleanup_connection(sock)
                return

            if packet_opcode == 10:
                nonce = get_random_bytes(16)
                iv = get_random_bytes(16)
                out_packet = clientClasses[sock].prepare_packet(20, nonce, iv)
                sock.send(out_packet)
                clientClasses[sock].phase = "ACTIVE"

            elif packet_opcode == 30:
                try:
                    val = sum(int(num) for num in plaintext.decode('utf-8').split())
                    r_num = clientClasses[sock].cur_round
                    if r_num not in round_storage:
                        round_storage[r_num] = {}
                    round_storage[r_num][sock] = val
                except ValueError:
                    cleanup_connection(sock)
            
            elif packet_opcode in [50, 60]:
                cleanup_connection(sock)
        else:
            cleanup_connection(sock)

def cleanup_connection(sock):
    print(f"Closing connection.")
    try:
        sel.unregister(sock)
        sock.close()
    except Exception:
        pass
    if sock in clientClasses:
        del clientClasses[sock]
    for r in list(round_storage.keys()):
        if sock in round_storage[r]:
            del round_storage[r][sock]

def process_aggregation_window():
    rounds_to_clear = []
    for r_num, clients_in_round in round_storage.items():
        if not clients_in_round:
            continue
        total_sum = sum(clients_in_round.values())
        sum_bytes = total_sum.to_bytes((total_sum.bit_length() + 7) // 8 or 1, "big")
        for sock in list(clients_in_round.keys()):
            if sock in clientClasses:
                iv = get_random_bytes(16)
                out_packet = clientClasses[sock].prepare_packet(40, sum_bytes, iv)
                try:
                    sock.send(out_packet)
                except Exception:
                    cleanup_connection(sock)
        rounds_to_clear.append(r_num)
    for r in rounds_to_clear:
        del round_storage[r]

lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

lsock.bind((host, port))
lsock.listen()
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

print(f"Listening on {(host, port)}. Type 'exit' and press Enter to shutdown gracefully.")

running = True
try:
    while running:
        events = sel.select(timeout=0.5)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask)
        
        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
            line = sys.stdin.readline()
            if "exit" in line:
                print("Shutdown command received. Closing all sessions...")
                running = False

        current_time = time.time()
        if current_time - last_aggregation_time >= AGGREGATION_INTERVAL:
            process_aggregation_window()
            last_aggregation_time = current_time

except KeyboardInterrupt:
    print("\nInterrupted by user.")
finally:
    for sock in list(clientClasses.keys()):
        cleanup_connection(sock)
    sel.close()
    lsock.close()
    print("Server socket closed. Address is now free.")