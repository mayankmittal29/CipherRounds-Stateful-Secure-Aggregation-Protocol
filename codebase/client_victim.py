import sys
import socket
import csv
import select
import time
from protocol_fsm import ProtocolFSM_Client
from Crypto.Random import get_random_bytes

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 65433 

clientID = int(input("Enter Victim Client ID:\n"))
masterkey = None
with open("MasterKeys.csv", newline='') as f:
    reader = csv.reader(f)
    for row in reader:
        if row and row[0] == str(clientID):
            masterkey = row[1].encode('utf-8')
            break

if masterkey is None:
    print(f"No key found for Client {clientID}. Aborting...")
    sys.exit()

client_fsm = ProtocolFSM_Client(masterkey, clientID)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((PROXY_HOST, PROXY_PORT))
    s.setblocking(False)
    
    iv = get_random_bytes(16)
    init_packet = client_fsm.prepare_packet(10, b"Initiate", iv)
    s.sendall(init_packet)
    
    while True:
        ready = select.select([s], [], [], 5.0)
        if ready[0]:
            challenge = s.recv(1024)
            client_fsm.process_incoming_packet(challenge)
            client_fsm.phase = "ACTIVE"
            print("[+] Handshake Complete. Phase: ACTIVE")
            break

    while True:
        print("\n[VICTIM MODE] Enter numbers to sum, or 'q' to quit:")
        user_input = input("> ")
        
        if user_input.lower() == 'q':
            s.send(client_fsm.prepare_error_packet(60, b"Quit", get_random_bytes(16)))
            break
        
        iv = get_random_bytes(16)
        out_packet = client_fsm.prepare_packet(30, user_input.encode('utf-8'), iv)
        s.sendall(out_packet)

        start_wait = time.time()
        print("Waiting for server response (12s timeout)...")
        
        while True:
            ready = select.select([s], [], [], 1.0)
            
            if ready[0]:
                server_response = s.recv(1024)
                if not server_response:
                    print("[!] Connection closed by proxy.")
                    sys.exit(0)
                
                try:
                    opcode, _, _, ptext = client_fsm.process_incoming_packet(server_response)
                    if opcode == 60:
                        print(f"Server Terminated Session: {ptext.decode()}")
                        sys.exit(0)
                    print(f"Aggregated result: {int.from_bytes(ptext, 'big')}")
                    break
                except ValueError as e:
                    print(f"Protocol Error: {e}")
                    sys.exit(0)
            
            if time.time() - start_wait > 12.0:
                print("[Timeout] No response in 12s. Re-sending packet to test state...")
                s.sendall(out_packet)
                start_wait = time.time()