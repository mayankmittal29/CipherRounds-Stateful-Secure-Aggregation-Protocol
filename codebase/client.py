import sys
import socket
import selectors
import types
import csv
from protocol_fsm import ProtocolFSM_Client
from Crypto.Random import get_random_bytes

sel = selectors.DefaultSelector()

HOST = "127.0.0.1"
PORT = 65432
clientID = int(input("Enter your Client ID:\n"))
masterkey = None
search_id = str(clientID)
with open("MasterKeys.csv", newline='') as f:
    reader = csv.reader(f)
    for row in reader:
        if row and row[0] == search_id:
            masterkey = row[1].encode('utf-8')
            break

if masterkey is None:
    print(f"No key found for the Client ID {clientID}. Aborting...")
    exit()

client_fsm = ProtocolFSM_Client(masterkey, clientID)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    iv = get_random_bytes(16)
    init_packet = client_fsm.prepare_packet(10, b"Initiate connection", iv)
    s.sendall(init_packet)
    server_challenge = s.recv(1024)
    try:
        packet_opcode, packet_iv, packet_ciphertext, plaintext = client_fsm.process_incoming_packet(server_challenge)
    except ValueError as e:
        print(f"Exiting the connection due to the following error in recieved packet: {e}")
        err_iv = get_random_bytes(16)
        err_packet = client_fsm.prepare_error_packet(60, b"User Quit", err_iv)
        s.send(err_packet)
        s.close()
        sys.exit(0)

    if packet_opcode != 20:
        s.close()
        print(f"Invalid OPCODE of expected server challenge: {packet_opcode}. Connection may be compromised.")
        err_iv = get_random_bytes(16)
        err_packet = client_fsm.prepare_error_packet(60, b"User Quit", err_iv)
        s.send(err_packet)
        s.close()
        sys.exit(0)
    
    client_fsm.phase = "ACTIVE"

    while True:
        print("\nEnter numbers to sum (separated by space), or 'q' to quit:")
        user_input = input("> ")
        
        if user_input.lower() == 'q':
            print("Ending connection...")
            err_iv = get_random_bytes(16)
            err_packet = client_fsm.prepare_error_packet(60, b"User Quit", err_iv)
            s.send(err_packet)
            s.close()
            sys.exit(0)
        
        input_numbers = user_input.encode('utf-8')
        iv = get_random_bytes(16)
        out_packet = client_fsm.prepare_packet(30, input_numbers, iv)
        s.send(out_packet)

        server_response = s.recv(1024)
        try:
            packet_opcode, packet_iv, packet_ciphertext, plaintext = client_fsm.process_incoming_packet(server_response)
        except ValueError as e:
            print(f"Exiting the connection due to the following error in recieved packet: {e}")
            err_iv = get_random_bytes(16)
            err_packet = client_fsm.prepare_error_packet(60, b"User Quit", err_iv)
            s.send(err_packet)
            s.close()
            sys.exit(0)

        if packet_opcode in [50, 60]:
            print(f"Exiting connection due to server ending the connection with opcode {packet_opcode}")
            s.close()
            sys.exit(0)
        
        if packet_opcode != 40:
            s.close()
            print(f"Invalid OPCODE of expected server reply: {packet_opcode}. Connection may be compromised.")
            err_iv = get_random_bytes(16)
            err_packet = client_fsm.prepare_error_packet(60, b"User Quit", err_iv)
            s.send(err_packet)
            s.close()
            sys.exit(0)
        
        result = int.from_bytes(plaintext, 'big')
        print("The aggregated data from the server is:")
        print(result)