from crypto_utils import compute_hash, compute_hmac, aes_encrypt, aes_decrypt

class ProtocolFSM_Server:
    def __init__(self):
        # Direction 0 is Server to Client, 1 is Client to Server
        self.phase = "INIT"
        self.cur_round = 0

    def initialize_keys(self, master_key, clientID):
        self.master_key = master_key
        self.clientID = clientID
        self.C2S_Enc = compute_hash(master_key + b"C2S-ENC")[:16]
        self.C2S_Mac = compute_hash(master_key + b"C2S-MAC")
        self.S2C_Enc = compute_hash(master_key + b"S2C-ENC")[:16]
        self.S2C_Mac = compute_hash(master_key + b"S2C-MAC")

    def process_incoming_packet(self, packet):
        if self.phase == "TERMINATED":
            raise ValueError("Terminated connection is not allowed to communicate.")
        
        if len(packet) < 55:
            self.phase = "TERMINATED"
            raise ValueError("Packet too short to be valid.")

        packet_opcode = packet[0]

        if self.phase == "INIT":
            if packet_opcode != 10:
                print(f"Server: packetcode: {type(packet_opcode)}, {packet_opcode}")
                self.phase = "TERMINATED"
                raise ValueError("Invalid OPCODE during initialization phase.")
        elif self.phase == "ACTIVE":
            if not (packet_opcode == 30 or packet_opcode == 50 or packet_opcode == 60):
                self.phase = "TERMINATED"
                raise ValueError(f"Unexpected OPCODE during ACTIVE phase.")
        
        if packet_opcode == 50 or packet_opcode == 60:
            self.phase = "TERMINATED"
            raise ValueError(f"Session terminated by Client for OPCODE: {packet_opcode}")


        packet_round = int.from_bytes(packet[2:6], 'big')


        packet_without_hmac = packet[:-32]
        packet_hmac = packet[-32:]

        # if packet_hmac != compute_hmac(self.C2S_Mac, packet_without_hmac):
        #     self.phase = "TERMINATED"
        #     raise ValueError("Tampering Detected: Mismatched HMAC. Possible Desync Attack")
        if packet_hmac != compute_hmac(self.C2S_Mac, packet_without_hmac):
            self.phase = "TERMINATED"
            
            if packet_round < self.cur_round:
                raise ValueError("Key Desync or Replay Attack Detected: Round is stale.")
            
            elif packet_round > self.cur_round:
                raise ValueError("xReorder Attack Detected")
            
            else:
                raise ValueError("Tampering Detected: Ciphertext or MAC modification.")

        if packet_round != self.cur_round:
            self.phase = "TERMINATED"
            raise ValueError("Valid HMAC but Unmatching round number: Replay or Reorder Attack")
        
        packet_direction = packet[6]

        if packet_direction != 1:
            raise ValueError("Invalid Direction: Possible Desync or Replay")
        
        packet_iv = packet[7:23]
        packet_ciphertext = packet[23:-32]

        try:
            plaintext = aes_decrypt(self.C2S_Enc, packet_iv, packet_ciphertext)
        except ValueError:
            raise ValueError("Invalid Padding.")

        # TODO : Step 6 of Receiver Validate Plaintext

        self.C2S_Enc = compute_hash(self.C2S_Enc + packet_ciphertext)[:16]
        self.C2S_Mac = compute_hash(self.C2S_Mac + packet_iv)

        return packet_opcode, packet_iv, packet_ciphertext, plaintext
    
    def prepare_packet(self, opcode, data, iv):
        direction = 0

        ciphertext = aes_encrypt(self.S2C_Enc, data, iv)

        opcode_byte = opcode.to_bytes(1, "big")
        clientID_byte = self.clientID.to_bytes(1, "big")
        round_bytes = self.cur_round.to_bytes(4, 'big') 
        direction_byte = direction.to_bytes(1, "big")

        main_body =  opcode_byte + clientID_byte + round_bytes + direction_byte + iv + ciphertext
        hmac = compute_hmac(self.S2C_Mac, main_body)
        packet = main_body + hmac

        self.S2C_Enc = compute_hash(self.S2C_Enc + data)[:16]
        self.S2C_Mac = compute_hash(self.S2C_Mac + opcode_byte)

        self.cur_round += 1

        return packet
    
    def prepare_error_packet(self, opcode, error_message, iv):
        direction = 0

        ciphertext = aes_encrypt(self.S2C_Enc, error_message, iv)

        opcode_byte = opcode.to_bytes(1, "big")
        clientID_byte = self.clientID.to_bytes(1, "big")
        round_bytes = self.cur_round.to_bytes(4, 'big') 
        direction_byte = direction.to_bytes(1, "big")

        main_body =  opcode_byte + clientID_byte + round_bytes + direction_byte + iv + ciphertext
        hmac = compute_hmac(self.S2C_Mac, main_body)
        packet = main_body + hmac

        self.phase = "TERMINATED"

        return packet
    

class ProtocolFSM_Client:
    def __init__(self, master_key, clientID):
        # Direction 0 is Server to Client, 1 is Client to Server
        self.phase = "INIT"
        self.cur_round = 0
        self.master_key = master_key
        self.clientID = clientID
        self.C2S_Enc = compute_hash(master_key + b"C2S-ENC")[:16]
        self.C2S_Mac = compute_hash(master_key + b"C2S-MAC")
        self.S2C_Enc = compute_hash(master_key + b"S2C-ENC")[:16]
        self.S2C_Mac = compute_hash(master_key + b"S2C-MAC")

    def process_incoming_packet(self, packet):
        if self.phase == "TERMINATED":
            raise ValueError("Terminated connection is not allowed to communicate.")
        
        if len(packet) < 55:
            self.phase = "TERMINATED"
            raise ValueError("Packet too short to be valid.")

        packet_opcode = packet[0]

        if self.phase == "INIT":
            if packet_opcode != 20:
                print(f"Client: packetcode: {type(packet_opcode)}, {packet_opcode}")
                self.phase = "TERMINATED"
                raise ValueError("Invalid OPCODE during initialization phase.")
        elif self.phase == "ACTIVE":
            if not (packet_opcode == 40 or packet_opcode == 50 or packet_opcode == 60):
                self.phase = "TERMINATED"
                raise ValueError(f"Unexpected OPCODE during ACTIVE phase.")
        
        if packet_opcode == 50 or packet_opcode == 60:
            self.phase = "TERMINATED"
            raise ValueError(f"Session terminated by Server for OPCODE: {packet_opcode}")


        packet_round = int.from_bytes(packet[2:6], 'big')

        if packet_round != self.cur_round:
            self.phase = "TERMINATED"
            raise ValueError("Unmatching round number: Replay or Desync Attack")

        packet_without_hmac = packet[:-32]
        packet_hmac = packet[-32:]

        if packet_hmac != compute_hmac(self.S2C_Mac, packet_without_hmac):
            self.phase = "TERMINATED"
            raise ValueError("Tampering Detected: Mismatched HMAC")
        
        packet_direction = packet[6]

        if packet_direction != 0:
            raise ValueError("Invalid Direction: Possible Desync or Replay")

        packet_iv = packet[7:23]
        packet_ciphertext = packet[23:-32]

        try:
            plaintext = aes_decrypt(self.S2C_Enc, packet_iv, packet_ciphertext)
        except ValueError:
            raise ValueError("Invalid Padding.")

        # TODO : Step 6 of Receiver Validate Plaintext

        self.S2C_Enc = compute_hash(self.S2C_Enc + plaintext)[:16]
        self.S2C_Mac = compute_hash(self.S2C_Mac + packet_opcode.to_bytes(1, "big"))

        self.cur_round += 1

        return packet_opcode, packet_iv, packet_ciphertext, plaintext
    
    def prepare_packet(self, opcode, data, iv):
        direction = 1

        ciphertext = aes_encrypt(self.C2S_Enc, data, iv)

        opcode_byte = opcode.to_bytes(1, "big")
        clientID_byte = self.clientID.to_bytes(1, "big")
        round_bytes = self.cur_round.to_bytes(4, 'big') 
        direction_byte = direction.to_bytes(1, "big")

        main_body =  opcode_byte + clientID_byte + round_bytes + direction_byte + iv + ciphertext
        hmac = compute_hmac(self.C2S_Mac, main_body)
        packet = main_body + hmac

        self.C2S_Enc = compute_hash(self.C2S_Enc + ciphertext)[:16]
        self.C2S_Mac = compute_hash(self.C2S_Mac + iv)

        return packet
    
    def prepare_error_packet(self, opcode, error_message, iv):
        direction = 1

        ciphertext = aes_encrypt(self.C2S_Enc, error_message, iv)

        opcode_byte = opcode.to_bytes(1, "big")
        clientID_byte = self.clientID.to_bytes(1, "big")
        round_bytes = self.cur_round.to_bytes(4, 'big') 
        direction_byte = direction.to_bytes(1, "big")

        main_body =  opcode_byte + clientID_byte + round_bytes + direction_byte + iv + ciphertext
        hmac = compute_hmac(self.C2S_Mac, main_body)
        packet = main_body + hmac

        self.phase = "TERMINATED"

        return packet