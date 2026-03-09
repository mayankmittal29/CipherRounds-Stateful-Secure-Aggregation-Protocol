# SECURITY.md - Stateful Aggregation Protocol Analysis

## 1. Security Design Principles

### 1.1 Cryptographic Ratcheting (Key Evolution)
This implementation uses **Symmetric Key Ratcheting**. 
* **Encryption Keys** evolve based on the hash of the previous round's ciphertext.
* **MAC Keys** evolve based on the hash of the previous round's IV/Opcode.
This ensures **Forward Secrecy** within the session: compromising the keys used in Round i does not automatically allow an attacker to decrypt Round i-1 or forge Round i+1.

### 1.2 Unified Header & Payload Integrity
Every packet contains a header that includes the `ClientID`, `RoundNumber`, and `Direction`. The **HMAC-SHA256** signature covers the entire packet. This creates a cryptographic bind between the protocol's state (the round number) and the data (the ciphertext).

---

## 2. Defensive Scenarios



### 2.1 Protection Against Replay & Reordering
The protocol enforces a strict **Stateful Sequence**. The server maintains a persistent `cur_round` counter for every connected client.
* **Mechanism:** When a packet is received, the server first validates the HMAC. Because the MAC keys evolve every round, an "old" packet (Replay) or a "future" packet (Reorder) will result in a MAC mismatch.
* **Defense:** Even if an adversary captures a valid packet, they cannot re-inject it later because the server's expected key state has already progressed. Any out-of-order arrival results in immediate session termination.

### 2.2 Resistance to Key Desynchronization
Key Desynchronization occurs if one party advances their cryptographic state while the other does not (e.g., if a response is dropped by an attacker).
* **Mechanism:** Our implementation uses a non-blocking `select` loop with a re-transmission timeout. 
* **Defense:** If a response is dropped, the client re-sends its data. However, since the server has already evolved its keys for that round, the re-sent data will fail the integrity check. The server identifies this as a state synchronization failure, logs the error, and permanently closes the connection to prevent a potential man-in-the-middle from exploiting the desync.



### 2.3 Integrity and Modification Attacks
The protocol is designed to detect bit-level tampering in either the header or the ciphertext.
* **Mechanism:** HMAC-SHA256 verification occurs before any decryption or data processing.
* **Defense:** Any modification to the ciphertext, the IV, or the round number in the header will produce a different HMAC. The server catches this mismatch, identifies it as an integrity violation, and transitions to the `TERMINATED` state before the logic layer is ever exposed to the tampered data.

### 2.4 Reflection Attack Mitigation
An adversary might try to "reflect" the server's own messages back to it to bypass authentication.
* **Mechanism:** Every packet includes a `Direction` bit (1 for Client-to-Server, 0 for Server-to-Client).
* **Defense:** The FSM strictly validates the directionality. The server will reject any packet labeled with a "Server-to-Client" direction, rendering reflection attacks impossible.

---

## 3. Session Management & Failure Policy

The protocol implements a **"Fail-Fast"** security policy. Security is prioritized over session persistence:
1.  **Permanent Termination:** Any security violation (MAC mismatch, state error, or direction error) immediately moves the FSM to the `TERMINATED` state.
2.  **Encrypted Error Reporting:** Upon failure, the server attempts to send an encrypted **Opcode 60** (Termination) packet to the client before closing the socket.
3.  **Data Purging:** Once a session is terminated, the server clears all associated numeric data and state information for that client to ensure that no partial or compromised data is included in the final aggregation.

This architecture ensures that the protocol is not just robust against accidental errors, but actively resistant to the intentional manipulations of a network adversary.