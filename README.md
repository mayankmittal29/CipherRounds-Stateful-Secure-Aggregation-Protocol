# 🔐 CipherRounds – Stateful Secure Aggregation Protocol

A **secure multi-client communication protocol** designed for hostile network environments.  
The system ensures **confidentiality, integrity, synchronization, and replay protection** using **AES-128-CBC encryption**, **HMAC-SHA256 authentication**, and **cryptographic key ratcheting**.

Built as part of the **System and Network Security Course** at **IIIT Hyderabad**.

---

# 📌 Project Description

CipherRounds implements a **stateful symmetric-key protocol** where multiple clients securely send numeric data to a central server which aggregates the values and returns encrypted results.

The protocol operates under a **strong adversarial threat model** where attackers can:

- Replay packets
- Modify ciphertext
- Drop packets
- Reorder packets
- Perform reflection attacks

Despite these threats, the protocol guarantees:

✅ Data confidentiality  
✅ Message integrity  
✅ Replay protection  
✅ Forward secrecy within sessions  
✅ Strict protocol synchronization  

---

# 🏗️ System Architecture

```

Clients → Secure Encrypted Channel → Server

```

Each client shares a **unique symmetric master key** with the server.

Communication happens in **stateful rounds** where:

- Keys evolve after every successful message
- Round numbers enforce strict ordering
- Protocol FSM enforces valid transitions

---

# ⚙️ Cryptographic Design

| Component | Implementation |
|-----------|---------------|
| Block Cipher | AES-128 |
| Mode | CBC |
| MAC | HMAC-SHA256 |
| Padding | Manual PKCS#7 |
| Randomness | OS Secure RNG |

🚫 Forbidden:
- AES-GCM
- Fernet
- Automatic padding
- Authenticated encryption modes

---

# 🔑 Key Initialization

Each client **Ci** shares a master key **Ki** with the server.

Initial keys are derived using hashing:

```

C2S_Enc_0 = H(Ki || "C2S-ENC")
C2S_Mac_0 = H(Ki || "C2S-MAC")

S2C_Enc_0 = H(Ki || "S2C-ENC")
S2C_Mac_0 = H(Ki || "S2C-MAC")

```

---

# 🔄 Key Evolution (Cryptographic Ratcheting)

Keys evolve after every successful round.

Client → Server

```

C2S_Enc_{R+1} = H(C2S_Enc_R || Ciphertext_R)
C2S_Mac_{R+1} = H(C2S_Mac_R || Nonce_R)

```

Server → Client

```

S2C_Enc_{R+1} = H(S2C_Enc_R || AggregatedData_R)
S2C_Mac_{R+1} = H(S2C_Mac_R || StatusCode_R)

```

This ensures **forward secrecy within the session**.

---

# 📦 Message Format

```

| Opcode (1) | ClientID (1) | Round (4) | Direction (1) | IV (16) |
| Ciphertext (variable) | HMAC (32) |

```

The **HMAC covers the entire packet**.

---

# 📡 Protocol Opcodes

| Opcode | Type | Description |
|------|------|-------------|
| 10 | CLIENT_HELLO | Client initiates protocol |
| 20 | SERVER_CHALLENGE | Encrypted server challenge |
| 30 | CLIENT_DATA | Encrypted numeric data |
| 40 | SERVER_AGGR_RESPONSE | Aggregated result |
| 50 | KEY_DESYNC_ERROR | Desynchronization detected |
| 60 | TERMINATE | Session termination |

---

# 🧠 Protocol State Machine

Each client session maintains:

- Current round number
- Encryption keys
- MAC keys
- Protocol phase

Valid phases:

```

INIT → ACTIVE → TERMINATED

```

A message is accepted **only if**:

✔ Correct round number  
✔ Valid opcode for phase  
✔ Correct HMAC  

Failure of any check **terminates the session immediately**.

---

# 📁 Project Structure

```

.
├── server.py
├── client.py
├── client_victim.py
├── attack.py
├── protocol_fsm.py
├── crypto_utils.py
├── MasterKeys.csv
├── README.md
└── SECURITY.md

````

| File | Description |
|-----|-------------|
| `server.py` | Aggregation server handling multiple clients |
| `client.py` | Normal client |
| `client_victim.py` | Client used in attack simulations |
| `attack.py` | Man-in-the-middle attack simulator |
| `protocol_fsm.py` | Protocol logic and state machine |
| `crypto_utils.py` | AES-CBC, PKCS#7 padding, HMAC implementation |
| `MasterKeys.csv` | Pre-shared client master keys |
| `SECURITY.md` | Security analysis |

---

# 🖥️ Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/cipherrounds.git
cd cipherrounds
````

Activate the environment:

```bash
source ./snsenv/bin/activate
```

Dependencies include:

* Python 3.x
* pycryptodome

---

# ▶️ Running the System

## 1️⃣ Start Server

```bash
python3 server.py
```

---

## 2️⃣ Start Clients

Open multiple terminals and run:

```bash
python3 client.py
```

Each client will ask for:

```
Client ID
```

The master key will automatically be loaded from:

```
MasterKeys.csv
```

---

## 3️⃣ Enter Data

Clients can input numeric values.

The server aggregates them and sends back:

```
Encrypted aggregated result
```

---

# ⚔️ Attack Simulation (MitM)

This project includes a **Man-in-the-Middle attack simulator**.

### Setup

Terminal 1:

```
python3 server.py
```

Terminal 2:

```
python3 attack.py
```

Terminal 3:

```
python3 client_victim.py
```

---

# 🧪 Supported Attack Simulations

The attacker can perform:

### 🔁 Replay Attack

Resends an old packet.

**Defense:**
MAC key ratcheting causes verification failure.

---

### 🔀 Reordering Attack

Packets delivered out of order.

**Defense:**
Round number validation terminates session.

---

### ✏️ Tampering Attack

Modify ciphertext or header bits.

**Defense:**
HMAC verification fails.

---

### 📉 Packet Drop Attack

Attacker drops server responses.

**Defense:**
Desynchronization detected → session termination.

---

### 🔁 Reflection Attack

Server messages sent back to server.

**Defense:**
Direction field validation blocks reflection.

---

# 🛡️ Security Properties

| Property          | Implementation         |
| ----------------- | ---------------------- |
| Confidentiality   | AES-128-CBC encryption |
| Integrity         | HMAC-SHA256            |
| Replay Protection | Stateful round numbers |
| Forward Secrecy   | Key ratcheting         |
| Synchronization   | FSM state enforcement  |

---

# 🚨 Fail-Fast Security Policy

Any security violation results in:

1️⃣ Immediate session termination
2️⃣ Encrypted termination message
3️⃣ Session state purge

This prevents attackers from exploiting partial failures.

---

# 🎓 Course Information

**Course:** System and Network Security
**Institute:** IIIT Hyderabad
**Assignment:** Secure Multi-Client Communication Protocol

---

# 👨‍💻 Authors

Developed as part of the **SNS Lab Assignment** by:-
***Mayank Mittal***
***Aryaman Mahajan***
***Vansh Motwani***
---

# ⭐ Future Improvements

* TLS-like handshake mechanism
* Better attack visualization
* Performance benchmarking
* Distributed aggregation servers

---

# 📜 License

This project is for **academic and educational purposes**.
