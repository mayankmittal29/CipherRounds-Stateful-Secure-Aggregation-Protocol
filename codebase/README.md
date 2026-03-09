# Stateful Secure Aggregation Protocol

This project implements a secure, multi-client data aggregation protocol designed to resist active network adversaries. It features a custom Finite State Machine (FSM) with symmetric key ratcheting to ensure message integrity, freshness, and synchronization.

---

## 1. Prerequisites & Environment Setup

The project is bundled with a pre-configured Python virtual environment containing the necessary cryptographic libraries (`pycryptodome`).

To set up the environment, extract the folder and run the following command in your terminal:

```bash
source ./snsenv/bin/activate

```

---

## 2. Standard Operation (Data Aggregation)

Follow these steps to run a normal session where multiple clients submit data for aggregation:

1. **Start the Server**:
```bash
python3 server.py

```


2. **Start Multiple Clients**:
Open several new terminals (one for each client) and run:
```bash
python3 client.py

```


3. **Configuration**:
* Each client will prompt you for a **Client ID**.
* The script automatically extracts the correct **Master Key** from `MasterKeys.csv` based on the ID provided.


4. **Usage**:
* Enter numeric values in the client terminals when prompted.
* The server collects these values and, after the aggregation window (10 seconds), sends the total sum back to all connected clients.



---

## 3. Interactive Attack Simulations

To test the security of the protocol against a Man-in-the-Middle (MitM) adversary, use the `attack.py` bridge.

### Setup for Attacks

1. **Terminal 1 (Server)**: Start the server normally.
```bash
python3 server.py

```


2. **Terminal 2 (Attacker)**: Start the interactive MitM bridge.
```bash
python3 attack.py

```


3. **Terminal 3 (Victim)**: Start the victim client.
```bash
python3 client_victim.py

```


* Enter a Client ID (e.g., 1, 2, or 3) when prompted. This client is hardcoded to connect to the Attacker Bridge on port `65433`.



### Executing the Attacks

The `attack.py` terminal acts as a gateway. Every time a message is sent (either from the Victim to the Server or vice versa), the attacker script will intercept it and provide an interactive menu. The terminal output is designed to guide you through the simulation step-by-step.

**Available Attack Options:**

* **Tamper HMAC**: Flips bits in the HMAC suffix to simulate a modification attack.
* **Replay Past Packet**: Allows you to select an old round number from the history and re-inject it into the session.
* **Reorder Attack**: Internally jumps the round number sequence (to a value like 99) to simulate out-of-order delivery and state inconsistency.
* **Drop Packet**: Blocks the message entirely. Use this on a Server-to-Client response to trigger **Key Desynchronization**.
* **Pass**: Forwards the packet transparently without modification.

The logs in `server.py` or `client_victim.py` will display the specific protocol error (e.g., "Integrity Failure" or "Replay Detected") triggered by your choice.

---

## 4. Project Structure

* **`server.py`**: The aggregation server handling multiple client states using `selectors`.
* **`client.py`**: Standard client for normal aggregation.
* **`client_victim.py`**: Client configured to connect via the MitM proxy port (`65433`).
* **`attack.py`**: The interactive MitM bridge and attack injector.
* **`protocol_fsm.py`**: The core logic implementing ratcheting and verification.
* **`crypto_utils.py`**: Wrapper for AES-CBC and HMAC-SHA256 primitives.
* **`MasterKeys.csv`**: Database for client master secrets.
* **`SECURITY.md`**: Detailed explanation of the protocol's defensive design.

---
