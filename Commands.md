# Simulation Commands & Cheat Sheet

This document outlines how to run the four specific attack scenarios included in the `ns3cybermod` suite.

---

### 1. Volumetric Attack (UDP Flood)
**Goal:** Test network saturation and packet loss.
This scenario sets up 3 Attackers and 1 Victim. The attackers blast UDP packets at 50Mbps each.

**Command:**
```bash
./ns3 run scratch/scenario-udp-flood

```

**Expected Output:**

* **Packets Sent:** High (e.g., ~15,000)
* **Packets Received:** Lower than sent.
* **Observation:** The difference between Sent/Received represents packets dropped due to congestion.

---

### 2. Service Exhaustion (TCP Flood)

**Goal:** Test server resource exhaustion (e.g., Web Server Port 80).
This scenario targets TCP connections. It verifies that the simulation correctly handles connection-oriented protocols.

**Command:**

```bash
./ns3 run scratch/scenario-tcp-flood

```

**Expected Output:**

* **Attackers:** 3 Nodes attacking Port 80.
* **Packets:** Shows successful TCP connection attempts and data transfer.

---

### 3. Identity Theft (IP Spoofing)

**Goal:** Demonstrate IP Header manipulation.
Attackers randomly select other nodes in the network and use *their* IP addresses as the Source IP.

**Command:**

```bash
./ns3 run scratch/scenario-spoofing

```

**Expected Output:**

* Look for logs like: `[IP SPOOFING] Attacker 0 impersonating PC4`.
* This confirms the randomization logic in the library is working.

---

### 4. Man-in-the-Middle (Replay Attack)

**Goal:** Capture and re-transmit traffic.

* **Phase 1 (1s-4s):** "Normal" background traffic flows between nodes.
* **Phase 2 (6s-10s):** Attacker captures this traffic and replays it.

**Command:**

```bash
./ns3 run scratch/scenario-replay

```

**Expected Output:**

* Look for logs like: `[REPLAY] Attacker 0 replaying packet...`.
* Verifies the "Traffic Capture" feature of the library.

---
