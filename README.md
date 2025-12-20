# NS-3 Cyber Attack Simulation Suite

This project is a modular cybersecurity simulation library built for **NS-3**. It implements a custom C++ module (`ns3cybermod`) that allows users to easily simulate, detect, and analyze various network attacks in a controlled environment.

## 1. Project Overview

The simulation focuses on Layer 3 and Layer 4 network attacks, utilizing a custom library to generate malicious traffic and capture metrics.

### Implemented Attack Scenarios

| Attack Type | File Name | Description |
| :--- | :--- | :--- |
| **UDP Flood** | `scenario-udp-flood` | **Volumetric DoS.** Floods the victim with high-bandwidth UDP traffic to saturate network links. |
| **TCP Flood** | `scenario-tcp-flood` | **Service Exhaustion.** Overwhelms the victim's connection queue (e.g., Port 80) with rapid TCP requests. |
| **IP Spoofing** | `scenario-spoofing` | **Identity Theft.** Attackers forge the "Source IP" in packet headers to frame innocent nodes. |
| **Replay Attack** | `scenario-replay` | **Man-in-the-Middle.** Captures legitimate traffic and re-transmits it later to duplicate transactions. |

---

## 2. Installation & Setup

Prerequisite: You must have a working installation of **NS-3 (ns-3-dev)**.

### Step 1: Clone or Download
Clone this repository to your local machine.

### Step 2: Install the Custom Module
Copy the `ns3cybermod` folder from this repo's `src/` directory into your NS-3 `src/` directory.
```bash
cp -r ns3-cyber-project/src/ns3cybermod ~/ns-3-dev/src/

```

### Step 3: Install the Scenarios

Copy the C++ files from this repo's `scratch/` directory into your NS-3 `scratch/` directory.

```bash
cp ns3-cyber-project/scratch/*.cc ~/ns-3-dev/scratch/

```

### Step 4: Rebuild NS-3

You must reconfigure NS-3 so it detects the new `ns3cybermod` library.

```bash
cd ~/ns-3-dev
./ns3 configure --enable-examples --enable-tests
./ns3 build

```

---

## 3. How to Run

Since the project is modular, you do not run a single file with flags anymore. Instead, you run the specific **scenario file** for the attack you want to simulate.

**Example: Running the TCP Flood**

```bash
./ns3 run scratch/scenario-tcp-flood

```

See `Commands.md` for the full list of commands and expected outputs.

### 5. Optional: Generating PCAP Files (Wireshark)

To view these attacks in Wireshark, you can modify any scenario file (e.g., `scenario-udp-flood.cc`) and add this line just before `Simulator::Run();`:

```cpp
csma.EnablePcapAll("cyber-attack");

```

**Then run:**

```bash
./ns3 run scratch/scenario-udp-flood

```

**View Results:**
Open the generated `.pcap` files in Wireshark to inspect the packet headers manually.
