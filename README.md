# NS-3 Cybersecurity Simulation: Attacks & Defense Module

This project simulates a network environment in **NS-3** consisting of an **Attacker Node** and a **Victim Node**. It implements three distinct cyber attacks and a corresponding Defense Module (IDS/Firewall) to detect and mitigate them.

## 1\. Project Overview

### Attacks Implemented (Attacker Node)

1.  **UDP Flood:** Continuous, recursive packet stream designed to overwhelm the vitim's processing capacity (DoS).
2.  **ICMP Flood:** Simulated via UDP Port 0 to mimic Ping flooding.
3.  **Malware Injection:** Packets containing a specific malicious payload signature ("MALWARE\_HASH").

### Defenses Implemented (Victim Node)

1.  **Rate Limiting:** Detects high-volume traffic from a single IP and temporarily drops packets.
2.  **Protocol Filtering:** Inspects headers to block malformed traffic (e.g., UDP to Port 0).
3.  **Deep Packet Inspection (DPI):** Scans packet payloads for known malware signatures.

-----

## 2\. Installation & Prerequisites

If you have not set up NS-3 yet, run these commands on your Ubuntu machine:

```bash
# 1. Install Dependencies
sudo apt update
sudo apt install -y build-essential python3-dev cmake git g++ python3-setuptools

# 2. Clone NS-3 Repository
git clone https://gitlab.com/nsnam/ns-3-dev.git
cd ns-3-dev

# 3. Build NS-3
./ns3 configure --enable-examples --enable-tests
./ns3 build
```

-----

## 3\. Setup

1.  Navigate to the scratch directory:
    ```bash
    cd ns-3-dev/scratch
    ```
2.  Create the project file:
    ```bash
    touch cyb-project.cc
    ```
3.  Paste the **final C++ code** provided into `cyb-project.cc`.

-----

## 4\. How to Run

### Basic Execution

To run the simulation with **all attacks** and **all defenses** enabled (By Default):

```bash
./ns3 run scratch/cyb-project
```

### Understanding the Output

The console uses color-coded logs to indicate events:

  * **RED:** Flood Detected (Rate Limiting triggered).
  * **YELLOW:** Protocol Violation (ICMP/Port 0 packet blocked).
  * **PURPLE:** Malware Signature Detected (DPI Block).

-----

## 5\. Configuration & Scenarios

You can enable or disable specific parts of the simulation using command-line flags without changing the code.

### Available Flags

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--firewall` | Master switch for the Defense Module | `true` |
| `--defenseFlood` | Enable/Disable Rate Limiting | `true` |
| `--defenseIcmp` | Enable/Disable Port 0 Filtering | `true` |
| `--defenseMalware` | Enable/Disable Deep Packet Inspection | `true` |
| `--attackFlood` | Run UDP Flood Attack | `true` |
| `--attackIcmp` | Run ICMP Flood Attack | `true` |
| `--attackMalware` | Run Malware Attack | `true` |

### Example Scenarios

#### Scenario A: The " Stress Test" (Default)

Run everything to see how the system handles multiple simultaneous threats.

```bash
./ns3 run scratch/cyb-project
```

#### Scenario B: "Malware Analysis"

Disable the noisy Flood attacks to clearly see the Malware Detection logic working.

```bash
./ns3 run "scratch/cyb-project --attackFlood=false --attackIcmp=false"
```

#### Scenario C: "Defense Failure"

Turn off the firewall completely to see the network process all malicious traffic (no blocked messages).

```bash
./ns3 run "scratch/cyb-project --firewall=false"
```

#### Scenario D: "Testing Specific Defenses"

Run attacks but disable the Rate Limiter to see the consequences of flooding.

```bash
./ns3 run "scratch/cyb-project --defenseFlood=false"
```
