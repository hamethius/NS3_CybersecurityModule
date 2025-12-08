# NS-3 Cybersecurity Simulation: Attacks & Defense Module

This project simulates a network environment in **NS-3** consisting of an **Attacker Node** and a **Victim Node**. It implements three distinct cyber attacks and a corresponding Defense Module (IDS/Firewall) to detect and mitigate them using Layer 3 inspection.

## 1\. Project Overview

### Attacks Implemented (Attacker Node)

1.  **UDP Flood:** Continuous, recursive packet stream designed to overwhelm the victim's processing capacity (DoS).
2.  **ICMP Flood:** Simulated via UDP Port 0 to mimic Ping flooding.
3.  **Malware Injection:** Packets containing a specific malicious payload signature ("MALWARE\_HASH").

### Defenses Implemented (Victim Node)

1.  **Rate Limiting:** Detects high-volume traffic from a single IP and drops packets exceeding a threshold (50 pkts/sec).
2.  **Protocol Filtering:** Inspects headers to block malformed traffic (e.g., UDP targeting Port 0).
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
3.  Paste the **final C++ code** provided in the project source into `cyb-project.cc`.

-----

## 4\. How to Run & Read Logs

### Basic Execution

To run the simulation with all attacks enabled and view the detailed log:

```bash
./ns3 run scratch/cyb-project
```

### Understanding the Output

The console output is now organized into a structured audit trail with the following columns:
`[TIME] | [NODE] | [SRC IP] | [PROTO] | [ACTION] | [REASON / INFO]`

The logs use color coding to indicate status:

  * **\<span style="color:green"\>GREEN (PASS):\</span\>** Legitimate traffic (e.g., TCP Background traffic).
  * **\<span style="color:red"\>RED (DROP):\</span\>** Flood Detected (Rate Limit Exceeded).
  * **\<span style="color:yellow"\>YELLOW (DROP):\</span\>** Protocol Violation (Fake ICMP/Port 0).
  * **\<span style="color:purple"\>PURPLE (DROP):\</span\>** Malware Signature Detected (DPI Block).

-----

## 5\. Configuration & Scenarios

You can enable or disable specific parts of the simulation using command-line flags.

### Available Flags

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--summary` | **New\!** Reduces log spam (shows only 3 drops/sec) | `false` |
| `--firewall` | Master switch for the Defense Module | `true` |
| `--defenseFlood` | Enable/Disable Rate Limiting | `true` |
| `--defenseIcmp` | Enable/Disable Port 0 Filtering | `true` |
| `--defenseMalware` | Enable/Disable Deep Packet Inspection | `true` |
| `--attackFlood` | Run UDP Flood Attack | `true` |
| `--attackIcmp` | Run ICMP Flood Attack | `true` |
| `--attackMalware` | Run Malware Attack | `true` |

### Example Scenarios

#### Scenario A: Clean Terminal View (Recommended)

Use summary mode to suppress the thousands of "Flood Detected" messages. This makes it easy to see the Malware and ICMP blocks on the screen.

```bash
./ns3 run "scratch/cyb-project --summary=true"
```

#### Scenario B: Full Audit Log (For Reports)

Capture every single packet decision (authorized and dropped) into a text file for analysis.

```bash
./ns3 run scratch/cyb-project > log_full.txt
```

#### Scenario C: "Malware Analysis"

Disable the noisy Flood attacks to isolate the Malware Detection logic.

```bash
./ns3 run "scratch/cyb-project --attackFlood=false --attackIcmp=false"
```

#### Scenario D: "Defense Failure"

Turn off the firewall completely to see the network process all malicious traffic (no blocked messages).

```bash
./ns3 run "scratch/cyb-project --firewall=false"
```
