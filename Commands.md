### 1\. The "Run Everything" Command (Default)

This runs the simulation with **all three attacks** (UDP Flood, ICMP, Malware) and **all defenses** enabled.

```bash
./ns3 run scratch/cyb-project
```

**What happens:** You will see the console light up with Red (Flood), Yellow (ICMP), and Purple (Malware) block messages.

-----

### 2\. Attack Scenarios (Isolate Specific Attacks)

Use these to turn off the "noise" and focus on testing one specific attack type.

**A. Test Only Malware Detection**
Disable the floods so you can clearly see the Deep Packet Inspection (DPI) logic working.

```bash
./ns3 run "scratch/cyb-project --attackFlood=false --attackIcmp=false"
```

**B. Test Only Rate Limiting (UDP Flood)**
Isolate the flood to see if the threshold triggers correctly without other distractions.

```bash
./ns3 run "scratch/cyb-project --attackIcmp=false --attackMalware=false"
```

**C. Test Only ICMP/Port Filtering**
Check if the specific Port 0 filter is working.

```bash
./ns3 run "scratch/cyb-project --attackFlood=false --attackMalware=false"
```

-----

### 3\. Defense Failure Scenarios (Simulate Vulnerabilities)

Use these to see "what happens" if a specific defense is missing or broken.

**D. Simulate Malware Infection (Defense OFF)**
Run the malware attack, but turn **OFF** the malware defense.
*Result:* You will see the attack launch, but **NO** "Malware Detected" message. The packet successfully reaches the victim.

```bash
./ns3 run "scratch/cyb-project --defenseMalware=false"
```

**E. Simulate Network Overload (Rate Limit OFF)**
Run the flood attack, but turn **OFF** the rate limiter.
*Result:* The attacker floods the network, but you will see **NO** "Flood Detected" messages.

```bash
./ns3 run "scratch/cyb-project --defenseFlood=false"
```

**F. Total System Failure**
Turn the entire firewall off.
*Result:* All attacks pass through successfully.

```bash
./ns3 run "scratch/cyb-project --firewall=false"
```

-----

### 4\. Cheat Sheet: All Available Flags

| Flag | Default | Function |
| :--- | :--- | :--- |
| `--firewall` | `true` | **Master Switch.** If false, the defense module does nothing. |
| `--defenseFlood` | `true` | **Rate Limiter.** If false, ignores high packet rates. |
| `--defenseIcmp` | `true` | **Port Filter.** If false, allows traffic to Port 0. |
| `--defenseMalware` | `true` | **DPI.** If false, ignores packet payload signatures. |
| `--attackFlood` | `true` | **UDP Flood.** If false, attacker stops sending flood packets. |
| `--attackIcmp` | `true` | **ICMP Flood.** If false, attacker stops sending ICMP packets. |
| `--attackMalware` | `true` | **Malware.** If false, attacker stops sending the malware packet. |

