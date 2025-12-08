# NS-3 Simulation Commands & Cheatsheet

This document outlines the various ways to run the Cybersecurity simulation, including how to isolate attacks, test specific defenses, and manage log output.

### 1\. The "Run Everything" Scenarios (Recommended)

These are the best ways to run the full simulation with all attacks (UDP, ICMP, Malware) and defenses active.

**A. Clean Terminal View (Best for Live Demo)**
Uses the **Summary Mode** to suppress the massive amount of Flood logs. You will see the attacks start and stop, and catch the specific Malware/ICMP events clearly on the screen.

```bash
./ns3 run "scratch/cyb-project --summary=true"
```

**B. Full Audit Log (Best for Reports)**
Runs the simulation in detailed mode and saves **every single packet decision** to a text file. The terminal will remain empty, but the file will contain the complete audit trail.

```bash
./ns3 run scratch/cyb-project > full_audit_log.txt
```

-----

### 2\. Attack Scenarios (Isolate Specific Attacks)

Use these to turn off the "noise" of other attacks and focus on testing one specific vector.

**A. Test Only Malware Detection**
Disable the floods so you can clearly see the Deep Packet Inspection (DPI) logic working without distraction.

```bash
./ns3 run "scratch/cyb-project --attackFlood=false --attackIcmp=false"
```

**B. Test Only Rate Limiting (UDP Flood)**
Isolate the flood to see if the threshold triggers correctly.
*(Note: This produces a lot of logs, so you might want to add `--summary=true`)*

```bash
./ns3 run "scratch/cyb-project --attackIcmp=false --attackMalware=false --summary=true"
```

**C. Test Only ICMP/Port Filtering**
Check if the specific Port 0 filter is working against the fake ICMP attack.

```bash
./ns3 run "scratch/cyb-project --attackFlood=false --attackMalware=false"
```

-----

### 3\. Defense Failure Scenarios (Simulate Vulnerabilities)

Use these to prove that your defenses are actually working by turning them off and observing the failure.

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
*Result:* All attacks pass through successfully. Valid traffic is marked as "PASS (Firewall Disabled)".

```bash
./ns3 run "scratch/cyb-project --firewall=false"
```

-----

### 4\. Cheat Sheet: All Available Flags

| Flag | Default | Function |
| :--- | :--- | :--- |
| `--summary` | `false` | **Log Reducer.** If true, shows only 3 events/sec to keep terminal clean. |
| `--firewall` | `true` | **Master Switch.** If false, the defense module does nothing. |
| `--defenseFlood` | `true` | **Rate Limiter.** If false, ignores high packet rates. |
| `--defenseIcmp` | `true` | **Port Filter.** If false, allows traffic to Port 0. |
| `--defenseMalware` | `true` | **DPI.** If false, ignores packet payload signatures. |
| `--attackFlood` | `true` | **UDP Flood.** If false, attacker stops sending flood packets. |
| `--attackIcmp` | `true` | **ICMP Flood.** If false, attacker stops sending ICMP packets. |
| `--attackMalware` | `true` | **Malware.** If false, attacker stops sending the malware packet. |
