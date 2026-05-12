# HoneyIoT-NG

**Multi-Attack Detection and Autonomous Reconfiguration in IoT Networks
Using a High-Interaction Honeypot on Contiki-NG/Cooja**

**Student:** Anam Sabah Khan (G202402840)
**Supervisor:** Dr. Waleed Al Gobi
**University:** King Fahd University of Petroleum and Minerals
**Department:** Information and Computer Science — Term 252

---

## Overview

HoneyIoT-NG is a high-interaction IoT honeypot framework built in
Contiki-NG and tested in the Cooja simulator. It detects 5 attack
types and autonomously reconfigures the entire network via IPv6
multicast (ff02::1) with no central controller.

**Overall effectiveness: 95.65% across 1,655 attack transmissions.**

---

## File Guide

### Condition C - Full HoneyIoT-NG (Main Experiment)

| File | Node(s) | Purpose |
|------|---------|---------|
| firmware/honeypot/udp-server-honeypot-reconfig-v2.c | 5, 6 | Primary & Secondary Honeypot |
| firmware/real-iot-nodes/finaludp-server-reconfig.c | 2, 3, 4 | Real IoT Devices |
| firmware/border-router/border-router.c | 1 (common for all conditions) | RPL DODAG Root (standard Contiki-NG) |
| firmware/attacker/single-attacker/2attacker-flood.c | 7 | Scenario 1: UDP Flood (T1498) |
| firmware/attacker/single-attacker/3attacker-scan.c | 7 | Scenario 2: Network Scan (T1046) |
| firmware/attacker/single-attacker/3attacker-unlock.c | 7 | Scenario 3: UNLOCK Injection (T1059) |
| firmware/attacker/single-attacker/3attacker-icmpv6-udp.c | 7 | Scenario 4: ICMPv6 Flood (T1498) |
| firmware/attacker/single-attacker/3attacker-rogue-ra.c | 7 | Scenario 5: Rogue RA (T1557) |

### Condition B - Passive Honeypot (Ablation Study)

| File | Node(s) | Purpose |
|------|---------|---------|
| firmware/honeypot/udp-server-honeypot-passive.c | 5, 6 | Detects attacks but does NOT broadcast BLOCK |
| firmware/real-iot-nodes/udp-server-reconfig.c | 2, 3, 4 | Real IoT Devices — no blocklist |

### Condition A - No Honeypot (Ablation Study)

| File | Node(s) | Purpose |
|------|---------|---------|
| firmware/real-iot-nodes/udp-server-reconfig.c | 2, 3, 4 | Real IoT only — no honeypot nodes loaded |

### Condition D - Multi-Attacker Scalability

| File | Node(s) | Purpose |
|------|---------|---------|
| firmware/attacker/multi-attacker/0multiudp-server-honeypot-reconfig-v2.c | 5, 6 | Honeypot (multi-attacker build) |
| firmware/attacker/multi-attacker/0multiudp-server-reconfig.c | 2, 3, 4 | Real IoT (multi-attacker build) |
| firmware/attacker/multi-attacker/multiattacker-flood-node7.c | 7 | UDP Flood attacker |
| firmware/attacker/multi-attacker/multiattacker-scan-node8.c | 8 | Network Scan attacker |

---

## Attack Results

| Attack | Tx | Rx | Effectiveness |
|--------|----|----|---------------|
| UDP Flood | 924 | 153 | 94.48% |
| Network Scan | 141 | 9 | 97.87% |
| UNLOCK Injection | 145 | 9 | 97.93% |
| ICMPv6 Flood | 289 | 36 | 95.85% |
| Rogue RA | 156 | 9 | 98.08% |
| **Overall** | **1,655** | **216** | **95.65%** |

---

## Ablation Study

| Condition | Effectiveness |
|-----------|---------------|
| No Honeypot | ~0.07% |
| Passive Honeypot (detection only) | ~0.27% |
| Full HoneyIoT-NG | **95.65%** |

Autonomous reconfiguration is the critical component.

---

## How to Run

### Requirements
- Ubuntu 22.04 or 24.04
- Contiki-NG v5.1
- Cooja Network Simulator
- Java (for Cooja)

### Steps
1. Copy firmware files into your contiki-ng/examples/rpl-udp/ folder
2. Open Cooja: cd ~/contiki-ng/tools/cooja && ant run
3. File → Open Simulation → select .csc from cooja-simulations/
4. Load correct firmware on each node as per File Guide table above
5. Press Start Simulation

---

## Platform
- OS: Ubuntu 24.04
- Framework: Contiki-NG v5.1
- Simulator: Cooja
- Language: C (firmware) + Python (validation + ML)
