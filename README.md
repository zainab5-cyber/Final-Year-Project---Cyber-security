# Adaptive Entropy and Trust-Based DDoS Detection and Mitigation in MANETs
**Final Year Project — B.S. Cybersecurity (Session 2022–2026)**  
Department of Information Security, Faculty of Computing  
The Islamia University of Bahawalpur  
Supervised by Ms. Rabia Kamran  & Dr. Waqar Aslam
Co-authored with Maryam Ilyas

This project presents an adaptive Intrusion Detection and Prevention System (IDPS) for Mobile Ad Hoc Networks (MANETs) to detect and mitigate Distributed Denial-of-Service (DDoS) attacks. Implemented in NS-3 using C++ and the AODV routing protocol, the framework combines packet count, packet rate, entropy analysis, and trust-based node evaluation to identify malicious behavior while preserving network performance. Simulation results were analyzed using FlowMonitor, NetAnim, and Wireshark to evaluate metrics such as Packet Delivery Ratio (PDR), throughput, packet loss, and end-to-end delay.

## The Problem
Mobile Ad Hoc Networks (MANETs) have no central base station. This makes them useful in disaster relief, military operations, and IoT deployments — and easy targets for DDoS attacks. Existing defences use fixed trust thresholds: if a node's traffic exceeds a static cutoff, it gets flagged. The problem is that attackers can learn these thresholds and stay just below them. Fixed rules also cause false positives, blocking legitimate nodes that happen to send a burst of normal traffic.
This project builds a detection and mitigation framework that combines three real-time techniques — packet count monitoring, rate-based analysis, and Shannon entropy measurement — with a dynamic trust scoring layer that responds proportionally rather than blocking immediately.

## Simulation Setup
- **Simulator:** NS-3 (v3.43), implemented in C++
- **Routing protocol:** AODV
- **Nodes:** 50 mobile nodes
- **Area:** 1000m × 1000m
- **Mobility model:** Random Waypoint
- **Wireless standard:** IEEE 802.11b
- **Traffic:** UDP On-Off (CBR), attack rate 1–10 Mbps
- **Simulation duration:** 200 seconds
- **Attack types:** UDP flooding (single-source and distributed)
- **Trust threshold:** 0.7 (no action) / 0.4 (blacklist boundary)

Three scenarios were compared:
1. Normal operation — no attack
2. DDoS attack with no mitigation
3. DDoS attack with the proposed detection + mitigation enabled

## Results
**Without mitigation:** DDoS attack caused sharp PDR degradation, throughput instability, and significant packet loss as malicious nodes overwhelmed the network.

**With mitigation enabled:** PDR recovered substantially. The Wireshark I/O graph (200-second capture) shows packet rate stabilising after the mitigation layer activated. FlowMonitor statistics confirmed improved transmission bitrates and reduced packet loss across monitored flows.

**Detection logs confirmed:** entropy-based distributed DDoS detection (H > 3.5) correctly identified coordinated multi-source attacks that count and rate methods alone would not have caught. Count and rate detection activated first for single-source flooding, with blacklisting enforced within seconds of threshold breach.

The combined detection + mitigation approach outperformed detection-only and static-threshold-only baselines on both PDR and throughput, with reduced false positives due to proportional response rather than immediate isolation.

Full result graphs, FlowMonitor XML output, Wireshark capture (merge.pcap), and NetAnim traces are in  branch `/keyfindings`.

## Built With

- NS-3 v3.43 — C++ simulation
- Python — result analysis (Matplotlib, Pandas)
- Wireshark — packet capture analysis
- NetAnim — network visualisation
