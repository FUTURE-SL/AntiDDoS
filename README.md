# 🛡️ SCP: Secret Laboratory — Server DDoS Protection
A high-performance **DDoS mitigation layer** built for the backend of **SCP: Secret Laboratory**, powered by the **LabAPI** framework.  
This module focuses on *stateless integrity*, *optimizations*, and *robust exploit prevention* without introducing latency or instability.

⚠️ This plugin will not protect you from the following attacks:
- Bandwidth saturation
- Clients with real (non-spoofed) IP addresses (consider using iptables protection below to counter this)
- Spoofing attacks that exceed your CPU's processing capacity (the plugin is technically capable of handling attacks only within a single CPU thread)

---

👉 You can additionally protect your server using iptables rules here:
🔗 https://github.com/FUTURE-SL/SCPSL-iptables

---

## ✨ Features

### 🔐 Stateless Anti-Spoofing (SipHash-2-4 Challenge–Response)
- Implements a **stateless challenge–response system** to filter spoofed or malicious connection attempts.
- Effectively mitigates spoof-based DDoS and connection floods.

### 🧠 Rewritten Source Engine Query System
- The Source Engine Query protocol is **fully reimplemented** under the stateless SipHash-2-4 model.
- Protects against query-flood attacks while maintaining compatibility and fast response times.

### ⚙️ Network thread safety control
- Detects unsafe multithreading and warns if plugins (or NW code :sweat_smile:) may harm network stability.

---

## 🐞 Fixed Exploits

### ✔️ Memory Exhaustion via Fragmented Packets
Fixes a vulnerability where fragmented or intentionally malformed packets caused uncontrolled RAM usage.

### ✔️ CPU overload via "Messages bomb"
Fixes a vulnerability that allows a large number of “server-heavy” short messages to be sent simultaneously.

---

## 🚀 Optimizations

### 📉 Network Log Rate Limiter
Prevents log flooding and improves clarity by limiting repetitive network log entries.

### 🧹 Bug Fix
Fixes the lack of cleaning observers with missing identity.  
Eliminates the error: **“Found 'null' entry in observing list...”**
