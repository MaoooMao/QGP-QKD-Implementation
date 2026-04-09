# QGP-QKD-Implementation

Source code and supplementary figures for:

**"Implementation of QGP with Quantum Key and Post-Quantum Authentication"**

## Code Listings

### Fig. 1: QGP Sender (`sender_pqc.py`)
Alice signs a message with ML-DSA-65 and sends the signed packet through the CN4010 QKD-encrypted channel.

![Fig. 1](figures/Fig1_sender_pqc.png)

Source: [`src/sender_pqc.py`](src/sender_pqc.py)

---

### Fig. 2: QGP Receiver (`receiver_pqc.py`)
Bob unpacks the received data, extracts the signature and message, and verifies the ML-DSA-65 signature.

![Fig. 2](figures/Fig2_receiver_pqc.png)

Source: [`src/receiver_pqc.py`](src/receiver_pqc.py)

---

### Fig. 3: Key Interception via ETSI 014 API (`grab_keys.py`)
Demonstrates the ETSI 014 access isolation vulnerability by intercepting QKD keys at 2 keys/second.

![Fig. 3](figures/Fig3_grab_keys.png)

Source: [`src/grab_keys.py`](src/grab_keys.py)

---

### Fig. 4: PQC Authentication Proxy (`proxy.py`)
Verifies ML-DSA-65 signatures on each ETSI 014 API request before forwarding to the QNC.

![Fig. 4](figures/Fig4_proxy.png)

Source: [`src/proxy.py`](src/proxy.py)

---

### Fig. 5: PQC Client (`client.py`)
Constructs signed API requests with ML-DSA-65 for the PQC authentication proxy.

![Fig. 5](figures/Fig5_client.png)

Source: [`src/client.py`](src/client.py)

---

## Architecture

### Fig. 8: Defense-in-Depth Architecture
Legitimate requests pass through both PQC signature verification and firewall IP check before reaching the QNC. Each attacker path is blocked by a different security layer.

![Fig. 8](figures/Fig8_defense_proxy.png)

---

## Experimental Output

### Fig. 15: E2 — Firewall Only
The SonicWall TZ350 firewall refuses the attacker's direct connection to QNC B (response time 1010 ms, TCP RST). The firewall's DENY rule blocks all traffic from non-whitelisted source addresses to the QNC ETSI 014 endpoints, while the ALLOW rules permit the two CN4010 encryptors' 60-second key rotation cycles to proceed uninterrupted.

![Fig. 15](figures/Fig15_E2_firewall_deny.png)

---

### Fig. 6: E3 — Proxy Only (3 tests)
Test 1: signed request via proxy succeeds (200 OK). Test 2: attacker bypasses proxy and connects directly to QNC (200 OK). Proxy log: only Test 1 is recorded; Test 2 is invisible to the proxy.

![Fig. 6a](figures/Fig6_E3_test1_proxy_200ok.png)
![Fig. 6b](figures/Fig6_E3_test2_bypass_200ok.png)
![Fig. 6c](figures/Fig6_E3_qms_proxy_log.png)

---

### Fig. 7: E4 — Firewall + Proxy (3 tests)
Test 1: direct QNC access refused by firewall. Test 2: unsigned proxy request rejected. Test 3: PQC-signed request succeeds (200 OK).

![Fig. 7a](figures/Fig7_E4_test1_connection_refused.png)
![Fig. 7b](figures/Fig7_E4_test2_no_sig_rejected.png)
![Fig. 7c](figures/Fig7_E4_test3_signed_200ok.png)

---

### Fig. 9: PQC Proxy Overhead Raw Output (100 rounds)
Raw terminal output comparing direct ETSI API access with PQC proxy access.

![Fig. 9](figures/Fig9_proxy_comparison_raw.png)

---

### Fig. 10: Alice ML-DSA-65 Signing Benchmark (100 rounds)
Signing latency per round through the CN4010 QKD-encrypted channel.

![Fig. 10](figures/Fig10_benchmark_alice.png)

---

### Fig. 11: Bob ML-DSA-65 Verification Benchmark (100 rounds)
Verification latency per round. All 100 rounds passed.

![Fig. 11](figures/Fig11_benchmark_bob.png)

---

### Fig. 12: SHIM Frame Timeline
Wireshark capture showing SHIM key exchange frames (0xFC0F) preceding encrypted data frames (0xF800) by approximately 2 seconds.

![Fig. 12](figures/Fig12_shim_timeline.png)

---

### Fig. 13: SHIM Key Rotation Periodicity
SHIM key rotation captured over 11 minutes at 60.4 ± 0.0 second intervals.

![Fig. 13](figures/Fig13_shim_rotation.png)

---

### Fig. 14: SHIM Hex Dump — CNET Mode
CNET mode hex dump showing zeros in the UUID region at offset 0x0380, compared with QKD mode which contains ASCII-encoded key UUIDs.

![Fig. 14](figures/Fig14_shim_uuid_cnet.png)

---

## Requirements

- Python 3.10+
- [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)

## Citation

```bibtex
@article{mao2026qgp,
  title={Implementation of QGP with Quantum Key and Post-Quantum Authentication},
  author={Mao, Jianzhou and Xu, Guobin and Sakk, Eric and Wang, Shuangbao Paul},
  journal={IEEE Journal on Selected Areas in Communications},
  year={2026}
}
```
