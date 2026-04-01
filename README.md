# QGP-QKD-Implementation

Source code and experimental data for the paper:

**"Implementation of QGP with Quantum Key and Post-Quantum Authentication"**

## Overview

This repository contains the implementation of the Quantum Good Authentication Protocol (QGP) deployed on commercial QKD hardware (IDQ Cerberis 3 + Thales CN4010), including:

- QGP sender/receiver with ML-DSA-65 digital signatures
- PQC authentication proxy for ETSI 014 key delivery API
- Key interception demonstration (ETSI 014 vulnerability)

## Repository Structure

```
scripts/
  sender/          # QGP sender (ML-DSA-65 signing)
    sender_pqc.py        # Sign and send text message
    sender_pqc_file.py   # Sign and send file
  receiver/        # QGP receiver (ML-DSA-65 verification)
    receiver_pqc.py      # Receive and verify
  attack/          # ETSI 014 vulnerability demonstration
    grab_keys.py         # Key interception via ETSI 014 API
pqc-proxy/         # PQC authentication proxy for ETSI 014
  proxy.py               # Proxy server (verify and forward)
  client.py              # Signed API client
  keygen.py              # ML-DSA-65 key generation
```

## Requirements

- Python 3.10+
- [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) (for ML-DSA-65)
- IDQ Cerberis 3 QKD system with ETSI 014 API access
- Thales CN4010 hardware encryptors (for Tier 1 encryption)

## Hardware Testbed

| Component | Model |
|-----------|-------|
| QKD Key Generator (x2) | IDQ Cerberis 3 |
| QKD Node Controller (x2) | IDQ QNC (ETSI 014 REST API) |
| Hardware Encryptor (x2) | Thales CN4010 (FIPS 140-2 Level 3) |
| Enterprise Firewall | SonicWall TZ350 (Native Bridge Mode) |

## Citation

If you use this code, please cite:

```bibtex
@article{mao2026qgp,
  title={Implementation of QGP with Quantum Key and Post-Quantum Authentication},
  author={Mao, Jianzhou and Xu, Guobin and Sakk, Eric and Wang, Shuangbao Paul},
  journal={IEEE Journal on Selected Areas in Communications},
  year={2026}
}
```

## License

This project is for academic research purposes.
