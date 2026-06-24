# AEGIS v4.0

**Enterprise-Grade Mass Network Sanitization Platform**

AEGIS is an advanced, air-gapped data sanitization and cryptographic audit platform designed for mass network deployment. It provides secure, automated drive wiping capabilities compliant with major international data destruction standards.

![AEGIS Dashboard Mockup](https://via.placeholder.com/800x400.png?text=AEGIS+v4.0+Enterprise+Dashboard)

## 🌟 Key Features

*   **CustomTkinter Enterprise Dashboard UI**: A modern, themeable graphical interface built for operations centers and secure facilities.
*   **Drive Scanner & OS Safety Lock**: Intelligently discovers connected drives and enforces strict OS safety locks to prevent accidental boot drive erasure.
*   **Edge AI S.M.A.R.T. Diagnostics**: Utilizes an embedded Random Forest machine learning model to predict imminent hardware failures based on S.M.A.R.T. telemetry data before initiating sanitization.
*   **Dual Wiping Engine**: Supports multiple secure destruction protocols:
    *   **NVMe Crypto-Erase**: Firmware-level cryptographic erasure.
    *   **NIST SP 800-88**: 1-Pass zero fill clear.
    *   **DoD 5220.22-M**: 3-Pass standard wipe.
    *   **Gutmann**: 7-pass paranoid multi-pass.
    *   **Surgical Folder Shred**: Target specific directories with a 3-pass file shredder (0x00, 0xFF, urandom).
*   **Cryptographic PDF Certificate Generator**: Automatically generates tamper-proof PDF Certificates of Data Destruction complete with SHA-256 integrity hashes and hardware QR codes.
*   **Mass Network Sanitization Server**: Includes a PXE/TFTP/DHCP foundation for booting and provisioning diskless network nodes across an enterprise environment.

## 🛠️ Installation & Dependencies

To run AEGIS v4.0 locally, you will need Python 3.8+ and the following dependencies:

```bash
pip install customtkinter fpdf2 Pillow scikit-learn numpy pandas qrcode psutil
```

## 🚀 Usage

**Run as Standalone Server / Master GUI:**
```bash
python AEGIS.py
```

**Run as Client Node (For Network Operation):**
```bash
python AEGIS.py --client <server_ip>
```

## 📜 Compliance & Auditing

Every successful sanitization operation automatically produces a **Cryptographic Certificate of Destruction** stored locally on the Desktop and in the `certificates` directory. These certificates serve as legal proof of sanitization and feature a SHA-256 hash verifying the integrity of the audit record.

## ⚠️ Disclaimer

**USE WITH EXTREME CAUTION.** This software is designed to permanently and irrecoverably destroy data. The authors are not responsible for accidental data loss. Ensure you have properly selected your target drives and disabled any critical volumes before initiating a wipe.

---
*Developed for Secure Air-Gapped Environments*
