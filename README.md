# Project Aegis 🛡️
### Self-Healing Integrity Guard

**Project Aegis** is a Host-based Intrusion Detection System (HIDS) developed to ensure data integrity in Linux environments.

## ✨ Key Features
- **SHA-256 Verification:** Detects unauthorized content changes.
- **Identity Attribution:** Distinguishes between authorized (Aditya) and unauthorized (Root/Others) modifications.
- **Automated Remediation:** Self-heals by restoring files from a secure backup vault.
- **Background Protection:** Runs as a persistent Systemd service.

## 🚀 Quick Start
1. Place files to protect in `files_to_watch/`.
2. Run `python3 integrity_checker.py` and select **Option 1** to initialize.
3. Install services: `sudo cp *.service /etc/systemd/system/ && sudo systemctl daemon-reload`.
