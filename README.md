# Deadsec-Ransomware for Linux and Windows Platforms

**Note:** This project is intentionally incomplete to prevent misuse by script kiddies. If you encounter difficulties in building it, please feel free to reach out to me for assistance.

## Features

- **File Encryption**: Scans the entire disk for files and encrypts them.
- **Decryption Key Delivery**: Sends the decryption key via a server file or through email.
- **Anti-Reverse Engineering Techniques**: Implements methods to hinder reverse engineering efforts.
- **Anti-VM Techniques**: Detects and avoids execution in virtual machines.
- **Anti-Virus Evasion**: Use Nuitka to compile the script into an executable, making it harder for antivirus software to detect.
- **Self-Destruct Mechanism**: Includes functionality to delete itself after execution.
- **Encrypted Communication**: Utilizes RSA for secure communication over sockets.
- **File Encryption**: Encrypts files using AES-ECB mode.
- **Persistence**: Remains active even after system reboots.
- **Graphical User Interface (GUI)**: Displays messages to the user through a GUI.

## Legal Disclaimer

This tool is intended for educational purposes only. I am not responsible for how you choose to use it. Always act ethically and responsibly.

## Installation

To run this project, you will need to install the following Python modules:

```bash
pip install time string binascii codecs sys platform smtplib ssl threading hashlib glob base64 tkinter
