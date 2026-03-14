# Cepheus FIDO2 Raspberry Pi

This project runs a FIDO2/CTAP authenticator service on Raspberry Pi hardware by exposing a USB HID gadget endpoint and serving CTAP2 commands from userspace. It is intended for research, prototyping, and learning.

Repository:
https://github.com/emiliodallatorre/cepheus-fido2-raspberrypi

![Banner](image.png)

## Attribution

This work is based on the original project by Aditya Mitra:
https://github.com/AdityaMitra5102/RPi-FIDO2-Security-Key

This fork keeps the original approach and extends it with a cleaner module layout and encrypted key storage using a hardware-derived key.

## What this project does

At boot, `usbgadget.service` prepares the USB gadget interface and `security_key_service.service` starts the Python authenticator process. The process listens on `/dev/hidg0`, parses CTAPHID packets, executes CTAP2 commands (`GetInfo`, `MakeCredential`, `GetAssertion`, `GetNextAssertion`, `Reset`), and returns responses to the host over USB HID.

For visual activity indication, connect an LED to `GPIO 16`.

## Security note

Private credential keys are no longer stored as cleartext CBOR. The key database is now encrypted at rest with AES-GCM. The encryption key is derived on-device from hardware identity data (CPU serial when available, with fallbacks), so copied storage files are not directly usable on another device.

This is more secure than plaintext storage, but it is still not equivalent to a certified hardware secure element. Treat this as a practical hardening step for a software authenticator prototype.

## Code organization

The runtime entrypoint remains a single executable script (`security_key.py`) for compatibility with systemd and installer behavior, while implementation details are split into modules:

- `fido2sk/key_store.py` - encrypted persistent credential storage and key lookup
- `fido2sk/crypto_ops.py` - key generation, signatures, COSE key conversion, certificate generation
- `fido2sk/authenticator_api.py` - CTAP2 authenticator command logic
- `security_key.py` - CTAPHID transport loop, packet framing, GPIO indicator, process orchestration

```mermaid
flowchart LR
    Host[Host Browser / OS] --> HID[/dev/hidg0]
    HID --> Main[security_key.py]
    Main --> API[fido2sk/authenticator_api.py]
    API --> Crypto[fido2sk/crypto_ops.py]
    API --> Store[fido2sk/key_store.py]
    Store --> File[/etc/fido2_security_key/keys.secret\nAES-GCM encrypted]
```

## Installation

Use Raspberry Pi OS Lite and ensure terminal access (local console or SSH).

1. Install Git

```bash
sudo apt update
sudo apt install -y git
```

2. Clone this repository

```bash
git clone https://github.com/emiliodallatorre/cepheus-fido2-raspberrypi.git
cd cepheus-fido2-raspberrypi
```

3. Run installer

```bash
sudo chmod +x installer.sh
sudo ./installer.sh
```

By default, the installer reboots at the end. To install without immediate reboot:

```bash
sudo ./installer.sh --no-reboot
```

After reboot, connect the Raspberry Pi to the host through the USB data port used for gadget mode.

## Uninstall

To remove services, binaries, gadget configuration lines, and local credential state:

```bash
sudo chmod +x uninstaller.sh
sudo ./uninstaller.sh
```

To also remove Python crypto packages installed by the installer:

```bash
sudo PURGE_PACKAGES=1 ./uninstaller.sh
```

Reboot after uninstall to fully clear runtime gadget/module state:

```bash
sudo reboot
```

## Power notes (Raspberry Pi 5)

Typical draw can be around 4 W (5 V, ~800 mA). Some host USB ports may not provide stable power at boot. If you see boot instability, power the board through GPIO or PoE and use USB only for data.

## Demo

https://youtu.be/K7gz3Q2Wtug

[![Video](https://img.youtube.com/vi/K7gz3Q2Wtug/0.jpg)](https://www.youtube.com/watch?v=K7gz3Q2Wtug)
