#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ./uninstaller.sh"
  exit 1
fi

echo "[1/7] Stopping and disabling services..."
systemctl stop security_key_service 2>/dev/null || true
systemctl disable security_key_service 2>/dev/null || true
systemctl stop usbgadget 2>/dev/null || true
systemctl disable usbgadget 2>/dev/null || true

echo "[2/7] Removing systemd unit files..."
rm -f /lib/systemd/system/security_key_service.service
rm -f /lib/systemd/system/usbgadget.service
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

echo "[3/7] Removing installed executables..."
rm -f /usr/bin/ctap_init
rm -f /usr/bin/security_key.py
rm -f /usr/bin/security_key_logs

echo "[4/7] Removing state/data directory..."
rm -rf /etc/fido2_security_key

echo "[5/7] Reverting boot/module config lines added by installer..."
if [[ -f /boot/firmware/config.txt ]]; then
  sed -i '/^dtoverlay=dwc2$/d' /boot/firmware/config.txt
fi

if [[ -f /etc/modules ]]; then
  sed -i '/^dwc2$/d' /etc/modules
  sed -i '/^libcomposite$/d' /etc/modules
fi

echo "[6/7] Optional package removal (disabled by default)..."
if [[ "${PURGE_PACKAGES:-0}" == "1" ]]; then
  apt remove -y python3-cbor2 python3-cryptography python3-ecdsa || true
  apt autoremove -y || true
  echo "Package purge completed."
else
  echo "Skipping package purge. Set PURGE_PACKAGES=1 to remove installed Python crypto packages."
fi

echo "[7/7] Done. A reboot is recommended to fully unload gadget/module state."
echo "Run: sudo reboot"
