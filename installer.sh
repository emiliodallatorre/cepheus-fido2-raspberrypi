#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	echo "Run as root: sudo ./installer.sh"
	exit 1
fi

NO_REBOOT=0
if [[ "${1:-}" == "--no-reboot" ]]; then
	NO_REBOOT=1
fi

apt update
apt -y upgrade

mkdir -p /etc/fido2_security_key

grep -qxF "dtoverlay=dwc2" /boot/firmware/config.txt || echo "dtoverlay=dwc2" >> /boot/firmware/config.txt
grep -qxF "dwc2" /etc/modules || echo "dwc2" >> /etc/modules
grep -qxF "libcomposite" /etc/modules || echo "libcomposite" >> /etc/modules

apt install -y --no-install-recommends python3 python3-dev python3-pip
apt install -y --no-install-recommends python3-cbor2 python3-cryptography python3-ecdsa 


cp ctap_init /usr/bin
chmod +x /usr/bin/ctap_init

cp security_key.py /usr/bin
chmod +x /usr/bin/security_key.py

cp security_key_logs /usr/bin
chmod +x /usr/bin/security_key_logs

cp usbgadget.service /lib/systemd/system
chmod 644 /lib/systemd/system/usbgadget.service

cp security_key_service.service /lib/systemd/system
chmod 644 /lib/systemd/system/security_key_service.service
systemctl daemon-reload
systemctl enable usbgadget
systemctl restart usbgadget
systemctl enable security_key_service
systemctl restart security_key_service

if [[ "${NO_REBOOT}" -eq 0 ]]; then
	reboot
else
	echo "Installation completed. Reboot skipped (--no-reboot)."
fi
