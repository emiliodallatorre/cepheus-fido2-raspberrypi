# Raspberry Pi FIDO2 Key
## This project converts an RPi 5 or RPi Zero/ Zero 2 W to a FIDO2 Security Key

![Banner](image.png)

### ⚠️ DO NOT USE THIS IN PRODUCTION, THE CRYPTOGRAPHIC KEYS ARE STORED IN CLEARTEXT

For visual outputs, connect an LED to `GPIO 16`.

Install Raspberry Pi OS Lite on the Raspberry Pi. (Lite is preferred for faster boot time).

You should be able to access the RPi Terminal with a keyboard + screen or via SSH.

## Installation steps:

1. Install Git
```
sudo apt update
sudo apt install git
```

2. Get this repository URL
    
    Click on the Green `<> Code` button on this page and copy the URL

3. Clone this repository
```
git clone <Repository URL>
```

```
git clone https://github.com/AdityaMitra5102/RPi-FIDO2-Security-Key.git
```

4. Go into the folder

    Use `cd` to go into the folder you just cloned

   ```
   cd RPi-FIDO2-Security-Key
   ```

6. Make the installer executable
```
sudo chmod +x installer.sh
```

6. Run the installer as root
```
sudo ./installer.sh
```
7. Wait till the system reboots.

The RPi will now behave like a security key. Connect the RPi to the PC via the USB C port.

## Uninstall

To undo the setup and remove installed services/files:

```
sudo chmod +x uninstaller.sh
sudo ./uninstaller.sh
```

If you also want to remove the Python crypto packages that were installed by `installer.sh`:

```
sudo PURGE_PACKAGES=1 ./uninstaller.sh
```

After uninstall, reboot to fully clear gadget/module runtime state:

```
sudo reboot
```

## Power consideration with RPi 5

The device ideally draws around 4w (5v, 800 mA). Normal laptops or phones (without Thunderbolt) may not be able to provide this amount. Hence, it is recommended to power the device via GPIO pins or POE if you notice the device being unable to boot up or frequently shutting down.

## Video Demo
https://youtu.be/K7gz3Q2Wtug

[![Video](https://img.youtube.com/vi/K7gz3Q2Wtug/0.jpg)](https://www.youtube.com/watch?v=K7gz3Q2Wtug)
