# SonOTA

## Updating a new Sonoff device

The latest updates include binary files (thanks to the great work by https://github.com/khcnz/Espressif2Arduino) so you can update your Sonoff device
from start to finish without having to build anything. 

The included final Arduino Sketch binary is https://github.com/arendst/Sonoff-Tasmota (v5.5.2, the only change is defaulting to AP mode rather than WPS when unconfigured).

### Running

To run, firstly download the repo (either using `git clone`, or downloading the .zip file). You must run Python 3.5 (later should work, but untested, v3.5 is recommended for Windows as the `netifaces` module has prebuilt wheels), and the python dependencies. To install the dependencies, change into the SonOTA directory and run:
`pip3 install --user -r requirements.txt`

Once installed, you can run SonOTA (`./sonota.py`, you may need something like `python3 sonota.py` on Windows), and it will prompt you for the various settings it needs, and guide you through what to do for each step.

### Update Steps

The update will go as follows (assuming a stock Sonoff device, the included .bin files have been tested with a Sonoff Basic and a Sonoff Dual). The program will prompt you what to do for each step as required.

1. You will be promted to fill out the settings for your network (the "server" IP, this is the IP of the PC you are running `sonota` on, and the SSID and password for your WiFi). (These can also be passed as command line arguments if preferred, or doing a lot of devices.)
2. Connect to the `ITEAD-*` WiFi network, you may need to reset your Sonoff to defaults to do this. This stage tells the Sonoff where to get future updates.
3. Typically, you will be disconnected automatically from the `ITEAD-*` WiFi network, and your PC will reconnect to your normal network. So this stage will require no intervention, and the Sonoff will connect to your PC to download the required firmware.
4. Once the firmware has been downloaded, there will be a new `FinalStage` SSID that you can connect to. Do this, and the device will then download the final stages of the firmware, including the Arduino image, replacing the default boot loader.
5. That's it! You should be all done and ready to use your new Arduino Firmware.

### Important Files

The `static/` directory includes 3 binary files, these are:

* **image_user1-0x01000.bin**: The image for the first half of the flash, this may not be required depending on the initial state of the Sonoff. This just downloads the user2 image below.
* **image_user2-0x81000.bin**: The image for the second half of the flash, this is the one that will replace the boot loader, then install *image_arduino.bin*.
* **image_arduino.bin**: The actual Arduino built image, the repo has Sonoff-Tasmota included, but can be overwritten.

The `ssl/` directory has some pregenerated SSL certificates. As the Sonoff does not verify the SSL certificates, these offer no real security, so to make things easy, they have been included in the repo.

### Changing Firmware

If you decide that Sonoff-Tasmota is not for you, it has an easy to use feature to allow uploading of new firmware.

If you connect to the web interface of the device (either normally, or in AP mode), then change the URL path to be `/up`, you can browse to a local binary file on your computer, and upload. Be sure to use something that you have tested as if this goes bad, you'll need to open up your Sonoff and update using the old serial method.

### Flashing Itead Sonoff devices via original OTA mechanism

This program is based on research documented here:

- https://blog.nanl.de/2017/05/sonota-flashing-itead-sonoff-devices-via-original-ota-mechanism/
- https://github.com/arendst/Sonoff-Tasmota/issues/476
- https://wiki.almeroth.com/doku.php?id=projects:sonoff

The script is fairly well documented (I think) - apart from that above stated links should provide some context of what's been done how and why. Feel free to open issue tickets or contact me directly: sonota@nanl.de

#### DNS redirect

~~The program only works if you made sure the hostname 'eu-disp.coolkit.cc' is being resolved to an IP address assigned to the machine this script is running on.~~

~~On a WiFi router running OpenWrt this can be easily done by adding the following line to `/etc/hosts` and restarting `dnsmasq`:~~

~~`10.23.42.5	eu-disp.coolkit.cc`~~

~~Adjust IP address and make sure variable `serving_host` in `sonota.py` is set to the same.~~

No DNS redirect is needed anymore with version 2 as the script can now also provision the Sonoff device and hence specify the `serving_host`.
Just connect to the WiFi network which the Sonoff devices open called "ITEAD-XXXXXX" -- password is "12345678" and run the script.

#### Creation of SSL certificates

`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${SONOTA}/ssl/server.key -out ${SONOTA}/ssl/server.crt -days 42235`

#### Building an user2 image with Arduino

```
--- a/~/.arduino15/packages/esp8266/hardware/esp8266/2.3.0/tools/sdk/ld/eagle.flash.1m64.ld
+++ b/~/.arduino15/packages/esp8266/hardware/esp8266/2.3.0/tools/sdk/ld/eagle.flash.1m64.ld
@@ -7,7 +7,7 @@ MEMORY
   dport0_0_seg :                        org = 0x3FF00000, len = 0x10
   dram0_0_seg :                         org = 0x3FFE8000, len = 0x14000
   iram1_0_seg :                         org = 0x40100000, len = 0x8000
-  irom0_0_seg :                         org = 0x40201010, len = 0xf9ff0
+  irom0_0_seg :                         org = 0x40281010, len = 0xf9ff0
 }
 
 PROVIDE ( _SPIFFS_start = 0x402FB000 );
 ```

#### Converting Arduino images to v2 images

`esptool.py elf2image --version 2 image_user1.ino.elf`
`esptool.py elf2image --version 2 image_user2.ino.elf`

`mv image_user1-0x01000.bin image_user2-0x81000.bin ${SONOTA}/static/`

#### Run

~~The script needs to be run as root, as it binds to port 443 to which the Sonoff device initially sets up a HTTPS POST request.~~

The script can now be run as a regular user; as *we* can do the provisioning now, we can also set the port to anything other than 443.

`python3 sonota.py --wifi-ssid foobar --wifi-password ew4Ookie 10.23.42.5`

#### Issues

~~As we don't override the bootloader which still expects v2 images and our custom firmware might end up in the user2 partition, vanilla Arduino OTA functionality - if provided by your custom image - will *not* work.~~

Due to the impressive work of @khcnz there's now a sketch for intermediate images: https://github.com/khcnz/Espressif2Arduino
Espressif2Arduino provides the correct linker scripts for ESP8266 and ESP8285 chips (user1 and user2) and -- once flashed and booted -- replaces the Espressif bootloader by the Arduino one.
From there it will attempt to download and flash and *un*modified Arduino image (e.g. a https://github.com/arendst/Sonoff-Tasmota one) from your local webserver via the Arduino OTA method.

