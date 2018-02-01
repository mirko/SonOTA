# SonOTA

A script to update a Sonoff device from the stock firmware to [Sonoff-Tasmota](https://github.com/arendst/Sonoff-Tasmota/) purely over WiFi.

This is **beta** software, and it may not work 100% of the time, and require to manually flash your device using serial.

# ATTENTION: It appears SonOTA does *not* work with devices running firmware version >= 1.6! #

See [#58](https://github.com/mirko/SonOTA/issues/58) for more information. Please request ITEAD to allow this again here: http://disq.us/p/1oqbm8m (_maybe_ with enough requests they'll do something, downgrading to the older firmware feels like the ideal solution for everyone)

## Updating a new Sonoff device

The latest updates include binary files (thanks to the great work by https://github.com/khcnz/Espressif2Arduino) so you can update your Sonoff device
from start to finish without having to build anything. 

The included final Arduino Sketch binary is v5.9.1, defaulting `WIFI_CONFIG_TOOL` to `WIFI_MANAGER`.


### Prerequisites

**Windows users:**
Skip if you use the sonota.exe file
* Download and install Python v3.5.x: https://www.python.org/downloads/windows/
  (Python v3.5.x is recommended for Windows as the `netifaces` module has prebuilt wheels)
* **All firewalls must be disabled** when running SonOTA

**Linux users:**
* Download and install `python3`, `python3-pip` and `python3-dev` packages (Python v3.5 or later is required)
* Update `pip` by running: `python3 -m pip install --upgrade pip` (see #22 for more information)
* All firewalls must be disabled when running SonOTA

**Mac users:**
* Downloaded and install the latest Python 3 for Mac: https://www.python.org/downloads/
* Install the clang developer tools if prompted during the `pip` install phase
* All firewalls must be disabled when running SonOTA


### Running

Method 1)
After setting up the prerequisites, download the repo (either using `git clone`, or downloading and extracting the .zip file). Then install the Python dependencies by changing into the SonOTA directory and running:
`pip3 install --user -r requirements.txt`

Once installed, you can run SonOTA (`./sonota.py`, you may need something like `python3 sonota.py` on Windows), and it will prompt you for the various settings it needs, and guide you through what to do for each step.

Method 2)
Download latest sonota.exe from the releases page

Run the exe as administrator**

A Console Windows will popup and it will prompt you for the various settings it needs, and guide you through what to do for each step.


**Ensure all firewalls are disabled on all WiFi networks, including FinalStage when connected.** This is the most common reason things to not complete.

Once complete and Sonoff-Tasmota is installed, you will have an AP called `sonoff-####` (note: this will be up for a minute then down for a minute until configured).

For more information see the [Sonoff-Tasmota Initial Config](https://github.com/arendst/Sonoff-Tasmota/wiki/Initial-Configuration) and [Button Functionality](https://github.com/arendst/Sonoff-Tasmota/wiki/Button-usage).

### Update Steps

The update will go as follows (assuming a stock Sonoff device, the included .bin files have been tested with a Sonoff Basic and a Sonoff Dual). The program will prompt you what to do for each step as required.

1. You will be promted to fill out the settings for your network (the "server" IP, this is the IP of the PC you are running `sonota` on, and the SSID and password for your WiFi). (These can also be passed as command line arguments if preferred, or doing a lot of devices.)
2. Connect to the `ITEAD-*` WiFi network, you may need to reset your Sonoff to defaults to do this. This stage tells the Sonoff where to get future updates.
3. Typically, you will be disconnected automatically from the `ITEAD-*` WiFi network, and your PC will reconnect to your normal network. So this stage will require no intervention, and the Sonoff will connect to your PC to download the required firmware.
4. Once the firmware has been downloaded, there will be a new `FinalStage` SSID that you can connect to. Do this, and the device will then download the final stages of the firmware, including the Arduino image, replacing the default boot loader.
5. That's it! You should be all done and ready to use your new Arduino Firmware (see the [Running](#running) section).

### Important Files

The `static/` directory includes 3 binary files, these are:

* **image_user1-0x01000.bin**: The image for the first half of the flash, this may not be required depending on the initial state of the Sonoff. This just downloads the user2 image below.
* **image_user2-0x81000.bin**: The image for the second half of the flash, this is the one that will replace the boot loader, then install *image_arduino.bin*.
* **image_arduino.bin**: The actual Arduino built image, the repo has Sonoff-Tasmota included, but can be overwritten.

The `ssl/` directory has some pregenerated SSL certificates. As the Sonoff does not verify the SSL certificates, these offer no real security, so to make things easy, they have been included in the repo.

### Updating the included Sonoff-Tasmota

If a new release of Sonoff-Tasmota is available and you wish to use it, download the binary from the [Sonoff-Tasmota Releases](https://github.com/arendst/Sonoff-Tasmota/releases) page, and copy it to `static/image_arduino.bin`, replacing the existing file.

This same process can be used if you have your own build with, for example, default settings for your network.

### Changing Firmware

If you have flashed your Sonoff and decide that Sonoff-Tasmota is not for you, it has an easy to use feature to allow uploading of new firmware.

If you connect to the web interface of the device (either normally, or in AP mode), then change the URL path to be `/up`, you can browse to a local binary file on your computer, and upload. Be sure to use something that you have tested as if this goes bad, you'll need to open up your Sonoff and update using the old serial method.

### Flashing Itead Sonoff devices via original OTA mechanism

This program is based on research documented here:

- https://blog.nanl.de/2017/05/sonota-flashing-itead-sonoff-devices-via-original-ota-mechanism/
- https://github.com/arendst/Sonoff-Tasmota/issues/476
- https://wiki.almeroth.com/doku.php?id=projects:sonoff

The script is fairly well documented (I think) - apart from that above stated links should provide some context of what's been done how and why. Feel free to open issue tickets or contact me directly: sonota@nanl.de



### Building own Exe File
just run the built.bat in the Release folder to create your own sonota.exe. You will find the exe in the Release/dist folder.

# Compatibility

Please see the [wiki](https://github.com/mirko/SonOTA/wiki) for known working configurations.

# Reporting issues

If you are having an issue runinng this, please include the following information:
 - The full output of the actual run, a log file is now produced which can be uploaded by dragging and dropping the file in your web browser
 - The model and version of your Sonoff device
 - The operating system and version of Python you're using
