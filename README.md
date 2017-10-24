# SonOTA

## Updating a new Sonoff device

The latest updates include binary files (thanks to the great work by https://github.com/khcnz/Espressif2Arduino) so you can update your Sonoff device
from start to finish without having to build anything. 

The included final Arduino Sketch binary is v5.8.0 from the Sonoff-Tasmota releases page: https://github.com/arendst/Sonoff-Tasmota/releases

### Prerequisites

**Windows users:**
* Download and install .NET Framework 4.5.1 or later: https://www.microsoft.com/en-us/download/details.aspx?id=40779
* Download and install Microsoft Visual C++ Build tools: http://landinghub.visualstudio.com/visual-cpp-build-tools
* Download and install latest Python (3.5+): https://www.python.org/downloads/windows/

**Linux users:**
* Download and install `python3`, `python3-pip`, `python3-setuptools` and `python3-dev` packages

### Running

To run, firstly download the repo (either using `git clone`, or downloading the .zip file). You must run Python 3.5 (later should work, but untested, v3.5.x is recommended for Windows as the `netifaces` module has prebuilt wheels, also update pip with `python3 -m pip install --upgrade pip`, see #22), and the python dependencies. To install the dependencies, change into the SonOTA directory and run:
`pip3 install --user -r requirements.txt`

Once installed, you can run SonOTA (`./sonota.py`, you may need something like `python3 sonota.py` on Windows), and it will prompt you for the various settings it needs, and guide you through what to do for each step.

**Ensure all firewalls are disabled on all WiFi networks, including FinalStage when connected.** This is the most common reason things to not complete.

Once complete and Sonoff-Tasmota is installed, when the LED starts flashing, you can enable AP mode by pressing the button 4 times (and waiting for a reboot, and the LED to start flashing again, it will then broadcast an AP `sonoff-###`). For more information see the [Sonoff-Tasmota Initial Config](https://github.com/arendst/Sonoff-Tasmota/wiki/Initial-Configuration) and [Button Functionality](https://github.com/arendst/Sonoff-Tasmota/wiki/Button-usage).

### Update Steps

The update will go as follows (assuming a stock Sonoff device, the included .bin files have been tested with a Sonoff Basic and a Sonoff Dual). The program
