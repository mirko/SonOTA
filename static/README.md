The `image_user*` files were built in the Arduino IDE using this file: https://github.com/sillyfrog/Espressif2Arduino/tree/master/Espressif2Arduino

These have been built to use a flash mode of DOUT, which appears to be most compatible with newer Sonoff devices.

The options used for the build (after doing the setup as per https://github.com/khcnz/Espressif2Arduino) were:

- Set flash mode to anything (.elf files don't use this)
- Board: Generic ESP8266 Module
- Flash Size: "1M (Espressif OTA Rom 1)"

Then I ran the following to get `Espressif2Arduino.ino-0x01000.bin`:

```
esptool.py elf2image --flash_freq=20m --flash_mode=dout --version 2 Espressif2Arduino.ino.elf
```

I then did a build again in Arduino with the option:

- Flash Size: "1M (Espressif OTA Rom 2)"

And finally to get `Espressif2Arduino.ino-0x81000.bin`:

```
esptool.py elf2image --flash_freq=20m --flash_mode=dout --version 2 Espressif2Arduino.ino.elf
```
