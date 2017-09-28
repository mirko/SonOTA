The `image_user*` files were built in the Arduino IDE using this file: https://github.com/sillyfrog/Espressif2Arduino/tree/master/Espressif2Arduino

The options used for the build (after doing the setup as per https://github.com/khcnz/Espressif2Arduino) were:

- Set flash mode to: QIO
- Board: Generic ESP8266 Module
- Flash Size: "1M (Espressif OTA Rom 1)"

Then I ran the following to get `Espressif2Arduino.ino-0x01000.bin`: 

```
esptool.py elf2image --version 2 Espressif2Arduino.ino.elf
```

I then did a build again in Arduino with the option:

- Flash Size: "1M (Espressif OTA Rom 2)”

And finally to get `Espressif2Arduino.ino-0x81000.bin`: 

```
esptool.py elf2image --version 2 Espressif2Arduino.ino.elf
``` 
