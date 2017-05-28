#!/usr/bin/env python
# 
# SonOTA - Flashing Sonoff devices with custom firmware via orig OTA mechanism
# Copyright (C) 2017  Mirko Vogt <sonota@nanl.de>
# 
# This file is part of SonOTA.
# 
# SonOTA is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
# 
# SonOTA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with SonOTA.  If not, see <http://www.gnu.org/licenses/>.

# using tornado as it provides support for websockets
import tornado.ioloop
import tornado.web
import tornado.httpserver
import tornado.websocket
import json
from datetime import datetime
from time import sleep, time
from uuid import uuid4
from hashlib import sha256

# host all requests initiated by the device get redirected to
#   IP address needs to be assigned to the machine this script is running on
serving_host = "10.23.42.5"

# the original bootloader expects so called v2 images which start with the
#   magic byte 0xEA instead of the Arduino ones (v1) starting with 0xE9
# we can convert the ELF binaries into v2 images with an undocumented
#   '--version' switch to elf2image using esptool.py, e.g.:
#     esptool.py elf2image --version 2 /tmp/arduino_build_XXXXXX/sonoff.ino.elf
upgrade_file_user1 = "image_user1-0x01000.bin"
upgrade_file_user2 = "image_user2-0x81000.bin"

class OTAUpdate(tornado.web.StaticFileHandler):
    # Override tornado.web.StaticHandler to debug-print GET request
    # FIXME: For some reason that fails horribly!
    #   What did I do wrong trying to override and eventually calling the
    #   original get method?request!
    def get(self, path, include_body=True):
        print("~~ HTTP GET")
        print(">> %s" % path)
        super(OTAUpdate, self).get(path, include_body)

class DispatchDevice(tornado.web.RequestHandler):
    def post(self):
        # telling device where to connect to in order to establish a WebSocket
        #   channel
        # as the initial request goes to port 443 anyway, we will just continue
        #   on this port
        print("~~ HTTP POST")
        data = {
            "error":    0,
            "reason":   "ok",
            "IP":       serving_host,
            "port":     443
        }
        print(">> %s" % json.dumps(data, indent=4))
        self.write(data)
        self.finish()

class WebSocketHandler(tornado.websocket.WebSocketHandler):
    def open(self, *args):
        print("~~ WEBSOCKET OPEN")
        # the device expects the server to generate and consistently provide
        #   an API key which equals the UUID format
        # it *must not* be the same apikey which the device uses in its requests
        self.uuid = str(uuid4())
        self.setup_completed = False
        self.test = False
        self.upgrade = False
        self.stream.set_nodelay(True)

    def on_message(self, message):
        print("~~ WEBSOCKET INPUT")
        dct = json.loads(message)
        print("<< %s" % json.dumps(dct, indent=4))
        if dct.has_key("action"):
            print("~~~ device sent action request, " \
                    "acknowledging / answering...")
            if dct['action'] == "register":
                print("~~~~ register")
                data = {
                    "error":    0,
                    "deviceid": dct['deviceid'],
                    "apikey":   self.uuid,
                    "config":   {
                        "hb":           1,
                        "hbInterval":   145
                    }
                }
                print(">> %s" % json.dumps(data, indent=4))
                self.write_message(data)
            if dct['action'] == "date":
                print("~~~~ date")
                data = {
                    "error":    0,
                    "deviceid": dct['deviceid'],
                    "apikey":   self.uuid,
                    "date":     datetime.isoformat(datetime.today())[:-3] + 'Z'
                }
                print(">> %s" % json.dumps(data, indent=4))
                self.write_message(data)
            if dct['action'] == "query":
                print("~~~~ query")
                data = {
                    "error":    0,
                    "deviceid": dct['deviceid'],
                    "apikey":   self.uuid,
                    "params":0
                }
                print(">> %s" % json.dumps(data, indent=4))
                self.write_message(data)
            if dct['action'] == "update":
                print("~~~~ update")
                data = {
                    "error":    0,
                    "deviceid": dct['deviceid'],
                    "apikey":   self.uuid
                }
                print(">> %s" % json.dumps(data, indent=4))
                self.write_message(data)
                self.setup_completed = True
        elif dct.has_key("sequence") and dct.has_key("error"):
            print("~~~ device acknowledged our action request (seq %s) " \
                    "with error code %d" % (dct['sequence'], dct['error']))
        else:
            print("### MOEP! Unknown request/answer from device!")

        if self.setup_completed and not self.test:
            # switching relais on and off - for fun and profit!
            data = {
                "action":       "update",
                "deviceid":     dct['deviceid'],
                "apikey":       self.uuid,
                "userAgent":    "app",
                "sequence":     str(int(time() * 1000)),
                "ts":           0,
                "params":       {
                    "switch":       "off"
                },
                "from":         "hackepeter"
            }
            print(">> %s" % json.dumps(data, indent=4))
            self.write_message(data)
            data = {
                "action":       "update",
                "deviceid":     dct['deviceid'],
                "apikey":       self.uuid,
                "userAgent":    "app",
                "sequence":     str(int(time() * 1000)),
                "ts":           0,
                "params":       {
                    "switch":       "on"
                },
                "from":         "hackepeter"
            }
            print(">> %s" % json.dumps(data, indent=4))
            self.write_message(data)
            data = {
                "action":       "update",
                "deviceid":     dct['deviceid'],
                "apikey":       self.uuid,
                "userAgent":    "app",
                "sequence":     str(int(time() * 1000)),
                "ts":           0,
                "params":       {
                    "switch":       "off"
                },
                "from":         "hackepeter"
            }
            print(">> %s" % json.dumps(data, indent=4))
            self.write_message(data)
            data = {
                "action":       "update",
                "deviceid":     dct['deviceid'],
                "apikey":       self.uuid,
                "userAgent":    "app",
                "sequence":     str(int(time() * 1000)),
                "ts":           0,
                "params":       {
                    "switch":       "on"
                },
                "from":         "hackepeter"
            }
 
            print(">> %s" % json.dumps(data, indent=4))
            self.write_message(data)
            data = {
                "action":       "update",
                "deviceid":     dct['deviceid'],
                "apikey":       self.uuid,
                "userAgent":    "app",
                "sequence":     str(int(time() * 1000)),
                "ts":           0,
                "params":       {
                    "switch":       "off"
                },
                "from":         "hackepeter"
            }
            print(">> %s" % json.dumps(data, indent=4))
            self.write_message(data)
            self.test = True

        if self.setup_completed and self.test and not self.upgrade:
            fd = open("static/%s" % upgrade_file_user1, "r")
            hash_user1 = sha256(fd.read()).hexdigest()
            fd.close()
            fd = open("static/%s" % upgrade_file_user2, "r")
            hash_user2 = sha256(fd.read()).hexdigest()
            fd.close()
            data = {
                "action":       "upgrade",
                "deviceid":     dct['deviceid'],
                "apikey":       self.uuid,
                "userAgent":    "app",
                "sequence":     str(int(time() * 1000)),
                "ts":           0,
                "params":       {
                    # the device expects two available images, as the original
                    #   firmware splits the flash into two halfs and flashes
                    #   the inactive partition (ping-pong).
                    # as we don't know which partition is (in)active, we
                    # provide our custom image as user1 as well as user2.
                    # unfortunately this also means that our firmware image
                    # must noch exceed FLASH_SIZE / 2 - (bootloader - spiffs)
                    # TODO: figure out how to build user1 and user2 incl.
                    #   its necessary differences
                    # TODO: check whether orig. bootloader can load and boot
                    #   code bigger than FLASH_SIZE / 2 - (bootloader - spiffs)
                    # TODO: check if original bootloader can also load v1 images
                    "binList":      [
                        {
                            "downloadUrl":  "http://%s:8080/ota/%s" %
                                (serving_host, upgrade_file_user1),
                            # the device expects and checks the sha256 hash of
                            #   the transmitted file
                            "digest":       hash_user1,
                            "name":         "user1.bin"
                        },
                        {
                            "downloadUrl":  "http://%s:8080/ota/%s" %
                                (serving_host, upgrade_file_user2),
                            # the device expects and checks the sha256 hash of
                            #   the transmitted file
                            "digest":       hash_user2,
                            "name":         "user2.bin"
                        }
                    ],
                    # if `model` is set to sth. else (I tried) the websocket
                    #   gets closed in the middle of the JSON transmission
                    "model":        "ITA-GZ1-GL",
                    # the `version` field doesn't seem to have any effect;
                    #   nevertheless set it to a ridiculously high number
                    #   to always be newer than the existing firmware
                    "version":      "23.42.5"
                }
            }
            print(">> %s" % json.dumps(data, indent=4))
            self.write_message(data)
            self.upgrade = True

    def on_close(self):
        print("~~ websocket close")

app = tornado.web.Application([
    # handling initial dispatch SHTTP POST call to eu-disp.coolkit.cc
    (r'/dispatch/device', DispatchDevice),
    # handling actual payload communication on WebSockets
    (r'/api/ws', WebSocketHandler),
    # serving upgrade files via HTTP
    # overriding get method of tornado.web.StaticFileHandler has some weird
    #   side effects - as we don't necessarily need our adjustments use default
    (r'/ota/(.*)', OTAUpdate, {'path': "static/"})
    #(r'/ota/(.*)', tornado.web.StaticFileHandler, {'path': "static/"})
])

if __name__ == '__main__':
    # listening on port 8080 for serving upgrade files
    print("----- This script only works if hostname 'eu-disp.coolkit.cc' is " \
            "being resolved to the machine this script is running on -----")
    app.listen(8080)
    app_ssl = tornado.httpserver.HTTPServer(app, ssl_options = {
        "certfile": "ssl/server.crt",
        "keyfile":  "ssl/server.key",
    })
    # listening on port 443 to catch initial POST request to eu-disp.coolkit.cc
    app_ssl.listen(443)
    tornado.ioloop.IOLoop.instance().start()
