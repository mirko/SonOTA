#!/usr/bin/env python3
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

import logging
import argparse
# using tornado as it provides support for websockets
import tornado.ioloop
import tornado.web
import tornado.httpserver
import tornado.websocket
import json
from httplib2 import Http
from datetime import datetime
from time import sleep, time
from uuid import uuid4
from hashlib import sha256
from socket import error as socket_error

logfmt = '%(asctime)s (%(levelname)s) %(message)s'
loglvl = logging.DEBUG
logging.basicConfig(format=logfmt, level=loglvl)
logger = logging.getLogger(__name__)

# from __future__ import print_function # python2

# the original bootloader expects so called v2 images which start with the
#   magic byte 0xEA instead of the Arduino ones (v1) starting with 0xE9
# we can convert the ELF binaries into v2 images with an undocumented
#   '--version' switch to elf2image using esptool.py, e.g.:
#     esptool.py elf2image --version 2 /tmp/arduino_build_XXXXXX/sonoff.ino.elf
default_port = 4223
upgrade_file_user1 = "image_user1-0x01000.bin"
upgrade_file_user2 = "image_user2-0x81000.bin"


# -----


parser = argparse.ArgumentParser()
parser.add_argument("serving_host", help="The host's ip address which will handle the HTTP(S)/WebSocket requests initiated by the device.\
 Normally the ip address of the WiFi interface of the machine this script is running on.")
parser.add_argument("--no-prov", help="Do not provision the device with WiFi credentials.\
 Only use if your device is already configured.", action="store_true")
parser.add_argument(
    "--wifi-ssid",
    help="The ESSID of the WiFi network the device should eventually connect to.")
parser.add_argument("--wifi-password", help="The password of the WiFi (WPA/WPA2)\
 network the device should eventually connect to.")
parser.add_argument("--no-check-ip", help="Do not check for correct network settings\
 applied on your interface(s).", action="store_true")
parser.add_argument("--legacy", action="store_true", help="Enable legacy mode for devices with older firmware "
                    "(requires root permission)")
args = parser.parse_args()


if args.legacy:     # requires root permission
    default_port = 443

if args.no_prov and (args.wifi_ssid or args.wifi_password):
    parser.error(
        "arguments --no-prov and --wifi-ssid | --wifi-password are mutually exclusive")

if (args.wifi_ssid or args.wifi_password) and not (args.wifi_ssid and args.wifi_password):
    parser.error(
        "arguments --wifi-ssid and --wifi-password must always occur together")

if not args.no_check_ip:
    import netifaces


class OTAUpdate(tornado.web.StaticFileHandler):
    # Override tornado.web.StaticHandler to debug-print GET request
    def get(self, path, *args, **kwargs):
        print("<< HTTP GET %s" % self.request.path)
        print(">> %s" % path)
        super(OTAUpdate, self).get(path, *args, **kwargs)


class DispatchDevice(tornado.web.RequestHandler):

    def post(self):
        # telling device where to connect to in order to establish a WebSocket
        #   channel
        # as the initial request goes to port 443 anyway, we will just continue
        #   on this port
        print("<< HTTP POST %s" % self.request.path)
        data = {
            "error": 0,
            "reason": "ok",
            "IP": args.serving_host,
            "port": default_port
        }
        print(">> %s" % self.request.path)
        print(">> %s" % json.dumps(data, indent=4))
        self.write(data)
        self.finish()


class WebSocketHandler(tornado.websocket.WebSocketHandler):

    def open(self, *args):
        logger.debug("<< WEBSOCKET OPEN")
        # the device expects the server to generate and consistently provide
        #   an API key which equals the UUID format
        # it *must not* be the same apikey which the device uses in its
        # requests
        self.uuid = str(uuid4())
        self.setup_completed = False
        self.test = False
        self.upgrade = False
        self.stream.set_nodelay(True)
        self.device_model = "ITA-GZ1-GL"

    def on_message(self, message):
        logger.debug("<< WEBSOCKET INPUT")
        dct = json.loads(message)
        logger.debug("<< %s" % json.dumps(dct, indent=4))
        # if dct.has_key("action"): # python2
        if "action" in dct:     # python3
            print("~~~ device sent action request, ",
                  "acknowledging / answering...")
            if dct['action'] == "register":
                # ITA-GZ1-GL, PSC-B01-GL, etc.
                if "model" in dct and dct["model"]:
                    self.device_model = dct["model"]
                    logger.info("We are dealing with a {} model.".format(self.device_model))
                print("~~~~ register")
                data = {
                    "error": 0,
                    "deviceid": dct['deviceid'],
                    "apikey": self.uuid,
                    "config": {
                        "hb": 1,
                        "hbInterval": 145
                    }
                }
                print(">> %s" % json.dumps(data, indent=4))
                self.write_message(data)
            if dct['action'] == "date":
                print("~~~~ date")
                data = {
                    "error": 0,
                    "deviceid": dct['deviceid'],
                    "apikey": self.uuid,
                    "date": datetime.isoformat(datetime.today())[:-3] + 'Z'
                }
                print(">> %s" % json.dumps(data, indent=4))
                self.write_message(data)
            if dct['action'] == "query":
                print("~~~~ query")
                data = {
                    "error": 0,
                    "deviceid": dct['deviceid'],
                    "apikey": self.uuid,
                    "params": 0
                }
                print(">> %s" % json.dumps(data, indent=4))
                self.write_message(data)
            if dct['action'] == "update":
                print("~~~~ update")
                data = {
                    "error": 0,
                    "deviceid": dct['deviceid'],
                    "apikey": self.uuid
                }
                print(">> %s" % json.dumps(data, indent=4))
                self.write_message(data)
                self.setup_completed = True
        # elif dct.has_key("sequence") and dct.has_key("error"): # python2
        elif "sequence" in dct and "error" in dct:
            logger.debug(
                "~~~ device acknowledged our action request (seq {}) "
                "with error code {}".format(
                    dct['sequence'],
                    dct['error']
                )
            )
        else:
            logger.warn("## MOEP! Unknown request/answer from device!")

        if self.setup_completed and not self.test:
            # switching relais on and off - for fun and profit!
            data = {
                "action": "update",
                "deviceid": dct['deviceid'],
                "apikey": self.uuid,
                "userAgent": "app",
                "sequence": str(int(time() * 1000)),
                "ts": 0,
                "params": {
                    "switch": "off"
                },
                "from": "hackepeter"
            }
            print(">> %s" % json.dumps(data, indent=4))
            self.write_message(data)
            data = {
                "action": "update",
                "deviceid": dct['deviceid'],
                "apikey": self.uuid,
                "userAgent": "app",
                "sequence": str(int(time() * 1000)),
                "ts": 0,
                "params": {
                    "switch": "on"
                },
                "from": "hackepeter"
            }
            print(">> %s" % json.dumps(data, indent=4))
            self.write_message(data)
            data = {
                "action": "update",
                "deviceid": dct['deviceid'],
                "apikey": self.uuid,
                "userAgent": "app",
                "sequence": str(int(time() * 1000)),
                "ts": 0,
                "params": {
                    "switch": "off"
                },
                "from": "hackepeter"
            }
            print(">> %s" % json.dumps(data, indent=4))
            self.write_message(data)
            data = {
                "action": "update",
                "deviceid": dct['deviceid'],
                "apikey": self.uuid,
                "userAgent": "app",
                "sequence": str(int(time() * 1000)),
                "ts": 0,
                "params": {
                    "switch": "on"
                },
                "from": "hackepeter"
            }
            print(">> %s" % json.dumps(data, indent=4))
            self.write_message(data)
            data = {
                "action": "update",
                "deviceid": dct['deviceid'],
                "apikey": self.uuid,
                "userAgent": "app",
                "sequence": str(int(time() * 1000)),
                "ts": 0,
                "params": {
                    "switch": "off"
                },
                "from": "hackepeter"
            }
            print(">> %s" % json.dumps(data, indent=4))
            self.write_message(data)
            self.test = True

        if self.setup_completed and self.test and not self.upgrade:

            hash_user1 = self.getFirmwareHash("static/%s" % upgrade_file_user1)
            hash_user2 = self.getFirmwareHash("static/%s" % upgrade_file_user2)

            if hash_user1 and hash_user2:
                data = {
                    "action": "upgrade",
                    "deviceid": dct['deviceid'],
                    "apikey": self.uuid,
                    "userAgent": "app",
                    "sequence": str(int(time() * 1000)),
                    "ts": 0,
                    "params": {
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
                        # TODO: check if original bootloader can also load v1
                        # images
                        "binList": [
                            {
                                "downloadUrl": "http://%s:8080/ota/%s" %
                                (args.serving_host, upgrade_file_user1),
                                # the device expects and checks the sha256 hash of
                                #   the transmitted file
                                "digest": hash_user1,
                                "name": "user1.bin"
                            },
                            {
                                "downloadUrl": "http://%s:8080/ota/%s" %
                                (args.serving_host, upgrade_file_user2),
                                # the device expects and checks the sha256 hash of
                                #   the transmitted file
                                "digest": hash_user2,
                                "name": "user2.bin"
                            }
                        ],
                        # if `model` is set to sth. else (I tried) the websocket
                        #   gets closed in the middle of the JSON transmission
                        "model": self.device_model,
                        # the `version` field doesn't seem to have any effect;
                        #   nevertheless set it to a ridiculously high number
                        #   to always be newer than the existing firmware
                        "version": "23.42.5"
                    }
                }
                print(">> %s" % json.dumps(data, indent=4))
                self.write_message(data)
                self.upgrade = True

    def on_close(self):
        logger.debug("~~ websocket close")

    def getFirmwareHash(self, filePath):
        hash_user = None
        try:
            with open(filePath, "rb") as firmware:
                hash_user = sha256(firmware.read()).hexdigest()
        except IOError as e:
            logger.warn(e)
        return hash_user


def make_app():
    return tornado.web.Application([
        # handling initial dispatch SHTTP POST call to eu-disp.coolkit.cc
        (r'/dispatch/device', DispatchDevice),
        # handling actual payload communication on WebSockets
        (r'/api/ws', WebSocketHandler),
        # serving upgrade files via HTTP
        # overriding get method of tornado.web.StaticFileHandler has some weird
        #   side effects - as we don't necessarily need our adjustments use default
        # (r'/ota/(.*)', OTAUpdate, {'path': "static/"})
        (r'/ota/(.*)', tornado.web.StaticFileHandler, {'path': "static/"})
    ])


def main():
    app = make_app()

    net_valid = False
    conn_attempt = 0

    if not args.no_prov:
        if not args.no_check_ip:
            net_valid = False
            conn_attempt = 0
            # fuzzy-check if machine is connected to ITEAD AP
            while True:
                conn_attempt += 1
                for iface in netifaces.interfaces():
                    # if not
                    # netifaces.ifaddresses(iface).has_key(netifaces.AF_INET):
                    # python2
                    if netifaces.AF_INET not in netifaces.ifaddresses(iface):   # python3
                        continue
                    for afinet in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
                        # print(afinet['addr'])
                        if afinet['addr'].startswith("10.10.7."):
                            net_valid = True
                            break
                if not net_valid:
                    try:
                        raise Exception("IPADDR_ITEAD_NOT_ASSIGNED",
                                        "You do not appear to be connected to the ITEAD device")
                    except Exception as e:
                        if(e.args[0] != "IPADDR_ITEAD_NOT_ASSIGNED"):
                            raise
                        if conn_attempt == 1:
                            print(
                                "** No ip address of the ITEAD DHCP range (10.10.7.0/24)",
                                "is assigned to any of your interfaces,",
                                "which means you don't appear to be connected to the IEAD WiFi network.")
                            print(
                                "** Please change into the ITEAD WiFi network (ITEAD-100001XXXX)")
                            print("** This application can be kept running.")
                        sleep(2)
                        print(".", end="", flush=True)
                        continue
                else:
                    break

        http = Http(timeout=2)

        print("~~ Connection attempt")
        conn_attempt = 0
        while True:
            conn_attempt += 1
            print(">> HTTP GET /10.10.7.1/device")
            try:
                resp, cont = http.request("http://10.10.7.1/device", "GET")
                break
            except socket_error as e:
                print(e)
                continue

        dct = json.loads(cont.decode('utf-8'))
        print("<< %s" % json.dumps(dct, indent=4))

        data = {
            "version": 4,
            "ssid": args.wifi_ssid,
            "password": args.wifi_password,
            "serverName": args.serving_host,
            "port": default_port
        }
        print(">> HTTP POST /10.10.7.1/ap")
        print(">> %s", json.dumps(data, indent=4))
        resp, cont = http.request(
            "http://10.10.7.1/ap", "POST", json.dumps(data))
        dct = json.loads(cont.decode('utf-8'))
        print("<< %s" % json.dumps(dct, indent=4))

        print("~~ Provisioning completed")

    if not args.no_check_ip:
        net_valid = False
        conn_attempt = 0
        # check if machine has <args.serving_host> being assigned on any iface
        while True:
            conn_attempt += 1
            for iface in netifaces.interfaces():
                # if not
                # netifaces.ifaddresses(iface).has_key(netifaces.AF_INET): #
                # python2
                if netifaces.AF_INET not in netifaces.ifaddresses(iface):   # python3
                    continue
                for afinet in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
                    # print(afinet['addr'])
                    if afinet['addr'] == args.serving_host:
                        net_valid = True
                        break
            if not net_valid:
                try:
                    raise Exception(
                        "IPADDR_SRVHOST_NOT_ASSIGNED",
                        "The IP address of <serving_host> (%s) is not assigned to any interface" % args.serving_host)
                except Exception as e:
                    if(e.args[0] != "IPADDR_SRVHOST_NOT_ASSIGNED"):
                        raise
                    if conn_attempt == 1:
                        print(
                            "** The IP address of <serve_host> (%s) is not " % args.serving_host,
                            "assigned to any interface on this machine.")
                        print(
                            "** Please change WiFi network to $ESSID and make ",
                            "sure %s is being assigned to your WiFi interface.")
                        print("** This application can be kept running.")
                    sleep(2)
                    print(".", end="", flush=True)
                    continue
            else:
                break

    print("~~ Starting web server")

    if args.legacy:
        old = make_app()
        # listening on port 8081 for serving upgrade files for older devices
        old.listen(8081)

    # listening on port 8080 for serving upgrade files
    app.listen(8080)

    app_ssl = tornado.httpserver.HTTPServer(app, ssl_options={
        "certfile": "ssl/server.crt",
        "keyfile": "ssl/server.key",
    })
    # listening on port 443 to catch initial POST request to eu-disp.coolkit.cc
    app_ssl.listen(default_port)

    print("~~ Waiting for device to connect")

    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Quitting.")
