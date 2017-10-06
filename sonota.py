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
import os
import sys
import threading
import netifaces
import _thread

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
DEFAULT_PORT_HTTPS = 8443
DEFAULT_PORT_HTTP = 8080
upgrade_file_user1 = "image_user1-0x01000.bin"
upgrade_file_user2 = "image_user2-0x81000.bin"
arduino_file = "image_arduino.bin"


# -----

# A horrible hack to track what has been downloaded in tornado so we don't
# exit early
seenurlpaths = []

parser = argparse.ArgumentParser()
parser.add_argument("--serving-host", help="The host's ip address which will handle the HTTP(S)/WebSocket requests initiated by the device.\
 Normally the ip address of the WiFi interface of the machine this script is running on.")
parser.add_argument("--no-prov", help="Do not provision the device with WiFi credentials.\
 Only use if your device is already configured (Not recommended, but useful if doing DNS spoofing).",
 action="store_true")
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
    DEFAULT_PORT_HTTPS = 443

if args.no_prov and (args.wifi_ssid or args.wifi_password):
    parser.error(
        "arguments --no-prov and --wifi-ssid | --wifi-password are mutually exclusive")

if (args.wifi_ssid or args.wifi_password) and not (args.wifi_ssid and args.wifi_password):
    parser.error(
        "arguments --wifi-ssid and --wifi-password must always occur together")

class OTAUpdate(tornado.web.StaticFileHandler):
    def should_return_304(self):
        """Used as a hook to get the retrived URL's, never allow caching.
        """
        print("Sending file: %s" % self.request.path)
        seenurlpaths.append(str(self.request.path))
        return False

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
            "port": DEFAULT_PORT_HTTPS
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
                        # must not exceed FLASH_SIZE / 2 - (bootloader - spiffs)
                        # TODO: figure out how to build user1 and user2 incl.
                        #   its necessary differences
                        # TODO: check whether orig. bootloader can load and boot
                        #   code bigger than FLASH_SIZE / 2 - (bootloader - spiffs)
                        # TODO: check if original bootloader can also load v1
                        # images
                        "binList": [
                            {
                                "downloadUrl": "http://%s:%s/ota/%s" %
                                (args.serving_host, DEFAULT_PORT_HTTP, upgrade_file_user1),
                                # the device expects and checks the sha256 hash of
                                #   the transmitted file
                                "digest": hash_user1,
                                "name": "user1.bin"
                            },
                            {
                                "downloadUrl": "http://%s:%s/ota/%s" %
                                (args.serving_host, DEFAULT_PORT_HTTP, upgrade_file_user2),
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
        # handling initial dispatch HTTPS POST call to eu-disp.coolkit.cc
        (r'/dispatch/device', DispatchDevice),
        # handling actual payload communication on WebSockets
        (r'/api/ws', WebSocketHandler),
        # serving upgrade files via HTTP
        (r'/ota/(.*)', OTAUpdate, {'path': "static/"})
        #(r'/ota/(.*)', tornado.web.StaticFileHandler, {'path': "static/"})
    ])

def defaultinterface():
    '''The interface the default gateway is on, if there is one.'''
    try:
        return netifaces.gateways()['default'][netifaces.AF_INET][1]
    except:
        return None

def ip4ips():
    '''A list of IP4 addresses on this host.

    This will try and return the default gateway first in the list, and will
    strip out localhost addresses automatically.
    '''
    ret = []
    defiface = defaultinterface()
    for iface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(iface)
        if netifaces.AF_INET not in addresses:   # python3
            continue
        for afinet in addresses[netifaces.AF_INET]:
            addr = afinet['addr']
            if addr.startswith('127.'):
                continue
            if iface == defiface:
                ret.insert(0, addr)
            else:
                ret.append(addr)
    return ret

def hassonoffip():
    '''True if one of the current system IP's is from the Sonoff'''
    for addr in ip4ips():
        if addr.startswith("10.10.7."):
            return True
    return False

def hasfinalstageip():
    '''True if one of the current system IP's is from the final stage image'''
    return '192.168.4.2' in ip4ips()

def promptforval(msg):
    while True:
        val = input('{}: '.format(msg)).strip()
        if val:
            return val

def checkargs():
    # Make sure all of the binary files that are needed are there
    for fn in [arduino_file, upgrade_file_user1, upgrade_file_user2]:
        fn = os.path.join('static', fn)
        if not os.path.isfile(fn):
            print("Required file missing!", fn)
            sys.exit(1)
        f = open(fn, 'rb').read()
        if len(f) < 100000:
            print("Binary file appears too small!", fn)
            sys.exit(1)

    if args.no_prov:
        # No further config is needed as things are already configured
        args.no_check_ip = True
        return

    # Get the serving IP
    while not args.serving_host:
        ips = ip4ips()
        i = 0
        print("Select IP address of the WiFi interface:")
        for ip in ips:
            print("    {}: {}".format(i, ip))
            i += 1
        selection = input('Select IP address [0]: ').strip()
        if selection == '':
            args.serving_host = ips[0]
        else:
            try:
                args.serving_host = ips[int(selection)]
            except:
                pass

    # Ensure the given IP is actually what is associated with the host
    # and not already on a Sonoff WiFi network.
    if args.serving_host not in ip4ips():
        print(
            "** The IP address of <serve_host> (%s) is not " % args.serving_host,
            "assigned to any interface on this machine.")
        print(
            "** Please change WiFi network to %s and make sure %s is " % (
                args.wifi_ssid, args.serving_host),
            "being assigned to your WiFi interface before connecting to the ",
            "Sonoff device.")
        sys.exit(1)
    if hasfinalstageip() or hassonoffip():
        print('It looks like you are already on a Sonoff/Final stage WiFi '\
            'network, please change to your normal WiFi network. If this '\
            'has already been done, you may need to modify the IP range of '\
            'your LAN to use this tool safely. If this is what you intended '\
            'run again with --no-prov to skip this step.')
        sys.exit(1)

    # Check there is a WiFi config
    if not args.wifi_ssid:
        args.wifi_ssid = promptforval("WiFi SSID")
    if not args.wifi_password:
        args.wifi_password = promptforval("WiFi Password")
    print()
    print('Using the following configuration:')
    print('\tServer IP Address:', args.serving_host)
    print('\tWiFi SSID:', args.wifi_ssid)
    print('\tWiFi Password:', args.wifi_password)

def stage1():
    '''Accept the Sonoff WebSocket connection, and configure it.'''
    net_valid = False
    conn_attempt = 0

    if not args.no_check_ip:
        conn_attempt = 0
        # fuzzy-check if machine is connected to ITEAD AP
        while True:
            conn_attempt += 1
            if hasfinalstageip():
                print("Appear to have connected to the final stage IP, "\
                    "moving to next stage.")
                return
            if hassonoffip():
                break
            else:
                if conn_attempt == 1:
                    print("** Now connect via WiFi to your Sonoff device.")
                    print("** Please change into the ITEAD WiFi",
                        "network (ITEAD-100001XXXX). The default password",
                        "is 12345678.")
                    print("To reset the Sonoff to defaults, press",
                        "the button for 7 seconds and the light will",
                        "start flashing rapidly.")
                    print("** This application should be kept running",
                        "and will wait until connected to the Sonoff...")
                sleep(2)
                print(".", end="", flush=True)
                continue

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
        "port": DEFAULT_PORT_HTTPS
    }
    print(">> HTTP POST /10.10.7.1/ap")
    print(">> %s", json.dumps(data, indent=4))
    resp, cont = http.request(
        "http://10.10.7.1/ap", "POST", json.dumps(data))
    dct = json.loads(cont.decode('utf-8'))
    print("<< %s" % json.dumps(dct, indent=4))

    print("~~ Provisioning completed")

def stage2():
    print("Starting stage2...")
    app = make_app()
    if not args.no_check_ip:
        net_valid = False
        conn_attempt = 0
        # check if machine has <args.serving_host> being assigned on any iface
        while True:
            conn_attempt += 1
            if args.serving_host in ip4ips():
                break
            else:
                if conn_attempt == 1:
                    print(
                        "** The IP address of <serve_host> (%s) is not " % args.serving_host,
                        "assigned to any interface on this machine.")
                    print(
                        "** Please change WiFi network to %s and make sure %s is" % (
                            args.wifi_ssid, args.serving_host),
                        "being assigned to your WiFi interface.")
                    print("** This application should be kept running",
                        "and will wait until connected to the WiFi...")
                sleep(2)
                print(".", end="", flush=True)
                continue

    print("~~ Starting web server (HTTP port: %s, HTTPS port %s)" % (
        DEFAULT_PORT_HTTP, DEFAULT_PORT_HTTPS))


    if args.legacy:
        old = make_app()
        # listening on port 8081 for serving upgrade files for older devices
        old.listen(8081)

    # listening on port 8080 for serving upgrade files
    app.listen(DEFAULT_PORT_HTTP)

    app_ssl = tornado.httpserver.HTTPServer(app, ssl_options={
        "certfile": "ssl/server.crt",
        "keyfile": "ssl/server.key",
    })
    # listening on HTTPS port to catch initial POST request to eu-disp.coolkit.cc
    app_ssl.listen(DEFAULT_PORT_HTTPS)

    print("~~ Waiting for device to connect")

    stage3thread = threading.Thread(target=stage3, daemon=True)
    stage3thread.start()

    tornado.ioloop.IOLoop.instance().start()

def stage3():
    '''This is just a thread to provide feedback to the user.'''
    net_valid = False
    while not net_valid:
        print()
        print()
        print("*** IMPORTANT! ***")
        print("** AFTER the first download is COMPLETE, with in a minute or so",
            'you should connect to the new SSID "FinalStage" to finish the process.')
        print('** ONLY disconnect when the new "FinalStage" SSID is visible',
            'as an available WiFi network.')
        print('This server should automatically be allocated the IP address:',
            '192.168.4.2.')
        print('If you have successfully connected to "FinalStage" and this is',
            'not the IP Address you were allocated, please ensure no other',
            'device has connected, and reboot your Sonoff.')

        count = 0
        while True:
            count += 1
            if count > 10:
                break
            if hasfinalstageip():
                net_valid = True
                break
            else:
                sleep(2)
                print(".", end="", flush=True)

    count = 0
    while True:
        if not hasfinalstageip():
            if '/ota/image_arduino.bin' in seenurlpaths:
                # The arduino image has been downloaded, exit
                break
            else:
                print()
                print()
                print('It appears we have been disconnected from the',
                    '"FinalStage" SSID, however the final image has not been',
                    'downloaded. Reconnect to "FinalStage" when it returns to',
                    'continue the process (this may require a power cycle of',
                    'your Sonoff device)...')
                print()
                while not hasfinalstageip():
                    print(".", end="", flush=True)
                    sleep(2)

        if count % 10 == 0:
            print()
            print()
            print('The "FinalStage" SSID will disappear when the device has been',
                'fully flashed and image_arduino.bin has been installed')
            print('Once "FinalStage" has gone away, you can stop this program')
        count += 1
        sleep(2)
        print(".", end="", flush=True)

    print('No longer on "FinalStage" SSID, all done!')
    _thread.interrupt_main()

def main():
    checkargs()
    if not args.no_prov:
        stage1()
    stage2()

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Quitting.")
