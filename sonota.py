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

import argparse
import json
import logging
import os
import sys
import threading
import _thread
import ssl
from datetime import datetime
from hashlib import sha256
from httplib2 import Http
from socket import error as socket_error
from time import sleep, time
from uuid import uuid4

import netifaces
# using tornado as it provides support for websockets
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.websocket
from tornado import gen

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


rootlog = logging.getLogger()
rootlog.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter('%(message)s'))
rootlog.addHandler(ch)
ch = logging.FileHandler('debug_%d.log' % (time(),))
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter('%(asctime)s: %(levelname)s: %(message)s'))
rootlog.addHandler(ch)

log = logging.getLogger(__name__)

def logmulti(msg):
    '''Log multi lines and try and strip out WiFi passwords'''
    for l in msg.split('\n'):
        if l.strip():
            log.debug(l)

def logjson(data, outbound=True):
    if outbound:
        direction = '>>'
    else:
        direction = '<<'
    if 'password' in data:
        # Don't update original dict
        data = dict(data)
        data['password'] = '*' * len(data['password'])
    logmulti("{} {}".format(direction, json.dumps(data, indent=4)))

# -----

# A horrible hack to track what has been downloaded in tornado so we don't
# exit early
seenfiles = []

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
parser.add_argument("-s", "--slowstream", action="store_true",
        help="Serve files slowly, use if getting 404 errors")
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
        log.debug("Sending file: %s" % self.request.path)
        seenfiles.append(os.path.basename(str(self.request.path)))
        return False

class SlowOTAUpdate(tornado.web.RequestHandler):
    @gen.coroutine
    def get(self, path):
        log.debug("Slow Sending file: %s (This may take several minutes)" % self.request.path)
        seenfiles.append(os.path.basename(str(self.request.path)))
        f = open(os.path.join('static', path), 'rb')
        f.seek(0, 2)
        length = f.tell()
        f.seek(0, 0)
        self.set_header('Content-Length', str(length))
        self.set_header('X-Powered-By', 'Express')
        self.set_header('Transfer-Encoding', '')
        self.set_header('Content-Disposition',
                'attachment; filename="{}"'.format(path))
        self.set_header('Accept-Ranges', 'bytes')
        self.set_header('Cache-Control', 'public, max-age=0')
        self.set_header('Content-Type', 'application/octet-stream')
        chunk = f.read(10)
        self.write(chunk)
        yield self.flush()
        yield gen.sleep(0.9)
        while True:
            chunk = f.read(1400)
            if not chunk:
                break
            self.write(chunk)
            yield self.flush()
            print("  {}%   ".format(int(f.tell()*100/length)), end="\r", flush=True)
            yield gen.sleep(0.3)

class DispatchDevice(tornado.web.RequestHandler):

    def post(self):
        # telling device where to connect to in order to establish a WebSocket
        #   channel
        # as the initial request goes to port 443 anyway, we will just continue
        #   on this port
        log.debug("<< HTTP POST %s" % self.request.path)
        if not args.serving_host:
            raise ValueError('args.serving_host is required')
        data = {
            "error": 0,
            "reason": "ok",
            "IP": args.serving_host,
            "port": DEFAULT_PORT_HTTPS
        }
        log.debug(">> %s" % self.request.path)
        logjson(data)
        self.write(data)
        self.finish()


class WebSocketHandler(tornado.websocket.WebSocketHandler):

    def open(self, *args):
        log.debug("<< WEBSOCKET OPEN")
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
        log.debug("<< WEBSOCKET INPUT")
        dct = json.loads(message)
        logjson(dct, False)
        # if dct.has_key("action"): # python2
        if "action" in dct:     # python3
            log.debug("~~~ device sent action request, acknowledging / answering...")
            if dct['action'] == "register":
                # ITA-GZ1-GL, PSC-B01-GL, etc.
                if "model" in dct and dct["model"]:
                    self.device_model = dct["model"]
                    log.info("We are dealing with a {} model.".format(self.device_model))
                log.debug("~~~~ register")
                data = {
                    "error": 0,
                    "deviceid": dct['deviceid'],
                    "apikey": self.uuid,
                    "config": {
                        "hb": 1,
                        "hbInterval": 145
                    }
                }
                logjson(data)
                self.write_message(data)
            if dct['action'] == "date":
                log.debug("~~~~ date")
                data = {
                    "error": 0,
                    "deviceid": dct['deviceid'],
                    "apikey": self.uuid,
                    "date": datetime.isoformat(datetime.today())[:-3] + 'Z'
                }
                logjson(data)
                self.write_message(data)
            if dct['action'] == "query":
                log.debug("~~~~ query")
                data = {
                    "error": 0,
                    "deviceid": dct['deviceid'],
                    "apikey": self.uuid,
                    "params": 0
                }
                logjson(data)
                self.write_message(data)
            if dct['action'] == "update":
                log.debug("~~~~ update")
                data = {
                    "error": 0,
                    "deviceid": dct['deviceid'],
                    "apikey": self.uuid
                }
                logjson(data)
                self.write_message(data)
                self.setup_completed = True
        # elif dct.has_key("sequence") and dct.has_key("error"): # python2
        elif "sequence" in dct and "error" in dct:
            log.debug(
                "~~~ device acknowledged our action request (seq {}) "
                "with error code {}".format(
                    dct['sequence'],
                    dct['error'] # 404 here
                )
            )
            if dct['error'] == 404:
                log.error("*************************************************")
                log.error("Received a 404 error, try running with " \
                    "'--slowstream' option.")
                log.error("*************************************************")
                log.info("Setting slowstream for following call...")
                args.slowstream = True
                self.upgrade = True
        else:
            log.warn("## MOEP! Unknown request/answer from device!")

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
            logjson(data)
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
            logjson(data)
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
            logjson(data)
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
            logjson(data)
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
            logjson(data)
            self.write_message(data)
            self.test = True

        if self.setup_completed and self.test and not self.upgrade:

            hash_user1 = self.getFirmwareHash(resource_path(os.path.join("static", upgrade_file_user1)))
            hash_user2 = self.getFirmwareHash(resource_path(os.path.join("static", upgrade_file_user2)))

            if not args.serving_host:
                raise ValueError('args.serving_host is required')
            if hash_user1 and hash_user2:
                if args.slowstream:
                    udir = 'slowota'
                else:
                    udir = 'ota'
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
                        "binList": [
                            {
                                "downloadUrl": "http://%s:%s/%s/%s" %
                                (args.serving_host, DEFAULT_PORT_HTTP, udir, upgrade_file_user1),
                                # the device expects and checks the sha256 hash of
                                #   the transmitted file
                                "digest": hash_user1,
                                "name": "user1.bin"
                            },
                            {
                                "downloadUrl": "http://%s:%s/%s/%s" %
                                (args.serving_host, DEFAULT_PORT_HTTP, udir, upgrade_file_user2),
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
                logjson(data)
                self.write_message(data)
                self.upgrade = True

    def on_close(self):
        log.debug("~~ websocket close")

    def getFirmwareHash(self, filePath):
        hash_user = None
        try:
            with open(filePath, "rb") as firmware:
                hash_user = sha256(firmware.read()).hexdigest()
        except IOError as e:
            log.warning(e)
        return hash_user


def make_app():
    apps = [
        # handling initial dispatch HTTPS POST call to eu-disp.coolkit.cc
        (r'/dispatch/device', DispatchDevice),
        # handling actual payload communication on WebSockets
        (r'/api/ws', WebSocketHandler),
        (r'/slowota/(.*)', SlowOTAUpdate),
        (r'/ota/(.*)', OTAUpdate, {'path': resource_path("static/")}),
    ]
    return tornado.web.Application(apps)

def defaultinterface():
    '''The interface the default gateway is on, if there is one.'''
    try:
        return netifaces.gateways()['default'][netifaces.AF_INET][1]
    except:
        return None

lastip4ips = []
def ip4ips():
    '''A list of IP4 addresses on this host.

    This will try and return the default gateway first in the list, and will
    strip out localhost addresses automatically.
    '''
    global lastip4ips
    ret = []
    defiface = defaultinterface()
    for iface in netifaces.interfaces():
        try:
            addresses = netifaces.ifaddresses(iface)
        except ValueError:  # You must specify a valid interface name.
            continue
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
    if ret != lastip4ips:
        log.debug('Current IPs: %s', ret)
        lastip4ips = ret
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

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(sys.argv[0])

    return os.path.join(base_path, relative_path)

def checkargs():
    # Make sure all of the binary files that are needed are there
    for fn in [arduino_file, upgrade_file_user1, upgrade_file_user2]:
        fn = os.path.join('static', fn)
        fn = resource_path(fn)
        if not os.path.isfile(fn):
            log.critical("Required file missing!", fn)
            sys.exit(1)
        f = open(fn, 'rb').read()
        if len(f) < 100000:
            log.critical("Binary file appears too small!", fn)
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
        log.info(
            "** The IP address of <serve_host> ({}) is not assigned to any interface "
            "on this machine.".format(args.serving_host))
        log.info(
            "** Please change WiFi network to {} and make sure {} is "
            "being assigned to your WiFi interface before connecting to the "
            "Sonoff device.".format(args.wifi_ssid, args.serving_host))
        sys.exit(1)
    if hasfinalstageip() or hassonoffip():
        log.critical('It looks like you are already on a Sonoff/Final stage WiFi '\
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
    log.info('Using the following configuration:')
    log.info('\tServer IP Address: ' + args.serving_host)
    log.info('\tWiFi SSID: ' + args.wifi_ssid)
    log.info('\tWiFi Password: ' + '*' * len(args.wifi_password))

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
                log.info("Appear to have connected to the final stage IP, "\
                    "moving to next stage.")
                return
            if hassonoffip():
                break
            else:
                if conn_attempt == 1:
                    log.info("** Now connect via WiFi to your Sonoff device.")
                    log.info("** Please change into the ITEAD WiFi "
                        "network (ITEAD-100001XXXX). The default password "
                        "is 12345678.")
                    log.info("To reset the Sonoff to defaults, press "
                        "the button for 7 seconds and the light will "
                        "start flashing rapidly.")
                    log.info("** This application should be kept running "
                        "and will wait until connected to the Sonoff...")
                sleep(2)
                print(".", end="", flush=True)
                continue

    http = Http(timeout=2)

    log.debug("~~ Connection attempt")
    conn_attempt = 0
    while True:
        conn_attempt += 1
        log.debug(">> HTTP GET /10.10.7.1/device")
        try:
            resp, cont = http.request("http://10.10.7.1/device", "GET")
            break
        except socket_error as e:
            log.debug(e)
            continue

    dct = json.loads(cont.decode('utf-8'))
    logjson(dct, False)

    if not args.serving_host:
        raise ValueError('args.serving_host is required')
    data = {
        "version": 4,
        "ssid": args.wifi_ssid,
        "password": args.wifi_password,
        "serverName": args.serving_host,
        "port": DEFAULT_PORT_HTTPS
    }
    log.debug(">> HTTP POST /10.10.7.1/ap")
    logjson(data)
    resp, cont = http.request(
        "http://10.10.7.1/ap", "POST", json.dumps(data))
    dct = json.loads(cont.decode('utf-8'))
    logjson(dct, False)

    log.info("~~ Provisioning completed")

def stage2():
    log.info("Starting stage2...")
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
                    log.info("** The IP address of <serve_host> ({}) is not assigned "
                        "to any interface on this machine.".format(args.serving_host))
                    log.info(
                        "** Please change WiFi network to {} and make sure {} is "
                        "being assigned to your WiFi interface.".format(
                            args.wifi_ssid, args.serving_host))
                    log.info("** This application should be kept running "
                        "and will wait until connected to the WiFi...")
                sleep(2)
                print(".", end="", flush=True)
                continue

    log.info("~~ Starting web server (HTTP port: %s, HTTPS port %s)" % (
        DEFAULT_PORT_HTTP, DEFAULT_PORT_HTTPS))

    # Ensure ProactorEventLoop not used on windows (not yet release in latest tornado)
    # https://github.com/python/pyperformance/pull/65/files
    if sys.platform == 'win32' and sys.version_info[:2] == (3, 8):
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    if args.legacy:
        old = make_app()
        # listening on port 8081 for serving upgrade files for older devices
        old.listen(8081)

    # listening on port 8080 for serving upgrade files
    app.listen(DEFAULT_PORT_HTTP)

    app_ssl = tornado.httpserver.HTTPServer(app, ssl_options={
        "certfile": resource_path("ssl/server.crt"),
        "keyfile": resource_path("ssl/server.key"),
        "ssl_version": ssl.PROTOCOL_TLSv1_1,
    })
    # listening on HTTPS port to catch initial POST request to eu-disp.coolkit.cc
    app_ssl.listen(DEFAULT_PORT_HTTPS)

    log.info("~~ Waiting for device to connect")

    stage3thread = threading.Thread(target=stage3, daemon=True)
    stage3thread.start()

    tornado.ioloop.IOLoop.instance().start()

def stage3():
    '''This is just a thread to provide feedback to the user.'''
    count = 0
    while not hasfinalstageip():
        if count % 30 == 0:
            print()
            log.info("*** IMPORTANT! ***")
            log.info("** AFTER the first download is COMPLETE, with in a minute or so "
                'you should connect to the new SSID "FinalStage" to finish the process.')
            log.info('** ONLY disconnect when the new "FinalStage" SSID is visible '
                'as an available WiFi network.')
            log.info('This server should automatically be allocated the IP address: '
                '192.168.4.2.')
            log.info('If you have successfully connected to "FinalStage" and this is '
                'not the IP Address you were allocated, please ensure no other '
                'device has connected, and reboot your Sonoff.')
        count += 1
        sleep(2)
        print(".", end="", flush=True)

    count = 0
    while True:
        if not hasfinalstageip():
            if 'image_arduino.bin' in seenfiles:
                # The arduino image has been downloaded, exit
                break
            else:
                print()
                print()
                log.info('It appears we have been disconnected from the '
                    '"FinalStage" SSID, however the final image has not been '
                    'downloaded. Reconnect to "FinalStage" when it returns to '
                    'continue the process (this may require a power cycle of '
                    'your Sonoff device)...')
                print()
                while not hasfinalstageip():
                    print(".", end="", flush=True)
                    sleep(2)

        if count % 30 == 0:
            print()
            print()
            log.info('The "FinalStage" SSID will disappear when the device has been '
                'fully flashed and image_arduino.bin has been installed.')
            log.info('If there is no "Sending file: /ota/image_arduino.bin" '
                'log entry, ensure all firewalls have been COMPLETELY disabled '
                'on your system.')
        count += 1
        sleep(2)
        print(".", end="", flush=True)

    log.info('No longer on "FinalStage" SSID, all done! Now connect to the '
            'sonoff-#### SSID and configure for your WiFi (it will not be '
            'configured).')
    _thread.interrupt_main()

def main():
    checkargs()
    log.info("Platform: %s" % (sys.platform))
    if not args.no_prov:
        stage1()
    stage2()

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        log.info("Quitting.")
