from threading import Thread
from datetime import datetime
import logging
import time
from scapy.layers.l2 import arping, Ether
from scapy.layers.inet import IP, ICMP
from scapy.all import srp, sr
from db_start import Session
from device_monitoring.models import Device, DevicePresence


PRESENCE_LOGGER = logging.getLogger('Device Monitoring')


class PingHandler:

    def __init__(self, alert_handler):
        self.devices_ping = dict()
        self.session = Session()
        self.alert_handler = alert_handler
        self._create_device_pinger()

    def add_device(self, device):
        if device.mac_address not in self.devices_ping:
            device_ping = DevicePing(device, self.alert_handler)
            device_ping.start()
            self.devices_ping[device.mac_address] = device_ping
        else:
            raise ConnectionError("THIS DEVICE IS ALREADY BEING PINGED")

    def remove_device(self, mac_address):
        if mac_address in self.devices_ping:
            self.devices_ping.pop(mac_address)

    def _create_device_pinger(self):
        devices = self.session.query(Device)
        for device in devices:
            try:
                self.add_device(device)
                time.sleep(2)  # Avoid pinging all devices at the same time
            except ConnectionError as error:
                PRESENCE_LOGGER.warning('PING HANDLER WARNING. DEVICE IP: %s. DEVICE MAC: %s. ERROR: %s',
                                        device.ip, device.mac_address, error)


class DevicePing(Thread):

    def __init__(self, device, alert_handler, time_btw_ping=60):
        super().__init__()
        self.session = None
        self.device = device
        self.alert_handler = alert_handler
        self.device_presence = None
        self.time_btw_ping = time_btw_ping
        self.present = True
        self.running = True

    @staticmethod
    def handle_frame_response(ans, unans):
        if len(ans) > 0:
            return True

        return False

    @staticmethod
    def handle_packet_response(ans, unans):
        if len(ans) > 0:
            return True

        return False

    def send_icmp_frame(self, timeout=1.0):
        ans, unans = srp(Ether(dst=self.device.mac_address) / IP(dst=self.device.ip) / ICMP(), timeout=timeout)
        return self.handle_frame_response(ans, unans)

    def send_icmp_packet(self, timeout=1.0):
        ans, unans = sr(IP(dst=self.device.ip) / ICMP(), timeout=timeout)
        return self.handle_packet_response(ans, unans)

    def send_arp_req(self, timeout=1.0):
        ans, unans = arping(self.device.ip, timeout=timeout)
        return self.handle_frame_response(ans, unans)

    def ping_device(self):
        if self.send_icmp_frame(2):
            self.update_presence()
            return
        PRESENCE_LOGGER.warning("************ ICMP FRAME FAILED / MAC ADDRESS: %s / IP: %s ************",
                                self.device.mac_address, self.device.ip)

        time.sleep(10)
        if self.send_arp_req(4):
            self.update_presence()
            return
        PRESENCE_LOGGER.warning("************ ARP REQUEST FAILED / MAC ADDRESS: %s ************",
                                self.device.mac_address)

        time.sleep(10)
        if self.send_icmp_packet(4):
            self.update_presence()
            return
        PRESENCE_LOGGER.warning("************ ICMP PACKET FAILED / MAC ADDRESS: %s / IP: %s ************",
                                self.device.mac_address, self.device.ip)

        time.sleep(10)
        if self.send_icmp_frame(10):
            self.update_presence()
            return

        PRESENCE_LOGGER.warning(
            "************ SECOND ICMP FRAME FAILED. DEVICE DOWN / MAC ADDRESS: %s / IP: %s ************",
            self.device.mac_address, self.device.ip)

        self._handle_down()

    def _handle_down(self):
        timestamp = datetime.now()
        if self.present:
            self.alert_handler.create_presence_alert(timestamp, self.device_presence.mac_address,
                                                     self.device_presence.last_seen)
        self.present = False

    def update_presence(self):
        timestamp = datetime.now()
        if not self.present:
            self.present = True
            self.alert_handler.update_presence_alert(self.device_presence.mac_address, self.device_presence.last_seen,
                                                     timestamp)

        self.device_presence = DevicePresence(mac_address=self.device.mac_address, last_seen=timestamp)
        self.session.merge(self.device_presence)
        self.session.commit()

    def run(self):
        self.session = Session()
        self.device_presence = self.session.query(DevicePresence).filter_by(mac_address=self.device.mac_address).first()
        while self.running:
            try:
                self.ping_device()
                time.sleep(self.time_btw_ping)
            except Exception as error:
                PRESENCE_LOGGER.error('EXCEPTION IN DEVICE PING. DEVICE IP: %s. DEVICE MAC: %s. ERROR: %s',
                                      self.device.ip, self.device.mac_address, error)
                raise
