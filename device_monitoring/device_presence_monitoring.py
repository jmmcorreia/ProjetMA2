"""
Module that contains everything to monitor the presence of a device on the network
"""

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
    """
    This class creates and handles all the objects used to ping the devices (Device Ping)
    """

    def __init__(self, alert_handler):
        """

        :param alert_handler:
        """
        self.devices_ping = dict()
        self.session = Session()
        self.alert_handler = alert_handler
        self._create_device_pinger()

    def add_device(self, device):
        """
        Add a new device to be monitored using ping.
        :raises Connection Error if the device is already being monitored

        :param Device device: device object containing the information of the device to monitor
        :return: None
        """
        if device.mac_address not in self.devices_ping:
            device_ping = DevicePing(device, self.alert_handler)
            device_ping.start()
            self.devices_ping[device.mac_address] = device_ping
        else:
            raise ConnectionError("THIS DEVICE IS ALREADY BEING PINGED")

    def remove_device(self, mac_address):
        """
        Stop pinging a device that is currently being pinged
        :param str mac_address: MAC address of the device we no longer want to ping
        :return: None
        """
        if mac_address in self.devices_ping:
            self.devices_ping.pop(mac_address)

    def _create_device_pinger(self):
        """
        Private Method.
        Creates a DevicePing object for each device entry on the database.
        :return: None
        """
        devices = self.session.query(Device)
        for device in devices:
            try:
                self.add_device(device)
                time.sleep(2)  # Avoid pinging all devices at the same time
            except ConnectionError as error:
                PRESENCE_LOGGER.warning('PING HANDLER WARNING. DEVICE IP: %s. DEVICE MAC: %s. ERROR: %s',
                                        device.ip, device.mac_address, error)


class DevicePing(Thread):
    """
    This class monitors the device presence using a combination of ICMP and ARP pings
    """

    def __init__(self, device, alert_handler, time_btw_ping=60):
        """

        :param device:
        :param alert_handler:
        :param time_btw_ping:
        """
        super().__init__()
        self.session = None
        self.device = device
        self.alert_handler = alert_handler
        self.device_presence = None
        self.time_btw_ping = time_btw_ping
        self.present = True
        self.running = True

    def send_icmp_frame(self, timeout=1.0):
        """
        Sends an ICMP echo-request in an Ethernet frame that already contains the destination's
        MAC address. Returns true if the device responded to the request, false otherwise

        :param int timeout: maximum time to wait for a ICMP echo-reply
        :return boolean: True if device answered, False otherwise
        """
        ans, unans = srp(Ether(dst=self.device.mac_address) / IP(dst=self.device.ip) / ICMP(), timeout=timeout)
        return len(ans)

    def send_icmp_packet(self, timeout=1.0):
        """
        Sends an ICMP echo-request. Layer 2 content is not specified, that will be handled by the
        OS. Returns true if the device responded to the request, false otherwise

        :param int timeout: maximum time to wait for a ICMP echo-reply
        :return boolean: True if device answered, False otherwise
        """
        ans, unans = sr(IP(dst=self.device.ip) / ICMP(), timeout=timeout)
        return len(ans)

    def send_arp_req(self, timeout=1.0):
        """
        Broadcast an ARP request with the device's IPv4 address.
        Returns true if the device responded to the request, false otherwise

        :param int timeout: maximum time to wait for an answer
        :return boolean: True if device answered, False otherwise
        """
        ans, unans = arping(self.device.ip, timeout=timeout)
        return len(ans)

    def ping_device(self):
        """
        This method pings the device in multiple ways trying to obtain a response from the device.
        If the device does not respond to any of the pings then it is considered to be down or
        not present in the network.

        :return: None
        """
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
        """
        Handles the down state of a device.

        :return: None
        """
        timestamp = datetime.now()
        if self.present:
            self.alert_handler.create_presence_alert(timestamp, self.device_presence.mac_address,
                                                     self.device_presence.last_seen)
        self.present = False

    def update_presence(self):
        """
        Updates the last seen presence value in the database regarding the monitored device.
        Moreover, if the device as an ongoing alert for not being present, that alert is closed.
        Therefore, this method should only be called when we know that the device is present in
        the network.

        :return: None
        """
        timestamp = datetime.now()
        if not self.present:
            self.present = True
            self.alert_handler.update_presence_alert(self.device_presence.mac_address, self.device_presence.last_seen,
                                                     timestamp)

        self.device_presence = DevicePresence(mac_address=self.device.mac_address, last_seen=timestamp)
        self.session.merge(self.device_presence)
        self.session.commit()

    def run(self):
        """
        This method launches the ping every time_btw_ping seconds.
        :return: None
        """
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
