"""
Module that contains everything that is required to create a map of a network.
"""

import logging
import time
import ipaddress
import constants
import nmap
import netifaces
from threading import Thread
from datetime import datetime
from utils import get_config_file_section, get_file, UnknownFileExtension
from db_start import Session
from device_monitoring.device_presence_monitoring import Device

NMAPPER_LOGGER = logging.getLogger('Network Mapper')


def get_device_type(ip_address, mac):
    """
    Get the device type from the DEVICE_FILENAME(see config file) file.
    The ip or the MAC addresses can be used to identify a device.

    :raise ValueError: ValueError is raised when the the ip address and the mac parameters do not match the same
    device type

    :param str ip_address: ip address of the device we want the type
    :param str mac: mac address from the device we want the type
    :return str: Device's type
    """
    config = get_config_file_section(constants.CONFIG_FILE, constants.NMAP_SECTION)
    try:
        devices_file = get_file(config['DEVICES_FILENAME'])
    except (FileNotFoundError, UnknownFileExtension) as error:
        NMAPPER_LOGGER.error("File containing device types was not found. Exception %s", error)
        devices_file = {}

    type_ip = devices_file.get(ip_address, None)
    type_mac = devices_file.get(mac, None)
    if type_ip is not None and type_mac is not None:
        if type_ip == type_mac:
            return type_ip
        NMAPPER_LOGGER.error("Two different types were identified for the IP: %s and MAC: %s combination.",
                             ip_address, mac)
        raise ValueError("Two different types were identified for the IP: %s and MAC: %s combination." %
                         (ip_address, mac))

    if type_ip is not None:
        return type_ip
    if type_mac is not None:
        return type_mac
    return constants.UNKNOWN_DEVICE_TYPE


class NetworkMapper(Thread):
    """
    Use a NetworkMapper object to map all the devices in a network.
    (The device from which the NetworkMapper is launched IS NOT INCLUDED in the result)
    """

    def __init__(self, if_name, cmds, network=None):
        """
        :param str if_name: name of the interface that shall be used to scan the network
        :param list cmds: list of NMAP commands that shall be used to map the network
        :param IPv4Network network: IPv4Network object that represents the network we want to MAP.
        If the network is not provided, then the interface's address and netmask will be used to identify the network
        """
        super().__init__()
        self.if_name = if_name
        self.if_ip = None
        self.network = network
        self.cmds = cmds
        self.attempts = 0
        self.session = Session()

    def _nmap_scan(self, cmd):
        """
        Maps the network using NMAP.

        :param str cmd: NMAP command used to map the network
        :return dict: scan result
        """
        if self.network is not None:
            network_scanner = nmap.PortScanner()
            return network_scanner.scan(hosts=self.network.with_prefixlen, arguments=cmd, sudo=True)

        self._get_local_network()
        return self._nmap_scan(cmd)

    def _get_local_network(self):
        """
        Retrieves the local network address and netmask from the network interface
        :return: None
        """
        NMAPPER_LOGGER.info("************ LOCAL NETWORK WAS NONE ************")
        if_addresses = netifaces.ifaddresses(self.if_name)
        if netifaces.AF_INET in if_addresses:
            ip_address = if_addresses[netifaces.AF_INET][0]['addr']
            netmask = if_addresses[netifaces.AF_INET][0]['netmask']
            self.if_ip = ipaddress.IPv4Interface('{ip}/{netmask}'.format(ip=ip_address, netmask=netmask))
            self.network = self.if_ip.network

            NMAPPER_LOGGER.info("************ FOUND LOCAL NETWORK: %s ************", self.network.with_prefixlen)

    def _create_device(self, ip_address, scan_data):
        """
        Creates a device object given an ip address and the scan result for the particular device.
        :param str ip_address: IP address of the device
        :param scan_data: Scan result for the device only
        :return: None
        """
        mac_address = scan_data['addresses'].get('mac', None)
        if mac_address is not None:
            vendor = scan_data['vendor'].get(mac_address, "")
            device_type = get_device_type(ip_address, mac_address)
            device = Device(mac_address=mac_address, ip=ip_address, device_type=device_type, vendor=vendor,
                            discovery_date=datetime.now())
            self.session.merge(device)

    def _scan_network(self, cmd):
        """
        Performs a full scan of the network and parses the result to create the devices object.
        If a NMAP PortScanner error is raised, the method will sleep and then retry again until
        constants.MAX_NMAP_ATTEMPS retries are reached.

        :param str cmd: NMAP command that shall be used to scan the network
        :return: None
        """
        try:
            network_scan = self._nmap_scan(cmd)
            NMAPPER_LOGGER.info("************ NETWORK SCAN FINISHED ************")
            scan_res = network_scan['scan']
            for ip_address, data in scan_res.items():
                self._create_device(ip_address, data)
            self.attempts = 0
            self.session.commit()
        except nmap.PortScannerError as error:
            NMAPPER_LOGGER.error("ERROR WHILE MAPPING THE NETWORK. ERROR: %s", error)
            if self.attempts < constants.MAX_NMAP_ATTEMPS:
                self.attempts += 1
                time.sleep(5)
                self._scan_network(cmd)
            else:
                NMAPPER_LOGGER.error("ERROR WHILE MAPPING THE NETWORK. SKIPPING COMMAND %s", cmd)

    def _stop(self):
        """
        Close the session
        """
        Session.remove()

    def run(self):
        """
        Thread run
        """
        for cmd in self.cmds:
            self._scan_network(cmd)
        self._stop()
