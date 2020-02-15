import datetime
import logging
import time
import constants
import ipaddress
from threading import Thread
import nmap
import netifaces
from utils import get_config_file_section, get_file, UnknownFileExtension
from db_start import Session
from device_monitoring.devices_dao import Device

logging.basicConfig(filename='NetworkMap.log', format=constants.LOGGING_FORMAT)


class NetworkMapper(Thread):

    def __init__(self, if_name, commands, network=None):
        super().__init__()
        self.if_name = if_name
        self.if_ip = None
        self.network = network
        self.commands = commands
        self.attempts = 0
        self.session = Session()

    def _scan_network(self, commands):
        if self.network is not None:
            network_scanner = nmap.PortScanner()
            return network_scanner.scan(hosts=self.network.with_prefixlen, arguments=commands)

        self._get_local_network()
        return self._scan_network(commands)

    def _get_local_network(self):
        if_addresses = netifaces.ifaddresses(self.if_name)
        if netifaces.AF_INET in if_addresses:
            ip = if_addresses[netifaces.AF_INET][0]['addr']
            netmask = if_addresses[netifaces.AF_INET][0]['netmask']
            self.if_ip = ipaddress.IPv4Interface('{ip}/{netmask}'.format(ip=ip, netmask=netmask))
            self.network = self.if_ip.network

    def _get_device_type(self, ip, mac):
        config = get_config_file_section(constants.CONFIG_FILE, constants.NMAP_SECTION)
        try:
            devices_file = get_file(config['DEVICES_FILENAME'])
        except (FileNotFoundError, UnknownFileExtension) as e:
            logging.error("File containing device types was not found. Exception {}".format(e))
            devices_file = dict()

        type_ip = devices_file.get(ip, None)
        type_mac = devices_file.get(mac, None)
        if type_ip is not None and type_mac is not None:
            if type_ip == type_mac:
                return type_ip
            raise ValueError("Two different types were identified for the IP: {ip} and MAC: {mac} combination.".format(
                ip=ip, mac=mac))
        elif type_ip is not None:
            return type_ip
        elif type_mac is not None:
            return type_mac
        else:
            return constants.UNKNOWN_DEVICE_TYPE

    def _create_device(self, ip, scan_data):
        mac_address = scan_data['addresses'].get('mac', None)
        if mac_address is not None:
            vendor = scan_data['vendor'].get(mac_address, "")
            device_type = self._get_device_type(ip, mac_address)
            device = Device(mac_address=mac_address, ip=ip, device_type=device_type, vendor=vendor,
                            discovery_date=datetime.datetime.now())
            self.session.merge(device)
            self.session.commit()
        else:
            pass  # test if it is local host

    def run(self):
        for command in self.commands:
            try:
                network_scan = self._scan_network(command)
                scan_res = network_scan['scan']
                for ip, data in scan_res.items():
                    self._create_device(ip, data)
            except nmap.PortScannerError as e:
                logging.error("ERROR WHILE MAPPING THE NETWORK. ERROR: {}".format(e))
                if self.attempts < constants.MAX_NMAP_ATTEMPS:
                    self.attempts += 1
                    time.sleep(5)
                    self.run()


n = NetworkMapper('{ABDBE570-3CFB-4C82-850B-862878445FD1}', ['-n -T4 -sn --max-rate 10'])
n.start()
