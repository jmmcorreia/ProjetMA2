from db_start import Session
from device_monitoring.devices_dao import Device, DeviceMonitoring
from threading import Thread
from datetime import datetime
import nmap
import time
import logging
import constants

logging.basicConfig(filename="DeviceMonitoring.log", format=constants.LOGGING_FORMAT)


class PingHandler:

    def __init__(self):
        self.devices_ping = dict()
        self.session = Session()
        self.create_device_pinger()

    def create_device_pinger(self):
        devices = self.session.query(Device)
        for device in devices:
            device_ping = DevicePing(device)
            device_ping.start()
            self.devices_ping[device.mac_address] = device_ping


class DevicePing(Thread):

    def __init__(self, device, time_btw_ping=60):
        super().__init__()
        self.device = device
        self.time_btw_ping = time_btw_ping
        self.network_scanner = nmap.PortScanner()
        self.session = Session()
        self.running = True

    def _handle_ping_result(self, ping):
        stats = ping.get('scanstats', None)
        if stats is not None:
            timestamp = datetime.strptime(stats['timestr'], '%a %b %d %H:%M:%S %Y')
            up = bool(stats['uphosts'])
            if up:
                device_mon = DeviceMonitoring(mac_address=self.device.mac_address, last_seen=timestamp)
                self.session.merge(device_mon)
                self.session.commit()
            else:
                self._handle_down_state()

    def _handle_down_state(self):
        logging.ERROR("DEVICE IS DOWN")

    def run(self):
        while self.running:
            try:
                ping = self.network_scanner.scan(hosts=self.device.ip, arguments='-n -T4 -sn')['nmap']
                self._handle_ping_result(ping)
            except (nmap.PortScannerError, nmap.nmap.PortScannerError, Exception) as e:
                print('ERROR: {0}'.format(e))


test = PingHandler()
time.sleep(600)
