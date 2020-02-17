from threading import Thread
from db_start import Session, Base, engine
from sqlalchemy import Column, DateTime, String, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import logging
import nmap
import time
import constants

logging.basicConfig(filename="DeviceMonitoring.log", format=constants.LOGGING_FORMAT)


class PingHandler:

    def __init__(self):
        self.devices_ping = dict()
        self.session = Session()
        self._create_device_pinger()

    def add_device(self, device):
        if device.mac_address not in self.devices_ping:
            device_ping = DevicePing(device)
            device_ping.start()
            self.devices_ping[device.mac_address] = device_ping
        else:
            raise Exception("This device is already being pinged")  # TODO

    def _create_device_pinger(self):
        devices = self.session.query(Device)
        for device in devices:
            self.add_device(device)


class DevicePing(Thread):

    def __init__(self, device, time_btw_ping=60, alert_time=120):
        super().__init__()
        self.session = Session()
        self.device = device
        self.device_mon = self.session.query(DeviceMonitoring).filter_by(mac_address=self.device.mac_address).first()
        self.time_btw_ping = time_btw_ping
        self.alert_time = alert_time
        self.network_scanner = nmap.PortScanner()
        self.never_seen = 0
        self.running = True

    def _handle_ping_result(self, ping):
        stats = ping.get('scanstats', None)
        up = False
        timestamp = None

        if stats is not None:
            timestamp = datetime.strptime(stats['timestr'], '%a %b %d %H:%M:%S %Y')
            up = bool(stats['uphosts'])

        if up:
            self.device_mon = DeviceMonitoring(mac_address=self.device.mac_address, last_seen=timestamp)
            self.session.merge(self.device_mon)
            self.session.commit()
        else:
            self._handle_down()

    def _handle_down(self):
        alert = False

        if self.device_mon is not None:
            alert = self.device_mon.test_alert()
        else:
            if self.never_seen > 3:
                alert = True
            else:
                self.never_seen += 1

        if alert:
            pass  # TODO

    def run(self):
        while self.running:
            try:
                ping = self.network_scanner.scan(hosts=self.device.ip, arguments='-n -T4 -sn')['nmap']
                self._handle_ping_result(ping)
            except nmap.PortScannerError as error:
                print('ERROR: %s' % error)
                time.sleep(5)  # TODO


class Device(Base):
    __tablename__ = "device"

    mac_address = Column(String, primary_key=True)
    ip = Column(String)  # TODO
    device_type = Column(String)
    vendor = Column(String)
    discovery_date = Column(DateTime)
    monitoring = relationship('DeviceMonitoring')

    def __repr__(self):
        return 'MAC: {mac_address}, IP: {ip}, TYPE: {device_type}, VENDOR: {vendor}, DISCOVERY: {discovery_date}'.format(
            **self.__dict__)


class DeviceMonitoring(Base):
    __tablename__ = "device_monitoring"
    mac_address = Column(String, ForeignKey('device.mac_address'), primary_key=True)
    last_seen = Column(DateTime)

    def test_alert(self, alert_time):
        delta = datetime.now() - self.last_seen
        delta_sec = delta.total_seconds()
        if delta_sec > alert_time:
            return True

        return False

    def __repr__(self):
        return 'MAC: {mac_address}, LAST SEEN: {last_seen}'.format(**self.__dict__)

test = PingHandler()
time.sleep(600)
