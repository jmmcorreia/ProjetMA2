from datetime import datetime
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey
from sqlalchemy.orm import relationship
from db_start import Base, engine
import constants


class Device(Base):
    __tablename__ = "device"

    mac_address = Column(String, primary_key=True)
    ip = Column(String)
    device_type = Column(String)
    vendor = Column(String)
    discovery_date = Column(DateTime)
    presence = relationship('DevicePresence')

    def __repr__(self):
        return 'MAC: {mac_address}, IP: {ip}, TYPE: {device_type}, VENDOR: {vendor}, DISCOVERY: {discovery_date}'.format(
            **self.__dict__)


class DevicePresence(Base):
    __tablename__ = "device_presence"
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


class DeviceUptime(Base):
    __tablename__ = "device_uptime"

    mac_address = Column(String, ForeignKey('device.mac_address'), primary_key=True)
    uptime = Column(Integer)
    date = Column(DateTime)

    @staticmethod
    def get_previous_uptime(mac_address, session):
        return session.query(DeviceUptime).filter_by(mac_address=mac_address).first()

    def test_alert(self, session):
        alert = False
        previous_uptime = self.get_previous_uptime(self.mac_address, session)
        if previous_uptime is not None:
            alert = self.compare_uptime(previous_uptime)
        return alert, previous_uptime

    def compare_uptime(self, previous_uptime):
        delta_time = self.date - previous_uptime.date
        expected_uptime = (previous_uptime.uptime + delta_time.total_seconds() * constants.SECONDS_TO_HUNDREDTHS) % 2 ** constants.COUNTER_BITS  # *100 because server_uptime is in hundredths of a second
        if expected_uptime > previous_uptime.uptime:  # No overflow
            return previous_uptime.uptime > self.uptime

        # Handle overflow
        # eps is used to handle possible measure error date attribute does not correspond exactly to the time of measure
        eps = 2 * constants.SECONDS_TO_HUNDREDTHS
        return expected_uptime - eps > self.uptime

    def __repr__(self):
        return 'MAC_ADDRESS: {mac_address}, SERVER_UPTIME:{uptime}, DATE:{date}'.format(**self.__dict__)


class DeviceMonitoredValue(Base):
    __tablename__ = "device_monitored_value"

    id = Column(Integer, primary_key=True)
    mac_address = Column(String, ForeignKey('device.mac_address'))
    value_name = Column(String)
    value = Column(String)
    date = Column(DateTime)

    def __repr__(self):
        if self.id is not None:
            return 'ID: {id}, MAC_ADDRESS: {mac_address}, VALUE_NAME: {value_name}, VALUE:{value}, DATE:{date}'.format(
                **self.__dict__)

        return 'ID: None, MAC_ADDRESS: {mac_address}, VALUE_NAME: {value_name}, VALUE:{value}, DATE:{date}'.format(
            **self.__dict__)


class DeviceProcess(Base):
    __tablename__ = "device_process"

    mac_address = Column(String, ForeignKey('device.mac_address'), primary_key=True)
    process = Column(String, primary_key=True)
    date = Column(DateTime)

    @staticmethod
    def get_process(process, mac_address, session):
        device_process = session.query(DeviceProcess).filter_by(mac_address=mac_address, process=process).first()
        return device_process

    def __repr__(self):
        return 'MAC_ADDRESS: {mac_address}, PROCESS:{process}, DATE:{date}'.format(**self.__dict__)


Base.metadata.create_all(engine)
