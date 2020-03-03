"""
This module contains all the models required to monitor a device including the device itself.
"""
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey
from sqlalchemy.orm import relationship
from db_start import Base, engine
import constants


class Device(Base):
    """
    Class that represents any device on the network and that we may want to monitor.
    This object also represents the device table on the database.
    """
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
    """
    Object used to represent if a device is present on the network and what was the last time it
    was saw/pinged.
    """
    __tablename__ = "device_presence"
    mac_address = Column(String, ForeignKey('device.mac_address'), primary_key=True)
    last_seen = Column(DateTime)

    def __repr__(self):
        return 'MAC: {mac_address}, LAST SEEN: {last_seen}'.format(**self.__dict__)


class DeviceUptime(Base):
    """
    Object used to represent a device's uptime that was obtained from the device itself.
    (Not related to how long we have been monitoring the device)
    """
    __tablename__ = "device_uptime"

    mac_address = Column(String, ForeignKey('device.mac_address'), primary_key=True)
    uptime = Column(Integer)
    date = Column(DateTime)

    @staticmethod
    def get_previous_uptime(mac_address, session):
        """
        Queries the database and gets the last DeviceUptime object belonging to the
        device with the parameter mac_address
        :param str mac_address: MAC address of the device we want the uptime
        :param Session session: SQLAclchemy session connected to the database
        :return: DeviceUptime from the device possessing the MAC address given as a parameter
        """
        return session.query(DeviceUptime).filter_by(mac_address=mac_address).first()

    def test_alert(self, session):
        """
        Compares a DeviceUptime object with the current one present in the database
        to check if there is any alert related with the uptime.

        :param Session session: SQLAclchemy session connected to the database
        :return tuple: boolean that is true if there is an alert, DeviceUptime present in the DB
        """
        alert = False
        previous_uptime = self.get_previous_uptime(self.mac_address, session)
        if previous_uptime is not None:
            alert = self._compare_uptime(previous_uptime)
        return alert, previous_uptime

    def _compare_uptime(self, previous_uptime):
        """
        Checks if the current uptime of the device is lower than an expected uptime value
        calculated using the previous uptime gotten from the device

        :param DeviceUptime previous_uptime: DeviceUptime object that contains the previous
        uptime of the device
        :return boolean: True if the current uptime is smaller than the expected uptime,
        False otherwise
        """
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
    """
    Object used to store any monitored values that are not used to generate alerts.
    """
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
    """
    Object used to store information regarding processes in a device.
    In particular it stores the last time the process was seen running.
    """
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
