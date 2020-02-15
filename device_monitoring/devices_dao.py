from db_start import Base, engine
from sqlalchemy import Column, DateTime, String, ForeignKey, Integer
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import func
import constants


class Device(Base):
    __tablename__ = "device"

    mac_address = Column(String, primary_key=True)
    ip = Column(String)  # TODO
    device_type = Column(String)
    vendor = Column(String)
    discovery_date = Column(DateTime)
    monitoring = relationship('DeviceMonitoring')

    def __repr__(self):
        return 'MAC: {mac_address}, IP: {ip}, TYPE: {device_type}, VENDOR: {vendor}, DISCOVERY: {discovery_date}'.format(**self.__dict__)


class DeviceMonitoring(Base):
    __tablename__ = "device_monitoring"
    mac_address = Column(String, ForeignKey('device.mac_address'), primary_key=True)
    last_seen = Column(DateTime)

    def __repr__(self):
        return 'MAC: {mac_address}, LAST SEEN: {last_seen}'.format(**self.__dict__)


class ServerUptime(Base):
    __tablename__ = "server_uptime"

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer)  # TODO
    server_uptime = Column(Integer)
    date = Column(DateTime)

    def test_alert(self, session):
        alert = False
        previous_id = session.query(func.max(ServerUptime.id))
        if previous_id is not None:
            previous_uptime = session.query(ServerUptime).filter_by(server_id=self.server_id, id=previous_id).first()
            if previous_uptime is not None:
                alert = self.compare_uptime(previous_uptime)
        return alert

    def compare_uptime(self, previous_uptime):
        delta_time = self.date - previous_uptime.date
        expected_uptime = (previous_uptime.server_uptime + delta_time.total_seconds() * constants.SECONDS_TO_HUNDREDTHS) % 2**constants.COUNTER_BITS  # *100 because server_uptime is in hundredths of a second
        if expected_uptime > previous_uptime.server_uptime:  # No overflow
            return previous_uptime.server_uptime > self.server_uptime
        else:  # Handle overflow
            eps = 2 * constants.SECONDS_TO_HUNDREDTHS  # Handle possible measure error. datetime does not correspond exactly to the time of measure
            return expected_uptime - eps > self.server_uptime

    def __repr__(self):
        if self.id is not None:
            return 'ID: {id}, SERVER_ID: {server_id}, SERVER_UPTIME:{server_uptime}, DATE:{date}'.format(**self.__dict__)
        else:
            return 'ID: None, SERVER_ID: {server_id}, SERVER_UPTIME:{server_uptime}, DATE:{date}'.format(**self.__dict__)


class ServerMonitoredValue(Base):
    __tablename__ = "server_monitored_value"

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer)  # TODO
    value_name = Column(String)
    value = Column(String)
    date = Column(DateTime)

    def __repr__(self):
        if self.id is not None:
            return 'ID: {id}, SERVER_ID: {server_id}, VALUE_NAME: {value_name}, VALUE:{value}, DATE:{date}'.format(
                **self.__dict__)

        else:
            return 'ID: None, SERVER_ID: {server_id}, VALUE_NAME: {value_name}, VALUE:{value}, DATE:{date}'.format(
                **self.__dict__)


Base.metadata.create_all(bind=engine)
