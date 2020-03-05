"""
Contains all the models related to the alerts
"""

from sqlalchemy import Column, DateTime, String, Integer, ForeignKey
from device_monitoring.models import Device  # Avoids errors regarding import order. The alerts require the device table to be created beforehand to the key constraints
from db_start import Base, engine


class Alert(Base):
    """
    Defines the baseline content of an alert.
    """
    __tablename__ = "alert"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    type = Column(String(20))

    __mapper_args__ = {
        'polymorphic_identity': 'alert',
        'polymorphic_on': type
    }

    def __repr__(self):
        if self.id is not None:
            return 'ID: {id}, TIMESTAMP: {timestamp}, TYPE: {type}'.format(**self.__dict__)

        return 'ID: None, TIMESTAMP: {timestamp}, TYPE: {type}'.format(**self.__dict__)


class UptimeAlert(Alert):
    """
    Alert related to the uptime of a device.
    Create this alert when the current uptime of the device does not match the expected uptime
    """
    __tablename__ = "uptime_alert"

    id = Column(Integer, ForeignKey('alert.id'), primary_key=True)
    mac_address = Column(String, ForeignKey('device_uptime.mac_address'))
    uptime_before_alert = Column(Integer)
    new_uptime = Column(Integer)

    __mapper_args__ = {
        'polymorphic_identity': 'uptime_alert',
    }

    def __repr__(self):
        if self.id is not None:
            return super().__repr__() + 'MAC_ADDRESS: {mac_address}, UPTIME_BEFORE_ALERT: {uptime_before_alert}, ' \
                                        'NEW_UPTIME: {new_uptime}'.format(**self.__dict__)

        return super().__repr__() + 'ID: None, MAC_ADDRESS: {mac_address}, UPTIME_BEFORE_ALERT: {' \
                                    'uptime_before_alert}, NEW_UPTIME: {new_uptime}'.format(**self.__dict__)


class PresenceAlert(Alert):
    """
    Alert related to the presence of a device on the network.
    Raise this alert when the device was deemed to not be currently present in the network.
    Once the device is recovered, the created alert should also be updated with the time at which
    the device was recovered.
    """
    __tablename__ = "presence_alert"

    id = Column(Integer, ForeignKey('alert.id'))
    mac_address = Column(String, ForeignKey('device.mac_address'), primary_key=True)
    last_seen = Column(DateTime, primary_key=True)
    recovered = Column(DateTime)

    __mapper_args__ = {
        'polymorphic_identity': 'presence_alert',
    }

    @staticmethod
    def get_presence_alert(mac_address, last_seen, session):
        """
        Queries the database and gets the PresenceAlert matching the mac_address and last_seen
        :param str mac_address: MAC address of the device
        :param datetime.datetime last_seen: last time the device was saw on the network
        :param Session session: SQLAlchemy session connected to the database
        :return PresenceAlert: PresenceAlert having the (mac_address, last_seen) composite key
        """
        return session.query(PresenceAlert).filter_by(mac_address=mac_address, last_seen=last_seen).first()

    def __repr__(self):
        if self.id is not None:
            return super().__repr__() + 'ID: {id}, MAC_ADDRESS: {mac_address}, LAST_SEEN: {last_seen}, RECOVERED: {' \
                                        'recovered}'.format(**self.__dict__)

        return super().__repr__() + 'ID: None, MAC_ADDRESS: {mac_address}, LAST_SEEN: {last_seen}, RECOVERED: {' \
                                    'recovered}'.format(**self.__dict__)


class SNMPNoAnswerAlert(Alert):
    """
    Alert used when a device that is currently being monitored using SNMP did not respond to the
    SNMP query. Update this alert once the device starts answering once again.
    """
    __tablename__ = "snmp_noanswer_alert"

    id = Column(Integer, ForeignKey('alert.id'), primary_key=True)
    mac_address = Column(String, ForeignKey('device.mac_address'), primary_key=True)
    alert_end = Column(DateTime)

    __mapper_args__ = {
        'polymorphic_identity': 'snmp_noanswer_alert',
    }

    @staticmethod
    def get_open_alert(mac_address, session):
        """
        Get the current open alert for a device that is not responding to SNMP requests.
        (open means the alert_end value is equal to None)

        :raise ValueError if more than one alert for the same device is currently open

        :param str mac_address: MAC address of the device
        :param Session session: SQLAlchemy session connected to the database
        :return ProcessAlert:
        """
        open_alerts = session.query(SNMPNoAnswerAlert).filter_by(mac_address=mac_address, alert_end=None).all()
        if len(open_alerts) == 1:
            return open_alerts[0]

        if len(open_alerts) > 1:
            raise ValueError("MORE THAN ONE SNMPNoAnswerAlert FOR THE SAME DEVICE IS CURRENTLY OPEN.")

        return None

    @staticmethod
    def get_all_open_alerts(mac_address,  session):
        """
        Get all the current open alerts for a device that is not responding to SNMP requests.
        This should only be used if the get_open_alert method raised a ValueError.
        In this case, use this function to get all the open alerts and close them all.
        Nevertheless, using this method means that there is a bug in the code that should be fixed!!

        THIS METHOD IS ONLY A SAFETY TO USE WHEN THE SAME ALERT AS BEEN ENTERED MULTIPLE TIMES!!

        :param str mac_address: MAC address of the device
        :param Session session: SQLAlchemy session connected to the database
        :return list: list containing all the open alerts for the given process in the device
        """
        open_alerts = session.query(SNMPNoAnswerAlert).filter_by(mac_address=mac_address, alert_end=None)
        return open_alerts.all()

    def __repr__(self):
        if self.id is not None:
            return super().__repr__() + 'ID: {id}, MAC_ADDRESS: {mac_address}'.format(**self.__dict__)

        return super().__repr__() + 'ID: None, MAC_ADDRESS: {mac_address}'.format(**self.__dict__)


class ProcessAlert(Alert):
    """
    Alert regarding the monitoring of a process.
    Raise this alert when the process from the monitored device stops running. Update the alert
    once the process start running once again with the recovered time.
    """
    __tablename__ = "process_alert"

    id = Column(Integer, ForeignKey('alert.id'))
    mac_address = Column(String, ForeignKey('device.mac_address'), primary_key=True)
    process = Column(String, primary_key=True)
    last_seen = Column(DateTime, primary_key=True)
    recovered = Column(DateTime)

    __mapper_args__ = {
        'polymorphic_identity': 'process_alert',
    }

    @staticmethod
    def get_open_alert(mac_address, process, session):
        """
        Get the current open alert for a given process in the device possessing the mac_address.
        (open means the recovered value is currently None)

        :raise ValueError if there is more than one alert currently open for the same process in the same
        device

        :param str mac_address: MAC address of the device
        :param str process: name of process
        :param Session session: SQLAlchemy session connected to the database
        :return ProcessAlert: ProcessAlert with th current open alert if there is one (None otherwise)
        """
        open_alerts = session.query(ProcessAlert).filter_by(mac_address=mac_address,
                                                            process=process,
                                                            recovered=None).all()
        if len(open_alerts) == 1:
            return open_alerts[0]

        if len(open_alerts) > 1:
            raise ValueError("MORE THAN ONE ProcessAlert FOR THE SAME DEVICE IS CURRENTLY OPEN.")

        return None

    @staticmethod
    def get_all_open_alerts(mac_address, process, session):
        """
        Get all the current open alerts for a given process in the device possessing the mac_address.
        This should only be used if the get_open_alert method raised a ValueError.
        In this case, use this function to get all the alerts and close them all.
        Nevertheless, using this method means that there is a bug in the code that should be fixed!!

        THIS METHOD IS ONLY A SAFETY TO USE WHEN THE SAME ALERT AS BEEN ENTERED MULTIPLE TIMES!!

        :param str mac_address: MAC address of the device
        :param str process: name of process
        :param Session session: SQLAlchemy session connected to the database
        :return list: list containing all the open alerts for the given process in the device
        """
        open_alerts = session.query(ProcessAlert).filter_by(mac_address=mac_address, process=process, recovered=None)
        return open_alerts.all()

    def __repr__(self):
        if self.id is not None and self.recovered is not None:
            return super().__repr__() + 'ID: {id}, MAC_ADDRESS: {mac_address}, PROCESS: {process}, ' \
                                        'LAST_SEEN: {last_seen}, RECOVERED: {recovered}'.format(**self.__dict__)

        return super().__repr__() + 'ID: None, MAC_ADDRESS: {mac_address}, PROCESS: {process}, ' \
                                    'LAST_SEEN: {last_seen}'.format(**self.__dict__)


Base.metadata.create_all(engine)
