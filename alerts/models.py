from sqlalchemy import Column, DateTime, String, Integer, ForeignKey
from db_start import Base, engine


class Alert(Base):
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
    __tablename__ = "presence_alert"

    id = Column(Integer, ForeignKey('alert.id'), primary_key=True)
    mac_address = Column(String, ForeignKey('device.mac_address'))
    last_seen = Column(DateTime)
    recovered = Column(DateTime)

    __mapper_args__ = {
        'polymorphic_identity': 'presence_alert',
    }

    def __repr__(self):
        if self.id is not None:
            return super().__repr__() + 'ID: {id}, MAC_ADDRESS: {mac_address}, LAST_SEEN: {last_seen}, RECOVERED: {' \
                                        'recovered}'.format(**self.__dict__)

        return super().__repr__() + 'ID: None, MAC_ADDRESS: {mac_address}, LAST_SEEN: {last_seen}, RECOVERED: {' \
                                    'recovered}'.format(**self.__dict__)


class SNMPNoAnswerAlert(Alert):
    __tablename__ = "snmp_noanswer_alert"

    id = Column(Integer, ForeignKey('alert.id'), primary_key=True)
    mac_address = Column(String, ForeignKey('device.mac_address'))
    alert_end = Column(DateTime)

    __mapper_args__ = {
        'polymorphic_identity': 'snmp_noanswer_alert',
    }

    def __repr__(self):
        if self.id is not None:
            return super().__repr__() + 'ID: {id}, MAC_ADDRESS: {mac_address}'.format(**self.__dict__)

        return super().__repr__() + 'ID: None, MAC_ADDRESS: {mac_address}'.format(**self.__dict__)


class ProcessAlert(Alert):
    __tablename__ = "process_alert"

    id = Column(Integer, ForeignKey('alert.id'), primary_key=True)
    mac_address = Column(String, ForeignKey('device.mac_address'), primary_key=True)
    process = Column(String, primary_key=True)
    last_seen = Column(DateTime, primary_key=True)
    recovered = Column(DateTime)

    __mapper_args__ = {
        'polymorphic_identity': 'process_alert',
    }

    @staticmethod
    def get_open_alert(mac_address, process, session):
        open_alerts = session.query(ProcessAlert).filter_by(mac_address=mac_address,
                                                            process=process,
                                                            recovered=None).all()
        if len(open_alerts) == 1:
            return open_alerts[0]
        elif len(open_alerts) > 1:
            raise ValueError("MORE THAN ONE ERROR CURRENTLY OPEN")

        return None

    @staticmethod
    def get_all_open_alerts(mac_address, process, session):
        open_alert = session.query(ProcessAlert).filter_by(mac_address=mac_address, process=process, recovered=None)
        return open_alert.all()

    def __repr__(self):
        if self.id is not None:
            return super().__repr__() + 'ID: {id}, MAC_ADDRESS: {mac_address}, PROCESS: {process}, ' \
                                        'LAST_SEEN: {last_seen}, RECOVERED: {recovered}'.format(**self.__dict__)

        return super().__repr__() + 'ID: None, MAC_ADDRESS: {mac_address}, PROCESS: {process}, ' \
                                    'LAST_SEEN: {last_seen}, RECOVERED: {recovered}'.format(**self.__dict__)


Base.metadata.create_all(engine)
