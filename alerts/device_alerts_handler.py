"""
This module contains everything needed to create and save alerts regarding
the monitored devices.
"""


import logging
import time
from threading import Thread
from db_start import Session
from alerts.models import UptimeAlert, PresenceAlert, SNMPNoAnswerAlert, ProcessAlert
from constants import UPTIME_ALERT_MESSAGE, PRESENCE_ALERT_MESSAGE


ALERT_LOGGER = logging.getLogger('Device Alerts Handler')


class DeviceAlertsHandler(Thread):
    """
    This class contains all the methods needed to create different alerts regarding the monitored
    devices.
    """

    def __init__(self):
        super().__init__()
        self.session = Session()
        self.alerts = []
        self.presence_alerts_updates = []
        self.process_alert_updates = []
        self.noanswer_alerts_updates = []

    @staticmethod
    def _get_uptime_alert_message(**kwargs):
        return UPTIME_ALERT_MESSAGE.format(**kwargs)

    @staticmethod
    def _get_presence_alert_message(**kwargs):
        return PRESENCE_ALERT_MESSAGE.format(**kwargs)

    def create_process_alert(self, timestamp, mac_address, process, last_seen):
        process_alert = ProcessAlert(timestamp=timestamp, mac_address=mac_address, process=process, last_seen=last_seen)
        self.alerts.append(process_alert)

    def update_process_alert(self, updated_process_alert):
        self.process_alert_updates.append(updated_process_alert)

    def create_uptime_alert(self, timestamp, mac_address, uptime_before_alert, new_uptime):
        uptime_alert = UptimeAlert(timestamp=timestamp, mac_address=mac_address, uptime_before_alert=uptime_before_alert, new_uptime=new_uptime)
        self.alerts.append(uptime_alert)

    def create_presence_alert(self, timestamp, mac_address, last_seen):
        presence_alert = PresenceAlert(timestamp=timestamp, mac_address=mac_address, last_seen=last_seen)
        self.alerts.append(presence_alert)

    def update_presence_alert(self, mac_address, last_seen, recovered):
        presence_alert = PresenceAlert(mac_address=mac_address, last_seen=last_seen, recovered=recovered)
        self.presence_alerts_updates.append(presence_alert)

    def _update_presence_alerts(self):
        for alert in self.presence_alerts_updates:
            open_alerts = self.session.query(PresenceAlert).filter_by(mac_address=alert.mac_address,
                                                                      last_seen=alert.last_seen,
                                                                      recovered=None).all()
            if len(open_alerts) == 1:
                open_alert = open_alerts.pop()
                open_alert.recovered = alert.recovered
                self.session.flush()
                # self.session.merge(alert)

            else:  # Should not happen. If it does, close them all as the device was found
                for open_alert in open_alerts:
                    open_alert.recovered = alert.recovered
                    self.session.flush()

    def create_snmp_noanswer_alert(self, timestamp, mac_address):
        alert = SNMPNoAnswerAlert(timestamp=timestamp, mac_address=mac_address)
        self.alerts.append(alert)

    def update_snmp_noanswer_alert(self, alert_end, mac_address):
        alert = SNMPNoAnswerAlert(alert_end=alert_end, mac_address=mac_address)
        self.noanswer_alerts_updates.append(alert)

    def _update_noanswer_alerts(self):
        for alert in self.noanswer_alerts_updates:
            open_alerts = self.session.query(SNMPNoAnswerAlert).filter_by(mac_address=alert.mac_address,
                                                                          alert_end=None).all()
            if len(open_alerts) == 1:
                open_alert = open_alerts.pop()
                open_alert.alert_end = alert.alert_end

            else:  # Should not happen. If it does, close them all as the device was found
                for open_alert in open_alerts:
                    open_alert.alert_end = alert.alert_end

        self.session.flush()

    def run(self):
        while True:
            if len(self.alerts) > 0:
                self.session.add_all(self.alerts)
                self.alerts = []

            if len(self.presence_alerts_updates) > 0:
                self._update_presence_alerts()

            if len(self.noanswer_alerts_updates) > 0:
                self._update_noanswer_alerts()

            if len(self.process_alert_updates) > 0:
                for alert in self.process_alert_updates:
                    self.session.merge(alert)

            self.session.commit()
            time.sleep(60)
