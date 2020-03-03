"""
This module contains everything that is required to monitor a device of type server.
"""

import time
import logging
from threading import Thread
from datetime import datetime
from db_start import Session
import constants
from device_monitoring.models import DeviceProcess, DeviceUptime, DeviceMonitoredValue
from alerts.models import ProcessAlert
from snmp_monitoring.snmp_query_handler import SnmpQueryHandler, SnmpAgentQueryException, SnmpVersionException, \
    SnmpMissingCredentialsException
from utils import get_config_file_section


SERVER_LOGGER = logging.getLogger('Server Monitoring')


class ServerMonitoring(Thread):
    """
    Handles the monitoring of a LINUX server using the SNMP protocol.
    """

    def __init__(self, server_ip, server_mac, time_btw_queries, alert_handler):
        super().__init__()
        self.time_btw_queries = time_btw_queries
        self.server_mac = server_mac
        self.alert_handler = alert_handler
        self._snmp_query_handler = SnmpQueryHandler(server_ip,
                                                    get_config_file_section(constants.CONFIG_FILE, constants.GET_OIDS),
                                                    get_config_file_section(constants.CONFIG_FILE, constants.WALK_OIDS),
                                                    version=2)
        self._noanswer_alert = False
        self._monitor_processes = self._get_monitor_processes(server_ip)
        self._session = Session()
        self._running = True

    def _verify_previous_answer(self):
        if self._noanswer_alert:
            self._noanswer_alert = False
            self.alert_handler.update_snmp_noanswer_alert(datetime.now(), self.server_mac)

    def handle_get_result(self, result):
        for key, value in result.items():
            if key == "SYSTEM_UPTIME":
                # There should only be a single system uptime value in the list returned by the query handler
                self.handle_server_uptime(value[0])
            else:
                self.handle_monitored_values(key, value)

    def handle_walk_result(self, result):
        for key, value in result.items():
            if "PROCESS" in key:
                self.handle_process_monitoring(value)

    def handle_server_uptime(self, server_uptime):
        try:
            sys_uptime = int(server_uptime)
            timestamp = datetime.now()
            server_uptime = DeviceUptime(mac_address=self.server_mac, uptime=sys_uptime, date=timestamp)
            alert, previous_uptime = server_uptime.test_alert(self._session)
            if alert:
                self.alert_handler.create_uptime_alert(timestamp, self.server_mac, previous_uptime.uptime, sys_uptime)
            self._session.merge(server_uptime)
        except ValueError as error:
            SERVER_LOGGER.warning("Failed to cast server uptime value as an int. Error: %s", error)

    def _update_process_monitoring(self, device_process):
        timestamp = datetime.now()
        device_process.date = timestamp
        self._session.merge(device_process)

    def _handle_process_alert(self, device_process):
        try:
            process_alert = ProcessAlert.get_open_alert(self.server_mac, device_process.process, self._session)
            if process_alert is not None:
                process_alert.recovered = datetime.now()
                self.alert_handler.update_process_alert(process_alert)
        except ValueError as error:
            SERVER_LOGGER.error("PROCESS ALERT EXCEPTION. ERROR: %s", error)
            process_alerts = ProcessAlert.get_all_open_alerts(self.server_mac, device_process.process, self._session)
            for process_alert in process_alerts:
                process_alert.recovered = datetime.now()
                self.alert_handler.update_process_alert(process_alert)

    def handle_process_monitoring(self, processes_info):
        running_processes = set()
        for process in processes_info:
            process_name = str(process[1])
            running_processes.add(process_name)

        for process in self._monitor_processes:
            device_process = (DeviceProcess.get_process(process, self.server_mac, self._session) or
                              DeviceProcess(mac_address=self.server_mac, process=process))
            if process in running_processes:
                self._update_process_monitoring(device_process)
                self._handle_process_alert(device_process)
            else:
                now = datetime.now()
                if device_process is not None:
                    self.alert_handler.create_process_alert(now, self.server_mac, process, device_process.date)
                else:
                    self.alert_handler.create_process_alert(now, self.server_mac, process, datetime.min)

    def handle_monitored_values(self, name, value):
        try:
            value = str(value)
            monitored_value = DeviceMonitoredValue(mac_address=self.server_mac, value_name=name, value=value,
                                                   date=datetime.now())
            self._session.add(monitored_value)
        except ValueError as error:
            SERVER_LOGGER.warning("Failed to cast a monitored value as a string. Error: %s", error)

    def handle_noanswer_error(self):
        if not self._noanswer_alert:
            self.alert_handler.create_snmp_noanswer_alert(datetime.now(), self.server_mac)
            self._noanswer_alert = True

    def _stop(self):
        Session.remove()

    @staticmethod
    def _get_monitor_processes(server_ip):
        config = get_config_file_section(constants.CONFIG_FILE, constants.AGENT_CONFIG.format(ip=server_ip))
        res = config.get("PROCESS_MONITOR", None)
        if res is not None:
            return set(res.split(','))
        return None

    def run(self):
        while self._running:
            try:
                get_values, walk_values = self._snmp_query_handler.query_agent()
                self.handle_get_result(get_values)
                self.handle_walk_result(walk_values)
                self._verify_previous_answer()
                self._session.commit()
                time.sleep(self.time_btw_queries)
                SERVER_LOGGER.debug('************ SUCCESSFUL SNMP QUERY. AGENT %s ************', self.server_mac)
            except SnmpAgentQueryException as error:
                self.handle_noanswer_error()
                SERVER_LOGGER.warning('Agent not responding. ERROR: %s', error)
            except (SnmpVersionException, SnmpMissingCredentialsException) as error:
                SERVER_LOGGER.error("TERMINAL ERROR: %s", error)
                self._running = False  # terminal failure
            except Exception as error:
                SERVER_LOGGER.error(
                    'UNEXPECTED EXCEPTION CATCHED. SERVER MONITORING WILL TERMINATE. EXCEPTION MESSAGE: %s', error)
                self._running = False
                raise

        self._stop()
