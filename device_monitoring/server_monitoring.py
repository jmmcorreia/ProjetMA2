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
from alerts.models import ProcessAlert, UptimeAlert, SNMPNoAnswerAlert
from snmp_monitoring.snmp_query_handler import SnmpQueryHandler, SnmpAgentQueryException, SnmpVersionException
from utils import get_config_file_section

SERVER_LOGGER = logging.getLogger('Server Monitoring')


class ServerMonitoring(Thread):
    """
    Handles the monitoring of a LINUX server using the SNMP protocol.
    """

    def __init__(self, server_ip, server_mac, time_btw_queries):
        """
        :param str server_ip: ip address of the server
        :param str server_mac: mac address of the server
        :param int time_btw_queries: time in seconds between each SNMP request
        """
        super().__init__()
        self.time_btw_queries = time_btw_queries
        self.server_mac = server_mac
        self._snmp_query_handler = SnmpQueryHandler(server_ip,
                                                    get_config_file_section(constants.CONFIG_FILE, constants.GET_OIDS),
                                                    get_config_file_section(constants.CONFIG_FILE, constants.WALK_OIDS),
                                                    version=2)
        self._monitor_processes = self._get_monitor_processes(server_ip)
        self._session = None
        self._running = True

    def _verify_previous_answer(self):
        """
        Verifies if there is an open SNMPNoAnswerAlert, and closes it if it is the case.
        (Closing means adding alert_end time to the row)
        :return: None
        """
        try:
            open_alert = SNMPNoAnswerAlert.get_open_alert(self.server_mac, self._session)
            if open_alert is not None:
                open_alert.alert_end = datetime.now()
                self._session.merge(open_alert)
        except ValueError as error:
            SERVER_LOGGER.error("HANDLING ERROR: %s DEVICE: %s", error, self.server_mac)
            open_alerts = SNMPNoAnswerAlert.get_all_open_alerts(self.server_mac, self._session)
            for open_alert in open_alerts:
                open_alert.alert_end = datetime.now()
                self._session.merge(open_alert)

    def _handle_get_result(self, result):
        """
        Handles the results from a SNMP Get Request.
        If the parameter key is SYSTEM_UPTIME, it means the value needs to be processed to identify a possible alert
        situation.

        For all the other keys, the result is simply added to the monitored values table.

        :param dict result: result of the SNMP Get request
        :return: None
        """
        for key, value in result.items():
            if key == "SYSTEM_UPTIME":
                # There should only be a single system uptime value in the list returned by the query handler
                self._handle_server_uptime(value)
            else:
                self.handle_monitored_values(key, value)

    def _handle_walk_result(self, result):
        """
        Handles the results from a SNMP Walk Request.
        If the parameter key contains the word PROCESS, then the result will be parsed under the process monitoring
        section to detect any possible alerts.

        :param dict result: result of the SNMP walk request
        :return: None
        """
        for key, value in result.items():
            if "PROCESS" in key:
                running_processes = set()
                for process in value:
                    process_name = str(process[1])
                    running_processes.add(process_name)

                self.handle_process_monitoring(running_processes)

    def _handle_server_uptime(self, server_uptime):
        """
        Receives a server uptime values, logs it into the database and verifies if there is any alert.
        If an alert is detected, that is also logged into the database.

        :param str server_uptime: Server uptime value
        :return: None
        """
        try:
            sys_uptime = int(server_uptime)
            timestamp = datetime.now()
            server_uptime = DeviceUptime(mac_address=self.server_mac, uptime=sys_uptime, date=timestamp)
            self._session.merge(server_uptime)
            alert, previous_uptime = server_uptime.test_alert(self._session)
            if alert:
                alert = UptimeAlert(timestamp=timestamp, mac_address=self.server_mac,
                                    uptime_before_alert=previous_uptime.uptime, new_uptime=sys_uptime)
                self._session.add(alert)

        except ValueError as error:
            SERVER_LOGGER.warning("Failed to cast server uptime value as an int. Error: %s", error)

    def _update_process_monitoring(self, device_process):
        """
        Updates the last_seen value of a device process.

        :param DeviceProcess device_process: device process for which the last seen value will be updated
        :return: None
        """
        timestamp = datetime.now()
        device_process.last_seen = timestamp
        self._session.merge(device_process)

    def _handle_process_alert(self, device_process):
        """
        Checks if a process alert is currently open for the given process.
        If that is the case, it closes the said alert.

        :param DeviceProcess device_process: process that is going to be checked for any open alerts
        :return: None
        """
        try:
            process_alert = ProcessAlert.get_open_alert(self.server_mac, device_process.process, self._session)
            if process_alert is not None:
                process_alert.recovered = datetime.now()
                self._session.merge(process_alert)
        except ValueError as error:
            #  If there are multiple similar alerts open, just close them all.
            #  This is a preventive measure. If the code hits this a bug should be fixed somewhere else
            SERVER_LOGGER.error("PROCESS ALERT EXCEPTION. ERROR: %s", error)
            process_alerts = ProcessAlert.get_all_open_alerts(self.server_mac, device_process.process, self._session)
            for process_alert in process_alerts:
                process_alert.recovered = datetime.now()
                self._session.merge(process_alert)

    def _create_process_alert(self, device_process):
        """
        Creates a process alert for the given process and adds it to the database.

        :param DeviceProcess device_process: process that raised the alert
        :return: None
        """
        try:
            open_alert = ProcessAlert.get_open_alert(self.server_mac, device_process.process, self._session)
            if open_alert is None:
                now = datetime.now()
                alert = ProcessAlert(timestamp=now, mac_address=self.server_mac, process=device_process.process,
                                     last_seen=device_process.last_seen)
                self._session.add(alert)
        except ValueError as error:
            SERVER_LOGGER.error("%s DEVICE: %s", error, self.server_mac)

    def handle_process_monitoring(self, running_processes):
        """
        Checks if all the monitored process are currently current on the agent machine.
        Creates an individual alert for each process if that is not the case.

        :param set running_processes: list containing the names of all the running processes
        :return: None
        """
        for process in self._monitor_processes:
            device_process = (DeviceProcess.get_process(process, self.server_mac, self._session) or
                              DeviceProcess(mac_address=self.server_mac, process=process, last_seen=datetime.min))
            if process in running_processes:
                self._update_process_monitoring(device_process)
                self._handle_process_alert(device_process)
            else:
                # Make sure the device process is in the DB. It may not be if the device is not running since the beginning
                self._session.merge(device_process)
                self._create_process_alert(device_process)

    def handle_monitored_values(self, name, value):
        """
        Adds monitored values to the database.
        A monitored value is something we got from the agent machine but that is not being used to raise any
        alerts regarding the state of the agent.

        :param str name: name assigned to the monitored value
        :param value: the monitored value itself that must be able to be casted as a string
        :return: None
        """
        try:
            value = str(value)
            monitored_value = DeviceMonitoredValue(mac_address=self.server_mac, value_name=name, value=value,
                                                   date=datetime.now())
            self._session.add(monitored_value)
        except ValueError as error:
            SERVER_LOGGER.warning("Failed to cast a monitored value as a string. Error: %s", error)

    def handle_noanswer_error(self):
        """
        Checks if there is a SNMPNoAnswerAlert currently open for the agent.
        If that is the case, no action is taken.

        However, if it isn't, then a SNMPNoAnswerAlert is created regarding the monitored agent.

        :return: None
        """
        try:
            open_alert = SNMPNoAnswerAlert.get_open_alert(self.server_mac, self._session)
            if not open_alert:
                timestamp = datetime.now()
                alert = SNMPNoAnswerAlert(timestamp=timestamp, mac_address=self.server_mac)
                self._session.add(alert)
        except ValueError as error:
            SERVER_LOGGER.error("%s DEVICE: %s", error, self.server_mac)

    def _stop(self):
        Session.remove()

    @staticmethod
    def _get_monitor_processes(server_ip):
        """
        Get a set with the names of all the processes that shall be monitored for the given agent.
        The process list should be specified in the configuration file

        :param str server_ip: ip address of the agent
        :return: set of processes to be monitored for the given agent. (empty set if there aren't any processes)
        """
        config = get_config_file_section(constants.CONFIG_FILE, constants.AGENT_CONFIG.format(ip=server_ip))
        res = config.get("PROCESS_MONITOR", None)
        if res is not None:
            return set(res.split(','))
        return set()

    def run(self):
        """
        Thread
        Handles the monitoring of the agent
        :return: None
        """
        # Make sure to init the session in the Thread itself. The lazy initialization does not seem to always
        # work leading to weird bugs
        self._session = Session()
        while self._running:
            try:
                get_values, walk_values = self._snmp_query_handler.query_agent()
                self._handle_get_result(get_values)
                self._handle_walk_result(walk_values)
                self._verify_previous_answer()
                self._session.commit()
                time.sleep(self.time_btw_queries)
                SERVER_LOGGER.debug('************ SUCCESSFUL SNMP QUERY. AGENT %s ************', self.server_mac)
            except SnmpAgentQueryException as error:
                self.handle_noanswer_error()
                SERVER_LOGGER.warning('Agent not responding. ERROR: %s', error)
            except SnmpVersionException as error:
                SERVER_LOGGER.error("TERMINAL ERROR: %s", error)
                self._running = False  # terminal failure
            except Exception as error:
                SERVER_LOGGER.error(
                    'UNEXPECTED EXCEPTION CATCHED. SERVER MONITORING WILL TERMINATE. EXCEPTION MESSAGE: %s', error)
                self._running = False
                raise

        self._stop()
