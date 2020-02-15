from snmp_monitoring.snmp_query_handler import SnmpQueryHandler, SnmpAgentQueryException, SnmpVersionException, \
    SnmpMissingCredentialsException
from utils import get_config_file_section
from threading import Thread
from db_start import Session
from device_monitoring.devices_dao import ServerMonitoredValue, ServerUptime
import datetime
import time
import logging
import constants

logging.basicConfig(filename='ServerMonitoring.log')


class ServerMonitoring(Thread):

    def __init__(self, server_ip, time_btw_queries, server_db_id):
        super().__init__()
        self.snmp_query_handler = SnmpQueryHandler(server_ip, get_config_file_section(constants.CONFIG_FILE, constants.OIDS_SECTION), get_config_file_section(constants.CONFIG_FILE, constants.OIDS_SECTION2), version=2)
        self.time_btw_queries = time_btw_queries
        self.running = True
        self.server_id = server_db_id
        self.session = Session()

    def handle_query_result(self, result):
        for key, value in result.items():
            if key == "SYSTEM_UPTIME":
                self.handle_server_uptime(value)
            else:
                self.handle_monitored_values(key, value)

    def handle_server_uptime(self, server_uptime):
        try:
            sys_uptime = int(server_uptime)
            server_uptime = ServerUptime(server_id=self.server_id, server_uptime=sys_uptime, date=datetime.datetime.now())
            alert = server_uptime.test_alert(self.session)  # TODO
            self.session.add(server_uptime)
            self.session.commit()
        except ValueError as e:
            logging.warning("Failed to cast server uptime value as an int. Error: {0}".format(e))

    def handle_monitored_values(self, name, value):
        try:
            value = str(value)
            monitored_value = ServerMonitoredValue(server_id=self.server_id, value_name=name, value=value, date=datetime.datetime.now())
            self.session.add(monitored_value)
            self.session.commit()
        except ValueError as e:
            logging.warning("Failed to cast a monitored value as a string. Error: {0}".format(e))

    def run(self):
        while self.running:
            try:
                server_values, server_values2 = self.snmp_query_handler.query_agent()
                self.handle_query_result(server_values)
                time.sleep(self.time_btw_queries)
            except SnmpAgentQueryException as e:
                print("Agent not responding")  # TODO Agent not responding
            except (SnmpVersionException, SnmpMissingCredentialsException) as e:
                self.running = False  # terminal failure


query = ServerMonitoring("192.168.0.111", 20, 1)
query.start()
time.sleep(6000)
query.running = False

