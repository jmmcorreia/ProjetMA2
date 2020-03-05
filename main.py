"""
Entry point for the application/service. This module contains all the methods required to start the application.
"""
import logging
import sys
from constants import CONFIG_FILE, NMAP_SECTION, AGENTS_SECTION, LOGGING_FORMAT
from utils import get_config_file

# START LOGGING BEFORE THE DB IMPORT OTHERWISE WE WILL MISS THE FIRST FEW MESSAGES REGARDING SQLALCHEMY
logging.basicConfig(level=logging.DEBUG, filename="app.log", format=LOGGING_FORMAT)

from db_start import Session, engine
from device_monitoring.network_mapper import NetworkMapper
from device_monitoring.server_monitoring import ServerMonitoring
from device_monitoring.device_presence_monitoring import PingHandler, Device


def map_network(nmap_config):
    """
    This function creates and runs a NetworkMapper object. (i.e. it maps the network following the user's
    NMAP commands entered in the configuration.

    :param dict nmap_config: string containing all the nmap commands. Each command should be separated by a comma
    :return: None
    """
    commands = nmap_config['COMMANDS'].split(',')
    interface = nmap_config['NETWORK_INTERFACE']
    nmap = NetworkMapper(interface, commands)
    nmap.start()
    nmap.join()


def start_server_monitoring(agents_config, session):
    """
    Creates and starts a ServerMonitoring object for each server that should be monitored.
    However, the object is only created if the server is present in the device list of the database.

    :param dict agents_config: configuration common to all the server agents
    :param Session session: a SQLAlchemy session to connect to the database
    :return list: returns a list with all the ServerMonitoring (one for each monitored agent)
    """
    snmp_agents = []
    time_btw_queries = int(agents_config['TIME_BETWEEN_QUERIES'])
    for key, value in agents_config.items():
        if 'AGENT' in key:
            agent_values = value.split(',')
            ip_address = agent_values[0]
            agent = session.query(Device).filter_by(ip=ip_address).first()
            if len(agent_values) > 1 and agent is not None:
                agent_query_time = int(agent_values[1])
                agent_monitoring = ServerMonitoring(ip_address, agent.mac_address, agent_query_time)
                snmp_agents.append(agent_monitoring)
            elif agent is not None:
                agent_monitoring = ServerMonitoring(ip_address, agent.mac_address, time_btw_queries)
                snmp_agents.append(agent_monitoring)
            else:
                logging.error("AGENT WITH IP %s WAS NOT FOUND IN THE NETWORK", ip_address)
                # raise ConnectionError("AGENT WITH IP {ip} WAS NOT FOUND IN THE NETWORK".format(ip=ip))

    for agent in snmp_agents:
        agent.start()

    return snmp_agents


def main():
    """
    launches the program
    :return: None
    """
    try:
        session = Session()
        config = get_config_file(CONFIG_FILE)
        map_network(config[NMAP_SECTION])

        agents = start_server_monitoring(config[AGENTS_SECTION], session)

        ping_handler = PingHandler()

        for agent in agents:
            agent.join()



    except Exception as error:
        logging.error("TERMINAL ERROR IN THE MAIN MODULE: %s", error)
        Session.remove()
        engine.dispose()
        sys.exit(-1)


if __name__ == "__main__":
    main()
