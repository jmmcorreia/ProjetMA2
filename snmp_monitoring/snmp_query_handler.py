"""
Module containing everything that is required to perform SNMP Queries.
Only supports SNMPv1 or SNPv2c
"""

from itertools import tee
import logging
import time
from pysnmp.hlapi import SnmpEngine, getCmd, nextCmd, ObjectIdentity, CommunityData, UdpTransportTarget, ContextData, \
    ObjectType


SNMP_LOGGER = logging.getLogger('SNMP Query Handler')


class SnmpQueryHandler:
    """
    This class handles all the SNMP queries to an agent.
    """

    def __init__(self, server_address, get_values_dict, walk_values_dict, max_nb_tries=4, sleep_between_tries=5,
                 snmp_port=161, version=2, community_index='public'):
        """
        :param str server_address: IP address (IPv4 format) of the agent to be monitored
        :param dict get_values_dict: Dict containing all the OIDS where a SNMP GET will be performed
        :param walk_values_dict: Dict containing all the OIDS where a SNMP GET will be performed
        :param int max_nb_tries: Number of tries before the query time out and raises and error
        :param int sleep_between_tries: Time in seconds to wait between queries if the first one fails
        :param int snmp_port: Agent's port used to connect to the agent
        :param int version: SNMP version to be used (it can either be 1, 2, or 3)
        """
        self.server_address = server_address
        self.snmp_version = version
        self.max_nb_tries = max_nb_tries
        self.sleep_between_tries = sleep_between_tries
        self.snmp_port = snmp_port
        self.community_index = community_index
        self.snmp_engine = SnmpEngine()
        self.oid_get = {}
        self.var_name_get = {}
        self.oid_walk = {}
        self.var_name_walk = {}
        self.parse_oid_dict(get_values_dict, walk_values_dict)

    def query_agent(self):
        """
        Queries the agent that is currently being monitored

        :raises: SnmpVersionException: if the SNMP version specified is not valid.
        :raises: SnmpAgentQueryException: if unable to get any information from the agent.

        :return: tuple with 2 dicts. The first dict contains the information obtained doing SNMP GET while the second
            one has all the information obtained using SNMP WALK. The key in the dicts corresponds to the key used by
            the user to identify the OID/name and the value is the monitored value returned by the Server.
        """
        agent_information_get = {}
        agent_information_walk = {}

        for key, value in self.oid_get.items():
            agent_information_get[key] = self._snmp_get(self._create_cmd_generator_by_oid(value, getCmd))

        for key, value in self.var_name_get.items():
            agent_information_get[key] = self._snmp_get(self._create_getcmd_generator_by_name(*value))

        for key, value in self.oid_walk.items():
            agent_information_walk[key] = self._snmp_walk(self._create_cmd_generator_by_oid(value, nextCmd))

        for key, value in self.var_name_walk.items():
            agent_information_walk[key] = self._snmp_walk(self._create_nextcmd_generator_by_name(*value))

        return agent_information_get, agent_information_walk

    def add_new_oid(self, key, value):
        """
        Add new OID/name of value to monitor

        :param key: name of value to monitor
        :param value: OID or name that is present in the SNMPv2-MIB tree.
        :return: None
        """
        if value[0] == "." or value[0].isdigit():
            self.oid_get[key] = value
        else:
            self.var_name_get[key] = value

    def _create_cmd_generator_by_oid(self, oid_str, cmd_command):
        """
        Sends a request to the server asking for the information corresponding to the oid
        :param str oid_str: SNMP OID that allows to specify which information we are looking for
        :return:
        """
        return self._create_cmd_generator(ObjectIdentity(oid_str), cmd_command)

    def _create_getcmd_generator_by_name(self, mib, variable, variable_id):
        """
        Sends a request to the server asking for the information corresponding to the oid
        :param str variable: SNMP variable name that specifies which information we are looking for
        :param str variable_id: value representing MIB variable instance identification
        :return:
        """
        return self._create_cmd_generator(ObjectIdentity(mib, variable, variable_id), getCmd)

    def _create_nextcmd_generator_by_name(self, mib, variable):
        """
        Sends a request to the server asking for the information corresponding to the oid
        :param str variable: SNMP variable name that specifies which information we are looking for
        :return:
        """
        return self._create_cmd_generator(ObjectIdentity(mib, variable), nextCmd)

    def _create_cmd_generator(self, object_identity, cmd_command):
        """
        Generates the getCmd (see pySNMP doc) required to retrieve information from the agent.

        :raises: SnmpVersionException: if the SNMP version specified is not valid.

        :param object_identity: pySNMP object identity corresponding to the information we are looking for
        :return: cmd_command result
        """

        if self.snmp_version == 1 or self.snmp_version == 2:
            data = CommunityData(self.community_index, mpModel=self.snmp_version - 1)
            return cmd_command(SnmpEngine(),
                               data,
                               UdpTransportTarget((self.server_address, self.snmp_port)),
                               ContextData(),
                               ObjectType(object_identity),
                               lexicographicMode=False)  # STOPS WALKS WITHOUT CROSSING BOUNDARIES # EXAMPLE: IF WE GIVE OID 1.3.6.1.2.1.25.4.2.1.2, WE WILL ONLY WALK 1.3.6.1.2.1.25.4.2.1.2.X VALUES. IF THIS IS TRUE, WE WALK THE WHOLE TREE AFTER 1.3.6.1.2.1.25.4.2.1.2

        SNMP_LOGGER.error("SNMPv%d does not currently exist or isn't supported by this query", self.snmp_version)
        raise SnmpVersionException("SNMPv%d does not currently exist or isn't supported by this query" %
                                   self.snmp_version)

    def _snmp_get(self, cmd_generator, tries=0):
        """
        Uses a previously generated getCmd to send a request to the agent and retrieve the required information

        :raises: SnmpAgentQueryException: if unable to get any information from the agent.

        :param cmd_generator: pySNMP result of a getCmd function call
        :return: information retrieved from the server

        """
        cmd_generator, copy_cmd_generator = tee(cmd_generator)
        if tries < self.max_nb_tries:
            # http://snmplabs.com/pysnmp/examples/hlapi/asyncore/sync/manager/cmdgen/snmp-versions.html#snmpv2c
            error_indication, error_status, error_index, var_bind = next(cmd_generator)
        else:
            SNMP_LOGGER.error("Server did not respond to any of the %d SNMP query performed.", self.max_nb_tries)
            raise SnmpAgentQueryException("Server did not respond to any of the %d SNMP query performed." %
                                          self.max_nb_tries)

        if error_indication:
            SNMP_LOGGER.warning(error_indication)
        elif error_status:
            SNMP_LOGGER.warning('%s at %s', error_status.prettyPrint(), error_index and var_bind[0] or '?')

        if error_indication or error_status:
            time.sleep(self.sleep_between_tries)
            return self._snmp_get(copy_cmd_generator, tries + 1)

        _, value = var_bind[0]
        return value

    def _snmp_walk(self, cmd_generator, tries=0):
        cmd_generator, copy_cmd_generator = tee(cmd_generator)
        result = []
        error = False

        if tries < self.max_nb_tries:
            for (error_indication, error_status, error_index, var_binds) in cmd_generator:

                if error_indication:
                    SNMP_LOGGER.warning(error_indication)
                elif error_status:
                    SNMP_LOGGER.warning('%s at %s', error_status.prettyPrint(),
                                        error_index and var_binds[int(error_index) - 1][0] or '?')
                    error = True
                    break
                else:
                    for var_bind in var_binds:
                        result.append(var_bind)
                        # print(' = '.join([x.prettyPrint() for x in var_bind]))

        else:
            SNMP_LOGGER.error("Server did not respond to any of the %d SNMP query performed.", self.max_nb_tries)
            raise SnmpAgentQueryException("Server did not respond to any of the %d SNMP query performed." %
                                          self.max_nb_tries)

        if error:
            time.sleep(self.sleep_between_tries)
            return self._snmp_walk(copy_cmd_generator, tries + 1)

        return result

    def parse_oid_dict(self, get_values_dict, walk_values_dict):
        """
        Receives two dicts where the key is the user defined name for the parameter we want to monitor using SNMP and
        the value is either the OID or the MIB name followed by the resource name and the last portion of the OID
        if required. In this last case, a comma should be use to split the parameter's name and the MIB
        such as HOST-RESOURCES-MIB,hrSystemUptime,0

        :param dict get_values_dict: Dict containing all the OIDS where a SNMP GET will be performed
        :param walk_values_dict: Dict containing all the OIDS where a SNMP GET will be performed
        :return: None
        """
        for key, value in get_values_dict.items():
            if value[0] == "." or value[0].isdigit():
                self.oid_get[key] = value
            else:
                self.var_name_get[key] = value.split(',')

        for key, value in walk_values_dict.items():
            if value[0] == "." or value[0].isdigit():
                self.oid_walk[key] = value
            else:
                self.var_name_walk[key] = value.split(',')


class SnmpAgentQueryException(Exception):
    """
    Raised when the SNMP query handler fails to obtain any response from the Server
    """


class SnmpVersionException(Exception):
    """
    Raised when the SNMP version chosen by the user does not exist or isn't supported.
    """
