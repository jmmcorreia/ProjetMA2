from pysnmp.hlapi import SnmpEngine, getCmd, nextCmd, ObjectIdentity, CommunityData, UsmUserData, UdpTransportTarget, \
    ContextData, ObjectType
from itertools import tee
import logging
import time

logging.basicConfig(filename='SNMP.log')


class SnmpQueryHandler:
    """
    This class handles all the SNMP queries to an agent.
    """

    def __init__(self, server_address, get_values_dict, walk_values_dict, max_nb_tries=3, sleep_between_tries=2,
                 snmp_port=161, version=2,
                 community_index='public', username=None, auth_key=None, priv_key=None):
        """
        :param str server_address: IP address (IPv4 format) of the agent to be monitored
        :param dict monitor_dict:  Dict containing all the parameters to be defined. Key is a user defined name and the value is the OID or the SNMPv2-MIB name.
        :param int max_nb_tries: Number of tries before the query time out and raises and error
        :param int sleep_between_tries: Time in seconds to wait between queries if the first one fails
        :param int snmp_port: Agent's port used to connect to the agent
        :param int version: SNMP version to be used (it can either be 1, 2, or 3)
        :param str username: SNMP username. Only specify if using version 3
        :param str auth_key: SNMP Authentication key.  Only specify if using version 3
        :param str priv_key: SNMP Private key. Only specify if using version 3
        """
        self.server_address = server_address
        self.snmp_version = version
        self.server_username = username
        self.max_nb_tries = max_nb_tries
        self.sleep_between_tries = sleep_between_tries
        self.snmp_port = snmp_port
        self.community_index = community_index
        self.server_authkey = auth_key
        self.server_privkey = priv_key
        self.snmp_engine = SnmpEngine()
        self.oid_get = dict()
        self.var_name_get = dict()
        self.oid_walk = dict()
        self.var_name_walk = dict()
        self.parse_oid_dict(get_values_dict, walk_values_dict)

    def query_agent(self):
        """
        Queries the agent that is currently being monitored

        :raises: SnmpMissingCredentialsException: if username and auth_key are missing and version is 3.
        :raises: SnmpVersionException: if the SNMP version specified is not valid.
        :raises: SnmpAgentQueryException: if unable to get any information from the agent.

        :return: dict where key corresponds to the key used by the user to identify the OID/name and the value is the
                 monitored value returned by the Server.
        """
        agent_information_get = dict()
        agent_information_walk = dict()

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

        :raises: SnmpMissingCredentialsException: if username and auth_key are missing and version is 3.
        :raises: SnmpVersionException: if the SNMP version specified is not valid.

        :param object_identity: pySNMP object identity corresponding to the information we are looking for
        :return: cmd_command result
        """
        data = None

        if self.snmp_version == 1 or self.snmp_version == 2:
            data = CommunityData(self.community_index, mpModel=self.snmp_version - 1)
        elif self.snmp_version == 3:
            if self.server_username is not None and self.server_authkey is not None:
                data = UsmUserData(self.server_username, authKey=self.server_authkey, privKey=self.server_privkey)
            else:
                raise SnmpMissingCredentialsException("SNMPv3 requires credentials but none were given")

        if data is not None:
            return cmd_command(SnmpEngine(),
                               data,
                               UdpTransportTarget((self.server_address, self.snmp_port)),
                               ContextData(),
                               ObjectType(object_identity),
                               lexicographicMode=False)  # STOPS WALKS WITHOUT CROSSING BOUNDARIES EXAMPLE: IF WE GIVE OID 1.3.6.1.2.1.25.4.2.1.2, WE WILL ONLY WALK 1.3.6.1.2.1.25.4.2.1.2.X VALUES. IF THIS IS TRUE, WE WALK THE WHOLE TREE AFTER 1.3.6.1.2.1.25.4.2.1.2

        raise SnmpVersionException(
            "SNMPv{}  does not currently exist or is not supported by this query".format(self.snmp_version))

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
            raise SnmpAgentQueryException(
                "Server did not response to any of the {} SNMP query performed.".format(self.max_nb_tries))

        if error_indication:
            logging.warning(error_indication)
        elif error_status:
            logging.warning('{} at {}'.format(error_status.prettyPrint(), error_index and var_bind[0] or '?'))

        if error_indication or error_status:
            time.sleep(self.sleep_between_tries)
            return self._snmp_get(copy_cmd_generator, tries + 1)

        oid, value = var_bind[0]
        return value

    def _snmp_walk(self, cmd_generator, tries=0):
        cmd_generator, copy_cmd_generator = tee(cmd_generator)
        result = []
        error = False

        if tries < self.max_nb_tries:
            for (error_indication, error_status, error_index, var_binds) in cmd_generator:

                if error_indication:
                    logging.warning(error_indication)
                elif error_status:
                    logging.warning('{} at {}'.format(error_status.prettyPrint(),
                                                      error_index and var_binds[int(error_index) - 1][0] or '?'))
                    error = True
                    break
                else:
                    for var_bind in var_binds:
                        result.append(var_bind)
                        # print(' = '.join([x.prettyPrint() for x in var_bind]))

        else:
            raise SnmpAgentQueryException(
                "Server did not response to any of the {} SNMP query performed.".format(self.max_nb_tries))

        if error:
            time.sleep(self.sleep_between_tries)
            return self._snmp_get(copy_cmd_generator, tries + 1)

        return result

    def parse_oid_dict(self, get_values_dict, walk_values_dict):
        """
        Receives a dict where the key is the user defined name for the parameter we want to monitor using SNMP and the
        value is either the OID or the name of the said parameter. The name must be the one as presented in the
        SNMPv2-MIB standard. For example, the value can either be 1.3.6.1.2.1.1.3.0 or sysUpTime.

        Only the names on the following list are supported: http://www.oidview.com/mibs/0/SNMPv2-MIB.html
        Use the OID if the name is not present on the list

        :param dict monitor_dict: dict containing all the parameters to be defined. Key is a user defined name and the
               value is the OID or the SNMPv2-MIB name.
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


class SnmpMissingCredentialsException(Exception):
    """
    Raised when the SNMP version chosen by the user requires credentials but they were not specified.
    """
