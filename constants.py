CONFIG_FILE = 'config.ini'
CONFIG_SECTION = 'CONFIG'
AGENTS_SECTION = 'SNMP SERVER AGENTS'
GET_OIDS = 'GET OIDS'
WALK_OIDS = 'WALK OIDS'
NMAP_SECTION = 'NMAP'
AGENT_CONFIG = 'AGENT {ip}'
NEVER_SEEN_DATE = ''


UNKNOWN_DEVICE_TYPE = 'UNKNOWN'

MAX_NMAP_ATTEMPS = 5

SECONDS_TO_HUNDREDTHS = 100
COUNTER_BITS = 32

LOGGING_FORMAT = '[%(asctime)-15s] %(name)s - %(levelname)s - %(levelno)s - LINE:%(lineno)d - %(message)s'

UPTIME_ALERT_MESSAGE = 'Erreur UPTIME. DISPOSITIF: {mac_address}'

PRESENCE_ALERT_MESSAGE = 'Erreur PRESENCE. DISPOSITIF: {mac_address}. Derniere vue: {last_seen}'
