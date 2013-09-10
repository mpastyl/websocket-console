# -*- coding: utf-8 -*-
#
# API configuration
#####################


DEBUG = False

# Top-level URL for deployment. Numerous other URLs depend on this.
CYCLADES_BASE_URL = "https://compute.example.synnefo.org/compute/"

# The API will return HTTP Bad Request if the ?changes-since
# parameter refers to a point in time more than POLL_LIMIT seconds ago.
POLL_LIMIT = 3600

#
# Network Configuration
#

# Maximum allowed network size for private networks.
MAX_CIDR_BLOCK = 22

# Default settings used by network flavors
DEFAULT_MAC_PREFIX = 'aa:00:0'
DEFAULT_BRIDGE = 'br0'

# Boolean value indicating whether synnefo would hold a Pool and allocate IP
# addresses. If this setting is set to False, IP pool management will be
# delegated to Ganeti. If machines have been created with this option as False,
# you must run network reconciliation after turning it to True.
PUBLIC_USE_POOL = True

# Network flavors that users are allowed to create through API requests
API_ENABLED_NETWORK_FLAVORS = ['MAC_FILTERED']

# Settings for IP_LESS_ROUTED network:
# -----------------------------------
# In this case VMCs act as routers that forward the traffic to/from VMs, based
# on the defined routing table($DEFAULT_ROUTING_TABLE) and ip rules, that
# exist in every node, implenting an IP-less routed and proxy-arp setup.
DEFAULT_ROUTING_TABLE = 'snf_public'

# Settings for MAC_FILTERED network:
# ------------------------------------------
# All networks of this type are bridged to the same bridge. Isolation between
# networks is achieved by assigning a unique MAC-prefix to each network and
# filtering packets via ebtables.
DEFAULT_MAC_FILTERED_BRIDGE = 'prv0'


# Firewalling
GANETI_FIREWALL_ENABLED_TAG = 'synnefo:network:0:protected'
GANETI_FIREWALL_DISABLED_TAG = 'synnefo:network:0:unprotected'
GANETI_FIREWALL_PROTECTED_TAG = 'synnefo:network:0:limited'

# The default firewall profile that will be in effect if no tags are defined
DEFAULT_FIREWALL_PROFILE = 'DISABLED'

# Fixed mapping of user VMs to a specific backend.
# e.g. BACKEND_PER_USER = {'example@synnefo.org': 2}
BACKEND_PER_USER = {}

# List of backend IDs used *only* for archipelago.
ARCHIPELAGO_BACKENDS = []


# URL templates for the stat graphs.
# The API implementation replaces '%s' with the encrypted backend id.
# FIXME: For now we do not encrypt the backend id.
CPU_BAR_GRAPH_URL = 'http://stats.synnefo.org/%s/cpu-bar.png'
CPU_TIMESERIES_GRAPH_URL = 'http://stats.synnefo.org/%s/cpu-ts.png'
NET_BAR_GRAPH_URL = 'http://stats.synnefo.org/%s/net-bar.png'
NET_TIMESERIES_GRAPH_URL = 'http://stats.synnefo.org/%s/net-ts.png'

# Recommended refresh period for server stats
STATS_REFRESH_PERIOD = 60

# The maximum number of file path/content pairs that can be supplied on server
# build
MAX_PERSONALITY = 5

# The maximum size, in bytes, for each personality file
MAX_PERSONALITY_SIZE = 10240


# Top-level URL of the astakos instance to be used for user management
ASTAKOS_BASE_URL = 'https://accounts.example.synnefo.org/'

# Tune the size of the Astakos http client connection pool
# This limit the number of concurrent requests to Astakos.
CYCLADES_ASTAKOSCLIENT_POOLSIZE = 50

# Key for password encryption-decryption. After changing this setting, synnefo
# will be unable to decrypt all existing Backend passwords. You will need to
# store again the new password by using 'snf-manage backend-modify'.
# SECRET_ENCRYPTION_KEY may up to 32 bytes. Keys bigger than 32 bytes are not
# supported.
SECRET_ENCRYPTION_KEY = "Password Encryption Key"

# Astakos service token
# The token used for astakos service api calls (e.g. api to retrieve user email
# using a user uuid)
CYCLADES_SERVICE_TOKEN = ''

# Let cyclades proxy user specific api calls to astakos, via self served
# endpoints. Set this to False if you deploy cyclades-app/astakos-app on the
# same machine.
CYCLADES_PROXY_USER_SERVICES = True
