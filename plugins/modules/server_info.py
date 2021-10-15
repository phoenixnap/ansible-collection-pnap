#!/usr/bin/python
# (c) 2021, Pavle Jojkic <pavlej@phoenixnap.com> , Goran Jelenic <goranje@phoenixnap.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'certified'
}

DOCUMENTATION = '''
---
module: server_info

short_description: Gather information about phoenixNAP BMC servers
description:
    - Gather information about servers available.
    - This module has a dependency on requests

version_added: "0.7.0"

author:
    - Pavle Jojkic (@pajuga) <pavlej@phoenixnap.com>
    - Goran Jelenic (@goranje) <goranje@phoenixnap.com>

options:
  client_id:
    description: Client ID (Application Management)
    type: str
  client_secret:
    description: Client Secret (Application Management)
    type: str
  hostnames:
    description: Name of server.
    type: list
    elements: str
  server_ids:
    description: The unique identifier of the server.
    type: list
    elements: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

# List all servers information for account
- name: List all servers
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.server_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
    register: output
  - name: Print the gathered infos
    debug:
      var: output.servers

# List server information based on the specified hostnames
- name: List the server details
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.server_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      hostnames: [server-red]
    register: output
  - name: Print the gathered infos
    debug:
      var: output.servers

# List server information based on the specified ids
- name: List the server details
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.server_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      server_ids: [60ffdc90fa7a2d75544cd8fb]
    register: output
  - name: Print the gathered infos
    debug:
      var: output.servers

'''

RETURN = '''
servers:
    description: The servers information as list
    returned: success
    type: complex
    contains:
      id:
        description: The unique identifier of the server.
        returned: always
        type: str
        sample: x78sdkjds879sd7cx8
      status:
        description: The status of the server.
        returned: always
        type: str
        sample: powered-on
      hostname:
        description: Hostname of server.
        returned: always
        type: str
        sample: my-server-1
      description:
        description: Description of server.
        returned: always
        type: str
        sample: Server #1 used for computing.
      os:
        description: The server's OS ID used when the server was created.
        returned: always
        type: str
        sample: ubuntu/bionic
      type:
        description: Server type ID. Cannot be changed once a server is created.
        returned: always
        type: str
        sample: s1.c1.small
      location:
        description: Server location ID. Cannot be changed once a server is created.
        returned: always
        type: str
        sample: PHX
      cpu:
        description: A description of the machine CPU.
        returned: always
        type: str
        sample: E-2276G
      cpuCount:
        description: The number of CPUs available in the system.
        returned: always
        type: int
        sample: 2
      coresPerCpu:
        description: The number of physical cores present on each CPU.
        returned: always
        type: int
        sample: 28
      cpuFrequency:
        description: The CPU frequency in GHz.
        returned: always
        type: float
        sample: 3.6
      ram:
        description: A description of the machine RAM.
        returned: always
        type: str
        sample: 64GB RAM
      storage:
        description: A description of the machine storage.
        returned: always
        type: str
        sample: 1x 960GB NVMe
      privateIpAddresses:
        description: Private IP addresses assigned to server.
        returned: always
        type: list
        sample: [ "172.16.0.1" ]
      publicIpAddresses:
        description: Public IP addresses assigned to server.
        returned: always
        type: list
        sample: [ "182.16.0.1", "183.16.0.1" ]
      reservationId:
        description: The reservation reference id if any.
        returned: always
        type: str
        sample: x78sdkjds879sd7cx8
      pricingModel:
        description: The pricing model this server is being billed.
        returned: always
        type: str
        sample: HOURLY
      password:
        description: Password set for user Admin on Windows server which will only be returned in response to provisioning a server.
        returned: always
        type: str
        sample: MyP@ssw0rd_01
      networkType:
        description: The type of network configuration for this server.
        returned: always
        type: str
        sample: PUBLIC_AND_PRIVATE
      clusterId:
        description: The cluster reference id if any.
        returned: always
        type: str
        sample: x78sdkjds879sd7cx8
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, SERVER_API

import os


def server_info(module):
    set_token_headers(module)
    servers = requests_wrapper(SERVER_API, module=module).json()
    filter_servers = []
    server_ids = module.params['server_ids']
    hostnames = module.params['hostnames']

    if server_ids:
        [filter_servers.append(es) for es in servers if es['id'] in server_ids]
        servers = filter_servers

    if hostnames:
        [filter_servers.append(es) for es in servers if es['hostname'] in hostnames]
        servers = filter_servers

    return{
        'servers': servers
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            hostnames=dict(type='list', elements='str'),
            server_ids=dict(type='list', elements='str')
        ),
        supports_check_mode=True,
        mutually_exclusive=[('hostnames', 'server_ids')],
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests is required for this module.')

    if not module.params.get('client_id') or not module.params.get('client_secret'):
        _fail_msg = ("if BMC_CLIENT_ID and BMC_CLIENT_SECRET are not in environment variables, "
                     "the client_id and client_secret parameters are required")
        module.fail_json(msg=_fail_msg)

    try:
        module.exit_json(**server_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
