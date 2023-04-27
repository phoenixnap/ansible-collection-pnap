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
      tags:
        description: The tags assigned if any.
        returned: always
        type: list
        contains:
          id:
            description: The unique id of the tag.
            type: str
            sample: 60ffafcdffb8b074c7968dad
          name:
            description: The name of the tag.
            type: str
            sample: Environment
          value:
            description: The value of the tag assigned to the resource.
            type: str
            sample: PROD
          isBillingTag:
            description: Whether or not to show the tag as part of billing and invoices
            type: bool
            sample: true
          createdBy:
            description: Who the tag was created by.
            type: str
            sample: USER
      provisionedOn:
        description: Date and time when server was provisioned.
        type: str
        sample: "2021-03-13T20:24:32.491Z"
      osConfiguration:
        description: OS specific configuration properties.
        type: dict
        contains:
          netrisController:
            description: Netris Controller configuration properties.
            type: dict
            contains:
              hostOs:
                description: Host OS on which the Netris Controller is installed.
                type: str
              netrisWebConsoleUrl:
                description: The URL for the Netris Controller web console. Will only be returned in response to provisioning a server.
                type: str
              netrisUserPassword:
                description:
                  - Auto-generated password set for user 'netris' in the web console.
                  - The password is not stored and therefore will only be returned in response to provisioning a server.
                  - Copy and save it for future reference.
                type: str
          netrisSoftgate:
            description: Netris Softgate configuration properties.
            type: dict
            contains:
              hostOs:
                description: Host OS on which the Netris Softgate is installed.
                type: str
              controllerAddress:
                description: IP address or hostname through which to reach the Netris Controller.
                type: str
              controllerVersion:
                description: The version of the Netris Controller to connect to.
                type: str
          windows:
            description: Windows OS configuration properties.
            type: dict
            contains:
              rdpAllowedIps:
                description:
                  - List of IPs allowed for RDP access to Windows OS. Supported in single IP, CIDR and range format.
                  - When undefined, RDP is disabled. To allow RDP access from any IP use 0.0.0.0/0.
                  - This will only be returned in response to provisioning a server.
                type: list
                elements: str
                sample: ["172.217.22.14", "10.111.14.40/29", "10.111.14.66 - 10.111.14.71"]
          rootPassword:
            description: Password set for user root on an ESXi server which will only be returned in response to provisioning a server.
            type: str
            sample: MyP@ssw0rd_01
          managementUiUrl:
            description: The URL of the management UI which will only be returned in response to provisioning a server.
            type: str
            sample: https://172.217.22.14
          managementAccessAllowedIps:
            description:
              - List of IPs allowed to access the Management UI. Supported in single IP, CIDR and range format
              - When undefined, Management UI is disabled. This will only be returned in response to provisioning a server.
            type: list
            elements: str
            sample: ["172.217.22.14", "10.111.14.40/29", "10.111.14.66 - 10.111.14.71"]
          installOsToRam:
            description:
              - If true, OS will be installed to and booted from the server's RAM.
              - On restart RAM OS will be lost and the server will not be reachable unless a custom bootable OS has been deployed.
            type: bool
            sample: false
          cloudInit:
            description: Cloud-init configuration details.
            type: dict
            contains:
              userData:
                description: User data for the cloud-init configuration in base64 encoding. NoCloud format is supported.
                type: str
      networkConfiguration:
        description: Entire network details of bare metal server.
        type: dict
        contains:
          gatewayAddress:
            description:
              - The address of the gateway assigned / to assign to the server.
              - When used as part of request body, IP address has to be part of a private/public network or an IP block assigned to this server.
              - Gateway address also has to be assigned on an already deployed resource unless the address matches
                the BMC gateway address in a public network/IP block or the force query parameter is true.
            type: str
            sample: 182.16.0.145
          privateNetworkConfiguration:
            description: Private network details of bare metal server.
            type: dict
            contains:
              configurationType:
                description: Determines the approach for configuring private network(s) for the server being provisioned.
                type: str
                sample: USER_DEFINED
              privateNetworks:
                description: The list of private networks this server is member of.
                type: list
                elements: dict
                contains:
                  id:
                    description: The network identifier.
                    type: str
                    sample: 603f3b2cfcaf050643b89a4b
                  ips:
                    description: IPs to configure/configured on the server. Should be null or empty list if DHCP is true.
                    type: list
                    elements: str
                    sample: ["10.1.1.1", "10.1.1.2"]
                  dhcp:
                    description: Determines whether DHCP is enabled for this server. Should be false if ips is not an empty list. Not supported for proxmox OS.
                    type: bool
                    sample: false
                  statusDescription:
                    description: The status of the network.
                    type: str
                    sample: assigned
          ipBlocksConfiguration:
            description:
              - The IP blocks to assign to this server. This is an exclusive allocation, i.e. the IP blocks cannot be shared with other servers.
              - If IpBlocksConfiguration is not defined, the purchase of a new IP block is determined by the networkType field.
            type: dict
            contains:
              configurationType:
                description: Determines the approach for configuring IP blocks for the server being provisioned.
                type: str
                sample: PURCHASE_NEW
              ipBlocks:
                description:
                  - Used to specify the previously purchased IP blocks to assign to this server upon provisioning
                  - Used alongside the USER_DEFINED configurationType.
                type: list
                elements: dict
                contains:
                  id:
                    description: The IP block's ID.
                    type: str
                    sample: 60473a6115e34466c9f8f083
                  vlanId:
                    description: The VLAN on which this IP block has been configured within the network switch.
                    type: int
                    sample: 10
          publicNetworkConfiguration:
            description: Public network details of bare metal server.
            type: dict
            contains:
              publicNetworks:
                description: The list of public networks this server is member of.
                type: list
                elements: dict
                contains:
                  id:
                    description: The network identifier.
                    type: str
                    sample: 60473c2509268bc77fd06d29
                  ips:
                    description: IPs to configure/configured on the server. IPs must be within the network's range.
                    type: list
                    elements: str
                    sample: ["182.16.0.146", "182.16.0.147"]
                  statusDescription:
                    description: The status of the assignment to the network.
                    type: str
                    sample: assigned
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

    return {
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
