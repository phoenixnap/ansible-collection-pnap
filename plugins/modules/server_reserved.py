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
module: server_reserved

short_description: Provision reserved server.
description:
    - Provision reserved server.
    - This module has a dependency on requests

version_added: "1.16.0"

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
  cloud_init_user_data:
    description: User data for the cloud-init configuration in base64 encoding. NoCloud format is supported.
    type: str
    default: ''
  description:
    description: Description of server.
    type: str
  gateway_address:
    description:
      - The address of the gateway assigned / to assign to the server.
      - When used as part of request body, IP address has to be part of a private/public network or an IP block assigned to this server.
      - Gateway address also has to be assigned on an already deployed resource unless the address matches
        the BMC gateway address in a public network/IP block or the force query parameter is true.
    type: str
  force:
    description:
      - parameter controlling advanced features availability.
      - Currently applicable for networking. It is advised to use with caution since it might lead to unhealthy setups.
    type: bool
  install_default_sshkeys:
    description: Whether or not to install ssh keys marked as default in addition to any ssh keys specified in this request.
    type: bool
    default: true
  install_os_to_ram:
    description:
      - If true, OS will be installed to and booted from the server's RAM.
      - On restart RAM OS will be lost and the server will not be reachable unless a custom bootable OS has been deployed.
    type: bool
    default: false
  ip_block_configuration_type:
    description:
      - Determines the approach for configuring IP blocks for the server being provisioned.
      - If PURCHASE_NEW is selected, the smallest supported range, depending on the operating system, is allocated to the server.
      - Default value is "PURCHASE_NEW"
    type: str
  ip_block:
    description:
      - Used to specify the previously purchased IP blocks to assign to this server upon provisioning.
      - Used alongside the USER_DEFINED configurationType.
      - must contain at most 1 item
    type: str
  hostname:
    description: Name of server.
    type: str
  management_access_allowed_ips:
    description: Define list of IPs allowed to access the Management UI. Supported in single IP, CIDR and range format.
    type: list
    elements: str
  netris_controller:
    description: Netris Controller configuration properties.
    type: dict
  netris_softgate:
    description: Netris Softgate configuration properties.
    type: dict
    suboptions:
      controller_address:
        description: IP address or hostname through which to reach the Netris Controller.
        type: str
      controller_version:
        description: The version of the Netris Controller to connect to.
        type: str
      controller_auth_key:
        description:
          - The authentication key of the Netris Controller to connect to.
          - Required for the softgate agent to be able to interact with the Netris Controller.
        type: str
  network_type:
    description: The type of network configuration for this server
    default: "PUBLIC_AND_PRIVATE"
    type: str
  os:
    description: The server's OS used when the server was created. See BMC API for current list - U(https://developers.phoenixnap.com/docs/bmc/1/types/Server).
    type: str
    required: true
  private_network_configuration_type:
    description: Determines the approach for configuring IP blocks for the server being provisioned.
    default: "USE_OR_CREATE_DEFAULT"
    type: str
  private_networks:
    description: The list of private networks this server is member of.
    type: list
    elements: dict
    suboptions:
      id:
        type: str
        description: The network identifier.
      ips:
        type: list
        elements: str
        description: IPs to configure/configured on the server. Should be null or empty list if DHCP is true.
      dhcp:
        type: bool
        description: Determines whether DHCP is enabled for this server. Should be false if ips is not an empty list.
  public_networks:
    description: The list of public networks this server is member of.
    type: list
    elements: dict
    suboptions:
      id:
        type: str
        description: The network identifier.
      ips:
        type: list
        elements: str
        description: IPs to configure/configured on the server. IPs must be within the network's range.
  rdp_allowed_ips:
    description: List of IPs allowed for RDP access to Windows OS. Supported in single IP, CIDR and range format. When undefined, RDP is disabled.
    type: list
    elements: str
  bring_your_own_license:
    description:
      - Use a Bring Your Own (BYO) Windows license. If true, the server is provisioned in trial mode, and you must activate your own license.
      - If false (default), the server includes a managed Windows license billed by the platform.
    type: bool
  server_id:
    description: The unique identifier of the server.
    type: str
    required: true
  ssh_key:
    description: A list of SSH Keys that will be installed on the Linux server.
    type: list
    elements: str
  ssh_key_ids:
    description: A list of SSH Key IDs that will be installed on the server in addition to any ssh keys specified in request.
    type: list
    elements: str
  storage_configuration:
    description: Storage configuration.
    type: dict
    suboptions:
      rootPartition:
        description: Root partition configuration.
        type: dict
        suboptions:
          raid:
            description: Software RAID configuration.
            type: str
            default: NO_RAID
          size:
            description: The size of the root partition in GB. -1 to use all available space.
            type: int
            default: -1
  tags:
    description: Tags to set to server, if any.
    type: list
    elements: dict
    suboptions:
      name:
        type: str
        description: The name of the tag.
      value:
        type: str
        description: The value of the tag assigned to the resource.
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: Provision reserved server.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Provision reserved server.
      phoenixnap.bmc.server_reserved:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        server_id: e6afba51-7de8-4080-83ab-0f915570659c
        hostname: my-server-1
        os: ubuntu/bionic
      register: output
    - name: Print the server ip block information
      ansible.builtin.debug:
        var: output.server_reserved
'''

RETURN = '''
server_reserved:
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
              bringYourOwnLicense:
                description:
                  - Use a Bring Your Own (BYO) Windows license. If true, the server is provisioned in trial mode, and you must activate your own license.
                  - If false (default), the server includes a managed Windows license billed by the platform.
                type: bool
                sample: false
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
      storageConfiguration:
        description: Storage configuration.
        type: dict
        contains:
          rootPartition:
            description: Root partition configuration.
            type: dict
            contains:
              raid:
                description: Software RAID configuration.
                type: str
              size:
                description: The size of the root partition in GB. -1 to use all available space.
                type: int
      gpuConfiguration:
        description: The GPU configuration.
        type: dict
        contains:
          longName:
            description: The long name of the GPU.
            type: str
            sample: Intel Max 1100 GPU
          count:
            description: The number of GPUs.
            type: int
            sample: 2
      supersededBy:
        description: Unique identifier of the server to which the reservation has been
        type: str
        sample: "64a539b8d9c2c9ba8424ca31"
      supersedes:
        description: Unique identifier of the server from which the reservation has been transferred.
        type: str
        sample: "76915b5c85121d411f26e92f"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import (set_token_headers, HAS_REQUESTS, requests_wrapper,
                                                                          SERVER_API, remove_empty_elements)

import os
import json
import time
from base64 import standard_b64encode

CHECK_FOR_STATUS_CHANGE = 5
TIMEOUT_STATUS_CHANGE = 1800


def get_existing_server(server_id):
    existing_server = requests_wrapper(SERVER_API + server_id).json()
    return existing_server


def wait_for_status_change(server_id, target_state):
    timeout = time.time() + TIMEOUT_STATUS_CHANGE
    while timeout > time.time():
        existing_server = get_existing_server(server_id)
        if existing_server.get('status').lower() == target_state.lower():
            return existing_server
        time.sleep(CHECK_FOR_STATUS_CHANGE)
    raise Exception('waiting for status %s has expired' % target_state)


def get_module_params(module, current_hostname):
    netris_softgate = None
    if module.params['netris_softgate']:
        netris_softgate = {
            "controllerAddress": module.params['netris_softgate']['controller_address'],
            "controllerAuthKey": module.params['netris_softgate']['controller_auth_key'],
            "controllerVersion": module.params['netris_softgate']['controller_version'],
        }
    hostname = module.params.get('hostname') or current_hostname

    return json.dumps(remove_empty_elements({
        "description": module.params.get('description'),
        "hostname": hostname,
        "installDefaultSshKeys": module.params.get('install_default_sshkeys'),
        "sshKeys": module.params.get('ssh_key'),
        "sshKeyIds": module.params.get('ssh_key_ids'),
        "networkType": module.params.get('network_type'),
        "os": module.params.get('os'),
        "osConfiguration": {
            "netrisController": module.params.get('netris_controller'),
            "netrisSoftgate": netris_softgate,
            "windows": {
                "rdpAllowedIps": module.params.get('rdp_allowed_ips'),
                "bringYourOwnLicense": module.params['bring_your_own_license'],
            },
            "managementAccessAllowedIps": module.params.get('management_access_allowed_ips'),
            "installOsToRam": module.params.get('install_os_to_ram'),
            "cloudInit": {"userData": standard_b64encode(module.params.get('cloud_init_user_data').encode("utf-8")).decode("utf-8")},
        },
        "networkConfiguration": {
            "gatewayAddress": module.params.get('gateway_address'),
            "privateNetworkConfiguration": {
                "configurationType": module.params.get('private_network_configuration_type'),
                "privateNetworks": module.params.get('private_networks')
            },
            "ipBlocksConfiguration": {
                "configurationType": module.params.get('ip_block_configuration_type'),
                "ipBlocks": [
                    {
                        "id": module.params.get('ip_block')
                    }
                ]
            },
            "publicNetworkConfiguration": {
                "publicNetworks": module.params.get('public_networks')
            }
        },
        "tags": module.params.get('tags'),
        "storageConfiguration": module.params.get('storage_configuration'),
    }))


def server_reserved_action(module):
    set_token_headers(module)
    changed = False
    server_id = module.params['server_id']
    existing_server = get_existing_server(server_id)
    current_status = existing_server.get('status')

    if current_status.lower() == 'reserved':
        changed = True
        if not module.check_mode:
            current_hostname = existing_server.get('hostname')
            data = get_module_params(module, current_hostname)
            path = SERVER_API + server_id + '/actions/provision'
            if module.params['force'] is not None:
                path = path + '?force=' + str(module.params['force']).lower()
            requests_wrapper(path, data=data, method="POST").json()
            existing_server = wait_for_status_change(server_id, 'powered-on')

    return {
        'changed': changed,
        'server_reserved': existing_server
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            server_id=dict(required=True),
            cloud_init_user_data=dict(no_log=True, default=''),
            description={},
            force=dict(type='bool'),
            gateway_address={},
            hostname={},
            install_default_sshkeys=dict(type='bool', default=True),
            install_os_to_ram=dict(type='bool', default=False),
            ip_block_configuration_type={},
            ip_block={},
            management_access_allowed_ips=dict(type='list', elements='str'),
            network_type=dict(default='PUBLIC_AND_PRIVATE'),
            netris_controller=dict(type='dict'),
            netris_softgate=dict(
                type='dict',
                options=dict(
                    controller_address=dict(type='str'),
                    controller_version=dict(type='str'),
                    controller_auth_key=dict(no_log=True)
                )),
            os=dict(required=True),
            rdp_allowed_ips=dict(type='list', elements='str'),
            bring_your_own_license=dict(type='bool'),
            private_network_configuration_type=dict(default='USE_OR_CREATE_DEFAULT'),
            private_networks=dict(
                type='list',
                elements='dict',
                options=dict(
                    id={},
                    ips=dict(type='list', elements='str'),
                    dhcp=dict(type='bool')
                )),
            public_networks=dict(
                type='list',
                elements='dict',
                options=dict(
                    id={},
                    ips=dict(type='list', elements='str')
                )),
            ssh_key=dict(type='list', elements='str', no_log=True),
            ssh_key_ids=dict(type='list', elements='str', no_log=True),
            storage_configuration=dict(
                type='dict',
                options=dict(
                    rootPartition=dict(
                        type='dict',
                        options=dict(
                            raid=dict(default='NO_RAID'),
                            size=dict(default=-1, type='int')
                        )
                    )
                )
            ),
            tags=dict(
                type="list",
                elements='dict',
                options=dict(
                    name={},
                    value={}
                )),
        ),
        supports_check_mode=True
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests is required for this module.')

    if not module.params.get('client_id') or not module.params.get('client_secret'):
        _fail_msg = ("if BMC_CLIENT_ID and BMC_CLIENT_SECRET are not in environment variables, "
                     "the client_id and client_secret parameters are required")
        module.fail_json(msg=_fail_msg)

    try:
        module.exit_json(**server_reserved_action(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
