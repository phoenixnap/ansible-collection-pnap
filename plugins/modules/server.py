#!/usr/bin/python
# (c) 2020, Pavle Jojkic <pavlej@phoenixnap.com> , Goran Jelenic <goranje@phoenixnap.com>
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
module: server

short_description: Manage phoenixNAP Bare Metal Cloud servers
description:
    - Manage phoenixNAP Bare Metal Cloud servers
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/bmc/1/overview).

version_added: "0.5.0"

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
  delete_ip_blocks:
    description: When the state is absent, it determines whether the IP blocks assigned to the server should be deleted or not.
    type: bool
    default: true
  description:
    description: Description of server.
    type: str
  location:
    description: Server Location ID. See BMC API for current list - U(https://developers.phoenixnap.com/docs/bmc/1/types/Server).
    type: str
  install_default_sshkeys:
    description: Whether or not to install ssh keys marked as default in addition to any ssh keys specified in this request.
    type: bool
    default: true
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
  hostnames:
    description: Name of server.
    type: list
    elements: str
  management_access_allowed_ips:
    description: Define list of IPs allowed to access the Management UI. Supported in single IP, CIDR and range format.
    type: list
    elements: str
  network_type:
    description: The type of network configuration for this server
    default: "PUBLIC_AND_PRIVATE"
    type: str
  os:
    description: The server's OS used when the server was created. See BMC API for current list - U(https://developers.phoenixnap.com/docs/bmc/1/types/Server).
    type: str
  pricing_model:
    description: Server pricing model.
    default: "HOURLY"
    type: str
  private_network_configuration_type:
    description: Determines the approach for configuring IP blocks for the server being provisioned.
    default: "USE_OR_CREATE_DEFAULT"
    type: str
  private_network_gateway_address:
    description: The address of the gateway assigned / to assign to the server.
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
        description: IPs to configure/configured on the server. Should be null or empty list if DHCP is true.
      dhcp:
        type: bool
        description: Determines whether DHCP is enabled for this server. Should be false if ips is not an empty list.
  rdp_allowed_ips:
    description: List of IPs allowed for RDP access to Windows OS. Supported in single IP, CIDR and range format. When undefined, RDP is disabled.
    type: list
    elements: str
  reservation_id:
    description: Server reservation ID.
    type: str
  server_ids:
    description: The unique identifier of the server.
    type: list
    elements: str
  ssh_key:
    description: A list of SSH Keys that will be installed on the Linux server.
    type: list
    elements: str
  ssh_key_ids:
    description: A list of SSH Key IDs that will be installed on the server in addition to any ssh keys specified in request.
    type: list
    elements: str
  state:
    description: Desired state of the server.
    choices: [absent, present, powered-on, powered-off, rebooted, reset, shutdown]
    default: present
    type: str
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
  type:
    description: Server type ID. See BMC API for current list - U(https://developers.phoenixnap.com/docs/bmc/1/types/Server).
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml
# and generated SSH key pair in location: ~/.ssh/

# Create server

- name: Create new server for account
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.server:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      hostnames: [my-server-red, my-server-blue]
      location: PHX
      os: ubuntu/bionic
      type: s1.c1.medium
      state: present
      ssh_key: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}"
    register: output
  - name: Print the servers information
    debug:
      var: output.servers

# Create server | network example

- name: Create new server | network example
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.server:
        client_id: "{{clientId}}"
        client_secret: "{{clientSecret}}"
        hostnames: server-red
        description: custom description
        location: PHX
        os: ubuntu/bionic
        type: s0.d1.medium
        private_network_configuration_type: USER_DEFINED
        private_networks:
          - id: 60f81608e2f4665962b214db
            ips: [10.0.0.13 - 10.0.0.17]
            dhcp: false
          - id: 60f93142c5c1d6082d31382a
            ips: [10.0.0.11, 10.0.0.12]
            dhcp: false
        state: present
    register: output
  - name: Print the servers information
    debug:
      var: output.servers

# Power on servers

- name: power on servers
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.server:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      hostnames: [my-server-red, my-server-blue]
      state: powered-on
    register: output
  - name: Print the servers information
    debug:
      var: output.servers

# Shutdown servers
# use server_ids as server identifier

- name: shutdown servers
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.server:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      server_ids:
        - e6afba51-7de8-4080-83ab-0f9155706xxx
        - e6afBa51-7dg8-4380-8sab-0f9155705xxx
      state: shutdown
    register: output
  - name: Print the servers information
    debug:
      var: output.servers

# Reset servers
- name: reset servers
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.server:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      hostnames: [my-server-red, my-server-blue]
      ssh_key: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}"
      state: reset
    register: output
  - name: Print the servers information
    debug:
      var: output.servers

# For more examples, check out this helpful tutorial:
# https://phoenixnap.com/kb/how-to-install-phoenixnap-bmc-ansible-module#htoc-bmc-playbook-examples
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
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, remove_empty_elements, SERVER_API

import os
import json
import time


ALLOWED_STATES = ['absent', 'powered-on', 'powered-off', 'present', 'rebooted', 'reset', 'shutdown']
CHECK_FOR_STATUS_CHANGE = 5
TIMEOUT_STATUS_CHANGE = 1800


def get_target_list(module, target_state, existing_servers):
    if module.params['server_ids']:
        target_list = module.params['server_ids']
    elif target_state == 'present':
        target_list = module.params['hostnames']
    else:
        target_list = get_servers_id(module.params['hostnames'], existing_servers, target_state)
    return target_list


def state_api_remapping(target_state):
    if target_state == 'shutdown':
        state = 'powered-off'
    else:
        state = target_state
    return state


def state_final(target_state):
    if target_state in ['present', 'rebooted', 'reset']:
        state = 'powered-on'
    elif target_state == 'shutdown':
        state = 'powered-off'
    else:
        state = target_state
    return state


def get_existing_servers(module):
    response = requests_wrapper(SERVER_API, module=module)
    return response.json()


def refresh_server_list(module, target_servers):
    existing_servers = get_existing_servers(module)
    return [ex for ex in existing_servers if ex['id'] in target_servers]


def ratify_server_list_case_present(target_servers):
    process_servers = []
    [process_servers.append({'id': ts, 'status': 'absent'}) for ts in target_servers]
    return process_servers


def ratify_server_list_case_rebooted(process_servers):
    for ps in process_servers:
        if ps['status'] != 'powered-on':
            raise Exception('all servers must be in powered-on state')


def ratify_server_list(target_servers, target_state, existing_servers):
    if target_state == 'present':
        return ratify_server_list_case_present(target_servers)

    if len(target_servers) != len(set(target_servers)):
        raise Exception('List of servers can\'t contain duplicate server id')

    process_servers = [ex for ex in existing_servers if ex['id'] in target_servers]
    if len(target_servers) > len(process_servers):
        raise Exception('List of servers contain one or more invalid server id')

    if target_state == 'rebooted':
        ratify_server_list_case_rebooted(process_servers)

    return process_servers


def get_servers_id(server_names, existing_servers, target_state):
    if server_names is None:
        raise Exception('Please check provided server list.')

    if target_state == 'present':
        return [s['id'] for s in existing_servers if s['hostname'] in server_names]
    else:
        server_ids = []
        for es in existing_servers:
            if es['hostname'] in server_names:
                server_ids.append(es['id'])
        return server_ids


def get_api_params(module, server_id, target_state):
    method = 'POST'
    data = None

    if target_state == 'absent':
        path = '%s/actions/deprovision' % server_id
        data = {
            "deleteIpBlocks": module.params['delete_ip_blocks']
        }
    elif(target_state == 'powered-on'):
        path = '%s/actions/power-on' % server_id
    elif(target_state == 'powered-off'):
        path = '%s/actions/power-off' % server_id
    elif(target_state == 'shutdown'):
        path = '%s/actions/shutdown' % server_id
    elif(target_state == 'rebooted'):
        path = '%s/actions/reboot' % server_id
    elif(target_state == 'reset'):
        path = '%s/actions/reset' % server_id
        data = {
            "installDefaultSshKeys": module.params['install_default_sshkeys'],
            "sshKeys": module.params['ssh_key'],
            "sshKeyIds": module.params['ssh_key_ids'],
            "osConfiguration": {
                "windows": {
                    "rdpAllowedIps": module.params['rdp_allowed_ips']
                },
                "esxi": {
                    "managementAccessAllowedIps": module.params['management_access_allowed_ips']
                }
            }
        }
    elif(target_state == 'present'):
        path = ''
        data = {
            "description": module.params['description'],
            "location": module.params['location'],
            "hostname": server_id,
            "installDefaultSshKeys": module.params['install_default_sshkeys'],
            "sshKeys": module.params['ssh_key'],
            "sshKeyIds": module.params['ssh_key_ids'],
            "networkType": module.params['network_type'],
            "os": module.params['os'],
            "reservationId": module.params['reservation_id'],
            "pricingModel": module.params['pricing_model'],
            "type": module.params['type'],
            "osConfiguration": {
                "windows": {
                    "rdpAllowedIps": module.params['rdp_allowed_ips']
                },
                "managementAccessAllowedIps": module.params['management_access_allowed_ips']
            },
            "networkConfiguration": {
                "privateNetworkConfiguration": {
                    "configurationType": module.params['private_network_configuration_type'],
                    "gatewayAddress": module.params['private_network_gateway_address'],
                    "privateNetworks": module.params['private_networks']
                },
                "ipBlocksConfiguration": {
                    "configurationType": module.params['ip_block_configuration_type'],
                    "ipBlocks": [
                        {
                            "id": module.params['ip_block']
                        }
                    ]
                }
            },
            "tags": module.params['tags']
        }

    data = json.dumps(remove_empty_elements(data), sort_keys=True)
    endpoint = SERVER_API + path
    return{'method': method, 'endpoint': endpoint, 'data': data}


def wait_for_status_change(module, target_list, target_state, first_response):
    if target_state == 'absent':
        return first_response

    timeout = time.time() + TIMEOUT_STATUS_CHANGE
    while timeout > time.time():
        servers_refreshed = refresh_server_list(module, target_list)
        if all(sr['status'] == state_final(target_state) for sr in servers_refreshed):
            return servers_refreshed
        time.sleep(CHECK_FOR_STATUS_CHANGE)
    raise Exception('waiting for status %s has expired' % target_state)


def prepare_result_present(process_servers, target_state):
    for ps in process_servers:
        ps['status'] = state_final(target_state)
    return process_servers


def servers_action(module, target_state):
    changed = False
    set_token_headers(module)
    existing_servers = get_existing_servers(module)
    target_list = get_target_list(module, target_state, existing_servers)
    process_servers = ratify_server_list(target_list, target_state, existing_servers)

    first_response = []
    for ps in process_servers:
        if ps['status'] != state_api_remapping(target_state):
            changed = True
            if not module.check_mode:
                ap = get_api_params(module, ps['id'], target_state)
                first_response.append(requests_wrapper(ap['endpoint'], ap['method'], data=ap['data'], module=module).json())

    if target_state == 'present':
        existing_servers = get_existing_servers(module)
        target_list = get_servers_id(target_list, existing_servers, target_state)

    if not module.check_mode:
        if changed:
            process_servers = wait_for_status_change(module, target_list, target_state, first_response)
        if target_state in ['present', 'reset']:
            process_servers = prepare_result_present(first_response, target_state)
    else:
        if target_state == 'present':
            for pc in process_servers:
                pc['status'] = 'Server [%s] will be created' % pc['id']

    return{
        'changed': changed,
        'servers': process_servers
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            delete_ip_blocks=dict(type='bool', default=True),
            description={},
            location={},
            hostnames=dict(type='list', elements='str'),
            install_default_sshkeys=dict(type='bool', default=True),
            ip_block_configuration_type={},
            ip_block={},
            management_access_allowed_ips=dict(type='list', elements='str'),
            network_type=dict(default='PUBLIC_AND_PRIVATE'),
            os={},
            rdp_allowed_ips=dict(type='list', elements='str'),
            reservation_id={},
            pricing_model=dict(default='HOURLY'),
            private_network_configuration_type=dict(default='USE_OR_CREATE_DEFAULT'),
            private_network_gateway_address={},
            private_networks=dict(type="list", elements='dict'),
            server_ids=dict(type='list', elements='str'),
            ssh_key=dict(type='list', elements='str', no_log=True),
            ssh_key_ids=dict(type='list', elements='str', no_log=True),
            state=dict(choices=ALLOWED_STATES, default='present'),
            tags=dict(type="list", elements='dict'),
            type={},
        ),
        mutually_exclusive=[('hostnames', 'server_ids')],
        required_one_of=[('hostnames', 'server_ids')],
        required_if=[('state', 'present', ['hostnames'])],
        supports_check_mode=True
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests is required for this module.')

    if not module.params.get('client_id') or not module.params.get('client_secret'):
        _fail_msg = ("if BMC_CLIENT_ID and BMC_CLIENT_SECRET are not in environment variables, "
                     "the client_id and client_secret parameters are required")
        module.fail_json(msg=_fail_msg)

    state = module.params['state']

    try:
        module.exit_json(**servers_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
