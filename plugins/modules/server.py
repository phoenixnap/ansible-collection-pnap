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

version_added: "0.6.0"

author:
    - Pavle Jojkic (@pajuga) <pavlej@phoenixnap.com>
    - Goran Jelenic (@goranje) <goranje@phoenixnap.com>

options:
  client_id:
    description: Client ID (Application Management)
    type: str
    required: true
  client_secret:
    description: Client Secret (Application Management)
    type: str
    required: true
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
  hostnames:
    description: Name of server.
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
    type: str
  ssh_key_ids:
    description: A list of SSH Key IDs that will be installed on the server in addition to any ssh keys specified in request.
    type: list
    elements: str
  state:
    description: Desired state of the server.
    choices: [absent, present, powered-on, powered-off, rebooted, reset, shutdown]
    default: present
    type: str
  type:
    description: Server type ID. See BMC API for current list - U(https://developers.phoenixnap.com/docs/bmc/1/types/Server).
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml
# and generated SSH key pair in location: ~/.ssh/

# Creating server

- name: Create new servers for account
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
'''

RETURN = '''
changed:
    description: True if a server was altered in any way (created, modified or removed)
    type: bool
    sample: True
    returned: success
servers:
    description: Information about each server that was processed
    type: list
    sample: '[{"id": "5e502f94dea4835b112de8f0", "status": "powered-on", "hostname": "my-server-red",
               "description": "my test server", "os": "ubuntu/bionic", "type": "s1.c1.medium", "location": "PHX",
               "cpu": "Dual Silver 4110", "cpuCount": 1, "coresPerCpu": 6, "cpuFrequency": 3.8,
               "ram": "64GB RAM", "storage": "1x 1TB NVMe", privateIpAddresses": ["10.0.0.1"],
               "publicIpAddresses": ["198.15.65.2", "198.15.65.3", "198.15.65.4", "198.15.65.5", "198.15.65.6"],
               "reservationId": null, "pricingModel": "HOURLY", "password": null, "networkType": "PUBLIC_AND_PRIVATE"}]'
    returned: success
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper

import json
import time


ALLOWED_STATES = ['absent', 'powered-on', 'powered-off', 'present', 'rebooted', 'reset', 'shutdown']
BASE_API = 'https://api.phoenixnap.com/bmc/v1/servers/'
CHECK_FOR_STATUS_CHANGE = 5
TIMEOUT_STATUS_CHANGE = 1800


def get_target_list(module, target_state):
    if module.params['server_ids']:
        target_list = module.params['server_ids']
    elif target_state == 'present':
        target_list = module.params['hostnames']
    else:
        target_list = get_servers_id(module, module.params['hostnames'])
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
    response = requests_wrapper(BASE_API, module=module)
    return response.json()


def equalize_server_list(module, target_servers):
    existing_servers = get_existing_servers(module)
    return [ex for ex in existing_servers if ex['id'] in target_servers]


def ratify_server_list_case_present(target_servers):
    process_servers = []
    [process_servers.append({'id': ts, 'status': 'not present'}) for ts in target_servers]
    return process_servers


def ratify_server_list_case_rebooted(process_servers):
    for ps in process_servers:
        if ps['status'] != 'powered-on':
            raise Exception('all servers must be in powered-on state')


def ratify_server_list(module, target_servers, target_state):
    if target_state == 'present':
        return ratify_server_list_case_present(target_servers)

    if len(target_servers) != len(set(target_servers)):
        raise Exception('List of servers can\'t contain duplicate server id')

    process_servers = equalize_server_list(module, target_servers)
    if len(target_servers) > len(process_servers):
        raise Exception('List of servers contain one or more invalid server id')

    if target_state == 'rebooted':
        ratify_server_list_case_rebooted(process_servers)

    return process_servers


def get_servers_id(module, server_names):
    if server_names is None:
        raise Exception('Please check provided server list.')
    existing_servers = get_existing_servers(module)
    return [s['id'] for s in existing_servers if s['hostname'] in server_names]


def get_api_params(module, server_id, target_state):
    method = 'POST'
    data = None

    if target_state == 'absent':
        path = server_id
        method = 'DELETE'
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
            "sshKeys": [module.params['ssh_key']],
            "sshKeyIds": module.params['ssh_key_ids']
        }
    elif(target_state == 'present'):
        path = ''
        data = {
            "description": module.params['description'],
            "location": module.params['location'],
            "hostname": server_id,
            "installDefaultSshKeys": module.params['install_default_sshkeys'],
            "sshKeys": [module.params['ssh_key']],
            "sshKeyIds": module.params['ssh_key_ids'],
            "networkType": module.params['network_type'],
            "os": module.params['os'],
            "reservationId": module.params['reservation_id'],
            "pricingModel": module.params['pricing_model'],
            "type": module.params['type'],
            "osConfiguration": {
                "windows": {
                    "rdpAllowedIps": module.params['rdp_allowed_ips']
                }
            }
        }
    data = json.dumps(data)
    endpoint = BASE_API + path
    return{'method': method, 'endpoint': endpoint, 'data': data}


def wait_for_status_change_case_absent(target_list):
    servers_refreshed = []
    [servers_refreshed.append({'id': ts, 'status': 'Server has been deleted'}) for ts in target_list]
    return servers_refreshed


def wait_for_status_change(module, target_list, target_state):
    if target_state == 'absent':
        return wait_for_status_change_case_absent(target_list)

    timeout = time.time() + TIMEOUT_STATUS_CHANGE
    while timeout > time.time():
        servers_refreshed = equalize_server_list(module, target_list)
        if all(sr['status'] == state_final(target_state) for sr in servers_refreshed):
            return servers_refreshed
        time.sleep(CHECK_FOR_STATUS_CHANGE)
    raise Exception('waiting for status %s has expired' % target_state)


def servers_action(module, target_state):
    changed = False
    set_token_headers(module)
    target_list = get_target_list(module, target_state)
    process_servers = ratify_server_list(module, target_list, target_state)

    for ps in process_servers:
        if ps['status'] != state_api_remapping(target_state):
            ap = get_api_params(module, ps['id'], target_state)
            requests_wrapper(ap['endpoint'], ap['method'], data=ap['data'], module=module)
            changed = True

    if target_state == 'present':
        target_list = get_servers_id(module, target_list)
    if changed:
        process_servers = wait_for_status_change(module, target_list, target_state)

    return{
        'changed': changed,
        'servers': process_servers
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(required=True),
            client_secret=dict(required=True, no_log=True),
            description=dict(),
            location=dict(),
            hostnames=dict(type='list', elements='str'),
            install_default_sshkeys=dict(type='bool', default=True),
            network_type=dict(default='PUBLIC_AND_PRIVATE'),
            os=dict(),
            rdp_allowed_ips=dict(type='list', elements='str'),
            reservation_id=dict(),
            pricing_model=dict(default='HOURLY'),
            server_ids=dict(type='list', elements='str'),
            ssh_key=dict(no_log=True),
            ssh_key_ids=dict(type='list', elements='str', no_log=True),
            state=dict(choices=ALLOWED_STATES, default='present'),
            type=dict(),
        ),
        mutually_exclusive=[('hostnames', 'server_ids')],
        required_one_of=[('hostnames', 'server_ids')],
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests is required for this module.')

    state = module.params['state']

    try:
        module.exit_json(**servers_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
