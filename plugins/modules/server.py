#!/usr/bin/python
# (c) 2020, Goran Jelenic <goranje@phoenixnap.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: server

short_description: Manage PhoenixNAP Bare Metal Cloud servers
description:
    - Manage PhoenixNAP Bare Metal Cloud servers
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/bmc/1/overview).

version_added: "x.x"

author:
    - Goran Jelenic (@xxx) <goranje@phoenixnap.com>

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
    description: Server Location ID. Cannot be changed once a server is created.
    choices: ['PHX']
    default: PHX
    type: str
  hostnames:
    description: Name of server.
    type: list
    elements: str
  os:
    description: The server's OS ID used when the server was created
    choices: [ubuntu/bionic, centos/centos7]
    default: ubuntu/bionic
    type: str
  password:
    description: Password set for user Admin on Windows server.
    type: str
  server_ids:
    description: The unique identifier of the server.
    type: list
    elements: str
  ssh_key:
    description: A list of SSH Keys that will be installed on the Linux server.
    type: str
  state:
    description: Desired state of the server.
    choices: [absent, present, powered-on, powered-off, rebooted, reset, shutdown]
    default: present
    type: str
  type:
    description: Server type ID. Cannot be changed once a server is created.
    choices: [s1.c1.tiny, s1.c1.medium]
    default: s1.c1.medium
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
    - phoenixnap.ansible_pnap
  tasks:
  - server:
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
    - phoenixnap.ansible_pnap
  tasks:
  - server:
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
    - phoenixnap.ansible_pnap
  tasks:
  - server:
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
    - phoenixnap.ansible_pnap
  tasks:
  - server:
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
devices:
    description: Information about each server that was processed
    type: list
    sample: '[{"cpu": "Dual Silver 4110", "description": null, "hostname": "my-server-red",
               "id": "5e502f94dea4835b112de8f0", "location": "PHX", "os": "ubuntu/bionic",
               "privateIpAddresses": ["10.0.0.1"],
               "publicIpAddresses": ["198.15.65.2", "198.15.65.3", "198.15.65.4", "198.15.65.5", "198.15.65.6"],
               "ram": "64GB RAM", "status": "powered-on", "storage": "1x 1TB NVMe", "type": "s1.c1.medium"}]'
    returned: success
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

HAS_REQUESTS = True
try:
    import requests
    REQUEST = requests.Session()
    REQUEST.headers.update({'Content-Type': 'application/json'})
except ImportError:
    HAS_REQUESTS = False
import json
import time
from base64 import standard_b64encode

ALLOWED_STATES = ['absent', 'powered-on', 'powered-off', 'present', 'rebooted', 'reset', 'shutdown']
BASE_API = 'https://api.phoenixnap.com/bmc/v0/servers/'
TOKEN_API = 'https://auth.phoenixnap.com/auth/realms/BMC/protocol/openid-connect/token'

BASE_API = 'https://api-dev.phoenixnap.com/bmc/v0/servers/'
TOKEN_API = 'https://auth-dev.phoenixnap.com/auth/realms/BMC/protocol/openid-connect/token'

CHECK_FOR_STATUS_CHANGE = 5
TIMEOUT_STATUS_CHANGE = 900


def set_token_headers(module):
    auth_data = "%s:%s" % (module.params["client_id"], module.params["client_secret"])
    basic_auth = standard_b64encode(auth_data.encode("utf-8"))
    data = {
        'grant_type': 'client_credentials'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic %s' % basic_auth.decode("utf-8")
    }
    response = requests.request('POST', TOKEN_API, data=data, headers=headers)
    if response.status_code != 200:
        raise Exception('%s' % response.json()['error_description'])
    token = response.json()['access_token']
    REQUEST.headers.update({'Authorization': 'Bearer %s' % token})


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


def requests_wrapper(endpoint, method='GET', data=None, module=None):
    try:
        response = REQUEST.request(method, endpoint, data=data)
        if response.status_code == 401:
            set_token_headers(module)
            return requests_wrapper(endpoint, method, data, module)
        elif response.status_code != 200:
            error_message = response.json()['message']
            validation_errors = response.json()['validationErrors']
            raise Exception('status code %s \n%s\nValidation errors: %s' % (response.status_code, error_message, validation_errors))
    except requests.exceptions.RequestException as e:
        raise Exception("Communications error: %s" % str(e), e)
    return response


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
            "sshKeys": [module.params['ssh_key']]
        }
    elif(target_state == 'present'):
        path = ''
        data = {
            "description": module.params['description'],
            "location": module.params['location'],
            "hostname": server_id,
            "os": module.params['os'],
            "password": module.params['password'],
            "type": module.params['type'],
            "sshKeys": [module.params['ssh_key']]
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
            location=dict(choices=['PHX'], default='PHX'),
            hostnames=dict(type='list', elements='str'),
            os=dict(choices=['ubuntu/bionic', 'centos/centos7'], default='ubuntu/bionic'),
            password=dict(no_log=True),
            type=dict(choices=['s1.c1.tiny', 's1.c1.medium'], default='s1.c1.medium'),
            server_ids=dict(type='list', elements='str'),
            ssh_key=dict(),
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
        mutually_exclusive=[('hostnames', 'server_ids')],
        required_one_of=[('hostnames', 'server_ids')],
        required_if=[["state", "present", ["hostnames", "ssh_key"]]]
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests is required for this module. [pip install requests]')

    state = module.params['state']

    try:
        module.exit_json(**servers_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
