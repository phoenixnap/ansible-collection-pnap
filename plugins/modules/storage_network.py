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
module: storage_network

short_description: Create/delete storage network on phoenixNAP Bare Metal Cloud.
description:
    - Create/delete storage network on phoenixNAP Bare Metal Cloud.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/network-storage/1/overview).

version_added: "1.6.0"

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
  name:
    description: Storage network friendly name.
    type: str
  description:
    description: Storage network description.
    type: str
  location:
    description:
      - Location of storage network.
      - Once a network is created, it cannot be modified through a playbook
    type: str
  volumes:
    description:
      - Volume to be created alongside storage.
      - Once a volume is created, it cannot be modified through a playbook
    type: list
    elements: dict
    suboptions:
      name:
        description: Volume friendly name.
        type: str
      description:
        description: Volume description.
        type: str
      pathSuffix:
        description: Last part of volume's path.
        type: str
      capacityInGb:
        description: Capacity of Volume in GB.
        type: int
      tags:
        description: Tag request to assign to resource.
        type: list
        elements: dict
        suboptions:
          name:
            description: The name of the tag.
            type: str
          value:
            description: The value of the tag assigned to the resource.
            type: str
  client_vlan:
    description: Custom Client VLAN that the Storage Network will be set to.
    type: int
  state:
    description: Indicate desired state of the target.
    default: present
    choices: ['present', 'absent']
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

# Create a storage network and volume

- name: Create new storage network for account
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.storage_network:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      name: My storage network
      location: PHX
      description: My description
      volumes:
        - name: My volume name
          capacityInGb: 1000
      state: present
    register: output
  - name: Print the storage network information
    debug:
      var: output.storage_networks

# Delete storage network

- name: Delete storage network
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.storage_network:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      name: My storage network
      state: absent
    register: output
  - name: Print the storage network information
    debug:
      var: output.storage_networks

'''

RETURN = '''
storage_networks:
    description: The storage networks information as list
    returned: success
    type: complex
    contains:
      id:
        description: Storage network ID.
        returned: always
        type: str
        sample: 603f3b2cfcaf050643b89a4b
      name:
        description: Storage network friendly name.
        returned: always
        type: str
        sample: My storage network
      description:
        description: Storage network description.
        returned: always
        type: str
        sample: My storage network description
      status:
        description: Status of the resource.
        returned: always
        type: str
        sample: READY
      location:
        description: Location of storage network.
        returned: always
        type: str
        sample: PHX
      networkId:
        description: Id of network the storage belongs to.
        returned: always
        type: str
        sample: 603f3b2cfcaf050643b89a4b
      ips:
        description: IP of the storage network.
        returned: always
        type: list
        elements: str
        sample: ["100.64.0.1", "100.64.0.2"]
      createdOn:
        description: Date and time when this storage network was created.
        returned: always
        type: str
      volumes:
        description: Volume for a storage network.
        returned: always
        type: list
        contains:
          id:
            description: Volume ID.
            type: str
            sample: 50dc434c-9bba-427b-bcd6-0bdba45c4dd2
          name:
            description: Volume friendly name.
            type: str
            example: My volume name
          description:
            description: Volume description.
            type: str
            example: My volume description
          path:
            description: Volume's full path. It is in form of /{volumeId}/pathSuffix'.
            type: str
            example: /qjul77ahf5fplr2ba484/shared-docs
          pathSuffix:
            description: Last part of volume's path.
            type: str
            example: /shared-docs
          capacityInGb:
            description: Maximum capacity in GB.
            type: int
            example: 2000
          protocol:
            description: File system protocol. Currently this field should be set to NFS.
            type: str
            example: NFS
          status:
            description: Status of the resource.
            type: str
            example: READY
          createdOn:
            description: Date and time when this volume was created.
            returned: always
            type: str
          permissions:
            description: Permissions for a volume.
            type: dict
          tags:
            description: The tags assigned if any.
            type: list
            contains:
              id:
                description: The unique id of the tag.
                type: str
              name:
                description: The name of the tag.
                type: str
              value:
                description: The value of the tag assigned to the resource.
                type: str
              isBillingTag:
                description: Whether or not to show the tag as part of billing and invoices.
                type: bool
              createdBy:
                description: Who the tag was created by.
                type: str
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import (set_token_headers, HAS_REQUESTS, requests_wrapper,
                                                                          check_immutable_arguments, STORAGE_NETWORK_API)

import os
import json
import time

ALLOWED_STATES = ["present", "absent"]
IMMUTABLE_ARGUMENTS = {'location': 'location'}
CHECK_FOR_STATUS_CHANGE = 2
TIMEOUT_STATUS_CHANGE = 900


def get_existing_storage_networks(module):
    response = requests_wrapper(STORAGE_NETWORK_API, module=module)
    return response.json()


def wait_for_status_change(storage_network_id, target_status, response_create, module):
    timeout = time.time() + TIMEOUT_STATUS_CHANGE
    while timeout > time.time():
        time.sleep(CHECK_FOR_STATUS_CHANGE)
        response = requests_wrapper(STORAGE_NETWORK_API + storage_network_id, module=module).json()
        if response['status'].lower() == 'error':
            response_create['status'] = 'Error'
            raise Exception('An Error occurred: %s' % response_create)
        if response['status'].lower() == target_status.lower():
            response_create['status'] = target_status
            return response_create
    raise Exception('waiting for status %s has expired' % target_status)


def storage_network_action(module, state):
    set_token_headers(module)
    changed = False
    existing_networks = get_existing_storage_networks(module)
    new_storage_name = module.params['name']
    storage_network = next((storage for storage in existing_networks if storage['name'] == new_storage_name), 'absent')

    if state == 'present':
        if storage_network == 'absent':
            changed = True
            data = json.dumps({
                'name': new_storage_name,
                'location': module.params['location'],
                'description': module.params['description'],
                'volumes': module.params['volumes'],
                'clientVlan': module.params['client_vlan'],
            })
            if not module.check_mode:
                response_create = requests_wrapper(STORAGE_NETWORK_API, method='POST', data=data).json()
                storage_network = wait_for_status_change(response_create['id'], 'READY', response_create, module)

        else:
            check_immutable_arguments(IMMUTABLE_ARGUMENTS, storage_network, module)
            desc = storage_network.get('description')
            if desc != module.params['description']:
                changed = True
                data = json.dumps({
                    'name': storage_network['name'],
                    'description': module.params['description']
                })
                if not module.check_mode:
                    storage_network = requests_wrapper(STORAGE_NETWORK_API + storage_network['id'], method='PATCH', data=data).json()

    if state == 'absent' and storage_network != 'absent':
        changed = True
        if not module.check_mode:
            response = requests_wrapper(STORAGE_NETWORK_API + storage_network['id'], method='DELETE')
            storage_network = 'The network storage [%s] has been deleted.' % new_storage_name if len(response.text) == 0 else response.json()

    if storage_network == 'absent':
        storage_network = 'The storage network [%s]' % new_storage_name + ' is absent'

    return {
        'changed': changed,
        'storage_networks': storage_network
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            name={},
            description={},
            location={},
            volumes=dict(
                type="list",
                elements='dict',
                options=dict(
                    name={},
                    description={},
                    pathSuffix={},
                    capacityInGb=dict(type='int'),
                    tags=dict(type="list", elements='dict', options=dict(name={}, value={}))
                )),
            client_vlan=dict(type='int'),
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
        required_if=[["state", "present", ["name", "location", "volumes"]]],
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
        module.exit_json(**storage_network_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
