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
module: storage_network_volume

short_description: add/remove Volume from a Storage Network.
description:
    - add/remove Volume from a Storage Network.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/network-storage/1/overview).

version_added: "1.11.0"

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
  storage_network_id:
    description: ID of storage network.
    type: str
    required: true
  volume_id:
    description: ID of volume.
    type: str
  volume_name:
    description: Volume friendly name.
    type: str
  description:
    description: Volume description.
    type: str
  path_suffix:
    description: Last part of volume's path.
    type: str
  capacity_in_gb:
    description: Capacity of Volume in GB.
    type: int
  permissions:
    description: permissions for a volume.
    type: dict
    suboptions:
      nfs:
        type: dict
        description: NFS specific permissions on a volume.
        suboptions:
          read_write:
            description: Read/Write access.
            type: list
            elements: str
          read_only:
            description: Read only access.
            type: list
            elements: str
          root_squash:
            description: Root squash permission.
            type: list
            elements: str
          no_squash:
            description: No squash permission.
            type: list
            elements: str
          all_squash:
            description: All squash permission.
            type: list
            elements: str
  volume_new_name:
    description: Volume new name
    type: str
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
  state:
    description: Indicate desired state of the target.
    default: present
    choices: ['present', 'absent']
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: Create a volume belonging to a storage network.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Create a volume belonging to a storage network.
      phoenixnap.bmc.storage_network_volume:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        storage_network_id: e6afba51-7de8-4080-83ab-0f915570659c
        volume_name: myvolume
        capacityInGb: 1000
        state: present
      register: output
    - name: Print the storage network information
      ansible.builtin.debug:
        var: output.storage_network_ip_block

- name: Delete a Storage Network's Volume
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Delete a Storage Network's Volume
      phoenixnap.bmc.storage_network_volume:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        storage_network_id: e6afba51-7de8-4080-83ab-0f915570659c
        volume_id: 60473a6115e34466c9f8f083
        state: absent
      register: output
    - name: Print the storage network information
      ansible.builtin.debug:
        var: output.storage_network_volume
'''

RETURN = '''
storage_network_volume:
    description: The specified Volume information
    returned: success
    type: complex
    contains:
      id:
        description: Volume ID.
        returned: always
        type: str
        sample: 60473a6115e34466c9f8f083
      name:
        description: Volume friendly name.
        returned: always
        type: str
        sample: My volume name
      description:
        description: Volume description.
        returned: always
        type: str
        sample: My volume description
      path:
        description: Volume's full path.
        returned: always
        type: str
        sample: /qjul77ahf5fplr2ba484/shared-docs
      pathSuffix:
        description: Last part of volume's path.
        returned: always
        type: str
        sample: /shared-docs
      capacityInGb:
        description: Maximum capacity in GB.
        returned: always
        type: int
        sample: 1000
      usedCapacityInGb:
        description: Used capacity in GB, updated periodically.
        returned: always
        type: int
        sample: 1000
      protocol:
        description: File system protocol.
        returned: always
        type: str
        sample: NFS
      status:
        description: Status of the resource.
        returned: always
        type: str
        sample: READY
      createdOn:
        description: date-time
        returned: always
        type: str
      deleteRequestedOn:
        description: Date and time of the initial request for volume deletion.
        returned: always
        type: str
      permissions:
        description: Permissions for a volume.
        type: dict
        contains:
          nfs:
            description: NFS specific permissions on a volume.
            type: dict
            contains:
              readWrite:
                description: Read/Write access.
                type: list
                elements: str
              readOnly:
                description: Read only access.
                type: list
                elements: str
              rootSquash:
                description: Root squash permission.
                type: list
                elements: str
              noSquash:
                description: No squash permission.
                type: list
                elements: str
              allSquash:
                description: All squash permission.
                type: list
                elements: str
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
                                                                          STORAGE_NETWORK_API, remove_empty_elements)

import os
import json

ALLOWED_STATES = ["present", "absent"]
API_SUFFIX = "/volumes/"


def get_existing_volume_by_id(storage_network_id, target_volume_id, module):
    response = requests_wrapper(STORAGE_NETWORK_API + storage_network_id, module=module).json()
    volumes = response.get('volumes')
    existing_volume = next((v for v in volumes if v['id'] == target_volume_id), {})
    return existing_volume


def get_existing_volume_by_name(storage_network_id, target_volume_name, module):
    response = requests_wrapper(STORAGE_NETWORK_API + storage_network_id, module=module).json()
    volumes = response.get('volumes')
    existing_volume = next((v for v in volumes if v['name'] == target_volume_name), {})
    return existing_volume


def get_volume_diff(existing_volume, module):
    params = module.params
    request_data = {}
    top_level_params = {
        'volume_new_name': 'name',
        'capacity_in_gb': 'capacityInGb',
        'description': 'description',
        'path_suffix': 'pathSuffix'
    }

    def underscore_to_camel(param):
        words = param.split('_')
        return words[0] + ''.join([word.capitalize() for word in words[1:]])

    def get_top_level_params_diff(item):
        if params.get(item) and params[item] != existing_volume.get(top_level_params[item]):
            request_data[top_level_params[item]] = params[item]

    [get_top_level_params_diff(tlp) for tlp in top_level_params]

    if params.get('permissions'):
        permissions = params.get('permissions').get('nfs')
        existing_permissions = existing_volume['permissions']['nfs']
        request_data_permissions = {}

        if permissions:
            for item, value in permissions.items():
                if value is not None and set(value) != set(existing_permissions[underscore_to_camel(item)]):
                    request_data_permissions[underscore_to_camel(item)] = value
        if request_data_permissions:
            request_data['permissions'] = {'nfs': request_data_permissions}

    return request_data


def storage_network_volume_action(module, state):
    set_token_headers(module)
    changed = False
    storage_network_id = module.params['storage_network_id']

    if module.params['volume_name']:
        target_volume_name = module.params['volume_name']
        existing_volume = get_existing_volume_by_name(storage_network_id, target_volume_name, module)
        target_volume_id = existing_volume.get('id')
    else:
        target_volume_id = module.params['volume_id']
        existing_volume = get_existing_volume_by_id(storage_network_id, target_volume_id, module)
    existing_volume_id = existing_volume.get('id', 'missing')

    if state == 'present':
        if existing_volume == {}:
            changed = True
            if not module.check_mode:
                data = remove_empty_elements(json.dumps({
                    "name": module.params['volume_name'],
                    "capacityInGb": module.params['capacity_in_gb'],
                    "description": module.params['description'],
                    "pathSuffix": module.params['path_suffix'],
                    "permissions": module.params['permissions'],
                    "tags": module.params["tags"],
                }))
                existing_volume = requests_wrapper(STORAGE_NETWORK_API + storage_network_id + API_SUFFIX, method='POST', data=data).json()
        else:
            data = get_volume_diff(existing_volume, module)
            if data != {}:
                changed = True
                if not module.check_mode:
                    data = remove_empty_elements(json.dumps(data))
                    existing_volume = requests_wrapper(STORAGE_NETWORK_API + storage_network_id + API_SUFFIX + target_volume_id,
                                                       method='PATCH', data=data).json()

    if state == 'absent' and existing_volume_id == target_volume_id:
        changed = True
        if not module.check_mode:
            response = requests_wrapper(STORAGE_NETWORK_API + storage_network_id + API_SUFFIX + target_volume_id, method="DELETE")
            existing_volume = 'The Volume [%s] has been deleted.' % target_volume_id if response.status_code == 204 else response.json()

    return {
        'changed': changed,
        'storage_network_volume': existing_volume
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            storage_network_id=dict(required=True),
            volume_name={},
            volume_id={},
            capacity_in_gb=dict(type='int'),
            description={},
            path_suffix={},
            permissions=dict(
                type='dict',
                options=dict(
                    nfs=dict(
                        type='dict',
                        options=dict(
                            read_write=dict(
                                type='list',
                                elements='str'
                            ),
                            read_only=dict(
                                type='list',
                                elements='str'
                            ),
                            root_squash=dict(
                                type='list',
                                elements='str'
                            ),
                            no_squash=dict(
                                type='list',
                                elements='str'
                            ),
                            all_squash=dict(
                                type='list',
                                elements='str'
                            ),
                        )
                    )
                )
            ),
            volume_new_name={},
            tags=dict(type="list", elements='dict', options=dict(name={}, value={})),
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
        mutually_exclusive=[('volume_name', 'volume_id')],
        required_one_of=[('volume_name', 'volume_id')],
        required_if=[('state', 'present', ['capacity_in_gb'])],
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
        module.exit_json(**storage_network_volume_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
