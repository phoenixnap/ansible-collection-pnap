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
module: bgp_peer_group

short_description: Create/delete BGP Peer Group. on phoenixNAP Bare Metal Cloud.
description:
    - Create/delete BGP Peer Group on phoenixNAP Bare Metal Cloud.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/networks/1/overview).

version_added: "1.18.0"

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
  location:
    description:
      - The BGP Peer Group location.
      - Once a The BGP Peer Group is created, it cannot be modified through a playbook
    type: str
  asn:
    description: The BGP Peer Group ASN.
    type: int
  password:
    description: The BGP Peer Group password.
    type: str
  advertised_routes:
    description: The Advertised routes for the BGP Peer Group.
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

- name: Create new BGP Peer Group for account
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Create BGP Peer Group
      phoenixnap.bmc.bgp_peer_group:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        location: PHX
        asn: 65401
        advertisedRoutes: NONE
        state: present
      register: output
    - name: Print the BGP Peer Group information
      ansible.builtin.debug:
        var: output.bgp_peer_group

- name: Delete BGP Peer Group
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Delete network
      phoenixnap.bmc.bgp_peer_group:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        location: PHX
        asn: 65401
        advertisedRoutes: NONE
        state: absent
      register: output
    - name: Print the BGP Peer Group information
      ansible.builtin.debug:
        var: output.bgp_peer_group
'''

RETURN = '''
bgp_peer_groups:
    description: BGP Peer Groups information as list
    returned: success
    type: complex
    contains:
      id:
        description: The unique identifier of the BGP Peer Group.
        returned: always
        type: str
        sample: 60473c2509268bc77fd06d29
      status:
        description: The BGP Peer Group status.
        returned: always
        type: str
        sample: READY
      location:
        description: The BGP Peer Group location.
        returned: always
        type: str
        sample: PHX
      ipv4Prefixes:
        description: The List of the BGP Peer Group IPv4 prefixes.
        returned: always
        type: list
        contains:
          ipv4AllocationId:
            description: IPv4 allocation ID.
            type: str
            sample: 6047127fed34ecc3ba8402d2
          cidr:
            description: The IP block in CIDR format.
            type: str
            sample: 10.111.14.40/29
          status:
            description: The BGP IPv4 Prefix status.
            type: str
            example: READY
          isBringYourOwnIp:
            description: Identifies IP as a bring your own IP block.
            type: bool
          inUse:
            description: The Boolean value of the BGP IPv4 Prefix is in use.
            type: bool
      targetAsnDetails:
        description: BGP Peer Group ASN details.
        returned: always
        type: list
        contains:
          asn:
            description: The BGP Peer Group ASN.
            type: str
            sample: 65401
          isBringYourOwn:
            description: True if the BGP Peer Group ASN is a bring your own ASN.
            type: bool
          verificationStatus:
            description: The BGP Peer Group ASN verification status.
            type: str
            example: VERIFIED
          verificationReason:
            description: The BGP Peer Group ASN verification reason for the respective status.
            type: str
            example: Bring Your Own ASN verification succeeded all checks.
      activeAsnDetails:
        description: BGP Peer Group ASN details.
        returned: always
        type: list
        contains:
          asn:
            description: The BGP Peer Group ASN.
            type: str
            sample: 65401
          isBringYourOwn:
            description: True if the BGP Peer Group ASN is a bring your own ASN.
            type: bool
          verificationStatus:
            description: The BGP Peer Group ASN verification status.
            type: str
            example: VERIFIED
          verificationReason:
            description: The BGP Peer Group ASN verification reason for the respective status.
            type: str
            example: Bring Your Own ASN verification succeeded all checks.
      password:
        description: The BGP Peer Group password.
        type: str
        sample: E!73423ghhjfge45
      advertisedRoutes:
        description: The Advertised routes for the BGP Peer Group.
        type: str
        example: DEFAULT
      rpkiRoaOriginAsn:
        description: The RPKI ROA Origin ASN of the BGP Peer Group based on location.
        type: str
        sample: 20454
      eBgpMultiHop:
        description: The eBGP Multi-hop of the BGP Peer Group.
        type: int
        sample: 7
      peeringLoopbacksV4:
        description: The IPv4 Peering Loopback addresses of the BGP Peer Group. Valid IP formats are IPv4 addresses.
        type: list
        example: ["169.254.247.0", "169.254.247.1"]
      keepAliveTimerSeconds:
        description: The Keep Alive Timer in seconds of the BGP Peer Group.
        type: int
        sample: 10
      holdTimerSeconds:
        description: The Hold Timer in seconds of the BGP Peer Group.
        type: int
        example: 30
      createdOn:
        description: Date and time of creation.
        type: str
      lastUpdatedOn:
        description: Date and time of last update.
        type: str
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import (set_token_headers, HAS_REQUESTS, requests_wrapper, BGP_PEER_GROUP_API)


import os
import json

ALLOWED_STATES = ["present", "absent"]


def get_existing_bgp_peer_group(module):
    response = requests_wrapper(BGP_PEER_GROUP_API, module=module)
    return response.json()


def bgp_peer_group_action(module, state):
    set_token_headers(module)
    changed = False
    existing_bgp_peer_group = get_existing_bgp_peer_group(module)
    target_bgp_peer_group = next((bgp for bgp in existing_bgp_peer_group if bgp['location'] == module.params['location']), 'absent')

    if state == 'present':
        if target_bgp_peer_group == 'absent':
            changed = True
            data = json.dumps({
                'location': module.params['location'],
                'asn': module.params['asn'],
                'password': module.params['password'],
                'advertisedRoutes': module.params['advertised_routes'],
            })
            if not module.check_mode:
                response = requests_wrapper(BGP_PEER_GROUP_API, method='POST', data=data).json()
            else:
                response = 'There is no BGP Peer Group at the %s location' % module.params['location']
        else:
            data = {}
            if module.params['password'] and module.params['password'] != target_bgp_peer_group.get('password'):
                data.update({'password': module.params['password']})
            if module.params['asn'] and module.params['asn'] != target_bgp_peer_group.get('activeAsnDetails', {}).get('asn'):
                data.update({'asn': module.params['asn']})
            if module.params['advertised_routes'] and module.params['advertised_routes'].upper() != target_bgp_peer_group.get('advertisedRoutes'):
                data.update({'advertisedRoutes': module.params['advertised_routes']})

            if data:
                changed = True
                if not module.check_mode:
                    data = json.dumps(data)
                    response = requests_wrapper(BGP_PEER_GROUP_API + target_bgp_peer_group.get('id'), method='PATCH', data=data).json()
                else:
                    response = target_bgp_peer_group
            else:
                response = target_bgp_peer_group
    else:
        if target_bgp_peer_group != 'absent':
            changed = True
            if not module.check_mode:
                response = requests_wrapper(BGP_PEER_GROUP_API + target_bgp_peer_group.get('id'), method='DELETE').json()
            else:
                response = target_bgp_peer_group
        else:
            response = 'There is no BGP Peer Group at the %s location' % module.params['location']

    return {
        'changed': changed,
        'bgp_peer_group': response
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            location={},
            asn=dict(type='int'),
            password=dict(no_log=True),
            advertised_routes={},
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
        required_if=[["state", "present", ["location"]]],
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
        module.exit_json(**bgp_peer_group_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
