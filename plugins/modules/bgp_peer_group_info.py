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
module: bgp_peer_group_info

short_description: Gather information about phoenixNAP BGP Peer Groups owned by account.
description:
    - Gather information about BGP Peer Groups available.
    - This module has a dependency on requests

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
    description: If present will filter the result by the given location of the BGP Peer Group.
    type: str
  bgp_peer_group_id:
    description: The unique identifier of the BGP Peer Group.
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: List all BGP Peer Groups
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: List all BGP Peer Groups for account
      phoenixnap.bmc.bgp_peer_group_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.bgp_peer_groups
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
      ipPrefixes:
        description: The List of the BGP Peer Group IP prefixes.
        returned: always
        type: list
        contains:
          ipAllocationId:
            description: IP allocation ID.
            type: str
            sample: 6047127fed34ecc3ba8402d2
          cidr:
            description: The IP block in CIDR format, dependent on IP version.
            type: str
            sample: 10.111.14.40/29
          ipVersion:
            description: The IP block version.
            type: bool
            example: V4
          status:
            description: The BGP IPv4 Prefix status.
            type: str
            example: READY
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
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, BGP_PEER_GROUP_API

import os


def bgp_peer_group_info(module):
    set_token_headers(module)
    if module.params['bgp_peer_group_id']:
        bgp_peer_groups = requests_wrapper(BGP_PEER_GROUP_API + module.params['bgp_peer_group_id']).json()
    else:
        params = {
            'location': module.params['location']
        }
        bgp_peer_groups = requests_wrapper(BGP_PEER_GROUP_API, params=params, module=module).json()
    return {
        'bgp_peer_groups': bgp_peer_groups
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            location={},
            bgp_peer_group_id={},
        ),
        supports_check_mode=True,
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests is required for this module.')

    if not module.params.get('client_id') or not module.params.get('client_secret'):
        _fail_msg = ("if BMC_CLIENT_ID and BMC_CLIENT_SECRET are not in environment variables, "
                     "the client_id and client_secret parameters are required")
        module.fail_json(msg=_fail_msg)

    try:
        module.exit_json(**bgp_peer_group_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
