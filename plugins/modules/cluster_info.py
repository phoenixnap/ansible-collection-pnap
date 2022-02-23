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
module: cluster_info

short_description: Gather information about phoenixNAP clusters
description:
    - Retrieves all clusters associated with the authenticated account.
    - This module has a dependency on requests

version_added: "1.1.0"

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
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

# List clusters
- name: List clusters
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.cluster_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
    register: output
  - name: Print the gathered infos
    debug:
      var: output.clusters
'''

RETURN = '''
clusters:
    description: The clusters information as list
    returned: success
    type: complex
    contains:
      id:
        description: The Cluster identifier.
        returned: always
        type: str
        sample: 6047127fed34ecc3ba8402d2
      name:
        description: Cluster name. This field is autogenerated if not provided.
        returned: always
        type: str
        sample: Rancher Management Cluster
      description:
        description: My first Rancher Server Cluster.
        returned: always
        type: str
        sample: Cluster description.
      location:
        description: Deployment location.
        returned: always
        type: str
        sample: PHX
      initialClusterVersion:
        description: The Rancher version that was installed on the cluster during the first creation process.
        returned: always
        type: str
        sample: v2.5.9
      nodePools:
        description: The node pools associated with the cluster.
        returned: always
        type: list
        contains:
          name:
            description: The name of the node pool.
            type: str
            sample: Rancher Server node pool.
          nodeCount:
            description: The client ID of the application
            type: int
            sample: 1
          serverType:
            description: Node server type.
            type: str
            sample: s0.d1.small
          sshConfig:
            description:
              - Configuration defining which public SSH keys are pre-installed as authorized on the server.
              - Any manual configuration done on the server after installation is not reflected by this configuration.
            type: dict
            contains:
              installDefaultKeys:
                description:
                  - Define whether public keys marked as default should be installed on this node.
                  - These are public keys that were already recorded on this system.
                  - Use GET /ssh-keys to retrieve a list of possible values.
                type: bool
                sample: true
              keys:
                description: List of public SSH keys.
                type: list
                elements: str
              keyIds:
                description: List of public SSH key identifiers. These are public keys that were already recorded on this system.
                type: list
                elements: str
          nodes:
            description: The nodes associated with this node pool.
            type: list
            contains:
              serverId:
                description: The server identifier.
                type: str
                sample: 60b08f04adab617be44068bb
      configuration:
        description: Rancher configuration parameters.
        returned: always
        type: list
        contains:
          token:
            description: Shared secret used to join a server or agent to a cluster.
            type: str
            sample: gS7SnDnY5st0ryJxMXA7
          tlsSan:
            description: This maps to ranchers tls-san. Add additional hostname or IP as a Subject Alternative Name in the TLS cert.
            type: str
            sample: mydomain.com
          etcdSnapshotScheduleCron:
            description: This maps to ranchers etcd-snapshot-retention. Number of snapshots to retain.
            type: int
            sample: 5
          nodeTaint:
            description: This maps to ranchers node-taint. Registering kubelet with set of taints.
            type: str
            sample: CriticalAddonsOnly=true:NoExecute
          clusterDomain:
            description: This maps to ranchers cluster-domain. Cluster Domain.
            type: str
            sample: cluster.local
          certificates:
            description: Define the custom SSL certificates to be used instead of defaults.
            returned: always
            type: complex
            contains:
              caCertificate:
                description: The SSL CA certificate to be used for rancher admin.
                type: str
              certificate:
                description: The SSL certificate to be used for rancher admin.
                type: str
              certificateKey:
                description: The SSL certificate key to be used for rancher admin.
                type: str
      metadata:
        description: Connection parameters to use to connect to the Rancher Server Administrative GUI.
        returned: always
        type: complex
        contains:
          url:
            description: The Rancher Server URL.
            type: str
            sample: https://rancher/
          username:
            description:
              - The username to use to login to the Rancher Server.
              - This field is returned only as a response to the create cluster request.
              - Make sure to take note or you will not be able to access the server.
            type: str
            sample: admin
          password:
            description:
              - This is the password to be used to login to the Rancher Server.
              - This field is returned only as a response to the create cluster request.
              - Make sure to take note or you will not be able to access the server.
            type: str
            sample: 1234567890abcd!
      statusDescription:
        description: The cluster status
        type: str
        sample: Creating
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, CLUSTER_API

import os


def cluster_info(module):
    set_token_headers(module)
    clusters = requests_wrapper(CLUSTER_API, module=module).json()
    return{
        'clusters': clusters
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
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
        module.exit_json(**cluster_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
