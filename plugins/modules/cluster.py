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
module: cluster

short_description: Manage phoenixNAP Bare Metal Cloud clusters
description:
    - Create and manage clusters.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/rancher/1/overview).

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
  ca_certificate:
    type: str
    description:
      - The SSL CA certificate to be used for rancher admin.
      - Once a cluster is created, it cannot be modified through a playbook
  certificate:
    type: str
    description:
      - The SSL certificate to be used for rancher admin.
      - Once a cluster is created, it cannot be modified through a playbook
  certificate_key:
    type: str
    description:
      - The SSL certificate key to be used for rancher admin.
      - Once a cluster is created, it cannot be modified through a playbook
  cluster_domain:
    type: str
    description:
      - This maps to ranchers cluster-domain. Cluster Domain.
      - Once a cluster is created, it cannot be modified through a playbook
  description:
    description:
      - Cluster description.
      - Once a cluster is created, it cannot be modified through a playbook
    type: str
  etcd_snapshot_retention:
    type: int
    description:
      - This maps to ranchers etcd-snapshot-retention. Number of snapshots to retain.
      - Once a cluster is created, it cannot be modified through a playbook
      - Default is 5
  etcd_snapshot_schedule_cron:
    type: str
    description:
      - This maps to ranchers etcd-snapshot-schedule-cron. Snapshot interval time in cron spec. eg. every 5 hours
      - Once a cluster is created, it cannot be modified through a playbook
      - Default is '* */12 * * *'
  location:
    description:
      - Deployment location.
      - Once a cluster is created, it cannot be modified through a playbook
    type: str
  name:
    description: Cluster name.
    type: str
  node_pool_name:
    type: str
    description:
      - The name of the node pool.
      - Once a cluster is created, it cannot be modified through a playbook
  node_pool_count:
    type: int
    description:
      - Number of configured nodes, currently only node counts of 1 and 3 are possible.
      - Once a cluster is created, it cannot be modified through a playbook
  node_server_type:
    type: str
    description:
      - Node server type.
      - Once a cluster is created, it cannot be modified through a playbook
      - default is s0.d1.small
  node_install_default_keys:
    type: bool
    description:
      - Define whether public keys marked as default should be installed on this node.
      - These are public keys that were already recorded on this system.
      - Use GET /ssh-keys to retrieve a list of possible values.
      - Once a cluster is created, it cannot be modified through a playbook
      - deafult is true
  node_key_ids:
    type: list
    elements: str
    description:
      - List of public SSH key identifiers. These are public keys that were already recorded on this system.
      - Once a cluster is created, it cannot be modified through a playbook
  node_keys:
    type: list
    elements: str
    description:
      - List of public SSH keys.
      - Once a cluster is created, it cannot be modified through a playbook
  node_taint:
    type: str
    description:
    - This maps to ranchers node-taint. Registering kubelet with set of taints.
    - Once a cluster is created, it cannot be modified through a playbook
  state:
    description: Desired state of the cluster.
    choices: [absent, present]
    default: present
    type: str
  tls_san:
    type: str
    description:
      - This maps to ranchers tls-san. Add additional hostname or IP as a Subject Alternative Name in the TLS cert.
      - Once a cluster is created, it cannot be modified through a playbook
  token:
    type: str
    description:
      - Shared secret used to join a server or agent to a cluster.
      - Once a cluster is created, it cannot be modified through a playbook
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml
# and generated SSH key pair in location: ~/.ssh/

# Create cluster

- name: Create new cluster for account
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.cluster:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      location: PHX
      name: mycluster
      description: mydescritpion
      node_pool_name: mypool
      node_server_type: s1.c1.small
      node_pool_count: 1
      node_install_default_keys: false
      node_key_ids: 6xex7xbx7xex1x4x3xfxex3x, 6yfy6y4yby6ydy2y4ycy2ybyXyX
      state: present
    register: output
  - name: Print the cluster information
    debug:
      var: output.clusters


# Delete cluster

- name: Delete cluster
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.cluster:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      name: mycluster
    register: output
  - name: Print the cluster information
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
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import (set_token_headers, HAS_REQUESTS, requests_wrapper,
                                                                          remove_empty_elements, check_immutable_arguments, CLUSTER_API)
import os
import json
import time


ALLOWED_STATES = ['absent', 'present']
IMMUTABLE_ARGUMENTS = {'description': 'description', 'location': 'location'}
CHECK_FOR_STATUS_CHANGE = 5
TIMEOUT_STATUS_CHANGE = 1800


def get_existing_clusters(module):
    response = requests_wrapper(CLUSTER_API, module=module)
    return response.json()


def get_create_params(cluster_name, module):
    data = json.dumps(remove_empty_elements({
        'location': module.params['location'],
        'name': cluster_name,
        'description': module.params['description'],
        'nodePools': [{
            'name': module.params['node_pool_name'],
            'nodeCount': module.params['node_pool_count'],
            'serverType': module.params['node_server_type'],
            'sshConfig': {
                'installDefaultKeys': module.params['node_install_default_keys'],
                'keyIds': module.params['node_key_ids'],
                'keys': module.params['node_keys']
            }
        }],
        'configuration': {
            'certificates': {
                'certificate': module.params['certificate'],
                'caCertificate': module.params['ca_certificate'],
                'certificateKey': module.params['certificate_key'],
            },
            'clusterDomain': module.params['cluster_domain'],
            'etcdSnapshotRetention': module.params['etcd_snapshot_retention'],
            'etcdSnapshotScheduleCron': module.params['etcd_snapshot_schedule_cron'],
            'nodeTaint': module.params['node_taint'],
            'tlsSan': module.params['tls_san'],
            'token': module.params['token']
        }
    }))
    return data


def wait_for_status_change(cluster_id, target_status, response_create, module):
    timeout = time.time() + TIMEOUT_STATUS_CHANGE
    while timeout > time.time():
        time.sleep(CHECK_FOR_STATUS_CHANGE)
        response = requests_wrapper(CLUSTER_API + cluster_id, module=module).json()
        if response['statusDescription'] == 'Error':
            response_create['statusDescription'] = 'Error'
            raise Exception('An Error occurred: %s' % response_create)
        if response['statusDescription'] == target_status:
            response_create['statusDescription'] = target_status
            return response_create
    raise Exception('waiting for status %s has expired' % target_status)


def cluster_action(module, target_state):
    changed = False
    set_token_headers(module)
    name = module.params['name']
    existing_clusters = get_existing_clusters(module)
    cluster = next((cluster for cluster in existing_clusters if cluster['name'] == name), 'absent')

    if target_state == 'present':
        if cluster == 'absent':
            changed = True
            if not module.check_mode:
                data = get_create_params(name, module)
                response_create = requests_wrapper(CLUSTER_API, method='POST', data=data, module=module).json()
                cluster_id = response_create['id']
                cluster = wait_for_status_change(cluster_id, 'Ready', response_create, module)
        else:
            check_immutable_arguments(IMMUTABLE_ARGUMENTS, cluster, module)

    if target_state == 'absent' and cluster != 'absent':
        if not module.check_mode:
            cluster = requests_wrapper(CLUSTER_API + cluster['id'], method='DELETE', module=module).json()

    if cluster == 'absent':
        cluster = 'The cluster [%s]' % name + ' is absent'

    return{
        'changed': changed,
        'clusters': cluster
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            description={},
            location={},
            name={},
            node_pool_name={},
            node_pool_count=dict(type='int'),
            node_server_type={},
            node_install_default_keys=dict(type='bool'),
            node_keys=dict(type='list', elements='str', no_log=True),
            node_key_ids=dict(type='list', elements='str', no_log=True),
            certificate={},
            ca_certificate={},
            certificate_key=dict(no_log=True),
            cluster_domain={},
            etcd_snapshot_retention=dict(type='int'),
            etcd_snapshot_schedule_cron={},
            node_taint={},
            tls_san={},
            token=dict(no_log=True),
            state=dict(choices=ALLOWED_STATES, default='present'),
        ),
        required_if=[
            ["state", "present", ["location", "name"]],
            ["state", "absent", ["name"]],
        ],
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
        module.exit_json(**cluster_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
