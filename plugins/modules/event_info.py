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
module: event_info

short_description: Retrieves the event logs for given time period.
description:
    - Retrieves the event logs for given time period. All date & times are in UTC.
    - This module has a dependency on requests

version_added: "1.0.0"

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
  from_date:
    description: From the date and time (inclusive) to filter event log records by.
    type: str
  to_date:
    description: To the date and time (inclusive) to filter event log records by.
    type: str
  limit:
    description: Limit the number of records returned.
    type: int
  order:
    description: Ordering of the event's time. SortBy can be introduced later on.
    type: str
  username:
    description: The username that did the actions.
    type: str
  verb:
    description: The HTTP verb corresponding to the action.
    type: str
  uri:
    description: The request uri.
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: Retrieve the event logs
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Retrieve the event logs for given time period
      phoenixnap.bmc.event_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        from_date: "2021-12-01T16:24:57.123Z"
        to_date: "2021-12-02T16:24:57.123Z"
        limit: 10
        order: ASC
        username: user@domen.com
        verb: POST
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.events
'''

RETURN = '''
events:
    description: The events information as list
    returned: success
    type: complex
    contains:
      name:
        description: The name of the event.
        returned: always
        type: str
        sample: API.CreateServer
      timestamp:
        description: The UTC time the event initiated.
        returned: always
        type: str
        sample: 2020-03-19T16:39.123Z
      userInfo:
        description: Details related to the user / application performing this request
        returned: always
        type: list
        contains:
          accountId:
            description: The BMC account ID
            type: str
            sample: 1234dfgdsf
          clientId:
            description: The client ID of the application
            type: str
            sample: e9d335b1-3aa4-4760-9bad-2595c0449035
          username:
            description: The logged in user or owner of the client application
            type: str
            sample: johnd@phoenixnap.com
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, EVENT_API

import os


def event_info(module):
    set_token_headers(module)
    data = {
        'from': module.params['from_date'],
        'to': module.params['to_date'],
        'limit': module.params['limit'],
        'order': module.params['order'],
        'username': module.params['username'],
        'verb': module.params['verb'],
        'uri': module.params['uri'],
    }
    events = requests_wrapper(EVENT_API, module=module, params=data).json()
    return {
        'events': events
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            from_date={},
            to_date={},
            limit=dict(type='int'),
            order={},
            username={},
            verb={},
            uri={}
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
        module.exit_json(**event_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
