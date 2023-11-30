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
module: rated_usage_info

short_description: Retrieves all rated usage for given time period.
description:
    - Gather Retrieves all rated usage for given time period.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/bmc-billing/1/routes/rated-usage/get).

version_added: "1.15.0"

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
  from_year_month:
    description: From year month (inclusive) to filter rated usage records by.
    type: str
  to_year_month:
    description: To year month (inclusive) to filter rated usage records by.
    type: str
  product_category:
    description: The product category.
    type: str
  month_to_date:
    description: Retrieves all rated usage for the current calendar month if true.
    type: bool
    default: false
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: Retrieves all rated usage
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Retrieves all rated usage for given time period.
      phoenixnap.bmc.rated_usage_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        from_year_month: 2023-05
        to_year_month: 2023-10
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.rated_usage

- name: Retrieves all rated usage for the current calendar month.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Retrieves all rated usage for the current calendar month.
      phoenixnap.bmc.rated_usage_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        month_to_date: true
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.rated_usage
'''

RETURN = '''
rated_usage:
    description: List of all the rated usage records for given period of months.
    returned: success
    type: list
    contains:
      id:
        description: The unique identifier of the rated usage record.
        returned: always
        type: str
        sample: ec4a9d49-1cef-49e9-b85e-b560f88bcd26
      productCategory:
        description: The category of the product associated with this usage record.
        returned: always
        type: str
        sample: bmc-server
      productCode:
        description: The code identifying the product associated to this usage record.
        returned: always
        type: str
        sample: s1.c1.small
      location:
        description: The location code.
        returned: always
        type: str
        sample: PHX
      yearMonth:
        description: Year and month of the usage record.
        returned: always
        type: str
        sample: 2020-03
      startDateTime:
        description: The point in time (in UTC) when usage has started.
        returned: always
        type: str
      endDateTime:
        description: The point in time (in UTC) until usage has been rated.
        returned: always
        type: str
      cost:
        description: The rated usage in cents.
        returned: always
        type: int
        sample: 384
      costBeforeDiscount:
        description: The cost in cents before discount.
        returned: always
        type: int
        sample: 15456
      costDescription:
        description: The rated usage cost description.
        returned: always
        type: str
        sample: 24 Hour(s) @ $0.16 /Hour
      priceModel:
        description: The price model applied to this usage record.
        returned: always
        type: str
        sample: hourly
      unitPrice:
        description: The unit price.
        returned: always
        type: str
        sample: 0.16
      unitPriceDescription:
        description: User friendly description of the unit price.
        returned: always
        type: str
        sample: per hour
      quantity:
        description: The number of units being charged.
        returned: always
        type: str
        sample: 24
      active:
        description: A flag indicating whether the rated usage record is still active.
        returned: always
        type: bool
        sample: true
      usageSessionId:
        description:
          - The usage session ID is used to correlate rated usage records across periods of time.
          - For example, a server used for over a month will generate multiple rated usage records.
          - The entire usage session cost can be computed by aggregating the records having the same usage session ID.
          - It is usual to have one rated usage record per month or invoice.
        returned: always
        type: str
        sample: ec4a9d49-1cef-49e9-b85e-b560f88bcd26
      correlationId:
        description: Holds usage record id
        returned: always
        type: str
        sample: ec4a9d49-1cef-49e9-b85e-b560f88bcd26
      reservationId:
        description: Reservation id associated with this rated usage record.
        returned: always
        type: str
        sample: c32a24a1-5949-4b60-99c0-c8aaa3a92b04
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, RATED_USAGE_API

import os


def product_info(module, RATED_USAGE_API):
    set_token_headers(module)
    params = {
        'fromYearMonth': module.params['from_year_month'],
        'toYearMonth': module.params['to_year_month'],
        'productCategory': module.params['product_category'],
    }
    if module.params['month_to_date']:
        RATED_USAGE_API += 'month-to-date'
    rated_usage = requests_wrapper(RATED_USAGE_API, params=params, module=module).json()

    return {
        'rated_usage': rated_usage
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            from_year_month={},
            to_year_month={},
            product_category={},
            month_to_date=dict(type='bool', default=False),
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
        module.exit_json(**product_info(module, RATED_USAGE_API))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
