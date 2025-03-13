# -*- coding: utf-8 -*-
# (c) 2021, Pavle Jojkic <pavlej@phoenixnap.com> , Goran Jelenic <goranje@phoenixnap.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible.module_utils.six import raise_from
from base64 import standard_b64encode
import time
HAS_REQUESTS = True
try:
    import requests
    REQUEST = requests.Session()
    REQUEST.headers.update({'Content-Type': 'application/json'})
except ImportError:
    HAS_REQUESTS = False

VALID_RESPONSE_CODES = [200, 201, 202, 204]
AUTH_API = 'https://auth.phoenixnap.com/auth/realms/BMC/protocol/openid-connect/token'
SERVER_API = 'https://api.phoenixnap.com/bmc/v1/servers/'
SSH_API = 'https://api.phoenixnap.com/bmc/v1/ssh-keys/'
PRIVATE_NETWORK_API = 'https://api.phoenixnap.com/networks/v1/private-networks/'
PUBLIC_NETWORK_API = 'https://api.phoenixnap.com/networks/v1/public-networks/'
TAG_API = 'https://api.phoenixnap.com/tag-manager/v1/tags/'
EVENT_API = 'https://api.phoenixnap.com/audit/v1/events'
RESERVATION_API = 'https://api.phoenixnap.com/billing/v1/reservations/'
CLUSTER_API = 'https://api.phoenixnap.com/solutions/rancher/v1beta/clusters/'
IP_API = 'https://api.phoenixnap.com/ips/v1/ip-blocks/'
PRODUCT_API = 'https://api.phoenixnap.com/billing/v1/products/'
PRODUCT_AVAILABILITY_API = 'https://api.phoenixnap.com/billing/v1/product-availability/'
STORAGE_NETWORK_API = 'https://api.phoenixnap.com/network-storage/v1/storage-networks/'
RATED_USAGE_API = 'https://api.phoenixnap.com/billing/v1/rated-usage/'
INVOICE_API = 'https://api.phoenixnap.com/invoicing/v1/invoices/'
TRANSACTION_API = 'https://api.phoenixnap.com/payments/v1/transactions/'
BGP_PEER_GROUP_API = 'https://api.phoenixnap.com/networks/v1/bgp-peer-groups/'

NETWORK_TIMEOUT_STATUS_CHANGE = 180
CHECK_FOR_NETWORK_STATUS_CHANGE = 5


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
    response = requests.request('POST', AUTH_API, data=data, headers=headers)
    if response.status_code != 200:
        raise Exception('%s' % response.json()['error_description'])
    token = response.json()['access_token']
    REQUEST.headers.update({'Authorization': 'Bearer %s' % token})
    REQUEST.headers.update({'X-Powered-By': 'BMC-Ansible/1.19.0'})


def requests_wrapper(endpoint, method='GET', params=None, data=None, module=None, reauth_attempts=3, retries=3):
    try:
        response = REQUEST.request(method, endpoint, data=data, params=params)
        if response.status_code == 401:
            set_token_headers(module)
            if reauth_attempts == 0:
                raise Exception("Too many reauthentication attempts")
            return requests_wrapper(endpoint, method, params, data, module, reauth_attempts - 1)
        elif response.status_code not in VALID_RESPONSE_CODES:
            error_message = response.json().get('message')
            validation_errors = response.json().get('validationErrors')
            raise Exception('status code %s | %s | Validation errors: %s' % (response.status_code, error_message, validation_errors))
    except requests.exceptions.RequestException as e:
        if retries == 0:
            raise_from(Exception("Communications error: %s" % str(e)), e)
        return requests_wrapper(endpoint, method, params, data, module, retries=retries - 1)

    return response


def remove_empty_elements(d):
    """recursively remove empty lists, empty dicts, or None elements from a dictionary"""

    def empty(x):
        return x is None or x == {} or x == [] or x == ''

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements(v) for v in d) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements(v)) for k, v in d.items()) if not empty(v) or k == 'ips'}


def check_immutable_arguments(IMMUTABLE_ARGUMENTS, target, module):
    wrong_parameters = []
    for key in IMMUTABLE_ARGUMENTS:
        if module.params[key]:
            if module.params[key] != target[IMMUTABLE_ARGUMENTS[key]]:
                wrong_parameters.append(key)
    if wrong_parameters:
        raise Exception('The following arguments in the playbook could not be changed: ' + ', '.join(wrong_parameters))


def wait_for_network_status_change(server_id, network_id, get_existing_network_method, target_status, module):
    timeout = time.time() + NETWORK_TIMEOUT_STATUS_CHANGE
    while timeout > time.time():
        network = get_existing_network_method(server_id, network_id, module)
        if network["statusDescription"].lower() == "assigned":
            return network
        time.sleep(CHECK_FOR_NETWORK_STATUS_CHANGE)
    raise Exception('waiting for status %s has expired' % target_status)
