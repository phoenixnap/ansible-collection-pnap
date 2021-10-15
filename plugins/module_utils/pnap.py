# -*- coding: utf-8 -*-
# (c) 2021, Pavle Jojkic <pavlej@phoenixnap.com> , Goran Jelenic <goranje@phoenixnap.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible.module_utils.six import raise_from
from base64 import standard_b64encode
HAS_REQUESTS = True
try:
    import requests
    REQUEST = requests.Session()
    REQUEST.headers.update({'Content-Type': 'application/json'})
except ImportError:
    HAS_REQUESTS = False

VALID_RESPONSE_CODES = [200, 201, 202]
AUTH_API = 'https://auth.phoenixnap.com/auth/realms/BMC/protocol/openid-connect/token'
SERVER_API = 'https://api.phoenixnap.com/bmc/v1/servers/'
SSH_API = 'https://api.phoenixnap.com/bmc/v1/ssh-keys/'


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
    REQUEST.headers.update({'X-Powered-By': 'BMC-Ansible'})


def requests_wrapper(endpoint, method='GET', data=None, module=None, reauth_attempts=3):
    try:
        response = REQUEST.request(method, endpoint, data=data)
        if response.status_code == 401:
            set_token_headers(module)
            if reauth_attempts == 0:
                raise Exception("Too many reauthentication attempts")
            return requests_wrapper(endpoint, method, data, module, reauth_attempts - 1)
        elif response.status_code not in VALID_RESPONSE_CODES:
            error_message = response.json().get('message')
            validation_errors = response.json().get('validationErrors')
            raise Exception('status code %s | %s | Validation errors: %s' % (response.status_code, error_message, validation_errors))
    except requests.exceptions.RequestException as e:
        raise_from(Exception("Communications error: %s" % str(e), e))

    return response
