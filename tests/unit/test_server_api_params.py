from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
import json
from unittest import TestCase
from ansible_collections.phoenixnap.bmc.plugins.modules.server import get_api_params


class TestApiParams(TestCase):
    def test_api_params_for_state_absent(self):
        expected_output = {
            'method': 'DELETE',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id',
            'data': 'null'
        }
        self.assertDictEqual(get_api_params(None, 'some_server_id', 'absent'), expected_output)

    def test_api_params_for_state_powered_on(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id/actions/power-on',
            'data': 'null'
        }
        self.assertDictEqual(get_api_params(None, 'some_server_id', 'powered-on'), expected_output)

    def test_api_params_for_state_powered_off(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id/actions/power-off',
            'data': 'null'
        }
        self.assertDictEqual(get_api_params(None, 'some_server_id', 'powered-off'), expected_output)

    def test_api_params_for_state_shutdown(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id/actions/shutdown',
            'data': 'null'
        }
        self.assertDictEqual(get_api_params(None, 'some_server_id', 'shutdown'), expected_output)

    def test_api_params_for_state_rebooted(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id/actions/reboot',
            'data': 'null'
        }
        self.assertDictEqual(get_api_params(None, 'some_server_id', 'rebooted'), expected_output)

    def test_api_params_for_state_reset(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id/actions/reset',
            'data': json.dumps(
                {
                    'installDefaultSshKeys': True,
                    'sshKeys': ['xxx'],
                    'sshKeyIds': '123',
                    'osConfiguration': {
                        'windows': {
                            'rdpAllowedIps': '1.1.1.1'
                        },
                        'esxi': {
                            'managementAccessAllowedIps': '1.1.1.1'
                        }
                    }
                })
        }
        self.assertDictEqual(get_api_params(PseudoModule(), 'some_server_id', 'reset'), expected_output)


class PseudoModule:
    params = {
        'description': 'some description',
        'location': 'PHX',
        'hostname': 'my-server-red',
        'install_default_sshkeys': True,
        'ssh_key': 'xxx',
        'ssh_key_ids': '123',
        'network_type': 'PUBLIC_AND_PRIVATE',
        'os': 'ubuntu/bionic',
        'reservation_id': '1',
        'pricing_model': 'HOURLY',
        'type': 's1.c1.small',
        'rdp_allowed_ips': '1.1.1.1',
        'management_access_allowed_ips': '1.1.1.1'
    }
