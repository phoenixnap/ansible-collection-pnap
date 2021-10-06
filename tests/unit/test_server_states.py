from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from unittest import TestCase
from plugins.modules.server import state_api_remapping
from plugins.modules.server import state_final
from plugins.modules.server import ALLOWED_STATES
from plugins.modules.server import ratify_server_list_case_present
from plugins.modules.server import ratify_server_list_case_rebooted
from plugins.modules.server import wait_for_status_change_case_absent


class TestServerStates(TestCase):
    def test_total_number_of_allowed_states(self):
        self.assertEqual(len(ALLOWED_STATES), 7)

    def test_existance_of_absent_state_in_allowed_states(self):
        self.assertTrue('absent' in ALLOWED_STATES)

    def test_existance_of_powered_on_state_in_allowed_states(self):
        self.assertTrue('powered-on' in ALLOWED_STATES)

    def test_existance_of_powered_off_state_in_allowed_states(self):
        self.assertTrue('powered-off' in ALLOWED_STATES)

    def test_existance_of_present_state_in_allowed_states(self):
        self.assertTrue('present' in ALLOWED_STATES)

    def test_existance_of_rebooted_state_in_allowed_states(self):
        self.assertTrue('rebooted' in ALLOWED_STATES)

    def test_existance_of_reset_state_in_allowed_states(self):
        self.assertTrue('reset' in ALLOWED_STATES)

    def test_existance_of_shutdown_state_in_allowed_states(self):
        self.assertTrue('shutdown' in ALLOWED_STATES)

    def test_state_final_for_target_state_present(self):
        self.assertEqual(state_final('present'), 'powered-on')

    def test_state_final_for_target_state_rebooted(self):
        self.assertEqual(state_final('rebooted'), 'powered-on')

    def test_state_final_for_target_state_reset(self):
        self.assertEqual(state_final('reset'), 'powered-on')

    def test_state_final_for_target_state_shutdown(self):
        self.assertEqual(state_final('shutdown'), 'powered-off')

    def test_state_final_for_target_state_powered_on(self):
        self.assertEqual(state_final('powered-on'), 'powered-on')

    def test_state_final_for_target_state_powered_off(self):
        self.assertEqual(state_final('powered-off'), 'powered-off')

    def test_state_remapping_for_target_state_shutdown(self):
        self.assertEqual(state_api_remapping('shutdown'), 'powered-off')

    def test_state_remapping_for_target_state_reset(self):
        self.assertEqual(state_api_remapping('reset'), 'reset')

    def test_wait_for_status_change_case_absent(self):
        expected_output = [{
            'id': 'some_server_id',
            'status': 'absent'
        }]
        self.assertListEqual(wait_for_status_change_case_absent(['some_server_id']), expected_output)

    def test_ratify_server_list_case_present(self):
        expected_output = [{
            'id': 'some_server_id',
            'status': 'absent'
        }]
        self.assertListEqual(ratify_server_list_case_present(['some_server_id']), expected_output)

    def test_ratify_server_list_case_rebooted(self):
        process_servers_with_not_powered_on_state = [{
            'status': 'powered-off'
        }]
        self.assertRaises(Exception, ratify_server_list_case_rebooted, process_servers_with_not_powered_on_state)
