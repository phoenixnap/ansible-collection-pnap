from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from unittest import TestCase
from plugins.modules.ssh_key import ALLOWED_STATES


class TestSshKeyStates(TestCase):
    def test_total_number_of_allowed_states(self):
        self.assertEqual(len(ALLOWED_STATES), 2)

    def test_existance_of_absent_state_in_allowed_states(self):
        self.assertTrue('absent' in ALLOWED_STATES)

    def test_existance_of_present_state_in_allowed_states(self):
        self.assertTrue('present' in ALLOWED_STATES)
