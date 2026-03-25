#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Unit tests for check_clock_class function - secondary NIC locked, primary NIC holdover scenario
"""

import unittest
import sys
import os
from unittest.mock import MagicMock
from unittest.mock import patch
from unittest.mock import Mock
from datetime import datetime

# Mock all external dependencies before importing ptp module
sys.modules['collectd'] = MagicMock()
sys.modules['tsconfig'] = MagicMock()
sys.modules['tsconfig.tsconfig'] = MagicMock()
sys.modules['plugin_common'] = MagicMock()
sys.modules['fm_api'] = MagicMock()
sys.modules['fm_api.constants'] = MagicMock()
sys.modules['fm_api.fm_api'] = MagicMock()
sys.modules['ptp_interface'] = MagicMock()
sys.modules['ptp_gnss_monitor'] = MagicMock()
sys.modules['cgu_handler'] = MagicMock()
sys.modules['pynetlink'] = MagicMock()
sys.modules['oslo_utils'] = MagicMock()
sys.modules['oslo_utils.timeutils'] = MagicMock()

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import after mocking
import ptp
from pynetlink import DeviceType
from pynetlink import PinType
from pynetlink import LockStatus


class TestCheckClockClassSecondaryNIC(unittest.TestCase):
    """Test check_clock_class with secondary NIC locked and primary NIC in holdover"""

    def setUp(self):
        """Set up test fixtures"""
        # Mock constants
        ptp.CLOCK_STATE_LOCKED = LockStatus.LOCKED
        ptp.CLOCK_STATE_HOLDOVER = LockStatus.HOLDOVER
        ptp.CLOCK_STATE_INVALID = LockStatus.UNDEFINED
        ptp.CLOCK_STATE_UNLOCKED = LockStatus.UNLOCKED
        ptp.CLOCK_CLASS_7 = '7'
        ptp.CLOCK_CLASS_140 = '140'
        ptp.CLOCK_CLASS_248 = '248'
        ptp.PTP_INSTANCE_TYPE_TS2PHC = 'ts2phc'

        # Create mock interface
        self.mock_interface = Mock()
        self.mock_interface.get_family.return_value = 'Intel E810'  # Not Granite Rapid-D or Connorsville

        # Create mock pin with external type
        self.mock_pin = Mock()
        self.mock_pin.pin_type = PinType.EXT

        # Create mock GNSS pin
        self.mock_gnss_pin = Mock()
        self.mock_gnss_pin.pin_type = PinType.GNSS

        # Create mock control object
        self.mock_ctrl = Mock()
        self.mock_ctrl.interface = 'ens0f1'
        self.mock_ctrl.monitoring_parameters = {
            'holdover_seconds': 14400
        }
        self.mock_ctrl.holdover_timestamp = {}

        # Create mock ts2phc control object
        self.mock_ts2phc_ctrl = Mock()
        self.mock_ts2phc_ctrl.instance_type = ptp.PTP_INSTANCE_TYPE_TS2PHC
        self.mock_ts2phc_ctrl.monitoring_parameters = {
            'holdover_seconds': 14400
        }
        self.mock_ts2phc_ctrl.holdover_timestamp = {
            'ens0f0': datetime(2024, 1, 1, 12, 0, 0)  # Holdover timestamp
        }

        # Setup global state
        ptp.ptpinstances = {
            'ptp4l-0': self.mock_ctrl,
            'ts2phc-0': self.mock_ts2phc_ctrl
        }
        ptp.interfaces = {
            'ens0f1': self.mock_interface
        }
        ptp.ts2phc_source_interfaces = {
            'ens0f1': 'ens0f0'  # Secondary NIC maps to primary NIC
        }
        ptp.ts2phc_instance_map = {
            'ens0f1': 'ts2phc-0'
        }

    def _setup_common_mocks(
        self, mock_query_pmc, mock_get_base_port, mock_is_service_running, mock_is_local_gm
    ):
        """Setup common mock configurations"""
        mock_get_base_port.return_value = 'ens0f1'
        mock_is_service_running.return_value = True
        mock_is_local_gm.return_value = False

    def _verify_clock_class(
        self, mock_write_ptp4l_gm_fields, expected_class, expected_traceable
    ):
        """Verify the clock class and traceability settings"""
        mock_write_ptp4l_gm_fields.assert_called_once()
        call_args = mock_write_ptp4l_gm_fields.call_args[0]
        self.assertEqual(call_args[0], 'ptp4l-0')
        self.assertEqual(call_args[1]['clockClass'], expected_class)
        self.assertEqual(call_args[1]['timeTraceable'], expected_traceable)
        self.assertEqual(call_args[1]['frequencyTraceable'], expected_traceable)

    def _run_holdover_test(
        self, pin_mock, initial_clock_class, holdover_seconds,
        expected_class, expected_traceable, has_timestamp=True
    ):
        """Run a holdover test with specified parameters"""
        with patch('ptp.write_ptp4l_gm_fields') as mock_write, \
             patch('ptp.is_service_running') as mock_service, \
             patch('ptp.is_local_gm') as mock_gm, \
             patch('ptp.get_dpll_state') as mock_dpll, \
             patch('ptp.get_base_port') as mock_port, \
             patch('ptp.query_pmc') as mock_pmc, \
             patch('ptp.workaround_for_stale_parent_data_set') as mock_workaround, \
             patch('ptp.timeutils') as mock_time:

            self._setup_common_mocks(mock_pmc, mock_port, mock_service, mock_gm)
            mock_pmc.return_value = {'clockClass': initial_clock_class}
            mock_dpll.side_effect = [(LockStatus.LOCKED, pin_mock), (LockStatus.HOLDOVER, None)]

            if has_timestamp:
                mock_time.utcnow.return_value = datetime(2024, 1, 1, 13, 0, 0)
                mock_time.delta_seconds.return_value = holdover_seconds
            else:
                self.mock_ts2phc_ctrl.holdover_timestamp = {}

            ptp.check_clock_class('ptp4l-0')
            self._verify_clock_class(mock_write, expected_class, expected_traceable)

    def test_secondary_nic_locked_primary_nic_holdover_within_threshold(self):
        """Test secondary NIC locked, primary NIC holdover within threshold -> Clock Class 7"""
        self._run_holdover_test(self.mock_pin, '248', 3600, '7', 1)

    def test_secondary_nic_locked_primary_nic_holdover_exceeds_threshold(self):
        """Test secondary NIC locked, primary NIC holdover exceeds threshold -> Clock Class 140"""
        self._run_holdover_test(self.mock_pin, '248', 18000, '140', 0)

    def test_secondary_nic_locked_primary_nic_holdover_no_timestamp(self):
        """Test secondary NIC locked, primary NIC holdover with no timestamp -> Clock Class 248"""
        self._run_holdover_test(self.mock_pin, '7', 0, '248', 0, has_timestamp=False)

    def test_secondary_nic_locked_with_gnss_primary_nic_holdover_within_threshold(self):
        """Test secondary NIC locked with GNSS pin, primary NIC holdover within threshold -> Clock Class 6"""
        self._run_holdover_test(self.mock_gnss_pin, '248', 3600, '6', 1)

    def test_secondary_nic_locked_with_gnss_primary_nic_holdover_exceeds_threshold(self):
        # Test secondary NIC locked with GNSS pin, primary NIC holdover
        #  exceeds threshold -> Clock Class 6
        self._run_holdover_test(self.mock_gnss_pin, '248', 18000, '6', 1)

    def test_secondary_nic_locked_with_gnss_primary_nic_holdover_no_timestamp(self):
        # Test secondary NIC locked with GNSS pin, primary NIC holdover
        #   with no timestamp -> Clock Class 6

        self._run_holdover_test(self.mock_gnss_pin, '7', 0, '6', 1, has_timestamp=False)


if __name__ == '__main__':
    unittest.main()
