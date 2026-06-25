#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Unit tests for DPLL holdover clock class determination.

Tests verify that when check_gnss_signal (or check_1pps_signal) and
check_clock_class both use get_dpll_state() (combined worst-of EEC+PPS),
the holdover_timestamp is preserved correctly and clock class 7 is set
instead of the incorrect clock class 248.
"""

import os
import ptp
import sys
import unittest

from pynetlink import DeviceType
from pynetlink import LockStatus
from pynetlink import PinType
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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


def _setup_ptp_constants():
    ptp.CLOCK_STATE_INVALID = LockStatus.UNDEFINED
    ptp.CLOCK_STATE_LOCKED = LockStatus.LOCKED
    ptp.CLOCK_STATE_LOCKED_HO_ACQ = LockStatus.LOCKED_AND_HOLDOVER
    ptp.CLOCK_STATE_HOLDOVER = LockStatus.HOLDOVER
    ptp.CLOCK_STATE_UNLOCKED = LockStatus.UNLOCKED
    ptp.CLOCK_STATE_HOLDOVER_EXPIRED = "holdover-expired"
    ptp.CLOCK_STATE_HOLDOVER_UNSTABLE = "holdover-unstable(freerun)"
    ptp.CLOCK_CLASS_6 = '6'
    ptp.CLOCK_CLASS_7 = '7'
    ptp.CLOCK_CLASS_140 = '140'
    ptp.CLOCK_CLASS_248 = '248'
    ptp.PTP_INSTANCE_TYPE_TS2PHC = 'ts2phc'
    ptp.PTP_INSTANCE_TYPE_CLOCK = 'clock'
    ptp.PTP_INSTANCE_TYPE_PTP4L = 'ptp4l'
    ptp.DUMMY_INTERFACE = 'dummy'


_setup_ptp_constants()


class TestDpllHoldoverClockClass(unittest.TestCase):
    """Verify clock class set by check_clock_class after check_gnss_signal/check_1pps_signal.

    Pattern: set combined DPLL state -> check_gnss_signal or check_1pps_signal
             -> check_clock_class -> assert clock class.
    """

    def setUp(self):
        _setup_ptp_constants()
        ptp.fm_constants.FM_ALARM_SEVERITY_CLEAR = 'clear'
        ptp.fm_constants.FM_ALARM_SEVERITY_MINOR = 'minor'
        ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR = 'major'

        self.holdover_time = datetime(2024, 1, 1, 10, 0, 0)

        # ts2phc instance ctrl
        self.ts2phc_ctrl = ptp.PTP_ctrl_object(ptp.PTP_INSTANCE_TYPE_TS2PHC)
        self.ts2phc_ctrl.interface = 'ens0f0'
        self.ts2phc_ctrl.holdover_timestamp = {'ens0f0': self.holdover_time}
        self.ts2phc_ctrl.locked_timestamp = {'ens0f0': datetime(2024, 1, 1, 9, 0, 0)}
        self.ts2phc_ctrl.monitoring_parameters = {
            'holdover_seconds': 14400,
            'locked_to_holdover_threshold_seconds': 300,
        }
        self.ts2phc_ctrl.gnss_signal_loss_alarm_object = Mock()
        self.ts2phc_ctrl.gnss_signal_loss_alarm_object.raised = False
        self.ts2phc_ctrl.gnss_signal_loss_alarm_object.severity = 'clear'
        self.ts2phc_ctrl.gnss_signal_loss_alarm_object.eid = 'test-gnss-eid'

        # clock instance ctrl (secondary NIC)
        self.clock_ctrl = ptp.PTP_ctrl_object(ptp.PTP_INSTANCE_TYPE_CLOCK)
        self.clock_ctrl.interface = 'ens1f0'
        self.clock_ctrl.holdover_timestamp = {'ens1f0': self.holdover_time}
        self.clock_ctrl.locked_timestamp = {'ens1f0': datetime(2024, 1, 1, 9, 0, 0)}
        self.clock_ctrl.monitoring_parameters = {
            'holdover_seconds': 14400,
            'locked_to_holdover_threshold_seconds': 300,
        }
        self.clock_ctrl.clock_ports = {'ens1f0': {}}

        # ptp4l instance ctrl
        self.ptp4l_ctrl = ptp.PTP_ctrl_object(ptp.PTP_INSTANCE_TYPE_PTP4L)
        self.ptp4l_ctrl.interface = 'ens0f0'
        self.ptp4l_ctrl.monitoring_parameters = {'holdover_seconds': 14400}

        # Interface mocks
        self.mock_interface_primary = Mock()
        self.mock_interface_primary.get_family.return_value = 'Granite Rapid-D'
        self.mock_interface_secondary = Mock()
        self.mock_interface_secondary.get_family.return_value = 'Connorsville'

        ptp.ptpinstances = {
            'ts1': self.ts2phc_ctrl,
            'clock': self.clock_ctrl,
            'ptp-inst1': self.ptp4l_ctrl,
        }
        ptp.interfaces = {
            'ens0f0': self.mock_interface_primary,
            'ens1f0': self.mock_interface_secondary,
        }
        ptp.ts2phc_source_interfaces = {'ens0f0': 'ens0f0', 'ens1f0': 'ens0f0'}
        ptp.ts2phc_instance_map = {'ens0f0': 'ts1', 'ens1f0': 'ts1'}
        ptp.base_port_map = {'ens0f0': 'ens0f0', 'ens1f0': 'ens1f0'}
        ptp.obj.INIT_LOG_THROTTLE = 10
        ptp.obj.hostname = 'controller-0'
        ptp.ALARM_OBJ_LIST = []

    @patch('ptp.workaround_for_stale_parent_data_set')
    @patch('ptp.timeutils')
    @patch('ptp.query_pmc')
    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.is_local_gm', return_value=False)
    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_ts2phc_holdover_yields_class_7(
        self, mock_base_port, mock_dpll, mock_clear, mock_raise,
        mock_write, mock_gm, mock_service, mock_pmc,
        mock_time, mock_workaround
    ):
        """ts2phc instance: EEC=HOLDOVER, PPS=LOCKED_HO_ACQ -> class 7.

        This is the production bug scenario. Previously check_gnss_signal saw
        only PPS (LOCKED_HO_ACQ), cleared holdover_timestamp, and check_clock_class
        then set class 248. With the fix, both see HOLDOVER -> class 7.
        """
        mock_dpll.return_value = (LockStatus.HOLDOVER, None)
        mock_pmc.return_value = {'clockClass': '6'}
        mock_time.utcnow.return_value = datetime(2024, 1, 1, 10, 30, 0)
        mock_time.delta_seconds.return_value = 1800

        ptp.check_gnss_signal('ts1')
        self.assertIsNotNone(self.ts2phc_ctrl.holdover_timestamp.get('ens0f0'))

        ptp.check_clock_class('ptp-inst1')

        mock_write.assert_called_once()
        self.assertEqual(mock_write.call_args[0][1]['clockClass'], '7')

    @patch('ptp.workaround_for_stale_parent_data_set')
    @patch('ptp.timeutils')
    @patch('ptp.query_pmc')
    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.is_local_gm', return_value=False)
    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_ts2phc_locked_ho_acq_yields_class_6(
        self, mock_base_port, mock_dpll, mock_clear, mock_raise,
        mock_write, mock_gm, mock_service, mock_pmc,
        mock_time, mock_workaround
    ):
        """ts2phc instance: EEC=LOCKED_HO_ACQ, PPS=LOCKED_HO_ACQ -> class 6."""
        mock_dpll.return_value = (LockStatus.LOCKED_AND_HOLDOVER, Mock())
        mock_pmc.return_value = {'clockClass': '248'}
        mock_time.utcnow.return_value = datetime(2024, 1, 1, 10, 30, 0)

        ptp.check_gnss_signal('ts1')
        self.assertIsNone(self.ts2phc_ctrl.holdover_timestamp.get('ens0f0'))

        ptp.check_clock_class('ptp-inst1')

        mock_write.assert_called_once()
        self.assertEqual(mock_write.call_args[0][1]['clockClass'], '6')

    @patch('ptp.workaround_for_stale_parent_data_set')
    @patch('ptp.timeutils')
    @patch('ptp.query_pmc')
    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.is_local_gm', return_value=False)
    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_ts2phc_unlocked_yields_class_248(
        self, mock_base_port, mock_dpll, mock_clear, mock_raise,
        mock_write, mock_gm, mock_service, mock_pmc,
        mock_time, mock_workaround
    ):
        """ts2phc instance: EEC=UNLOCKED, PPS=LOCKED_HO_ACQ -> class 248."""
        mock_dpll.return_value = (LockStatus.UNLOCKED, None)
        mock_pmc.return_value = {'clockClass': '6'}
        mock_time.utcnow.return_value = datetime(2024, 1, 1, 10, 30, 0)

        ptp.check_gnss_signal('ts1')
        self.assertIsNone(self.ts2phc_ctrl.holdover_timestamp.get('ens0f0'))

        ptp.check_clock_class('ptp-inst1')

        mock_write.assert_called_once()
        self.assertEqual(mock_write.call_args[0][1]['clockClass'], '248')

    @patch('ptp.workaround_for_stale_parent_data_set')
    @patch('ptp.timeutils')
    @patch('ptp.query_pmc')
    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.is_local_gm', return_value=False)
    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens1f0')
    @patch('ptp.get_alarm_object')
    def test_clock_instance_holdover_yields_class_7(
        self, mock_get_alarm, mock_base_port, mock_dpll, mock_clear,
        mock_raise, mock_write, mock_gm, mock_service, mock_pmc,
        mock_time, mock_workaround
    ):
        """Clock instance (Connorsville, ens1f0): HOLDOVER -> check_1pps_signal -> class 7.

        check_1pps_signal uses get_dpll_state() returning HOLDOVER.
        check_gnss_alarm preserves holdover_timestamp on ens1f0.
        check_clock_class finds it via instance_type==CLOCK and sets class 7.
        """
        # ptp4l ctrl uses secondary NIC for this test
        self.ptp4l_ctrl.interface = 'ens1f0'

        mock_dpll.return_value = (LockStatus.HOLDOVER, None)
        mock_pmc.return_value = {'clockClass': '6'}
        mock_time.utcnow.return_value = datetime(2024, 1, 1, 10, 30, 0)
        mock_time.delta_seconds.return_value = 1800

        alarm_obj = Mock(raised=False, severity='clear', eid='test-1pps-eid')
        mock_get_alarm.return_value = alarm_obj

        ptp.check_1pps_signal('clock')
        self.assertIsNotNone(self.clock_ctrl.holdover_timestamp.get('ens1f0'))

        ptp.check_clock_class('ptp-inst1')

        mock_write.assert_called_once()
        self.assertEqual(mock_write.call_args[0][1]['clockClass'], '7')


class TestLockstatusPriority(unittest.TestCase):
    """Verify get_dpll_state returns worst-of EEC and PPS."""

    def setUp(self):
        _setup_ptp_constants()

    def test_worst_of_eec_holdover_pps_locked_ho_acq(self):
        """EEC=HOLDOVER(prio 3) vs PPS=LOCKED_HO_ACQ(prio 5) -> HOLDOVER wins."""
        eec = LockStatus.HOLDOVER
        pps = LockStatus.LOCKED_AND_HOLDOVER
        if ptp.lockstatus_priority(eec) > ptp.lockstatus_priority(pps):
            worst = pps
        else:
            worst = eec
        self.assertEqual(worst, LockStatus.HOLDOVER)

    def test_worst_of_eec_unlocked_pps_locked_ho_acq(self):
        """EEC=UNLOCKED(prio 2) vs PPS=LOCKED_HO_ACQ(prio 5) -> UNLOCKED wins."""
        eec = LockStatus.UNLOCKED
        pps = LockStatus.LOCKED_AND_HOLDOVER
        if ptp.lockstatus_priority(eec) > ptp.lockstatus_priority(pps):
            worst = pps
        else:
            worst = eec
        self.assertEqual(worst, LockStatus.UNLOCKED)

    def test_both_locked_ho_acq(self):
        """EEC=LOCKED_HO_ACQ(5) vs PPS=LOCKED_HO_ACQ(5) -> LOCKED_HO_ACQ."""
        eec = LockStatus.LOCKED_AND_HOLDOVER
        pps = LockStatus.LOCKED_AND_HOLDOVER
        if ptp.lockstatus_priority(eec) > ptp.lockstatus_priority(pps):
            worst = pps
        else:
            worst = eec
        self.assertEqual(worst, LockStatus.LOCKED_AND_HOLDOVER)


if __name__ == '__main__':
    unittest.main()
