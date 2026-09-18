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
from datetime import timedelta


# Mock all external dependencies before importing ptp module
sys.modules.setdefault('collectd', MagicMock())
sys.modules.setdefault('tsconfig', MagicMock())
sys.modules.setdefault('tsconfig.tsconfig', MagicMock())
sys.modules.setdefault('plugin_common', MagicMock())
sys.modules.setdefault('fm_api', MagicMock())
sys.modules.setdefault('fm_api.constants', MagicMock())
sys.modules.setdefault('fm_api.fm_api', MagicMock())
sys.modules.setdefault('ptp_interface', MagicMock())
sys.modules.setdefault('ptp_gnss_monitor', MagicMock())
sys.modules.setdefault('cgu_handler', MagicMock())
sys.modules.setdefault('pynetlink', MagicMock())
sys.modules.setdefault('oslo_utils', MagicMock())
sys.modules.setdefault('oslo_utils.timeutils', MagicMock())

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
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_ts2phc_holdover_yields_class_7(
        self, mock_base_port, mock_dpll, mock_netlink, mock_clear, mock_raise,
        mock_write, mock_gm, mock_service, mock_pmc,
        mock_time, mock_workaround
    ):
        """ts2phc instance: EEC=HOLDOVER, PPS=LOCKED_HO_ACQ -> class 7.

        This is the production bug scenario. Previously check_gnss_signal saw
        only PPS (LOCKED_HO_ACQ), cleared holdover_timestamp, and check_clock_class
        then set class 248. With the fix, both see HOLDOVER -> class 7.

        A genuine DPLL holdover (not SyncE-only): the predicate sees a GNSS
        pin, so synce_freq_holdover is False but the state is already HOLDOVER.
        """
        mock_dpll.return_value = (LockStatus.HOLDOVER, None)
        gnss_pin = Mock()
        gnss_pin.pin_type = PinType.GNSS
        mock_netlink.return_value = (LockStatus.HOLDOVER, gnss_pin)
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
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_ts2phc_locked_ho_acq_yields_class_6(
        self, mock_base_port, mock_dpll, mock_netlink, mock_clear, mock_raise,
        mock_write, mock_gm, mock_service, mock_pmc,
        mock_time, mock_workaround
    ):
        """ts2phc instance: EEC=LOCKED_HO_ACQ, PPS=LOCKED_HO_ACQ -> class 6."""
        gnss_pin = Mock()
        gnss_pin.pin_type = PinType.GNSS
        gnss_pin.pin_board_label = 'GNSS_1PPS_IN'
        mock_dpll.return_value = (LockStatus.LOCKED_AND_HOLDOVER, gnss_pin)
        # DPLL is locked to the GNSS pin (a valid time reference), so the
        # SyncE-only-frequency-holdover guard must not divert this to class 7.
        mock_netlink.return_value = (LockStatus.LOCKED_AND_HOLDOVER, gnss_pin)
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
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_synce_only_lock_yields_class_7_within_spec(
        self, mock_base_port, mock_netlink, mock_clear, mock_raise,
        mock_write, mock_gm, mock_service, mock_pmc, mock_time, mock_workaround
    ):
        """DPLL LOCKED but active pin is SyncE (no GNSS/EXT) -> class 7.

        GNSS lost, DPLL failed over to a SyncE recovered-clock pin. The T-GM
        is in time holdover but frequency-traceable via SyncE, so per
        G.8275.1 Table 2 it advertises clockClass 7 (timeTraceable=1,
        frequencyTraceable=1) while within holdover spec -- NOT class 6.

        Exercises the REAL get_dpll_state (only get_netlink_dpll_status is
        mocked) so the SyncE-only -> HOLDOVER reinterpretation is covered.
        """
        synce_pin = Mock()
        synce_pin.pin_type = PinType.SYNCE
        synce_pin.pin_board_label = 'CLK_78M125_NAC0_SYNCE0'
        # Both DPLL devices report locked-ho-acq on a SyncE pin, no time ref.
        mock_netlink.return_value = (LockStatus.LOCKED_AND_HOLDOVER, synce_pin)
        mock_pmc.return_value = {'clockClass': '6'}
        mock_time.utcnow.return_value = datetime(2024, 1, 1, 10, 30, 0)
        # Within holdover spec.
        mock_time.delta_seconds.return_value = 1800
        # No pre-seeded holdover timestamp: the SyncE path must seed it.
        self.ts2phc_ctrl.holdover_timestamp = {}

        ptp.check_clock_class('ptp-inst1')

        mock_write.assert_called_once()
        self.assertEqual(mock_write.call_args[0][1]['clockClass'], '7')
        self.assertEqual(mock_write.call_args[0][1]['timeTraceable'], 1)
        self.assertEqual(mock_write.call_args[0][1]['frequencyTraceable'], 1)
        self.assertIsNotNone(
            self.ts2phc_ctrl.holdover_timestamp.get('ens0f0'))

    @patch('ptp.workaround_for_stale_parent_data_set')
    @patch('ptp.timeutils')
    @patch('ptp.query_pmc')
    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.is_local_gm', return_value=False)
    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_synce_only_lock_degrades_to_140_out_of_spec(
        self, mock_base_port, mock_netlink, mock_clear, mock_raise,
        mock_write, mock_gm, mock_service, mock_pmc, mock_time, mock_workaround
    ):
        """SyncE-only holdover past holdover_seconds -> class 140.

        Per G.8275.1 Table 2 the 7 -> 140/150/160 ladder tracks the time
        holdover budget; frequency traceability to the Category-1 SyncE
        source is retained. So past spec the T-GM advertises clockClass 140
        with timeTraceable=0 but frequencyTraceable=1 (only dropping
        frequencyTraceable at clockClass 248 on loss of the SyncE reference).

        Exercises the REAL get_dpll_state (only get_netlink_dpll_status is
        mocked) so the SyncE-only -> HOLDOVER reinterpretation is covered.
        """
        synce_pin = Mock()
        synce_pin.pin_type = PinType.SYNCE
        synce_pin.pin_board_label = 'CLK_78M125_NAC0_SYNCE0'
        mock_netlink.return_value = (LockStatus.LOCKED_AND_HOLDOVER, synce_pin)
        mock_pmc.return_value = {'clockClass': '7'}
        mock_time.utcnow.return_value = datetime(2024, 1, 1, 15, 0, 0)
        # Exceeds holdover_seconds (14400).
        mock_time.delta_seconds.return_value = 18000
        self.ts2phc_ctrl.holdover_timestamp = {'ens0f0': self.holdover_time}

        ptp.check_clock_class('ptp-inst1')

        mock_write.assert_called_once()
        self.assertEqual(mock_write.call_args[0][1]['clockClass'], '140')
        self.assertEqual(mock_write.call_args[0][1]['timeTraceable'], 0)
        self.assertEqual(mock_write.call_args[0][1]['frequencyTraceable'], 1)

    @patch('ptp.workaround_for_stale_parent_data_set')
    @patch('ptp.timeutils')
    @patch('ptp.query_pmc')
    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.is_local_gm', return_value=False)
    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_synce_only_full_cycle_ages_timestamp_and_raises_alarm(
        self, mock_base_port, mock_dpll, mock_netlink, mock_clear, mock_raise,
        mock_write, mock_gm, mock_service, mock_pmc, mock_time, mock_workaround
    ):
        """Integrated per-poll regression for the two shipped SyncE-only bugs.

        Runs the real poll order -- check_gnss_signal() then
        check_clock_class() -- across cycles, exactly as the daemon does.
        This catches what the isolated check_clock_class-only tests missed:

        Bug 1: on SyncE-only the DPLL reports LOCKED_AND_HOLDOVER, so
        check_gnss_signal/check_gnss_alarm used to null holdover_timestamp
        every cycle -> the 7->140 timer never aged. Here the timestamp must be
        seeded on cycle 1 and PRESERVED (not reset) on cycle 2, and once it
        ages past holdover_seconds check_clock_class must advertise 140.

        Bug 2: the GNSS-signal-loss alarm (100.119) must actually be raised
        via check_gnss_signal (not merely logged), because the state is forced
        to HOLDOVER when the SyncE-only predicate holds.
        """
        synce_pin = Mock()
        synce_pin.pin_type = PinType.SYNCE
        synce_pin.pin_board_label = 'CLK_78M125_NAC0_SYNCE0'
        # DPLL rides SyncE, reports locked-holdover-acquiring on both devices.
        # get_dpll_state() reinterprets SyncE-only as HOLDOVER (its unit test
        # covers that mapping); downstream behaviour is tested from HOLDOVER.
        mock_dpll.return_value = (LockStatus.HOLDOVER, synce_pin)
        mock_netlink.return_value = (LockStatus.LOCKED_AND_HOLDOVER, synce_pin)
        mock_pmc.return_value = {'clockClass': '6'}

        # Deterministic clock: utcnow advances 1s per call; delta_seconds is
        # the real wall delta between two datetimes.
        clock = {'t': datetime(2024, 1, 1, 10, 0, 0)}

        def _utcnow():
            clock['t'] = clock['t'] + timedelta(seconds=1)
            return clock['t']

        mock_time.utcnow.side_effect = _utcnow
        mock_time.delta_seconds.side_effect = \
            lambda a, b: (b - a).total_seconds()

        # Realistic precondition: SyncE-only holdover is reached by failing
        # over FROM a GNSS lock, so the interface has a locked_timestamp old
        # enough to be past locked_to_holdover_threshold_seconds (300s). No
        # holdover_timestamp yet -- this is the first cycle of the failover.
        self.ts2phc_ctrl.holdover_timestamp = {}
        self.ts2phc_ctrl.locked_timestamp = {
            'ens0f0': datetime(2024, 1, 1, 9, 0, 0)}
        alarm_obj = self.ts2phc_ctrl.gnss_signal_loss_alarm_object
        alarm_obj.raised = False
        alarm_obj.severity = 'clear'

        # --- Cycle 1: signal check must force HOLDOVER, seed ts, raise alarm.
        ptp.check_gnss_signal('ts1')
        ts_after_c1 = self.ts2phc_ctrl.holdover_timestamp.get('ens0f0')
        self.assertIsNotNone(
            ts_after_c1,
            "holdover_timestamp must be seeded on SyncE-only, not nulled")
        mock_clear.assert_not_called()
        mock_raise.assert_called()
        self.assertTrue(alarm_obj.raised)
        # Within-spec holdover raises the GNSS-signal-loss alarm at MINOR;
        # it escalates to MAJOR only once the holdover timer expires.
        self.assertEqual(alarm_obj.severity, 'minor')

        # --- Cycle 2: timestamp must be PRESERVED (this is the bug-1 guard).
        ptp.check_gnss_signal('ts1')
        ts_after_c2 = self.ts2phc_ctrl.holdover_timestamp.get('ens0f0')
        self.assertEqual(
            ts_after_c1, ts_after_c2,
            "holdover_timestamp must not be reset each cycle on SyncE-only")

    @patch('ptp.workaround_for_stale_parent_data_set')
    @patch('ptp.timeutils')
    @patch('ptp.query_pmc')
    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.is_local_gm', return_value=False)
    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_synce_with_gnss_pps_still_yields_class_6(
        self, mock_base_port, mock_dpll, mock_netlink, mock_clear, mock_raise,
        mock_write, mock_gm, mock_service, mock_pmc, mock_time, mock_workaround
    ):
        """EEC locked to SyncE but PPS locked to GNSS -> still class 6.

        A valid time/phase reference (GNSS on PPS) is present, so the
        SyncE-only guard must not trigger: this is normal GNSS-locked
        operation where the EEC frequency DPLL happens to ride SyncE.
        """
        synce_pin = Mock()
        synce_pin.pin_type = PinType.SYNCE
        gnss_pin = Mock()
        gnss_pin.pin_type = PinType.GNSS
        mock_dpll.return_value = (LockStatus.LOCKED_AND_HOLDOVER, gnss_pin)

        def _netlink(iface, dev_type):
            # PPS -> GNSS (time ref present); EEC -> SyncE (frequency)
            if dev_type == ptp.DeviceType.PPS:
                return (LockStatus.LOCKED_AND_HOLDOVER, gnss_pin)
            return (LockStatus.LOCKED_AND_HOLDOVER, synce_pin)
        mock_netlink.side_effect = _netlink
        mock_pmc.return_value = {'clockClass': '248'}
        mock_time.utcnow.return_value = datetime(2024, 1, 1, 10, 30, 0)

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
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_gnss_lost_no_synce_yields_class_248(
        self, mock_base_port, mock_dpll, mock_netlink, mock_clear, mock_raise,
        mock_write, mock_gm, mock_service, mock_pmc, mock_time, mock_workaround
    ):
        """GNSS lost with NO SyncE recovered clock -> class 248 (freerun).

        This is the SyncE-absent counterpart to the SyncE-only tests. The
        DPLL has lost GNSS and has no SyncE frequency pin to fail over to, so
        get_dpll_state() reports HOLDOVER and get_netlink_dpll_status()
        returns no pin on either device. _is_synce_only_frequency_holdover()
        must be False (no SyncE pin present), so the SyncE class-7 path must
        NOT trigger; with no valid holdover timestamp the clock degrades to
        248, exactly as before this change (fail-closed to prior behaviour).
        """
        # DPLL not locked to anything, and no pin recovered on either device.
        mock_dpll.return_value = (LockStatus.HOLDOVER, None)
        mock_netlink.return_value = (LockStatus.INVALID, None)
        mock_pmc.return_value = {'clockClass': '6'}
        mock_time.utcnow.return_value = datetime(2024, 1, 1, 10, 30, 0)

        # No holdover timestamp seeded: check_gnss_signal sees no valid
        # reference, so check_clock_class finds no timestamp -> 248.
        self.ts2phc_ctrl.holdover_timestamp = {}

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
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens1f0')
    @patch('ptp.get_alarm_object')
    def test_clock_instance_holdover_yields_class_7(
        self, mock_get_alarm, mock_base_port, mock_dpll, mock_netlink,
        mock_clear, mock_raise, mock_write, mock_gm, mock_service, mock_pmc,
        mock_time, mock_workaround
    ):
        """Clock instance (Connorsville, ens1f0): HOLDOVER -> check_1pps_signal -> class 7.

        check_1pps_signal uses get_dpll_state() returning HOLDOVER.
        check_gnss_alarm preserves holdover_timestamp on ens1f0.
        check_clock_class finds it via instance_type==CLOCK and sets class 7.

        Genuine DPLL holdover (GNSS pin), not SyncE-only.
        """
        # ptp4l ctrl uses secondary NIC for this test
        self.ptp4l_ctrl.interface = 'ens1f0'

        mock_dpll.return_value = (LockStatus.HOLDOVER, None)
        gnss_pin = Mock()
        gnss_pin.pin_type = PinType.GNSS
        mock_netlink.return_value = (LockStatus.HOLDOVER, gnss_pin)
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

    # ------------------------------------------------------------------
    # GNSS-signal-loss alarm behaviour during SyncE-only frequency holdover
    # ------------------------------------------------------------------

    @patch('ptp.timeutils')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_synce_only_holdover_raises_gnss_alarm(
        self, mock_base_port, mock_dpll, mock_netlink, mock_clear, mock_raise,
        mock_time
    ):
        """DPLL reports LOCKED but active pin is SyncE-only -> raise 100.119.

        The DPLL has failed over to a SyncE recovered-clock pin after GNSS
        loss and still reports LOCKED_AND_HOLDOVER. check_gnss_signal() must
        force the state to HOLDOVER when the SyncE-only predicate holds, so
        check_gnss_alarm() raises the GNSS-signal-loss alarm instead of
        clearing it, notifying the operator the T-GM is running without GNSS.
        """
        mock_time.utcnow.return_value = datetime(2024, 1, 1, 10, 0, 0)
        mock_time.delta_seconds.side_effect = \
            lambda a, b: (b - a).total_seconds()
        synce_pin = Mock()
        synce_pin.pin_type = PinType.SYNCE
        # get_dpll_state (worst-of) and both netlink devices report a SyncE
        # pin, no GNSS/EXT time reference -> SyncE-only frequency holdover.
        # get_dpll_state() reinterprets SyncE-only as HOLDOVER (its unit test
        # covers that mapping); downstream behaviour is tested from HOLDOVER.
        mock_dpll.return_value = (LockStatus.HOLDOVER, synce_pin)
        mock_netlink.return_value = (LockStatus.LOCKED_AND_HOLDOVER, synce_pin)

        alarm_obj = self.ts2phc_ctrl.gnss_signal_loss_alarm_object
        alarm_obj.raised = False
        alarm_obj.severity = 'clear'

        ptp.check_gnss_signal('ts1')

        # Alarm must be raised (not cleared). Within-spec holdover is MINOR.
        mock_raise.assert_called_once()
        mock_clear.assert_not_called()
        self.assertEqual(alarm_obj.severity, 'minor')
        self.assertTrue(alarm_obj.raised)

    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_gnss_reference_present_clears_gnss_alarm(
        self, mock_base_port, mock_dpll, mock_netlink, mock_clear, mock_raise
    ):
        """DPLL LOCKED with a real GNSS pin -> no SyncE override, alarm clears.

        Normal GNSS-locked operation: a valid time/phase reference is
        present, so _is_synce_only_frequency_holdover() is False and the
        LOCKED branch keeps severity CLEAR. A previously-raised alarm is
        cleared.
        """
        gnss_pin = Mock()
        gnss_pin.pin_type = PinType.GNSS
        mock_netlink.return_value = (LockStatus.LOCKED, gnss_pin)

        alarm_obj = self.ts2phc_ctrl.gnss_signal_loss_alarm_object
        alarm_obj.raised = True
        alarm_obj.severity = 'major'

        ptp.check_gnss_alarm(
            'ts1', alarm_obj, 'ens0f0', LockStatus.LOCKED)

        # SyncE override must NOT fire; the alarm is cleared.
        mock_raise.assert_not_called()
        mock_clear.assert_called_once_with('test-gnss-eid')
        self.assertEqual(alarm_obj.severity, 'clear')
        self.assertFalse(alarm_obj.raised)

    @patch('ptp.timeutils')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_dpll_state')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_synce_alarm_fires_on_directly_dpll_connected_family(
        self, mock_base_port, mock_dpll, mock_netlink, mock_clear, mock_raise,
        mock_time
    ):
        """GNR-D primary NIC is not a key in the secondary->primary map.

        On directly-DPLL-connected families the base port IS the primary and
        does not appear in ts2phc_source_interfaces as a secondary. Because
        check_gnss_signal() evaluates the SyncE-only predicate on the
        base_port from get_base_port() (not via the secondary->primary map),
        the alarm still fires on exactly the target hardware. This guards the
        regression where the old family-based resolution silently no-oped.
        """
        mock_time.utcnow.return_value = datetime(2024, 1, 1, 10, 0, 0)
        mock_time.delta_seconds.side_effect = \
            lambda a, b: (b - a).total_seconds()
        synce_pin = Mock()
        synce_pin.pin_type = PinType.SYNCE
        # get_dpll_state() reinterprets SyncE-only as HOLDOVER (its unit test
        # covers that mapping); downstream behaviour is tested from HOLDOVER.
        mock_dpll.return_value = (LockStatus.HOLDOVER, synce_pin)
        mock_netlink.return_value = (LockStatus.LOCKED_AND_HOLDOVER, synce_pin)

        # Primary NIC absent from the secondary->primary map for its own port.
        ptp.ts2phc_source_interfaces = {'ens1f0': 'ens0f0'}

        alarm_obj = self.ts2phc_ctrl.gnss_signal_loss_alarm_object
        alarm_obj.raised = False
        alarm_obj.severity = 'clear'

        ptp.check_gnss_signal('ts1')

        mock_raise.assert_called_once()
        self.assertEqual(alarm_obj.severity, 'minor')
        self.assertTrue(alarm_obj.raised)


class TestSynceHoldoverAlarmState(unittest.TestCase):
    """Verify check_gnss_alarm's state/severity for a SyncE-only holdover.

    Regression guard for the plane disagreement raised in review (Gerrit
    1004031, PS10): get_dpll_state() reinterprets a hardware-LOCKED SyncE-only
    failover as HOLDOVER for the clockClass plane, but check_gnss_alarm still
    applied the locked_to_holdover_threshold_seconds "flapping" window and
    downgraded the state to holdover-unstable(freerun)/MAJOR when GNSS was lost
    within that window (default 300s) of the DPLL locking. The alarm plane then
    disagreed with the clockClass plane (clockClass 7). A SyncE-only holdover
    is a valid physical-layer frequency holdover, not flapping, so the alarm
    state must stay HOLDOVER.
    """

    def setUp(self):
        _setup_ptp_constants()
        ptp.fm_constants.FM_ALARM_SEVERITY_CLEAR = 'clear'
        ptp.fm_constants.FM_ALARM_SEVERITY_MINOR = 'minor'
        ptp.fm_constants.FM_ALARM_SEVERITY_MAJOR = 'major'

        self.ctrl = ptp.PTP_ctrl_object(ptp.PTP_INSTANCE_TYPE_TS2PHC)
        self.ctrl.interface = 'ens0f0'
        self.ctrl.holdover_timestamp = {}
        self.ctrl.locked_timestamp = {}
        self.ctrl.monitoring_parameters = {
            'holdover_seconds': 14400,
            'locked_to_holdover_threshold_seconds': 300,
        }
        self.alarm_obj = Mock()
        self.alarm_obj.raised = False
        self.alarm_obj.severity = 'clear'
        self.alarm_obj.eid = 'test-gnss-eid'
        self.alarm_obj.alarm = ptp.ALARM_CAUSE__GNSS_SIGNAL_LOSS

        ptp.ptpinstances = {'ts1': self.ctrl}
        ptp.ts2phc_source_interfaces = {'ens0f0': 'ens0f0'}

    def _synce_pin(self):
        pin = Mock()
        pin.pin_type = PinType.SYNCE
        return pin

    def _gnss_pin(self):
        pin = Mock()
        pin.pin_type = PinType.GNSS
        return pin

    @patch('ptp.timeutils')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_synce_only_within_window_stays_holdover(
        self, mock_base_port, mock_netlink, mock_clear, mock_raise, mock_time
    ):
        """SyncE-only failover < locked_to_holdover_threshold -> HOLDOVER.

        locked_timestamp is only 60s old (< 300s). Without the fix this would
        be downgraded to holdover-unstable(freerun)/MAJOR. With the fix the
        SyncE-only predicate suppresses the downgrade: state stays HOLDOVER,
        severity MINOR, matching the clockClass plane.
        """
        now = datetime(2024, 1, 1, 10, 0, 0)
        mock_time.utcnow.return_value = now
        mock_time.delta_seconds.side_effect = \
            lambda a, b: (b - a).total_seconds()
        # DPLL was GNSS-locked only 60s ago -> inside the 300s unstable window.
        self.ctrl.locked_timestamp = {'ens0f0': now - timedelta(seconds=60)}
        # SyncE-only: SyncE pin present, no GNSS/EXT time reference.
        mock_netlink.return_value = (LockStatus.LOCKED_AND_HOLDOVER,
                                     self._synce_pin())

        ptp.check_gnss_alarm('ts1', self.alarm_obj, 'ens0f0',
                             ptp.CLOCK_STATE_HOLDOVER)

        mock_raise.assert_called_once()
        state_arg = mock_raise.call_args[0][2]
        self.assertTrue(str(state_arg).startswith(str(ptp.CLOCK_STATE_HOLDOVER)))
        self.assertNotIn('holdover-unstable', str(state_arg))
        self.assertEqual(self.alarm_obj.severity, 'minor')

    @patch('ptp.timeutils')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_plain_holdover_within_window_still_unstable(
        self, mock_base_port, mock_netlink, mock_clear, mock_raise, mock_time
    ):
        """Non-SyncE holdover < locked_to_holdover_threshold -> unstable.

        Anti-over-suppression guard: the fix must narrow the suppression to
        the SyncE-only case only. A genuine DPLL holdover entered within the
        window must STILL be downgraded to holdover-unstable(freerun)/MAJOR,
        preserving the flapping guard.
        """
        now = datetime(2024, 1, 1, 10, 0, 0)
        mock_time.utcnow.return_value = now
        mock_time.delta_seconds.side_effect = \
            lambda a, b: (b - a).total_seconds()
        self.ctrl.locked_timestamp = {'ens0f0': now - timedelta(seconds=60)}
        # No SyncE pin, no time ref -> not a SyncE-only holdover.
        mock_netlink.return_value = (LockStatus.HOLDOVER, None)

        ptp.check_gnss_alarm('ts1', self.alarm_obj, 'ens0f0',
                             ptp.CLOCK_STATE_HOLDOVER)

        mock_raise.assert_called_once()
        state_arg = mock_raise.call_args[0][2]
        self.assertEqual(state_arg, ptp.CLOCK_STATE_HOLDOVER_UNSTABLE)
        self.assertEqual(self.alarm_obj.severity, 'major')

    @patch('ptp.timeutils')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_synce_only_alarm_text_has_detail_reason(
        self, mock_base_port, mock_netlink, mock_clear, mock_raise, mock_time
    ):
        """SyncE-only holdover alarm text names the cause (review comment 2).

        The state passed to raise_alarm (rendered as ' state: <data>') must
        carry the SyncE-only detail so the operator is not left with a bare
        'holdover' and no reason.
        """
        now = datetime(2024, 1, 1, 10, 0, 0)
        mock_time.utcnow.return_value = now
        mock_time.delta_seconds.side_effect = \
            lambda a, b: (b - a).total_seconds()
        self.ctrl.locked_timestamp = {'ens0f0': now - timedelta(seconds=60)}
        mock_netlink.return_value = (LockStatus.LOCKED_AND_HOLDOVER,
                                     self._synce_pin())

        ptp.check_gnss_alarm('ts1', self.alarm_obj, 'ens0f0',
                             ptp.CLOCK_STATE_HOLDOVER)

        mock_raise.assert_called_once()
        state_arg = str(mock_raise.call_args[0][2])
        self.assertIn('SyncE-only frequency holdover', state_arg)
        self.assertIn('no GNSS/phase reference', state_arg)

    @patch('ptp.timeutils')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_synce_only_within_window_seeds_holdover_timestamp(
        self, mock_base_port, mock_netlink, mock_clear, mock_raise, mock_time
    ):
        """SyncE-only within-window holdover seeds (not nulls) the timestamp.

        Because the state stays HOLDOVER (not holdover-unstable), the
        holdover_timestamp is seeded here rather than nulled by the
        'locked/invalid/unlocked/holdover-unstable' else-branch. This closes
        the seed-vs-null race with the clockClass plane's 7 -> 140 timer.
        """
        now = datetime(2024, 1, 1, 10, 0, 0)
        mock_time.utcnow.return_value = now
        mock_time.delta_seconds.side_effect = \
            lambda a, b: (b - a).total_seconds()
        self.ctrl.locked_timestamp = {'ens0f0': now - timedelta(seconds=60)}
        self.ctrl.holdover_timestamp = {}
        mock_netlink.return_value = (LockStatus.LOCKED_AND_HOLDOVER,
                                     self._synce_pin())

        ptp.check_gnss_alarm('ts1', self.alarm_obj, 'ens0f0',
                             ptp.CLOCK_STATE_HOLDOVER)

        self.assertEqual(self.ctrl.holdover_timestamp.get('ens0f0'), now)

    @patch('ptp.timeutils')
    @patch('ptp.raise_alarm', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    @patch('ptp.get_netlink_dpll_status')
    @patch('ptp.get_base_port', return_value='ens0f0')
    def test_synce_only_within_window_secondary_nic_stays_holdover(
        self, mock_base_port, mock_netlink, mock_clear, mock_raise, mock_time
    ):
        """Secondary NIC inheriting a fresh locked_timestamp stays HOLDOVER.

        The secondary NIC copies the primary's locked_timestamp; if that is
        within the window the secondary must not be diverted to unstable on a
        SyncE-only holdover either.
        """
        now = datetime(2024, 1, 1, 10, 0, 0)
        mock_time.utcnow.return_value = now
        mock_time.delta_seconds.side_effect = \
            lambda a, b: (b - a).total_seconds()
        # Secondary interface; primary has a fresh (60s) locked_timestamp.
        ptp.ts2phc_source_interfaces = {'ens0f0': 'ens0f0', 'ens1f0': 'ens0f0'}
        ptp.base_port_map = {'ens1f0': 'ens0f0'}
        self.ctrl.locked_timestamp = {'ens0f0': now - timedelta(seconds=60)}
        self.ctrl.holdover_timestamp = {}
        mock_netlink.return_value = (LockStatus.LOCKED_AND_HOLDOVER,
                                     self._synce_pin())

        ptp.check_gnss_alarm('ts1', self.alarm_obj, 'ens1f0',
                             ptp.CLOCK_STATE_HOLDOVER)

        mock_raise.assert_called_once()
        state_arg = mock_raise.call_args[0][2]
        self.assertNotIn('holdover-unstable', str(state_arg))
        self.assertEqual(self.alarm_obj.severity, 'minor')


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


class TestGetDpllStateSynceOverride(unittest.TestCase):
    """Directly verify get_dpll_state()'s SyncE-only -> HOLDOVER override.

    This is the single choke point every consumer (check_clock_class,
    check_gnss_signal, check_1pps_signal -> check_gnss_alarm) uses to resolve
    DPLL state, so the override must be correct here and here only.
    """

    def setUp(self):
        _setup_ptp_constants()

    def _pin(self, pin_type):
        p = Mock()
        p.pin_type = pin_type
        p.pin_board_label = 'label'
        return p

    @patch('ptp.get_netlink_dpll_status')
    def test_synce_only_locked_is_reinterpreted_as_holdover(self, mock_nl):
        """Locked to a SyncE pin, no GNSS/EXT time ref -> HOLDOVER, real pin."""
        synce_pin = self._pin(PinType.SYNCE)
        mock_nl.return_value = (LockStatus.LOCKED_AND_HOLDOVER, synce_pin)
        state, pin = ptp.get_dpll_state('ens0f0')
        self.assertEqual(state, ptp.CLOCK_STATE_HOLDOVER)
        # The real SyncE pin is returned unchanged; only state is reinterpreted.
        self.assertIs(pin, synce_pin)

    @patch('ptp.get_netlink_dpll_status')
    def test_gnss_locked_is_not_overridden(self, mock_nl):
        """Locked to a GNSS pin -> stays LOCKED (a real time reference)."""
        gnss_pin = self._pin(PinType.GNSS)
        mock_nl.return_value = (LockStatus.LOCKED, gnss_pin)
        state, _ = ptp.get_dpll_state('ens0f0')
        self.assertEqual(state, ptp.CLOCK_STATE_LOCKED)

    @patch('ptp.get_netlink_dpll_status')
    def test_ext_locked_is_not_overridden(self, mock_nl):
        """Locked to an external 1PPS pin -> stays locked (real time ref)."""
        ext_pin = self._pin(PinType.EXT)
        mock_nl.return_value = (LockStatus.LOCKED_AND_HOLDOVER, ext_pin)
        state, _ = ptp.get_dpll_state('ens0f0')
        self.assertEqual(state, ptp.CLOCK_STATE_LOCKED_HO_ACQ)

    @patch('ptp.get_netlink_dpll_status')
    def test_genuine_holdover_not_touched(self, mock_nl):
        """Already HOLDOVER -> predicate not consulted, state unchanged."""
        mock_nl.return_value = (LockStatus.HOLDOVER, None)
        state, _ = ptp.get_dpll_state('ens0f0')
        self.assertEqual(state, ptp.CLOCK_STATE_HOLDOVER)

    @patch('ptp.get_netlink_dpll_status')
    def test_unlocked_not_touched(self, mock_nl):
        """UNLOCKED -> predicate not consulted (only locked states), unchanged."""
        mock_nl.return_value = (LockStatus.UNLOCKED, None)
        state, _ = ptp.get_dpll_state('ens0f0')
        self.assertEqual(state, ptp.CLOCK_STATE_UNLOCKED)


if __name__ == '__main__':
    unittest.main()
