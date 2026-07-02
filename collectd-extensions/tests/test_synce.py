#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for synce collectd plugin."""

import os
import sys
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

# Mock collectd and fm_api before importing
sys.modules['collectd'] = MagicMock()
mock_fm_constants = MagicMock()
mock_fm_constants.FM_ALARM_STATE_SET = 'set'
mock_fm_constants.FM_ALARM_SEVERITY_MAJOR = 'major'
mock_fm_constants.FM_ALARM_SEVERITY_CRITICAL = 'critical'
mock_fm_constants.FM_ENTITY_TYPE_HOST = 'host'
mock_fm_constants.FM_ALARM_TYPE_1 = 1
mock_fm_constants.ALARM_PROBABLE_CAUSE_29 = 29
sys.modules['fm_api'] = MagicMock()
sys.modules['fm_api.constants'] = mock_fm_constants
sys.modules['fm_api.fm_api'] = MagicMock()
sys.modules['plugin_common'] = MagicMock()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Mock pynetlink with real-ish enum values
mock_pynetlink = MagicMock()


class MockLockStatus:
    LOCKED = 'locked'
    LOCKED_AND_HOLDOVER = 'locked_ho'
    HOLDOVER = 'holdover'
    UNLOCKED = 'unlocked'
    UNDEFINED = 'undefined'


class MockDeviceType:
    EEC = 'eec'
    PPS = 'pps'


mock_pynetlink.LockStatus = MockLockStatus
mock_pynetlink.DeviceType = MockDeviceType
sys.modules['pynetlink'] = mock_pynetlink

import synce  # noqa: E402


class TestSynceController(unittest.TestCase):

    def setUp(self):
        self.ctrl = synce.SynceController()
        # Provide required config so read() guard passes
        self.ctrl.socket_path = '/tmp/synce4l_socket_synce1'
        self.ctrl.device = 'synce1'
        self.ctrl.interface = 'eno8303'
        synce.obj.base_eid = 'host=controller-0.synce'
        self.ctrl._alarm_eid = 'host=controller-0.synce.interface=eno8303.synce=source-loss'
        synce.fm_api.Fault.reset_mock()

    def test_status_to_ql_locked_returns_none(self):
        """Locked state = pass-through (no override)."""
        self.assertIsNone(self.ctrl._status_to_ql(MockLockStatus.LOCKED))
        self.assertIsNone(
            self.ctrl._status_to_ql(MockLockStatus.LOCKED_AND_HOLDOVER))

    def test_status_to_ql_holdover(self):
        """Holdover maps to holdover_ql."""
        self.assertEqual(self.ctrl._status_to_ql(MockLockStatus.HOLDOVER),
                         0x04)

    def test_status_to_ql_unlocked(self):
        """Unlocked/freerun maps to DNU."""
        self.assertEqual(self.ctrl._status_to_ql(MockLockStatus.UNLOCKED),
                         0x0f)
        self.assertEqual(self.ctrl._status_to_ql(MockLockStatus.UNDEFINED),
                         0x0f)

    def test_alarm_entity_id_format(self):
        """FM alarm uses correct entity instance ID format."""
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-eid'
        self.ctrl._raise_alarm(MockLockStatus.HOLDOVER)

        fault_call_kwargs = synce.fm_api.Fault.call_args[1]
        self.assertEqual(fault_call_kwargs['entity_instance_id'],
                         'host=controller-0.synce.interface=eno8303.synce=source-loss')

    def test_set_ql_builds_correct_tlv(self):
        """SET_QL sends correct TLV message."""
        with patch('socket.socket') as mock_sock_cls:
            mock_sock = mock_sock_cls.return_value.__enter__.return_value
            mock_sock.recv.return_value = b'\x08\x00\x00\x00'

            self.ctrl._set_ql(0x04)

            mock_sock.connect.assert_called_once_with(self.ctrl.socket_path)
            sent = mock_sock.sendall.call_args[0][0]
            # Verify TLV structure: DEV_NAME + SRC_NAME + SET_QL + END
            self.assertIn(b'synce1\x00', sent)
            self.assertIn(b'GNSS\x00', sent)
            self.assertIn(b'\x04', sent)

    def test_read_no_change_skips_set(self):
        """If QL hasn't changed, don't re-send."""
        self.ctrl._dpll = MagicMock()
        self.ctrl._last_ql = 0x0f
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.UNLOCKED)
        with patch.object(self.ctrl, '_set_ql') as mock_set:
            self.ctrl.read()
            mock_set.assert_not_called()

    def test_read_state_change_triggers_set(self):
        """State change triggers SET_QL."""
        self.ctrl._dpll = MagicMock()
        self.ctrl._last_ql = None  # was pass-through
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.HOLDOVER)
        with patch.object(self.ctrl, '_set_ql', return_value=True) as mock_set:
            with patch.object(self.ctrl, '_raise_alarm') as mock_raise:
                self.ctrl.read()
                mock_set.assert_called_once_with(0x04)
                mock_raise.assert_called_once_with(MockLockStatus.HOLDOVER)

    def test_alarm_raised_on_holdover(self):
        """FM alarm raised when entering holdover."""
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-123'
        self.ctrl._raise_alarm(MockLockStatus.HOLDOVER)
        self.assertTrue(self.ctrl._alarm_raised)
        self.ctrl._api.set_fault.assert_called_once()

    def test_alarm_raised_on_freerun(self):
        """FM alarm raised with critical severity on freerun."""
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-456'
        self.ctrl._raise_alarm(MockLockStatus.UNLOCKED)
        self.assertTrue(self.ctrl._alarm_raised)

    def test_alarm_cleared_on_recovery(self):
        """FM alarm cleared when DPLL locks."""
        self.ctrl._api = MagicMock()
        self.ctrl._alarm_raised = True
        self.ctrl._clear_alarm()
        self.assertFalse(self.ctrl._alarm_raised)
        self.ctrl._api.clear_fault.assert_called_once()

    def test_alarm_not_raised_twice(self):
        """Don't re-raise if already raised at same severity."""
        self.ctrl._api = MagicMock()
        self.ctrl._alarm_raised = True
        # Use the actual severity value the plugin would set
        from synce import fm_constants
        self.ctrl._alarm_severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.ctrl._raise_alarm(MockLockStatus.HOLDOVER)
        self.ctrl._api.set_fault.assert_not_called()

    def test_alarm_escalation(self):
        """Severity escalation: FM updates in-place with same EID."""
        from synce import fm_constants
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-esc'
        self.ctrl._alarm_raised = True
        self.ctrl._alarm_severity = fm_constants.FM_ALARM_SEVERITY_MAJOR
        # Escalate from holdover (major) to freerun (critical)
        self.ctrl._raise_alarm(MockLockStatus.UNLOCKED)
        # FM updates in-place when same alarm_id+EID is re-raised
        self.ctrl._api.clear_fault.assert_not_called()
        self.ctrl._api.set_fault.assert_called_once()

    def test_alarm_not_cleared_if_not_raised(self):
        """Don't clear if not raised."""
        self.ctrl._api = MagicMock()
        self.ctrl._alarm_raised = False
        self.ctrl._clear_alarm()
        self.ctrl._api.clear_fault.assert_not_called()

    def test_dpll_status_returns_first_eec(self):
        """_get_dpll_status returns the first EEC device found."""
        mock_pps = MagicMock()
        mock_pps.dev_type = MockDeviceType.PPS
        mock_pps.lock_status = MockLockStatus.UNLOCKED

        mock_eec = MagicMock()
        mock_eec.dev_type = MockDeviceType.EEC
        mock_eec.lock_status = MockLockStatus.HOLDOVER

        self.ctrl._dpll = MagicMock()
        self.ctrl._dpll.get_all_devices.return_value = [mock_pps, mock_eec]

        result = self.ctrl._get_dpll_status()
        self.assertEqual(result, MockLockStatus.HOLDOVER)

    def test_dpll_status_skips_non_eec(self):
        """_get_dpll_status returns None if no EEC device present."""
        mock_pps = MagicMock()
        mock_pps.dev_type = MockDeviceType.PPS
        mock_pps.lock_status = MockLockStatus.LOCKED

        self.ctrl._dpll = MagicMock()
        self.ctrl._dpll.get_all_devices.return_value = [mock_pps]

        result = self.ctrl._get_dpll_status()
        self.assertIsNone(result)

    def test_read_recovery_clears_ql_and_alarm(self):
        """DPLL returns to LOCKED: QL override cleared, alarm cleared."""
        self.ctrl._dpll = MagicMock()
        self.ctrl._last_ql = 0x04  # was in holdover
        self.ctrl._alarm_raised = True
        self.ctrl._alarm_severity = 'major'
        self.ctrl._api = MagicMock()
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.LOCKED)
        self.ctrl.read()
        self.assertIsNone(self.ctrl._last_ql)
        self.ctrl._api.clear_fault.assert_called_once()
        self.assertFalse(self.ctrl._alarm_raised)

    def test_set_ql_failure_still_raises_alarm(self):
        """Alarm raised even when SET_QL socket fails (retry on next read)."""
        self.ctrl._dpll = MagicMock()
        self.ctrl._last_ql = None
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-fail'
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.HOLDOVER)
        with patch.object(self.ctrl, '_set_ql', return_value=False):
            self.ctrl.read()
        # QL not updated (will retry next cycle)
        self.assertIsNone(self.ctrl._last_ql)
        # But alarm is still raised
        self.ctrl._api.set_fault.assert_called_once()
        self.assertTrue(self.ctrl._alarm_raised)

    def test_read_guard_incomplete_config(self):
        """read() returns early with one-time log when config is incomplete."""
        ctrl = synce.SynceController()
        # Leave socket_path/device/interface as None (unconfigured)
        ctrl._dpll = MagicMock()  # init ran, but no config
        ctrl._get_dpll_status = MagicMock()

        ctrl.read()
        ctrl._get_dpll_status.assert_not_called()
        self.assertTrue(ctrl._config_logged)

        # Second call: still skips, no duplicate log
        ctrl.read()
        ctrl._get_dpll_status.assert_not_called()


if __name__ == '__main__':
    unittest.main()
