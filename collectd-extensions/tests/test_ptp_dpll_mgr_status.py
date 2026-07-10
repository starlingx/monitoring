#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Unit tests for dpll-mgr status.json reader and alarm logic.
Tests AptsMgrStatus class and _check_dpll_mgr_state() function.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

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

import ptp
from ptp import AptsMgrStatus
from ptp import DPLL_MGR_FORMAT_VERSION
from ptp import ALARM_CAUSE__DPLL_MGR_HOLDOVER
from ptp import ALARM_CAUSE__NO_LOCK
from ptp import PTP_INSTANCE_TYPE_DPLL_MGR
from ptp import PTP_ctrl_object


def _make_status(lock_status='locked', current_master='GNSS_REF4P',
                 in_holdover=False, holdover_level=-1,
                 ever_locked=True, **kwargs):
    """Helper to create a valid status.json dict."""
    data = {
        'format_version': DPLL_MGR_FORMAT_VERSION,
        'timestamp': '2026-07-08T12:00:00.000Z',
        'operation_mode': 'SW_BASED',
        'dpll_lock_status': lock_status,
        'current_master': current_master,
        'previous_master': kwargs.get('previous_master', current_master),
        'in_holdover': in_holdover,
        'holdover_duration_s': kwargs.get('holdover_duration_s', 0),
        'holdover_level': holdover_level,
        'gearshift': kwargs.get('gearshift', {'ptp_bh': 'NEUTRAL',
                                              'ts2_0': 'DRIVE'}),
        'phase_offset_ns': kwargs.get('phase_offset_ns', 0),
        'drift_rate_ns_per_s': kwargs.get('drift_rate_ns_per_s', 0.0),
        'ptp_port_state': kwargs.get('ptp_port_state', 'MASTER'),
        'connected_pin': kwargs.get('connected_pin', current_master),
        'ever_locked': ever_locked,
    }
    return data


class TestAptsMgrStatusRead(unittest.TestCase):
    """Test AptsMgrStatus.read() — JSON parsing and caching."""

    def setUp(self):
        self.reader = AptsMgrStatus()
        self.tmpdir = tempfile.mkdtemp()
        self.status_file = os.path.join(self.tmpdir, 'status.json')

    def tearDown(self):
        if os.path.exists(self.status_file):
            os.unlink(self.status_file)
        os.rmdir(self.tmpdir)

    def _write_status(self, data):
        with open(self.status_file, 'w') as f:
            json.dump(data, f)

    @patch('ptp.DPLL_MGR_STATUS_FILE', '/nonexistent/path/status.json')
    def test_returns_none_when_file_missing(self):
        """Test #1: returns None when file does not exist."""
        result = self.reader.read()
        self.assertIsNone(result)

    def test_returns_valid_dict_for_well_formed_json(self):
        """Test #2: returns valid dict for well-formed JSON."""
        data = _make_status()
        self._write_status(data)
        with patch('ptp.DPLL_MGR_STATUS_FILE', self.status_file):
            result = self.reader.read()
        self.assertIsNotNone(result)
        self.assertEqual(result['format_version'], DPLL_MGR_FORMAT_VERSION)
        self.assertEqual(result['dpll_lock_status'], 'locked')

    def test_returns_none_for_invalid_json(self):
        """Test #3: returns None for invalid JSON."""
        with open(self.status_file, 'w') as f:
            f.write('not valid json {{{')
        with patch('ptp.DPLL_MGR_STATUS_FILE', self.status_file):
            result = self.reader.read()
        self.assertIsNone(result)

    def test_returns_none_for_wrong_format_version(self):
        """Test #4: returns None for wrong format_version."""
        data = _make_status()
        data['format_version'] = 99
        self._write_status(data)
        with patch('ptp.DPLL_MGR_STATUS_FILE', self.status_file):
            result = self.reader.read()
        self.assertIsNone(result)

    def test_uses_mtime_cache(self):
        """Test #5: uses mtime cache (no re-read on unchanged file)."""
        data = _make_status()
        self._write_status(data)
        with patch('ptp.DPLL_MGR_STATUS_FILE', self.status_file):
            result1 = self.reader.read()
            # Patch open to verify it's not called again
            with patch('builtins.open', side_effect=AssertionError(
                    "Should not re-read")):
                result2 = self.reader.read()
        self.assertEqual(result1, result2)

    def test_rereads_when_mtime_changes(self):
        """Test #6: re-reads when mtime changes."""
        data1 = _make_status(lock_status='locked')
        self._write_status(data1)
        with patch('ptp.DPLL_MGR_STATUS_FILE', self.status_file):
            result1 = self.reader.read()
            self.assertEqual(result1['dpll_lock_status'], 'locked')

            # Update file with new content (mtime changes)
            import time
            time.sleep(0.05)  # ensure mtime differs
            data2 = _make_status(lock_status='holdover',
                                 in_holdover=True, holdover_level=0,
                                 current_master='HOLDOVER_0')
            self._write_status(data2)

            result2 = self.reader.read()
            self.assertEqual(result2['dpll_lock_status'], 'holdover')


class TestCheckDpllMgrState(unittest.TestCase):
    """Test _check_dpll_mgr_state() alarm raise/clear logic."""

    def setUp(self):
        # Setup dpll-mgr instance in ptpinstances
        self.instance_name = 'dpll-mgr1'
        self.ctrl = PTP_ctrl_object(PTP_INSTANCE_TYPE_DPLL_MGR)

        # Create mock alarm objects
        self.ctrl.process_alarm_object = MagicMock()
        self.ctrl.process_alarm_object.raised = False
        self.ctrl.process_alarm_object.eid = (
            'host=controller-1.instance=dpll-mgr1.ptp=process')

        self.ctrl.nolock_alarm_object = MagicMock()
        self.ctrl.nolock_alarm_object.raised = False
        self.ctrl.nolock_alarm_object.eid = (
            'host=controller-1.instance=dpll-mgr1.ptp=no-lock')

        self.ctrl.holdover_alarm_object = MagicMock()
        self.ctrl.holdover_alarm_object.raised = False
        self.ctrl.holdover_alarm_object.eid = (
            'host=controller-1.instance=dpll-mgr1.ptp=holdover')

        ptp.ptpinstances[self.instance_name] = self.ctrl
        ptp._dpll_mgr_instance_name = self.instance_name

    def tearDown(self):
        ptp.ptpinstances.pop(self.instance_name, None)
        ptp._dpll_mgr_instance_name = None

    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.raise_alarm', return_value=True)
    def test_raises_holdover_alarm(self, mock_raise, mock_running):
        """Test #7: raises holdover alarm when lock_status == holdover."""
        status = _make_status(lock_status='holdover', in_holdover=True,
                              holdover_level=0, current_master='HOLDOVER_0',
                              connected_pin='none')
        ptp._dpll_mgr_status._cache = status
        ptp._dpll_mgr_status._mtime = 1

        with patch('ptp.DPLL_MGR_STATUS_FILE', '/tmp/fake'), \
             patch('os.path.getmtime', return_value=1):
            ptp._check_dpll_mgr_state()

        mock_raise.assert_called_with(
            ALARM_CAUSE__DPLL_MGR_HOLDOVER, self.instance_name)

    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.raise_alarm', return_value=True)
    def test_raises_nolock_alarm_when_unlocked_and_ever_locked(
            self, mock_raise, mock_running):
        """Test #8: raises no-lock alarm when unlocked and ever_locked=True."""
        status = _make_status(lock_status='unlocked', ever_locked=True,
                              current_master='UNKNOWN', connected_pin='none')
        ptp._dpll_mgr_status._cache = status
        ptp._dpll_mgr_status._mtime = 1

        with patch('ptp.DPLL_MGR_STATUS_FILE', '/tmp/fake'), \
             patch('os.path.getmtime', return_value=1):
            ptp._check_dpll_mgr_state()

        mock_raise.assert_called_with(
            ALARM_CAUSE__NO_LOCK, self.instance_name)

    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    def test_clears_alarms_when_locked(self, mock_clear, mock_running):
        """Test #9: clears alarms when lock_status == locked."""
        self.ctrl.holdover_alarm_object.raised = True
        self.ctrl.nolock_alarm_object.raised = True

        status = _make_status(lock_status='locked')
        ptp._dpll_mgr_status._cache = status
        ptp._dpll_mgr_status._mtime = 1

        with patch('ptp.DPLL_MGR_STATUS_FILE', '/tmp/fake'), \
             patch('os.path.getmtime', return_value=1):
            ptp._check_dpll_mgr_state()

        # Both alarms should be cleared
        self.assertFalse(self.ctrl.holdover_alarm_object.raised)
        self.assertFalse(self.ctrl.nolock_alarm_object.raised)

    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.clear_alarm', return_value=True)
    def test_clears_alarms_when_locked_ho_acq(self, mock_clear, mock_running):
        """Test #10: clears alarms when lock_status == locked_ho_acq."""
        self.ctrl.holdover_alarm_object.raised = True

        status = _make_status(lock_status='locked_ho_acq')
        ptp._dpll_mgr_status._cache = status
        ptp._dpll_mgr_status._mtime = 1

        with patch('ptp.DPLL_MGR_STATUS_FILE', '/tmp/fake'), \
             patch('os.path.getmtime', return_value=1):
            ptp._check_dpll_mgr_state()

        self.assertFalse(self.ctrl.holdover_alarm_object.raised)

    @patch('ptp.raise_alarm')
    def test_does_nothing_when_no_dpll_mgr(self, mock_raise):
        """Test #11: does nothing when no dpll-mgr on this host."""
        ptp._dpll_mgr_instance_name = None

        ptp._check_dpll_mgr_state()

        mock_raise.assert_not_called()

    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.raise_alarm')
    def test_skips_status_check_when_process_alarm_raised(
            self, mock_raise, mock_running):
        """Test #12: skips status check when process alarm is raised."""
        self.ctrl.process_alarm_object.raised = True

        # Even with holdover status, should not raise alarm
        status = _make_status(lock_status='holdover', in_holdover=True,
                              holdover_level=0)
        ptp._dpll_mgr_status._cache = status
        ptp._dpll_mgr_status._mtime = 1

        with patch('ptp.DPLL_MGR_STATUS_FILE', '/tmp/fake'), \
             patch('os.path.getmtime', return_value=1):
            ptp._check_dpll_mgr_state()

        mock_raise.assert_not_called()

    @patch('ptp.is_service_running', return_value=True)
    @patch('ptp.raise_alarm')
    def test_no_alarm_when_unlocked_and_not_ever_locked(
            self, mock_raise, mock_running):
        """Boot grace: no alarm when unlocked but ever_locked=False."""
        status = _make_status(lock_status='unlocked', ever_locked=False,
                              current_master='UNKNOWN', connected_pin='none')
        ptp._dpll_mgr_status._cache = status
        ptp._dpll_mgr_status._mtime = 1

        with patch('ptp.DPLL_MGR_STATUS_FILE', '/tmp/fake'), \
             patch('os.path.getmtime', return_value=1):
            ptp._check_dpll_mgr_state()

        mock_raise.assert_not_called()


if __name__ == '__main__':
    unittest.main()
