#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for synce collectd plugin."""

import os
import sys
import subprocess
import unittest
import configparser
from unittest.mock import MagicMock
from unittest.mock import patch

# Mock collectd and fm_api before importing
sys.modules['collectd'] = MagicMock()
mock_collectd = sys.modules['collectd']
mock_fm_constants = MagicMock()
mock_fm_constants.FM_ALARM_STATE_SET = 'set'
mock_fm_constants.FM_ALARM_SEVERITY_MAJOR = 'major'
mock_fm_constants.FM_ALARM_SEVERITY_CRITICAL = 'critical'
mock_fm_constants.FM_ENTITY_TYPE_HOST = 'host'
mock_fm_constants.FM_ALARM_TYPE_1 = 1
mock_fm_constants.ALARM_PROBABLE_CAUSE_29 = 29
mock_fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN = 0
sys.modules['fm_api'] = MagicMock()
sys.modules['fm_api.constants'] = mock_fm_constants
sys.modules['fm_api.fm_api'] = MagicMock()
sys.modules['plugin_common'] = MagicMock()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Mock pynetlink with real-ish enum values
mock_pynetlink = MagicMock()


class LockStatus:
    """Mock pynetlink.LockStatus enum for testing."""
    LOCKED = 'locked'
    LOCKED_AND_HOLDOVER = 'locked_ho'
    HOLDOVER = 'holdover'
    UNLOCKED = 'unlocked'
    UNDEFINED = 'undefined'


class DeviceType:
    """Mock pynetlink.DeviceType enum for testing."""
    EEC = 'eec'
    PPS = 'pps'


mock_pynetlink.LockStatus = LockStatus
mock_pynetlink.DeviceType = DeviceType
mock_pynetlink.NetlinkDPLL = MagicMock
sys.modules['pynetlink'] = mock_pynetlink

# Imported after mocking — collectd, fm_api and pynetlink are runtime-only.
import synce  # noqa: E402


def _make_controller(instance_name='synce1', clock_id=12345678,
                     interface='eno8303', source='GNSS'):
    """Helper to create a configured SynceController for testing."""
    config = configparser.ConfigParser(delimiters=' ')
    config.read_string(
        f"[{instance_name}]\n"
        f"smc_socket_path /tmp/synce4l_socket_{instance_name}\n"
        f"interface {interface}\n"
        f"source {source}\n"
        f"holdover_ql 0x04\n"
        f"freerun_ql 0x0f\n"
    )
    # _parse_clock_id creates a new ConfigParser and calls .read(filepath).
    # We patch it to inject our fake content via read_string instead.
    fake_synce_conf = f"[<{instance_name}>]\nclock_id {clock_id}\n"

    def patched_read(cfg_self, filename):
        cfg_self.read_string(fake_synce_conf)

    with patch.object(configparser.ConfigParser, 'read', patched_read):
        ctrl = synce.SynceController(instance_name,
                                     f'/etc/linuxptp/ptpinstance/synce4l-{instance_name}.conf',
                                     config)
    ctrl._dpll = MagicMock()
    ctrl._api = MagicMock()
    synce.obj.base_eid = 'host=controller-0.synce'
    ctrl._source_loss_alarm_eid = (
        f'host=controller-0.synce.interface={interface}.synce=source-loss')
    ctrl._process_alarm_eid = (
        f'host=controller-0.synce.instance={instance_name}.synce=not-running')
    return ctrl


class TestSynceController(unittest.TestCase):

    def setUp(self):
        self.ctrl = _make_controller()
        synce.fm_api.Fault.reset_mock()

    def test_status_to_ql_locked_returns_none(self):
        """Locked state with SyncE source = pass-through (no override)."""
        self.ctrl.source = 'SYNCE'
        self.assertIsNone(self.ctrl._status_to_ql(LockStatus.LOCKED))
        self.assertIsNone(self.ctrl._status_to_ql(LockStatus.LOCKED_AND_HOLDOVER))

    def test_status_to_ql_holdover(self):
        """Holdover maps to holdover_ql."""
        self.assertEqual(self.ctrl._status_to_ql(LockStatus.HOLDOVER), 0x04)

    def test_status_to_ql_unlocked(self):
        """Unlocked/freerun maps to DNU."""
        self.assertEqual(self.ctrl._status_to_ql(LockStatus.UNLOCKED), 0x0f)
        self.assertEqual(self.ctrl._status_to_ql(LockStatus.UNDEFINED), 0x0f)

    def test_alarm_entity_id_format(self):
        """FM alarm uses correct entity instance ID format."""
        self.ctrl._api.set_fault.return_value = 'uuid-eid'
        self.ctrl._raise_source_loss_alarm(LockStatus.HOLDOVER)
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
            self.assertIn(b'synce1\x00', sent)
            self.assertIn(b'GNSS\x00', sent)
            self.assertIn(b'\x04', sent)

    def test_read_no_change_skips_set(self):
        """If QL hasn't changed, don't re-send."""
        self.ctrl._last_ql = 0x0f
        self.ctrl._get_dpll_status = MagicMock(
            return_value=LockStatus.UNLOCKED)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql') as mock_set:
                    with patch.object(self.ctrl, '_raise_source_loss_alarm'):
                        self.ctrl.read()
                        mock_set.assert_not_called()

    def test_read_state_change_triggers_set(self):
        """State change triggers SET_QL."""
        self.ctrl._last_ql = None
        self.ctrl._get_dpll_status = MagicMock(
            return_value=LockStatus.HOLDOVER)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True) as mock_set:
                    with patch.object(self.ctrl, '_raise_source_loss_alarm'):
                        self.ctrl.read()
                        mock_set.assert_called_once_with(0x04)

    def test_alarm_raised_on_holdover(self):
        """FM alarm raised when entering holdover."""
        self.ctrl._api.set_fault.return_value = 'uuid-123'
        self.ctrl._raise_source_loss_alarm(LockStatus.HOLDOVER)
        self.assertTrue(self.ctrl._source_loss_alarm_raised)
        self.ctrl._api.set_fault.assert_called_once()

    def test_alarm_raised_on_freerun(self):
        """FM alarm raised with critical severity on freerun."""
        self.ctrl._api.set_fault.return_value = 'uuid-456'
        self.ctrl._raise_source_loss_alarm(LockStatus.UNLOCKED)
        self.assertTrue(self.ctrl._source_loss_alarm_raised)

    def test_alarm_cleared_on_recovery(self):
        """FM alarm cleared when DPLL locks."""
        self.ctrl._source_loss_alarm_raised = True
        self.ctrl._clear_source_loss_alarm()
        self.assertFalse(self.ctrl._source_loss_alarm_raised)
        self.ctrl._api.clear_fault.assert_called_once()

    def test_alarm_not_raised_twice(self):
        """Don't re-raise if already raised at same severity."""
        self.ctrl._source_loss_alarm_raised = True
        self.ctrl._source_loss_alarm_severity = synce.fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.ctrl._raise_source_loss_alarm(LockStatus.HOLDOVER)
        self.ctrl._api.set_fault.assert_not_called()

    def test_alarm_escalation(self):
        """Severity escalation: FM updates in-place with same EID."""
        self.ctrl._api.set_fault.return_value = 'uuid-esc'
        self.ctrl._source_loss_alarm_raised = True
        self.ctrl._source_loss_alarm_severity = synce.fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.ctrl._raise_source_loss_alarm(LockStatus.UNLOCKED)
        self.ctrl._api.clear_fault.assert_not_called()
        self.ctrl._api.set_fault.assert_called_once()

    def test_alarm_not_cleared_if_not_raised(self):
        """Don't clear if not raised."""
        self.ctrl._source_loss_alarm_raised = False
        self.ctrl._clear_source_loss_alarm()
        self.ctrl._api.clear_fault.assert_not_called()

    def test_dpll_status_matches_by_clock_id(self):
        """_get_dpll_status finds DeviceType.EEC device matching clock_id."""
        mock_dev1 = MagicMock()
        mock_dev1.dev_type = DeviceType.EEC
        mock_dev1.dev_clock_id = 99999
        mock_dev1.lock_status = LockStatus.LOCKED

        mock_dev2 = MagicMock()
        mock_dev2.dev_type = DeviceType.EEC
        mock_dev2.dev_clock_id = 12345678
        mock_dev2.lock_status = LockStatus.HOLDOVER

        self.ctrl._dpll.get_all_devices.return_value = [mock_dev1, mock_dev2]
        result = self.ctrl._get_dpll_status()
        self.assertEqual(result, LockStatus.HOLDOVER)

    def test_dpll_status_returns_none_if_no_clock_id_match(self):
        """_get_dpll_status returns None if no DeviceType.EEC matches clock_id."""
        self.ctrl.clock_id = 99999999
        mock_dev = MagicMock()
        mock_dev.dev_type = DeviceType.EEC
        mock_dev.dev_clock_id = 12345678
        mock_dev.lock_status = LockStatus.LOCKED
        self.ctrl._dpll.get_all_devices.return_value = [mock_dev]
        result = self.ctrl._get_dpll_status()
        self.assertIsNone(result)

    def test_read_skips_when_clock_id_missing(self):
        """read() skips DPLL monitoring if clock_id is not set."""
        self.ctrl.clock_id = None
        self.ctrl._get_dpll_status = MagicMock()
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                self.ctrl.read()
                self.ctrl._get_dpll_status.assert_not_called()

    def test_read_skips_when_dpll_is_none(self):
        """read() skips DPLL monitoring if _dpll is None (no DeviceType.EEC hardware)."""
        self.ctrl._dpll = None
        self.ctrl._get_dpll_status = MagicMock()
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                self.ctrl.read()
                self.ctrl._get_dpll_status.assert_not_called()

    def test_init_disables_if_no_eec_device(self):
        """init() sets _dpll to None if no DeviceType.EEC device found."""
        mock_pps = MagicMock()
        mock_pps.dev_type = DeviceType.PPS
        mock_dpll = MagicMock()
        mock_dpll.get_all_devices.return_value = [mock_pps]
        with patch('synce.NetlinkDPLL', return_value=mock_dpll):
            with patch('synce.fm_api.FaultAPIs'):
                self.ctrl.init()
        self.assertIsNone(self.ctrl._dpll)

    def test_init_func_clears_all_stale_synce_alarms(self):
        """init_func() clears all stale synce alarms on startup."""
        stale_alarm = MagicMock()
        stale_alarm.entity_instance_id = (
            'host=controller-0.synce.instance=synce_removed.synce=not-running')
        mock_api = MagicMock()
        mock_api.get_faults_by_id.return_value = [stale_alarm]

        with patch('synce._discover_instances', return_value={'synce1': self.ctrl}):
            with patch('synce.fm_api.FaultAPIs', return_value=mock_api):
                with patch('synce.obj') as mock_obj:
                    mock_obj.config_complete.return_value = True
                    mock_obj.gethostname.return_value = 'controller-0'
                    synce.init_func()
        mock_api.clear_fault.assert_called_once_with(
            '100.119',
            'host=controller-0.synce.instance=synce_removed.synce=not-running')

    def test_init_func_skips_non_synce_alarms(self):
        """init_func() does not clear ptp alarms from FM."""
        ptp_alarm = MagicMock()
        ptp_alarm.entity_instance_id = (
            'host=controller-0.ptp.instance=ptp01.ptp=no-lock')
        mock_api = MagicMock()
        mock_api.get_faults_by_id.return_value = [ptp_alarm]

        with patch('synce._discover_instances', return_value={'synce1': self.ctrl}):
            with patch('synce.fm_api.FaultAPIs', return_value=mock_api):
                with patch('synce.obj') as mock_obj:
                    mock_obj.config_complete.return_value = True
                    mock_obj.gethostname.return_value = 'controller-0'
                    synce.init_func()
        mock_api.clear_fault.assert_not_called()

    def test_load_monitoring_config(self):
        """_load_monitoring_config sets values from config section."""
        config = configparser.ConfigParser(delimiters=' ')
        config.read_string(
            "[synce1]\n"
            "smc_socket_path /tmp/synce4l_socket_synce1\n"
            "interface eno8303\n"
            "source GNSS\n"
            "holdover_ql 0x04\n"
            "freerun_ql 0x0f\n"
        )
        ctrl = _make_controller()
        ctrl._load_monitoring_config(config)
        self.assertEqual(ctrl.device, 'synce1')
        self.assertEqual(ctrl.socket_path, '/tmp/synce4l_socket_synce1')
        self.assertEqual(ctrl.interface, 'eno8303')
        self.assertEqual(ctrl.source, 'GNSS')
        self.assertEqual(ctrl.holdover_ql, 0x04)
        self.assertEqual(ctrl.freerun_ql, 0x0f)

    def test_read_recovery_clears_ql_and_alarm(self):
        """DPLL returns to LockStatus.LOCKED: alarm cleared, SET_QL called."""
        self.ctrl._last_ql = 0x04
        self.ctrl._source_loss_alarm_raised = True
        self.ctrl._source_loss_alarm_severity = 'major'
        self.ctrl._get_dpll_status = MagicMock(
            return_value=LockStatus.LOCKED)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True) as mock_set:
                    self.ctrl.read()
                    mock_set.assert_called_once_with(0x02)
        self.ctrl._api.clear_fault.assert_called_once()
        self.assertFalse(self.ctrl._source_loss_alarm_raised)

    def test_set_ql_failure_still_raises_alarm(self):
        """Alarm raised even when SET_QL socket fails."""
        self.ctrl._last_ql = None
        self.ctrl._api.set_fault.return_value = 'uuid-fail'
        self.ctrl._get_dpll_status = MagicMock(
            return_value=LockStatus.HOLDOVER)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=False):
                    self.ctrl.read()
        self.assertIsNone(self.ctrl._last_ql)
        self.ctrl._api.set_fault.assert_called_once()
        self.assertTrue(self.ctrl._source_loss_alarm_raised)

    def test_status_to_ql_locked_gnss_returns_static_ql(self):
        """Locked with GNSS source returns static_ql."""
        self.ctrl.source = 'GNSS'
        self.assertEqual(self.ctrl._status_to_ql(LockStatus.LOCKED), 0x02)
        self.assertEqual(
            self.ctrl._status_to_ql(LockStatus.LOCKED_AND_HOLDOVER), 0x02)

    def test_status_to_ql_locked_gnss_custom_static_ql(self):
        """Locked with GNSS source returns custom static_ql."""
        self.ctrl.source = 'GNSS'
        self.ctrl.static_ql = 0x04
        self.assertEqual(self.ctrl._status_to_ql(LockStatus.LOCKED), 0x04)

    def test_read_locked_gnss_sets_static_ql_no_alarm(self):
        """LockStatus.LOCKED + GNSS sets static_ql and clears alarm."""
        self.ctrl.source = 'GNSS'
        self.ctrl._last_ql = None
        self.ctrl._get_dpll_status = MagicMock(
            return_value=LockStatus.LOCKED)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True) as mock_set:
                    with patch.object(self.ctrl, '_clear_source_loss_alarm') as mock_clear:
                        with patch.object(self.ctrl, '_raise_source_loss_alarm') as mock_raise:
                            self.ctrl.read()
                            mock_set.assert_called_once_with(0x02)
                            mock_clear.assert_called_once()
                            mock_raise.assert_not_called()

    def test_read_locked_synce_passthrough_no_alarm(self):
        """LockStatus.LOCKED + SyncE source = pass-through, no SET_QL."""
        self.ctrl.source = 'SYNCE'
        self.ctrl._last_ql = 0x04
        self.ctrl._get_dpll_status = MagicMock(
            return_value=LockStatus.LOCKED)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql') as mock_set:
                    with patch.object(self.ctrl, '_clear_source_loss_alarm') as mock_clear:
                        self.ctrl.read()
                        mock_set.assert_not_called()
                        mock_clear.assert_called_once()
                        self.assertIsNone(self.ctrl._last_ql)

    # --- Process alarm tests ---

    def test_read_service_not_running_raises_process_alarm(self):
        """Process alarm raised when service is enabled but not active."""
        self.ctrl._api.set_fault.return_value = 'uuid-proc'
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=False):
                self.ctrl.read()
        self.assertTrue(self.ctrl._process_alarm_raised)
        self.ctrl._api.set_fault.assert_called_once()

    def test_read_service_not_running_clears_source_loss_alarm(self):
        """Source-loss alarm cleared when service stops."""
        self.ctrl._api.set_fault.return_value = 'uuid-proc'
        self.ctrl._source_loss_alarm_raised = True
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=False):
                self.ctrl.read()
        self.assertFalse(self.ctrl._source_loss_alarm_raised)

    def test_read_service_disabled_clears_all_alarms(self):
        """All alarms cleared when service is intentionally disabled."""
        self.ctrl._source_loss_alarm_raised = True
        self.ctrl._process_alarm_raised = True
        with patch.object(self.ctrl, '_is_service_enabled', return_value=False):
            self.ctrl.read()
        self.assertFalse(self.ctrl._source_loss_alarm_raised)
        self.assertFalse(self.ctrl._process_alarm_raised)

    def test_read_service_resumes_clears_process_alarm(self):
        """Process alarm cleared when service starts running again."""
        self.ctrl._process_alarm_raised = True
        self.ctrl._get_dpll_status = MagicMock(
            return_value=LockStatus.LOCKED)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True):
                    self.ctrl.read()
        self.assertFalse(self.ctrl._process_alarm_raised)
        self.ctrl._api.clear_fault.assert_any_call(
            '100.119',
            'host=controller-0.synce.instance=synce1.synce=not-running')

    def test_process_alarm_not_raised_twice(self):
        """Process alarm not re-raised if already raised."""
        self.ctrl._process_alarm_raised = True
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=False):
                self.ctrl.read()
        self.ctrl._api.set_fault.assert_not_called()

    def test_is_service_enabled_returns_true(self):
        """_is_service_enabled returns True for 'enabled' output."""
        with patch('synce.subprocess.check_output', return_value=b'enabled\n'):
            self.assertTrue(
                self.ctrl._is_service_enabled('synce4l@synce1.service'))

    def test_is_service_enabled_returns_false_on_error(self):
        """_is_service_enabled returns False on CalledProcessError."""
        with patch('synce.subprocess.check_output',
                   side_effect=subprocess.CalledProcessError(1, 'cmd')):
            self.assertFalse(
                self.ctrl._is_service_enabled('synce4l@synce1.service'))

    def test_is_service_active_returns_true(self):
        """_is_service_active returns True for 'active' output."""
        with patch('synce.subprocess.check_output', return_value=b'active\n'):
            self.assertTrue(
                self.ctrl._is_service_active('synce4l@synce1.service'))

    def test_is_service_active_returns_false_for_failed(self):
        """_is_service_active returns False for 'failed' (exit code 3)."""
        with patch('synce.subprocess.check_output',
                   side_effect=subprocess.CalledProcessError(3, 'cmd')):
            self.assertFalse(
                self.ctrl._is_service_active('synce4l@synce1.service'))

    def test_read_incomplete_config_bails_early(self):
        """read() bails if required config fields missing."""
        config = configparser.ConfigParser(delimiters=' ')
        config.read_string("[empty]\ninterface eno8303\n")

        def patched_read(cfg_self, filename):
            cfg_self.read_string("[<bad>]\n")

        with patch.object(configparser.ConfigParser, 'read', patched_read):
            ctrl = synce.SynceController('bad', '/fake/path', config)
        ctrl._get_dpll_status = MagicMock()
        ctrl.read()
        ctrl._get_dpll_status.assert_not_called()

    # --- Holdover timer tests ---

    def test_holdover_timer_starts_on_holdover_entry(self):
        """Timer starts when DPLL enters LockStatus.HOLDOVER."""
        self.ctrl._last_ql = None
        self.ctrl._get_dpll_status = MagicMock(
            return_value=LockStatus.HOLDOVER)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True):
                    with patch.object(self.ctrl, '_raise_source_loss_alarm'):
                        self.ctrl.read()
        self.assertIsNotNone(self.ctrl._holdover_start)
        self.assertFalse(self.ctrl._holdover_expired)

    @patch('synce.time.monotonic')
    def test_holdover_timer_expiry_escalates_to_freerun(self, mock_time):
        """After timer expires, freerun_ql is set."""
        mock_time.return_value = 20000
        self.ctrl._last_ql = 0x04
        self.ctrl._holdover_start = 5599  # 14401s ago
        self.ctrl._holdover_expired = False
        self.ctrl._get_dpll_status = MagicMock(
            return_value=LockStatus.HOLDOVER)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True) as mock_set:
                    with patch.object(self.ctrl, '_raise_source_loss_alarm'):
                        self.ctrl.read()
                        mock_set.assert_called_once_with(0x0f)
        self.assertTrue(self.ctrl._holdover_expired)

    @patch('synce.time.monotonic')
    def test_holdover_timer_cancelled_on_recovery(self, mock_time):
        """Timer cancelled when DPLL returns to LockStatus.LOCKED."""
        mock_time.return_value = 1100
        self.ctrl._holdover_start = 1000
        self.ctrl._holdover_expired = False
        self.ctrl._last_ql = 0x04
        self.ctrl._source_loss_alarm_raised = True
        self.ctrl._source_loss_alarm_severity = 'major'
        self.ctrl._get_dpll_status = MagicMock(
            return_value=LockStatus.LOCKED)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True):
                    self.ctrl.read()
        self.assertIsNone(self.ctrl._holdover_start)
        self.assertFalse(self.ctrl._holdover_expired)

    @patch('synce.time.monotonic')
    def test_holdover_timer_custom_duration(self, mock_time):
        """Custom holdover_timer respected."""
        mock_time.return_value = 1061
        self.ctrl.holdover_timer = 60
        self.ctrl._last_ql = 0x04
        self.ctrl._holdover_start = 1000  # 61s ago
        self.ctrl._holdover_expired = False
        self.ctrl._get_dpll_status = MagicMock(
            return_value=LockStatus.HOLDOVER)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True) as mock_set:
                    with patch.object(self.ctrl, '_raise_source_loss_alarm'):
                        self.ctrl.read()
                        mock_set.assert_called_once_with(0x0f)
        self.assertTrue(self.ctrl._holdover_expired)

    def test_load_monitoring_config_reads_holdover_timer(self):
        """_load_monitoring_config parses holdover_timer."""
        config = configparser.ConfigParser(delimiters=' ')
        config.read_string(
            "[synce1]\n"
            "smc_socket_path /tmp/synce4l_socket_synce1\n"
            "interface eno8303\n"
            "holdover_timer 7200\n"
        )
        self.ctrl._load_monitoring_config(config)
        self.assertEqual(self.ctrl.holdover_timer, 7200)


class TestMultiInstance(unittest.TestCase):
    """Tests for multi-instance discovery and independent operation."""

    def test_discover_instances_finds_all_matching(self):
        """_discover_instances creates controller for each matching instance."""
        fake_synce1 = "[<synce1>]\nclock_id 111\n"
        fake_synce2 = "[<synce2>]\nclock_id 222\n"
        fake_monitoring = (
            "[synce1]\n"
            "smc_socket_path /tmp/synce4l_socket_synce1\n"
            "interface eno8303\n"
            "[synce2]\n"
            "smc_socket_path /tmp/synce4l_socket_synce2\n"
            "interface enp108s0f0\n"
        )

        def fake_glob(pattern):
            return [
                '/etc/linuxptp/ptpinstance/synce4l-synce1.conf',
                '/etc/linuxptp/ptpinstance/synce4l-synce2.conf',
            ]

        def fake_read(self_cfg, filename):
            if 'instance-monitoring' in filename:
                self_cfg.read_string(fake_monitoring)
            elif 'synce1' in filename:
                self_cfg.read_string(fake_synce1)
            elif 'synce2' in filename:
                self_cfg.read_string(fake_synce2)

        with patch('synce.glob', side_effect=fake_glob):
            with patch.object(configparser.ConfigParser, 'read', fake_read):
                controllers = synce._discover_instances()

        self.assertEqual(len(controllers), 2)
        self.assertIn('synce1', controllers)
        self.assertIn('synce2', controllers)
        self.assertEqual(controllers['synce1'].clock_id, 111)
        self.assertEqual(controllers['synce2'].clock_id, 222)
        self.assertEqual(controllers['synce1'].interface, 'eno8303')
        self.assertEqual(controllers['synce2'].interface, 'enp108s0f0')

    def test_discover_instances_skips_unmatched(self):
        """Instances without monitoring section are skipped."""
        fake_synce1 = "[<synce1>]\nclock_id 111\n"
        fake_monitoring = (
            "[synce1]\n"
            "smc_socket_path /tmp/synce4l_socket_synce1\n"
            "interface eno8303\n"
        )

        def fake_glob(pattern):
            return [
                '/etc/linuxptp/ptpinstance/synce4l-synce1.conf',
                '/etc/linuxptp/ptpinstance/synce4l-synce_no_mon.conf',
            ]

        def fake_read(self_cfg, filename):
            if 'instance-monitoring' in filename:
                self_cfg.read_string(fake_monitoring)
            else:
                self_cfg.read_string(fake_synce1)

        with patch('synce.glob', side_effect=fake_glob):
            with patch.object(configparser.ConfigParser, 'read', fake_read):
                controllers = synce._discover_instances()

        self.assertEqual(len(controllers), 1)
        self.assertIn('synce1', controllers)
        self.assertNotIn('synce_no_mon', controllers)

    def test_discover_instances_empty_when_no_files(self):
        """Returns empty dict when no synce4l conf files exist."""
        with patch('synce.glob', return_value=[]):
            controllers = synce._discover_instances()
        self.assertEqual(controllers, {})

    def test_independent_alarms_no_collision(self):
        """Two instances raise alarms with different EIDs."""
        ctrl1 = _make_controller('synce1', clock_id=111, interface='eno8303')
        ctrl2 = _make_controller('synce2', clock_id=222, interface='enp108s0f0')

        ctrl1._api.set_fault.return_value = 'uuid-1'
        ctrl2._api.set_fault.return_value = 'uuid-2'

        ctrl1._raise_source_loss_alarm(LockStatus.HOLDOVER)
        ctrl2._raise_source_loss_alarm(LockStatus.HOLDOVER)

        # Both raised independently
        self.assertTrue(ctrl1._source_loss_alarm_raised)
        self.assertTrue(ctrl2._source_loss_alarm_raised)

        # Different EIDs
        call1_kwargs = synce.fm_api.Fault.call_args_list[-2][1]
        call2_kwargs = synce.fm_api.Fault.call_args_list[-1][1]
        self.assertNotEqual(call1_kwargs['entity_instance_id'],
                            call2_kwargs['entity_instance_id'])
        self.assertIn('eno8303', call1_kwargs['entity_instance_id'])
        self.assertIn('enp108s0f0', call2_kwargs['entity_instance_id'])

    def test_independent_alarm_clear(self):
        """Clearing alarm on one instance doesn't affect the other."""
        ctrl1 = _make_controller('synce1', clock_id=111, interface='eno8303')
        ctrl2 = _make_controller('synce2', clock_id=222, interface='enp108s0f0')

        # Both alarm raised
        ctrl1._source_loss_alarm_raised = True
        ctrl2._source_loss_alarm_raised = True

        # Only ctrl1 recovers
        ctrl1._clear_source_loss_alarm()

        self.assertFalse(ctrl1._source_loss_alarm_raised)
        self.assertTrue(ctrl2._source_loss_alarm_raised)

    def test_independent_dpll_status(self):
        """Each controller reads its own clock_id from DPLL."""
        ctrl1 = _make_controller('synce1', clock_id=111)
        ctrl2 = _make_controller('synce2', clock_id=222)

        mock_eec1 = MagicMock()
        mock_eec1.dev_type = DeviceType.EEC
        mock_eec1.dev_clock_id = 111
        mock_eec1.lock_status = LockStatus.LOCKED

        mock_eec2 = MagicMock()
        mock_eec2.dev_type = DeviceType.EEC
        mock_eec2.dev_clock_id = 222
        mock_eec2.lock_status = LockStatus.HOLDOVER

        all_devices = [mock_eec1, mock_eec2]
        ctrl1._dpll.get_all_devices.return_value = all_devices
        ctrl2._dpll.get_all_devices.return_value = all_devices

        self.assertEqual(ctrl1._get_dpll_status(), LockStatus.LOCKED)
        self.assertEqual(ctrl2._get_dpll_status(), LockStatus.HOLDOVER)

    def test_read_func_iterates_all_controllers(self):
        """read_func() calls read() on every controller."""
        ctrl1 = MagicMock()
        ctrl2 = MagicMock()
        synce._controllers = {'synce1': ctrl1, 'synce2': ctrl2}

        synce.read_func()

        ctrl1.read.assert_called_once()
        ctrl2.read.assert_called_once()

        # Cleanup
        synce._controllers = {}

    def test_single_instance_backward_compatible(self):
        """Single instance works identically to before."""
        fake_synce1 = "[<synce1>]\nclock_id 12345\n"
        fake_monitoring = (
            "[synce1]\n"
            "smc_socket_path /tmp/synce4l_socket_synce1\n"
            "interface eno8303\n"
            "source GNSS\n"
        )

        def fake_glob(pattern):
            return ['/etc/linuxptp/ptpinstance/synce4l-synce1.conf']

        def fake_read(self_cfg, filename):
            if 'instance-monitoring' in filename:
                self_cfg.read_string(fake_monitoring)
            else:
                self_cfg.read_string(fake_synce1)

        with patch('synce.glob', side_effect=fake_glob):
            with patch.object(configparser.ConfigParser, 'read', fake_read):
                controllers = synce._discover_instances()

        self.assertEqual(len(controllers), 1)
        ctrl = controllers['synce1']
        self.assertEqual(ctrl.instance_name, 'synce1')
        self.assertEqual(ctrl.clock_id, 12345)
        self.assertEqual(ctrl.socket_path, '/tmp/synce4l_socket_synce1')
        self.assertEqual(ctrl.interface, 'eno8303')
        self.assertEqual(ctrl.source, 'GNSS')


if __name__ == '__main__':
    unittest.main()
