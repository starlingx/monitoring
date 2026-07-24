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

# Imported here because collectd, fm_api and pynetlink don't exist as installable
# packages — they're provided by the collectd runtime. We mock them above first.
import synce  # noqa: E402


class TestSynceController(unittest.TestCase):

    def setUp(self):
        self.ctrl = synce.SynceController()
        # Set required config values for tests
        self.ctrl.socket_path = '/tmp/synce4l_socket_synce1'
        self.ctrl.device = 'synce1'
        self.ctrl.interface = 'eno8303'
        self.ctrl.clock_id = 12345678
        self.ctrl.instance_name = 'synce1'
        self.ctrl._dpll = MagicMock()
        synce.obj.base_eid = 'host=controller-0.synce'
        self.ctrl._source_loss_alarm_eid = 'host=controller-0.synce.interface=eno8303.synce=source-loss'
        self.ctrl._process_alarm_eid = 'host=controller-0.synce.instance=synce1.synce=not-running'
        synce.fm_api.Fault.reset_mock()

    def test_status_to_ql_locked_returns_none(self):
        """Locked state with SyncE source = pass-through (no override)."""
        self.ctrl.source = 'SYNCE'
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
        self.ctrl._raise_source_loss_alarm(MockLockStatus.HOLDOVER)

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
        self.ctrl._last_ql = 0x0f
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.UNLOCKED)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql') as mock_set:
                    with patch.object(self.ctrl, '_raise_source_loss_alarm'):
                        self.ctrl.read()
                        mock_set.assert_not_called()

    def test_read_state_change_triggers_set(self):
        """State change triggers SET_QL."""
        self.ctrl._last_ql = None  # was pass-through
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.HOLDOVER)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True) as mock_set:
                    with patch.object(self.ctrl, '_raise_source_loss_alarm') as mock_raise:
                        self.ctrl.read()
                        mock_set.assert_called_once_with(0x04)
                        mock_raise.assert_called_once_with(MockLockStatus.HOLDOVER)

    def test_alarm_raised_on_holdover(self):
        """FM alarm raised when entering holdover."""
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-123'
        self.ctrl._raise_source_loss_alarm(MockLockStatus.HOLDOVER)
        self.assertTrue(self.ctrl._source_loss_alarm_raised)
        self.ctrl._api.set_fault.assert_called_once()

    def test_alarm_raised_on_freerun(self):
        """FM alarm raised with critical severity on freerun."""
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-456'
        self.ctrl._raise_source_loss_alarm(MockLockStatus.UNLOCKED)
        self.assertTrue(self.ctrl._source_loss_alarm_raised)

    def test_alarm_cleared_on_recovery(self):
        """FM alarm cleared when DPLL locks."""
        self.ctrl._api = MagicMock()
        self.ctrl._source_loss_alarm_raised = True
        self.ctrl._clear_source_loss_alarm()
        self.assertFalse(self.ctrl._source_loss_alarm_raised)
        self.ctrl._api.clear_fault.assert_called_once()

    def test_alarm_not_raised_twice(self):
        """Don't re-raise if already raised at same severity."""
        self.ctrl._api = MagicMock()
        self.ctrl._source_loss_alarm_raised = True
        # Use the actual severity value the plugin would set
        self.ctrl._source_loss_alarm_severity = synce.fm_constants.FM_ALARM_SEVERITY_MAJOR
        self.ctrl._raise_source_loss_alarm(MockLockStatus.HOLDOVER)
        self.ctrl._api.set_fault.assert_not_called()

    def test_alarm_escalation(self):
        """Severity escalation: FM updates in-place with same EID."""
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-esc'
        self.ctrl._source_loss_alarm_raised = True
        self.ctrl._source_loss_alarm_severity = synce.fm_constants.FM_ALARM_SEVERITY_MAJOR
        # Escalate from holdover (major) to freerun (critical)
        self.ctrl._raise_source_loss_alarm(MockLockStatus.UNLOCKED)
        # FM updates in-place when same alarm_id+EID is re-raised
        self.ctrl._api.clear_fault.assert_not_called()
        self.ctrl._api.set_fault.assert_called_once()

    def test_alarm_not_cleared_if_not_raised(self):
        """Don't clear if not raised."""
        self.ctrl._api = MagicMock()
        self.ctrl._source_loss_alarm_raised = False
        self.ctrl._clear_source_loss_alarm()
        self.ctrl._api.clear_fault.assert_not_called()

    def test_dpll_status_matches_by_clock_id(self):
        """_get_dpll_status finds EEC device matching clock_id."""
        mock_dev1 = MagicMock()
        mock_dev1.dev_type = MockDeviceType.EEC
        mock_dev1.dev_clock_id = 99999
        mock_dev1.lock_status = MockLockStatus.LOCKED

        mock_dev2 = MagicMock()
        mock_dev2.dev_type = MockDeviceType.EEC
        mock_dev2.dev_clock_id = 12345678
        mock_dev2.lock_status = MockLockStatus.HOLDOVER

        self.ctrl._dpll = MagicMock()
        self.ctrl._dpll.get_all_devices.return_value = [mock_dev1, mock_dev2]

        result = self.ctrl._get_dpll_status()
        self.assertEqual(result, MockLockStatus.HOLDOVER)

    def test_dpll_status_returns_none_if_no_clock_id_match(self):
        """_get_dpll_status returns None if no EEC matches clock_id."""
        self.ctrl.clock_id = 99999999

        mock_dev = MagicMock()
        mock_dev.dev_type = MockDeviceType.EEC
        mock_dev.dev_clock_id = 12345678
        mock_dev.lock_status = MockLockStatus.LOCKED

        self.ctrl._dpll = MagicMock()
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
        """read() skips DPLL monitoring if _dpll is None (no EEC hardware)."""
        self.ctrl._dpll = None
        self.ctrl._get_dpll_status = MagicMock()
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                self.ctrl.read()
                self.ctrl._get_dpll_status.assert_not_called()

    def test_init_disables_if_no_eec_device(self):
        """init() sets _dpll to None if no EEC device found."""
        mock_pps = MagicMock()
        mock_pps.dev_type = MockDeviceType.PPS

        mock_dpll = MagicMock()
        mock_dpll.get_all_devices.return_value = [mock_pps]

        with patch('synce.NetlinkDPLL', return_value=mock_dpll):
            with patch('synce.fm_api.FaultAPIs'):
                self.ctrl.init()

        self.assertIsNone(self.ctrl._dpll)

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
        self.ctrl._load_monitoring_config('synce1', config)

        self.assertEqual(self.ctrl.device, 'synce1')
        self.assertEqual(self.ctrl.socket_path, '/tmp/synce4l_socket_synce1')
        self.assertEqual(self.ctrl.interface, 'eno8303')
        self.assertEqual(self.ctrl.source, 'GNSS')
        self.assertEqual(self.ctrl.holdover_ql, 0x04)
        self.assertEqual(self.ctrl.freerun_ql, 0x0f)

    def test_load_monitoring_config_missing_section(self):
        """_load_monitoring_config handles missing section gracefully."""
        ctrl = synce.SynceController()
        config = configparser.ConfigParser(delimiters=' ')
        config.read_string("[other]\ninterface eth0\n")
        ctrl._load_monitoring_config('synce1', config)

        # Values remain None (not set)
        self.assertIsNone(ctrl.device)
        self.assertIsNone(ctrl.socket_path)

    def test_read_recovery_clears_ql_and_alarm(self):
        """DPLL returns to LOCKED: QL set to static_ql, alarm cleared."""
        self.ctrl._last_ql = 0x04  # was in holdover
        self.ctrl._source_loss_alarm_raised = True
        self.ctrl._source_loss_alarm_severity = 'major'
        self.ctrl._api = MagicMock()
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.LOCKED)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True):
                    self.ctrl.read()
        self.assertEqual(self.ctrl._last_ql, 0x02)  # static_ql (GNSS source)
        self.ctrl._api.clear_fault.assert_called_once()
        self.assertFalse(self.ctrl._source_loss_alarm_raised)

    def test_set_ql_failure_still_raises_alarm(self):
        """Alarm raised even when SET_QL socket fails (retry on next read)."""
        self.ctrl._last_ql = None
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-fail'
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.HOLDOVER)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=False):
                    self.ctrl.read()
        # QL not updated (will retry next cycle)
        self.assertIsNone(self.ctrl._last_ql)
        # But alarm is still raised
        self.ctrl._api.set_fault.assert_called_once()
        self.assertTrue(self.ctrl._source_loss_alarm_raised)

    def test_config_no_synce4l_files(self):
        """Early return when no synce4l-*.conf files exist."""
        with patch('synce.glob', return_value=[]):
            ctrl = synce.SynceController()
            ctrl.config()
            self.assertIsNone(ctrl.instance_name)

    def test_config_empty_monitoring_conf(self):
        """Early return when instance-monitoring.conf has no sections."""
        def fake_read(self_cfg, filename):
            pass  # simulate missing or empty file

        with patch('synce.glob', return_value=['/etc/linuxptp/ptpinstance/synce4l-synce1.conf']):
            with patch.object(configparser.ConfigParser, 'read', fake_read):
                ctrl = synce.SynceController()
                ctrl.config()

        self.assertIsNone(ctrl.instance_name)
        self.assertIsNone(ctrl.socket_path)

    def test_config_clock_id_missing_logs_warning(self):
        """Warning logged when clock_id not found in synce4l config."""
        fake_synce_conf = (
            "[<synce1>]\n"
            "# no clock_id here\n"
        )
        fake_monitoring_conf = (
            "[synce1]\n"
            "smc_socket_path /tmp/synce4l_socket_synce1\n"
            "interface eno8303\n"
        )

        def fake_read(self_cfg, filename):
            if 'instance-monitoring' in filename:
                self_cfg.read_string(fake_monitoring_conf)
            else:
                self_cfg.read_string(fake_synce_conf)

        mock_collectd.warning.reset_mock()

        with patch('synce.glob', return_value=['/etc/linuxptp/ptpinstance/synce4l-synce1.conf']):
            with patch.object(configparser.ConfigParser, 'read', fake_read):
                ctrl = synce.SynceController()
                ctrl.config()

        self.assertIsNone(ctrl.clock_id)
        # Verify warning was logged about missing clock_id
        warning_calls = [str(c) for c in mock_collectd.warning.call_args_list]
        self.assertTrue(any('clock_id' in c for c in warning_calls))

    def test_config_ignores_extra_instances(self):
        """Logs ignored instances when multiple synce4l configs exist."""
        fake_synce_conf = (
            "[<synce1>]\n"
            "clock_id 12345\n"
        )
        fake_monitoring_conf = (
            "[synce1]\n"
            "smc_socket_path /tmp/synce4l_socket_synce1\n"
            "interface eno8303\n"
        )

        def fake_read(self_cfg, filename):
            if 'instance-monitoring' in filename:
                self_cfg.read_string(fake_monitoring_conf)
            else:
                self_cfg.read_string(fake_synce_conf)

        import collectd as mock_collectd
        mock_collectd.info.reset_mock()

        with patch('synce.glob', return_value=[
            '/etc/linuxptp/ptpinstance/synce4l-synce1.conf',
            '/etc/linuxptp/ptpinstance/synce4l-synce2.conf',
        ]):
            with patch.object(configparser.ConfigParser, 'read', fake_read):
                ctrl = synce.SynceController()
                ctrl.config()

        self.assertEqual(ctrl.instance_name, 'synce1')
        # Verify info log about ignored instances
        info_calls = [str(c) for c in mock_collectd.info.call_args_list]
        self.assertTrue(any('ignoring' in c.lower() for c in info_calls))

    def test_config_happy_path(self):
        """Discovers instance, loads clock_id + monitoring params."""
        fake_synce_conf = (
            "[<synce1>]\n"
            "clock_id 12345\n"
        )
        fake_monitoring_conf = (
            "[synce1]\n"
            "smc_socket_path /tmp/synce4l_socket_synce1\n"
            "interface eno8303\n"
            "source GNSS\n"
            "holdover_ql 0x04\n"
            "freerun_ql 0x0f\n"
        )

        def fake_read(self_cfg, filename):
            if 'instance-monitoring' in filename:
                self_cfg.read_string(fake_monitoring_conf)
            else:
                self_cfg.read_string(fake_synce_conf)

        with patch('synce.glob', return_value=['/etc/linuxptp/ptpinstance/synce4l-synce1.conf']):
            with patch.object(configparser.ConfigParser, 'read', fake_read):
                ctrl = synce.SynceController()
                ctrl.config()

        self.assertEqual(ctrl.instance_name, 'synce1')
        self.assertEqual(ctrl.clock_id, 12345)
        self.assertEqual(ctrl.socket_path, '/tmp/synce4l_socket_synce1')
        self.assertEqual(ctrl.interface, 'eno8303')

    def test_status_to_ql_locked_gnss_returns_static_ql(self):
        """Locked with GNSS source returns static_ql."""
        self.ctrl.source = 'GNSS'
        self.assertEqual(self.ctrl._status_to_ql(MockLockStatus.LOCKED),
                         0x02)
        self.assertEqual(
            self.ctrl._status_to_ql(MockLockStatus.LOCKED_AND_HOLDOVER),
            0x02)

    def test_status_to_ql_locked_gnss_custom_static_ql(self):
        """Locked with GNSS source returns custom static_ql."""
        self.ctrl.source = 'GNSS'
        self.ctrl.static_ql = 0x04
        self.assertEqual(self.ctrl._status_to_ql(MockLockStatus.LOCKED),
                         0x04)

    def test_read_locked_gnss_sets_static_ql_no_alarm(self):
        """LOCKED + GNSS sets static_ql and clears alarm."""
        self.ctrl.source = 'GNSS'
        self.ctrl._last_ql = None
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.LOCKED)
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
        """LOCKED + SyncE source = pass-through, no SET_QL."""
        self.ctrl.source = 'SYNCE'
        self.ctrl._last_ql = 0x04  # was previously overriding
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.LOCKED)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql') as mock_set:
                    with patch.object(self.ctrl, '_clear_source_loss_alarm') as mock_clear:
                        self.ctrl.read()
                        mock_set.assert_not_called()
                        mock_clear.assert_called_once()
                        self.assertIsNone(self.ctrl._last_ql)

    def test_read_holdover_after_static_ql_raises_alarm(self):
        """Transition from LOCKED/GNSS to HOLDOVER raises alarm."""
        self.ctrl.source = 'GNSS'
        self.ctrl._last_ql = 0x02  # was static_ql
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.HOLDOVER)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True) as mock_set:
                    with patch.object(self.ctrl, '_raise_source_loss_alarm') as mock_raise:
                        self.ctrl.read()
                        mock_set.assert_called_once_with(0x04)
                        mock_raise.assert_called_once_with(MockLockStatus.HOLDOVER)

    def test_read_recovery_from_holdover_to_locked_gnss(self):
        """Recovery from HOLDOVER to LOCKED/GNSS clears alarm."""
        self.ctrl.source = 'GNSS'
        self.ctrl._last_ql = 0x04  # was holdover_ql
        self.ctrl._source_loss_alarm_raised = True
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.LOCKED)
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=True):
                with patch.object(self.ctrl, '_set_ql', return_value=True) as mock_set:
                    with patch.object(self.ctrl, '_clear_source_loss_alarm') as mock_clear:
                        with patch.object(self.ctrl, '_raise_source_loss_alarm') as mock_raise:
                            self.ctrl.read()
                            mock_set.assert_called_once_with(0x02)
                            mock_clear.assert_called_once()
                            mock_raise.assert_not_called()

    def test_load_monitoring_config_reads_static_ql(self):
        """_load_monitoring_config parses static_ql from config."""
        config = configparser.ConfigParser(delimiters=' ')
        config.read_string(
            "[synce1]\n"
            "smc_socket_path /tmp/synce4l_socket_synce1\n"
            "interface eno8303\n"
            "source GNSS\n"
            "static_ql 0x04\n"
        )
        self.ctrl._load_monitoring_config('synce1', config)
        self.assertEqual(self.ctrl.static_ql, 0x04)

    def test_load_monitoring_config_static_ql_default(self):
        """static_ql remains default when not in config."""
        config = configparser.ConfigParser(delimiters=' ')
        config.read_string(
            "[synce1]\n"
            "smc_socket_path /tmp/synce4l_socket_synce1\n"
            "interface eno8303\n"
        )
        ctrl = synce.SynceController()
        ctrl._load_monitoring_config('synce1', config)
        self.assertEqual(ctrl.static_ql, 0x02)

    # ---------------------------------------------------------------
    # Process alarm tests (service not running)
    # ---------------------------------------------------------------

    def test_read_service_not_running_raises_process_alarm(self):
        """Process alarm raised when service is enabled but not active."""
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-proc'
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=False):
                self.ctrl.read()
        self.assertTrue(self.ctrl._process_alarm_raised)
        self.ctrl._api.set_fault.assert_called_once()
        # Verify EID
        fault_kwargs = synce.fm_api.Fault.call_args[1]
        self.assertEqual(fault_kwargs['entity_instance_id'],
                         'host=controller-0.synce.instance=synce1.synce=not-running')

    def test_read_service_not_running_clears_source_loss_alarm(self):
        """Source-loss alarm cleared when service stops (not misleading)."""
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-proc'
        self.ctrl._source_loss_alarm_raised = True  # source-loss was active
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=False):
                self.ctrl.read()
        # Source-loss alarm cleared
        self.assertFalse(self.ctrl._source_loss_alarm_raised)
        self.ctrl._api.clear_fault.assert_called_once_with(
            '100.119',
            'host=controller-0.synce.interface=eno8303.synce=source-loss')

    def test_read_service_not_running_skips_dpll(self):
        """DPLL monitoring skipped when service not running."""
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-proc'
        self.ctrl._get_dpll_status = MagicMock()
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=False):
                self.ctrl.read()
        self.ctrl._get_dpll_status.assert_not_called()

    def test_read_service_disabled_clears_all_alarms(self):
        """All alarms cleared when service is intentionally disabled."""
        self.ctrl._api = MagicMock()
        self.ctrl._source_loss_alarm_raised = True
        self.ctrl._process_alarm_raised = True
        with patch.object(self.ctrl, '_is_service_enabled', return_value=False):
            self.ctrl.read()
        self.assertFalse(self.ctrl._source_loss_alarm_raised)
        self.assertFalse(self.ctrl._process_alarm_raised)

    def test_read_service_disabled_skips_dpll(self):
        """DPLL monitoring skipped when service is disabled."""
        self.ctrl._api = MagicMock()
        self.ctrl._get_dpll_status = MagicMock()
        with patch.object(self.ctrl, '_is_service_enabled', return_value=False):
            self.ctrl.read()
        self.ctrl._get_dpll_status.assert_not_called()

    def test_read_service_resumes_clears_process_alarm(self):
        """Process alarm cleared when service starts running again."""
        self.ctrl._api = MagicMock()
        self.ctrl._process_alarm_raised = True
        self.ctrl._get_dpll_status = MagicMock(
            return_value=MockLockStatus.LOCKED)
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
        self.ctrl._api = MagicMock()
        self.ctrl._process_alarm_raised = True
        with patch.object(self.ctrl, '_is_service_enabled', return_value=True):
            with patch.object(self.ctrl, '_is_service_active', return_value=False):
                self.ctrl.read()
        self.ctrl._api.set_fault.assert_not_called()

    def test_process_alarm_not_cleared_if_not_raised(self):
        """Process alarm not cleared if it wasn't raised."""
        self.ctrl._api = MagicMock()
        self.ctrl._process_alarm_raised = False
        self.ctrl._clear_process_alarm()
        self.ctrl._api.clear_fault.assert_not_called()

    def test_is_service_enabled_returns_true(self):
        """_is_service_enabled returns True for 'enabled' output."""
        with patch('synce.subprocess.check_output',
                   return_value=b'enabled\n'):
            self.assertTrue(
                self.ctrl._is_service_enabled('synce4l@synce1.service'))

    def test_is_service_enabled_returns_false_for_disabled(self):
        """_is_service_enabled returns False for 'disabled' output."""
        with patch('synce.subprocess.check_output',
                   return_value=b'disabled\n'):
            self.assertFalse(
                self.ctrl._is_service_enabled('synce4l@synce1.service'))

    def test_is_service_enabled_returns_false_on_error(self):
        """_is_service_enabled returns False on CalledProcessError."""
        with patch('synce.subprocess.check_output',
                   side_effect=subprocess.CalledProcessError(1, 'cmd')):
            self.assertFalse(
                self.ctrl._is_service_enabled('synce4l@synce1.service'))

    def test_is_service_active_returns_true(self):
        """_is_service_active returns True for 'active' output."""
        with patch('synce.subprocess.check_output',
                   return_value=b'active\n'):
            self.assertTrue(
                self.ctrl._is_service_active('synce4l@synce1.service'))

    def test_is_service_active_returns_false_for_inactive(self):
        """_is_service_active returns False for 'inactive' output."""
        with patch('synce.subprocess.check_output',
                   return_value=b'inactive\n'):
            self.assertFalse(
                self.ctrl._is_service_active('synce4l@synce1.service'))

    def test_is_service_active_returns_false_for_failed(self):
        """_is_service_active returns False for 'failed' (exit code 3)."""
        with patch('synce.subprocess.check_output',
                   side_effect=subprocess.CalledProcessError(3, 'cmd')):
            self.assertFalse(
                self.ctrl._is_service_active('synce4l@synce1.service'))

    def test_process_alarm_eid_format(self):
        """Process alarm uses correct entity instance ID format."""
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-proc'
        self.ctrl._raise_process_alarm('synce4l@synce1.service')
        fault_kwargs = synce.fm_api.Fault.call_args[1]
        self.assertEqual(
            fault_kwargs['entity_instance_id'],
            'host=controller-0.synce.instance=synce1.synce=not-running')
        self.assertEqual(fault_kwargs['severity'],
                         synce.fm_constants.FM_ALARM_SEVERITY_MAJOR)

    def test_process_alarm_reason_text(self):
        """Process alarm reason text includes service name."""
        self.ctrl._api = MagicMock()
        self.ctrl._api.set_fault.return_value = 'uuid-proc'
        self.ctrl._raise_process_alarm('synce4l@synce1.service')
        fault_kwargs = synce.fm_api.Fault.call_args[1]
        self.assertIn('synce4l@synce1.service',
                      fault_kwargs['reason_text'])
        self.assertIn('enabled but not running',
                      fault_kwargs['reason_text'])

    def test_read_incomplete_config_bails_early(self):
        """read() bails if required config fields missing."""
        ctrl = synce.SynceController()
        ctrl.instance_name = None  # incomplete
        ctrl._get_dpll_status = MagicMock()
        ctrl.read()
        ctrl._get_dpll_status.assert_not_called()


if __name__ == '__main__':
    unittest.main()
