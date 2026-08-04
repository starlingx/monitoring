#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Coverage-focused tests for collectd-extensions source modules."""

import os
import sys
import unittest
from unittest.mock import MagicMock

# Mock all external dependencies before importing modules
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
sys.modules.setdefault('gps', MagicMock())

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import tempfile


class TestPtpGnssMonitorHelpers(unittest.TestCase):
    """Tests for ptp_gnss_monitor helper functions."""

    def test_get_device_paths_with_paths(self):
        """Test extracting device paths from device list."""
        from src import ptp_gnss_monitor as gnss_monitor
        devices = [
            {'class': 'DEVICE', 'path': '/dev/gnss0'},
            {'class': 'DEVICE', 'path': '/dev/gnss1'},
        ]
        result = gnss_monitor.get_device_paths(devices)
        self.assertEqual(result, ['/dev/gnss0', '/dev/gnss1'])

    def test_get_device_paths_no_path_key(self):
        """Test device list without path key."""
        from src import ptp_gnss_monitor as gnss_monitor
        devices = [{'class': 'DEVICE'}]
        result = gnss_monitor.get_device_paths(devices)
        self.assertEqual(result, [])

    def test_get_device_paths_empty(self):
        """Verify get_device_paths_empty returns [] with empty input."""
        from src import ptp_gnss_monitor as gnss_monitor
        result = gnss_monitor.get_device_paths([])
        self.assertEqual(result, [])

    def test_trunc_positive(self):
        """Test truncation of positive float."""
        from src import ptp_gnss_monitor as gnss_monitor
        self.assertEqual(gnss_monitor.trunc(3.14159, 3), 3.141)

    def test_trunc_zero_precision(self):
        """Verify trunc with zero precision truncates to int."""
        from src import ptp_gnss_monitor as gnss_monitor
        self.assertEqual(gnss_monitor.trunc(3.9, 0), 3)

    def test_get_signal_to_noise_ratio_valid(self):
        """Test SNR calculation with valid data."""
        from src import ptp_gnss_monitor as gnss_monitor
        satellites = [
            {'PRN': 1, 'ss': 45.0, 'used': True},
            {'PRN': 2, 'ss': 40.0, 'used': False},
            {'PRN': 3, 'ss': 50.0, 'used': True},
        ]
        snr = gnss_monitor.get_signal_to_noise_ratio(satellites)
        self.assertEqual(snr.min, 45.0)
        self.assertEqual(snr.max, 50.0)

    def test_get_signal_to_noise_ratio_no_used(self):
        """Test SNR with no used satellites."""
        from src import ptp_gnss_monitor as gnss_monitor
        satellites = [
            {'PRN': 1, 'ss': 45.0, 'used': False},
        ]
        snr = gnss_monitor.get_signal_to_noise_ratio(satellites)
        self.assertEqual(snr.min, 0)
        self.assertEqual(snr.max, 0)
        self.assertEqual(snr.avg, 0)

    def test_get_signal_to_noise_ratio_no_ss(self):
        """Test SNR with used satellite but no ss key."""
        from src import ptp_gnss_monitor as gnss_monitor
        satellites = [
            {'PRN': 1, 'used': True},
        ]
        snr = gnss_monitor.get_signal_to_noise_ratio(satellites)
        self.assertEqual(snr.min, 0)

    def test_get_signal_to_noise_ratio_empty(self):
        """Test SNR with empty satellite list."""
        from src import ptp_gnss_monitor as gnss_monitor
        snr = gnss_monitor.get_signal_to_noise_ratio([])
        self.assertEqual(snr.min, 0)
        self.assertEqual(snr.max, 0)
        self.assertEqual(snr.avg, 0)

    def test_gps_data_defaults(self):
        """Verify gps_data returns 0."""
        from src import ptp_gnss_monitor as gnss_monitor
        data = gnss_monitor.GpsData()
        self.assertEqual(data.gpsd_running, 0)
        self.assertEqual(data.lock_state, 0)
        self.assertEqual(data.satellite_count, 0)
        self.assertEqual(data.signal_quality_db.min, 0)

    def test_signal_quality_db_defaults(self):
        """Verify signal_quality returns 0."""
        from src import ptp_gnss_monitor as gnss_monitor
        snr = gnss_monitor.SignalQualityDb()
        self.assertEqual(snr.min, 0)
        self.assertEqual(snr.max, 0)
        self.assertEqual(snr.avg, 0)

    def test_parse_gnss_monitor_config(self):
        """Test config parsing with temp file."""
        from src import ptp_gnss_monitor as gnss_monitor
        content = "[global]\ndevices /dev/gnss0\nsatellite_count 10\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf',
                                         delete=False) as temp_file:
            temp_file.write(content)
            temp_file.flush()
            config = gnss_monitor.parse_gnss_monitor_config(temp_file.name)
        os.unlink(temp_file.name)
        self.assertEqual(config['global']['devices'], '/dev/gnss0')
        self.assertEqual(config['global']['satellite_count'], '10')


class TestCguHandler(unittest.TestCase):
    """Tests for CguHandler class."""

    def test_init(self):
        """Verify init returns non-None value."""
        from src.cgu_handler import CguHandler
        handler = CguHandler()
        self.assertIsNotNone(handler)

    def test_read_cgu_no_dpll(self):
        """Test read_cgu when dpll is not initialized."""
        from src.cgu_handler import CguHandler
        handler = CguHandler()
        handler._dpll = None
        handler.read_cgu()
        self.assertIsNone(handler._pins)

    def test_read_cgu_with_dpll(self):
        """Test read_cgu with valid dpll."""
        from src.cgu_handler import CguHandler
        handler = CguHandler()
        mock_dpll = MagicMock()
        mock_dpll.get_all_devices.return_value = ['dev1']
        mock_dpll.get_all_pins.return_value = ['pin1']
        handler._dpll = mock_dpll
        handler.read_cgu()
        self.assertEqual(handler._devices, ['dev1'])
        self.assertEqual(handler._pins, ['pin1'])

    def test_search_pins_empty(self):
        """Test search_pins with no matching pins."""
        from src.cgu_handler import CguHandler
        handler = CguHandler()
        handler._pins = []
        result = handler.search_pins('clock1', 'pin1')
        self.assertEqual(result, [])

    def test_get_current_pin_reference_no_pins(self):
        """Test get_current_pin_reference with no pins."""
        from src.cgu_handler import CguHandler
        handler = CguHandler()
        handler._pins = None
        mock_device = MagicMock()
        result = handler.get_current_pin_reference(mock_device)
        self.assertIsNone(result)

    def test_get_current_pin_reference_empty_pins(self):
        """Test get_current_pin_reference with empty pins list."""
        from src.cgu_handler import CguHandler
        handler = CguHandler()
        handler._pins = []
        mock_device = MagicMock()
        result = handler.get_current_pin_reference(mock_device)
        self.assertIsNone(result)

    def test_cgu_output_to_dict_no_devices(self):
        """Test cgu_output_to_dict with no devices."""
        from src.cgu_handler import CguHandler
        handler = CguHandler()
        handler._devices = None
        result = handler.cgu_output_to_dict()
        self.assertEqual(result, {})

    def test_cgu_get_current_device_state_no_devices(self):
        """Test cgu_get_current_device_state with no devices."""
        from src.cgu_handler import CguHandler
        handler = CguHandler()
        handler._devices = None
        device, pin = handler.cgu_get_current_device_state('clock1', 'type1')
        self.assertIsNone(device)
        self.assertIsNone(pin)


class TestPtpGnssMonitorGetGpsData(unittest.TestCase):
    """Tests for get_gps_data function."""

    def test_get_gps_data_connection_error(self):
        """Test get_gps_data when gpsd connection fails."""
        from src import ptp_gnss_monitor as gnss_monitor
        mock_gps = sys.modules['gps']
        mock_gps.gps.side_effect = ConnectionRefusedError("refused")
        data = gnss_monitor.get_gps_data('/dev/gnss0')
        self.assertEqual(data.gpsd_running, 0)
        self.assertEqual(data.lock_state, 0)
        mock_gps.gps.side_effect = None

    def test_get_gps_data_by_session_sky_no_usat(self):
        """Test SKY report without uSat key."""
        from src import ptp_gnss_monitor as gnss_monitor
        session = [
            {'class': 'DEVICES', 'devices': [{'path': '/dev/gnss0'}]},
            {'class': 'TPV', 'device': '/dev/gnss0', 'mode': 3},
            {'class': 'SKY', 'device': '/dev/gnss0',
             'satellites': [{'PRN': 1, 'ss': 45.0, 'used': True}]},
        ]
        data = gnss_monitor.get_gps_data_by_session(session, '/dev/gnss0')
        self.assertEqual(data.lock_state, 1)
        self.assertEqual(data.satellite_count, 0)

    def test_get_gps_data_by_session_sky_no_satellites(self):
        """Test SKY report without satellites key."""
        from src import ptp_gnss_monitor as gnss_monitor
        session = [
            {'class': 'DEVICES', 'devices': [{'path': '/dev/gnss0'}]},
            {'class': 'TPV', 'device': '/dev/gnss0', 'mode': 2},
            {'class': 'SKY', 'device': '/dev/gnss0', 'uSat': 5},
        ]
        data = gnss_monitor.get_gps_data_by_session(session, '/dev/gnss0')
        self.assertEqual(data.lock_state, 1)
        self.assertEqual(data.satellite_count, 5)
        self.assertEqual(data.signal_quality_db.min, 0)

    def test_get_gps_data_by_session_tpv_no_device(self):
        """Test TPV report without device key (should be skipped)."""
        from src import ptp_gnss_monitor as gnss_monitor
        session = [
            {'class': 'DEVICES', 'devices': [{'path': '/dev/gnss0'}]},
            {'class': 'TPV', 'mode': 3},
        ]
        data = gnss_monitor.get_gps_data_by_session(session, '/dev/gnss0')
        self.assertEqual(data.lock_state, 0)

    def test_get_gps_data_by_session_sky_no_device(self):
        """Test SKY report without device key (should be skipped)."""
        from src import ptp_gnss_monitor as gnss_monitor
        session = [
            {'class': 'DEVICES', 'devices': [{'path': '/dev/gnss0'}]},
            {'class': 'TPV', 'device': '/dev/gnss0', 'mode': 3},
            {'class': 'SKY', 'uSat': 5},
        ]
        data = gnss_monitor.get_gps_data_by_session(session, '/dev/gnss0')
        self.assertEqual(data.lock_state, 1)

    def test_get_gps_data_by_session_tpv_wrong_device(self):
        """Test TPV report for different device."""
        from src import ptp_gnss_monitor as gnss_monitor
        session = [
            {'class': 'DEVICES', 'devices': [{'path': '/dev/gnss0'}]},
            {'class': 'TPV', 'device': '/dev/gnss1', 'mode': 3},
        ]
        data = gnss_monitor.get_gps_data_by_session(session, '/dev/gnss0')
        self.assertEqual(data.lock_state, 0)

    def test_get_gps_data_by_session_mode_0(self):
        """Test TPV with mode 0 (unknown)."""
        from src import ptp_gnss_monitor as gnss_monitor
        session = [
            {'class': 'DEVICES', 'devices': [{'path': '/dev/gnss0'}]},
            {'class': 'TPV', 'device': '/dev/gnss0', 'mode': 0},
        ]
        data = gnss_monitor.get_gps_data_by_session(session, '/dev/gnss0')
        self.assertEqual(data.lock_state, 0)


class TestExamplePlugin(unittest.TestCase):
    """Tests for example.py collectd plugin."""

    def test_example_object_creation(self):
        """Test exampleObject can be created."""
        from src import example
        self.assertIsNotNone(example.obj)

    def test_config_func_with_data(self):
        """Test config_func with data node."""
        from src import example
        mock_config = MagicMock()
        mock_node = MagicMock()
        mock_node.key = 'data'
        mock_node.values = ['10 200']
        mock_config.children = [mock_node]
        result = example.config_func(mock_config)
        self.assertEqual(result, 0)
        self.assertEqual(example.obj.plugin_data, ['10', '200'])

    def test_config_func_no_data(self):
        """Test config_func without data node."""
        from src import example
        mock_config = MagicMock()
        mock_config.children = []
        result = example.config_func(mock_config)
        self.assertEqual(result, 0)

    def test_init_func_not_configured(self):
        """Test init_func when config not complete."""
        from src import example
        example.obj.config_complete = MagicMock(return_value=False)
        result = example.init_func()
        self.assertFalse(result)

    def test_read_func_not_initialized(self):
        """Test read_func when not initialized."""
        from src import example
        example.obj.init_complete = False
        example.obj.config_complete = MagicMock(return_value=False)
        result = example.read_func()
        self.assertEqual(result, 0)


class TestServiceRes(unittest.TestCase):
    """Tests for service_res.py module."""

    def test_clear_alarm_success(self):
        """Verify clear_alarm_success returns True on success."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.hostname = 'testhost'
        service_res.api = MagicMock()
        service_res.api.clear_fault.return_value = True
        alarm = {"id": "100.150", "entity_id": "test_entity"}
        result = service_res.clear_alarm(alarm)
        self.assertTrue(result)

    def test_clear_alarm_already_cleared(self):
        """Test clear_alarm when already cleared."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.hostname = 'testhost'
        service_res.api = MagicMock()
        service_res.api.clear_fault.return_value = False
        alarm = {"id": "100.150", "entity_id": "test_entity"}
        result = service_res.clear_alarm(alarm)
        self.assertTrue(result)

    def test_clear_alarm_exception(self):
        """Verify clear_alarm_exception returns False on exception."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.hostname = 'testhost'
        service_res.api = MagicMock()
        service_res.api.clear_fault.side_effect = Exception("test error")
        alarm = {"id": "100.150", "entity_id": "test_entity"}
        result = service_res.clear_alarm(alarm)
        self.assertFalse(result)

    def test_raise_alarm_success(self):
        """Verify raise_alarm_success returns True on success."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.hostname = 'testhost'
        service_res.api = MagicMock()
        # Mock is_uuid_like to return True
        mock_pc = sys.modules['plugin_common']
        mock_pc.is_uuid_like.return_value = True
        service_res.api.set_fault.return_value = 'valid-uuid'
        alarm = {
            "id": "100.150",
            "entity_id": "test_entity",
            "severity": "major",
            "reason": "test reason",
            "repair": "test repair",
        }
        result = service_res.raise_alarm("test-service", alarm)
        self.assertTrue(result)

    def test_raise_alarm_exception(self):
        """Verify raise_alarm_exception returns False on exception."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.hostname = 'testhost'
        service_res.api = MagicMock()
        service_res.api.set_fault.side_effect = Exception("test error")
        alarm = {
            "id": "100.150",
            "entity_id": "test_entity",
            "severity": "major",
            "reason": "test reason",
            "repair": "test repair",
        }
        result = service_res.raise_alarm("test-service", alarm)
        self.assertFalse(result)

    def test_raise_alarm_invalid_uuid(self):
        """Test raise_alarm with invalid uuid return."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.hostname = 'testhost'
        service_res.api = MagicMock()
        mock_pc = sys.modules['plugin_common']
        mock_pc.is_uuid_like.return_value = False
        service_res.api.set_fault.return_value = 'not-a-uuid'
        alarm = {
            "id": "100.150",
            "entity_id": "test_entity",
            "severity": "major",
            "reason": "test reason",
            "repair": "test repair",
        }
        result = service_res.raise_alarm("test-service", alarm)
        self.assertFalse(result)

    def test_init_func_not_configured(self):
        """Test init_func when config not complete."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.config_complete.return_value = False
        result = service_res.init_func()
        self.assertEqual(result, 0)

    def test_process_service_alarm_clear(self):
        """Verify process_service_alarm_clear returns 0."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.hostname = 'testhost'
        service_res.api = MagicMock()
        service_res.api.clear_fault.return_value = True
        service = {
            "alarms_to_clear": [{"id": "100.150", "entity_id": "test"}],
            "alarm_to_raise": None,
            "alarm_raised": None,
            "service_name": "test",
        }
        service_res.process_service_alarm(service)
        self.assertEqual(len(service["alarms_to_clear"]), 0)

    def test_read_func_not_initialized(self):
        """Test read_func when not initialized."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.init_complete = False
        service_res.obj.config_complete.return_value = False
        result = service_res.read_func()
        self.assertEqual(result, 0)


if __name__ == '__main__':
    unittest.main()
