#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Extended tests for service_res, example, cgu_handler, ptp_interface,
   remotels, gpspipe, ntpq utility functions."""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock
from unittest.mock import mock_open
from unittest.mock import patch

sys.modules.setdefault('collectd', MagicMock())
sys.modules.setdefault('tsconfig', MagicMock())
sys.modules.setdefault('tsconfig.tsconfig', MagicMock())
sys.modules.setdefault('plugin_common', MagicMock())
sys.modules.setdefault('fm_api', MagicMock())
sys.modules.setdefault('fm_api.constants', MagicMock())
sys.modules.setdefault('fm_api.fm_api', MagicMock())
sys.modules.setdefault('gps', MagicMock())
sys.modules.setdefault('pynetlink', MagicMock())

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import socket


class TestServiceResExtended(unittest.TestCase):
    """Extended tests for service_res.py."""

    def test_init_func_config_complete_service_exists(self):
        """Verify init_func_config_complete is called once."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.config_complete.return_value = True
        service_res.services = [{"service_plugin": "/bin/true"}]
        with patch('os.path.exists', return_value=True):
            result = service_res.init_func()
        self.assertEqual(result, 0)
        service_res.obj.init_completed.assert_called_once()

    def test_init_func_service_missing(self):
        """Verify init_func_service_missing returns 1 when missing."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.config_complete.return_value = True
        service_res.services = [{"service_plugin": "/nonexistent"}]
        with patch('os.path.exists', return_value=False):
            result = service_res.init_func()
        self.assertEqual(result, 1)

    def test_check_service_status_with_existing_alarm(self):
        """Verify status change queues old alarm for clear."""
        from src import service_res
        existing_alarm = {"id": "100.150", "entity_id": "test"}
        service = {
            "service_name": "test",
            "service_plugin_cmdline": "echo 160",
            "service_plugin_env": {},
            "current_status": "0",
            "alarm_raised": existing_alarm,
            "alarms_to_clear": [],
            "alarm_to_raise": None,
            "service_status": [
                {"status": "0", "alarm": None},
                {"status": "160", "alarm": {
                    "severity": "major", "id": "100.150",
                    "entity_id": "t", "reason": "r",
                    "repair": "f"}},
            ],
        }
        with patch('subprocess.Popen') as mock_popen:
            mock_proc = MagicMock()
            mock_proc.communicate.return_value = ("160", "")
            mock_popen.return_value = mock_proc
            service_res.check_service_status(service)
        self.assertIn(existing_alarm, service["alarms_to_clear"])

    def test_process_service_alarm_raise(self):
        """Verify process_service_alarm_raise returns None."""
        from src import service_res
        service_res.obj = MagicMock()
        service_res.obj.hostname = 'testhost'
        service_res.api = MagicMock()
        mock_pc = sys.modules['plugin_common']
        mock_pc.is_uuid_like.return_value = True
        service_res.api.set_fault.return_value = 'uuid-val'
        alarm = {
            "id": "100.150", "entity_id": "test",
            "severity": "major", "reason": "r", "repair": "f"
        }
        service = {
            "alarms_to_clear": [],
            "alarm_to_raise": alarm,
            "alarm_raised": None,
            "service_name": "test",
        }
        service_res.process_service_alarm(service)
        self.assertIsNone(service["alarm_to_raise"])


class TestExampleExtended(unittest.TestCase):
    """Extended tests for example.py."""

    def test_init_func_configured(self):
        """Verify init_func_configured returns 0."""
        from src import example
        example.obj.config_complete = MagicMock(return_value=True)
        with patch('socket.gethostname', return_value='host1'):
            example.obj.gethostname = MagicMock(return_value='host1')
            result = example.init_func()
        self.assertEqual(result, 0)

    def test_read_func_initialized_ready(self):
        """Verify read_func_initialized_ready returns 0."""
        from src import example
        example.obj.init_complete = True
        example.obj._node_ready = True
        example.obj.plugin_data = ['1', '100']
        example.obj.hostname = 'host1'
        result = example.read_func()
        self.assertEqual(result, 0)

    def test_read_func_node_not_ready(self):
        """Verify read_func_node_not returns 0 when not ready."""
        from src import example
        example.obj.init_complete = True
        example.obj._node_ready = False
        result = example.read_func()
        self.assertEqual(result, 0)


class TestCguHandlerExtended(unittest.TestCase):
    """Extended tests for cgu_handler.py."""

    def test_search_pins_with_matches(self):
        """Verify search_pins returns 1."""
        from src.cgu_handler import CguHandler
        handler = CguHandler()
        pin1 = MagicMock()
        pin1.dev_clock_id = 'clk1'
        pin1.pin_board_label = 'GNSS'
        pin2 = MagicMock()
        pin2.dev_clock_id = 'clk1'
        pin2.pin_board_label = 'OTHER'
        handler._pins = [pin1, pin2]
        result = handler.search_pins('clk1', 'GNSS')
        self.assertEqual(len(result), 1)

    def test_get_current_pin_reference_with_match(self):
        """Verify get_current_pin_reference returns non-None value."""
        from src.cgu_handler import CguHandler
        PinDirection = sys.modules['pynetlink'].PinDirection
        PinState = sys.modules['pynetlink'].PinState
        handler = CguHandler()
        device = MagicMock()
        device.dev_id = 1
        pin = MagicMock()
        pin.dev_id = 1
        pin.pin_direction = PinDirection.INPUT
        pin.pin_state = PinState.CONNECTED
        pin.pin_priority = 1
        handler._pins = [pin]
        result = handler.get_current_pin_reference(device)
        self.assertIsNotNone(result)

    def test_cgu_output_to_dict_with_devices(self):
        """Verify cgu_output 'clk1' in result."""
        from src.cgu_handler import CguHandler
        handler = CguHandler()
        dev = MagicMock()
        dev.dev_clock_id = 'clk1'
        dev.dev_type = MagicMock()
        dev.dev_type.__str__ = MagicMock(return_value='EEC')
        dev.lock_status = 'locked'
        handler._devices = [dev]
        handler._pins = []
        result = handler.cgu_output_to_dict()
        self.assertIn('clk1', result)

    def test_cgu_get_current_device_state_with_match(self):
        """Verify cgu_get returns non-None value."""
        from src.cgu_handler import CguHandler
        handler = CguHandler()
        dev = MagicMock()
        dev.dev_clock_id = 'clk1'
        dev.dev_type = 'EEC'
        dev.dev_id = 1
        handler._devices = [dev]
        handler._pins = []
        device, pin = handler.cgu_get_current_device_state(
            'clk1', 'EEC')
        self.assertIsNotNone(device)


class TestPtpInterfaceUevent(unittest.TestCase):
    """Tests for ptp_interface.py Uevent class."""

    def test_uevent_load(self):
        """Verify uevent_load returns '0000:1a:00.0'."""
        from src.ptp_interface import Uevent
        content = (
            "DRIVER=ice\nPCI_CLASS=20000\nPCI_ID=8086:1593\n"
            "PCI_SUBSYS_ID=8086:0005\nPCI_SLOT_NAME=0000:1a:00.0\n"
            "MODALIAS=pci:test\n"
        )
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.txt', delete=False) as f:
            f.write(content)
            f.flush()
            uevent = Uevent.load(f.name)
        os.unlink(f.name)
        self.assertEqual(uevent.driver, 'ice')
        self.assertEqual(uevent.pci_id, '8086:1593')
        self.assertEqual(uevent.pci_slot_name, '0000:1a:00.0')

    def test_uevent_load_no_file(self):
        """Verify uevent_load raises ValueError."""
        from src.ptp_interface import Uevent
        with self.assertRaises(ValueError):
            Uevent.load('')

    def test_uevent_load_missing_file(self):
        """Verify uevent_load raises ValueError when missing."""
        from src.ptp_interface import Uevent
        with self.assertRaises(ValueError):
            Uevent.load('/nonexistent/path')

    def test_read_uevent_success(self):
        """Verify read_uevent loads Uevent for interface."""
        from src import interface
        from src import ptp_interface
        from src.ptp_interface import Uevent
        mock_uevent = MagicMock()
        with patch.object(ptp_interface, 'Uevent') as MockUe:
            MockUe.load.return_value = mock_uevent
            result = ptp_interface.read_uevent('eno1')
        self.assertEqual(result, mock_uevent)

    def test_read_uevent_none_interface(self):
        """Verify read_uevent_none_interface returns None with None."""
        from src import ptp_interface
        result = ptp_interface.read_uevent(None)
        self.assertIsNone(result)

    def test_read_uevent_error(self):
        """Verify read_uevent_error returns None on failure."""
        from src import ptp_interface
        from src.ptp_interface import Uevent
        with patch.object(ptp_interface, 'Uevent') as MockUe:
            MockUe.load.side_effect = ValueError("bad")
            result = ptp_interface.read_uevent('eno1')
        self.assertIsNone(result)


class TestNtpqFunctions(unittest.TestCase):
    """Tests for ntpq.py utility functions."""

    def test_is_uuid_like_valid(self):
        """Verify is_uuid_like_valid returns True with valid input."""
        from src import ntpq
        result = ntpq._is_uuid_like(
            '12345678-1234-1234-1234-123456789abc')
        self.assertTrue(result)

    def test_is_uuid_like_invalid(self):
        """Verify is_uuid_like_invalid ntpq._is_uuid_like() is False."""
        from src import ntpq
        self.assertFalse(ntpq._is_uuid_like('not-uuid'))

    def test_is_ip_address_ipv4(self):
        """Verify _is_ip_address returns AF_INET for IPv4."""
        from src import ntpq
        result = ntpq._is_ip_address('192.168.1.1')
        self.assertEqual(result, socket.AF_INET)

    def test_is_ip_address_ipv6(self):
        """Verify _is_ip_address returns AF_INET6 for IPv6."""
        from src import ntpq
        result = ntpq._is_ip_address('::1')
        self.assertEqual(result, socket.AF_INET6)

    def test_is_ip_address_invalid(self):
        """Verify is_ip_address_invalid ntpq._is_ip_address() is False."""
        from src import ntpq
        self.assertFalse(ntpq._is_ip_address('not-an-ip'))

    def test_is_controller_true(self):
        """Verify is_controller_true returns True."""
        from src import ntpq
        content = "192.168.1.1 controller-0\n"
        with patch('builtins.open', mock_open(read_data=content)):
            result = ntpq._is_controller('192.168.1.1')
        self.assertTrue(result)

    def test_is_controller_false(self):
        """Verify is_controller_false returns False."""
        from src import ntpq
        content = "192.168.1.1 worker-0\n"
        with patch('builtins.open', mock_open(read_data=content)):
            result = ntpq._is_controller('192.168.1.1')
        self.assertFalse(result)

    def test_is_controller_comment_line(self):
        """Verify is_controller_comment_line returns True."""
        from src import ntpq
        content = "# comment\n192.168.1.2 controller-0\n"
        with patch('builtins.open', mock_open(read_data=content)):
            result = ntpq._is_controller('192.168.1.2')
        self.assertTrue(result)

    def test_add_unreachable_server(self):
        """Verify _add_unreachable_server appends IP to list."""
        from src import ntpq
        ntpq.obj = MagicMock()
        ntpq.obj.unreachable_servers = []
        ntpq._add_unreachable_server('1.2.3.4')
        self.assertIn('1.2.3.4', ntpq.obj.unreachable_servers)

    def test_add_ip_to_ntpq_server_list(self):
        """Verify _add_ip_to_ntpq_server_list appends IP."""
        from src import ntpq
        ntpq.obj = MagicMock()
        ntpq.obj.server_list_ntpq = []
        ntpq._add_ip_to_ntpq_server_list('1.2.3.4')
        self.assertIn('1.2.3.4', ntpq.obj.server_list_ntpq)

    def test_clear_base_alarm_success(self):
        """Verify clear_base_alarm_success returns True on success."""
        from src import ntpq
        ntpq.obj = MagicMock()
        ntpq.obj.base_eid = 'host=h1'
        ntpq.api = MagicMock()
        ntpq.api.clear_fault.return_value = True
        result = ntpq._clear_base_alarm()
        self.assertTrue(result)

    def test_clear_base_alarm_exception(self):
        """Verify clear_base_alarm_exception returns False on."""
        from src import ntpq
        ntpq.obj = MagicMock()
        ntpq.obj.base_eid = 'host=h1'
        ntpq.api = MagicMock()
        ntpq.api.clear_fault.side_effect = Exception("fail")
        result = ntpq._clear_base_alarm()
        self.assertFalse(result)
        ntpq.api.clear_fault.side_effect = None

    def test_remove_ip_from_unreachable_list(self):
        """Verify _remove_ip clears IP and alarm."""
        from src import ntpq
        ntpq.obj = MagicMock()
        ntpq.obj.base_eid = 'host=h1'
        ntpq.obj.unreachable_servers = ['1.2.3.4']
        ntpq.api = MagicMock()
        ntpq.api.clear_fault.return_value = True
        ntpq._remove_ip_from_unreachable_list('1.2.3.4')
        self.assertNotIn('1.2.3.4', ntpq.obj.unreachable_servers)

    def test_raise_alarm_no_ip(self):
        """Verify raise_alarm_no_ip ntpq.obj.alarm_raised is True."""
        from src import ntpq
        ntpq.obj = MagicMock()
        ntpq.obj.alarm_raised = False
        ntpq.obj.base_eid = 'host=h1'
        ntpq.api = MagicMock()
        ntpq._is_uuid_like = MagicMock(return_value=True)
        ntpq.api.set_fault.return_value = 'uuid'
        ntpq._raise_alarm()
        self.assertTrue(ntpq.obj.alarm_raised)

    def test_raise_alarm_already_raised(self):
        """Verify raise_alarm_already_raised returns False."""
        from src import ntpq
        ntpq.obj = MagicMock()
        ntpq.obj.alarm_raised = True
        result = ntpq._raise_alarm()
        self.assertFalse(result)


class TestRemotelsExtended(unittest.TestCase):
    """Extended tests for remotels.py."""

    def test_raise_alarm(self):
        """Verify raise_alarm remotels.obj.alarmed is True."""
        from src import remotels
        remotels.obj = MagicMock()
        remotels.obj.base_eid = 'host=h1'
        remotels.api = MagicMock()
        mock_pc = sys.modules['plugin_common']
        mock_pc.is_uuid_like.return_value = True
        remotels.api.set_fault.return_value = 'uuid-val'
        remotels.raise_alarm()
        self.assertTrue(remotels.obj.alarmed)

    def test_clear_alarm_success(self):
        """Verify clear_alarm_success remotels.obj.alarmed is False on."""
        from src import remotels
        remotels.obj = MagicMock()
        remotels.obj.base_eid = 'host=h1'
        remotels.api = MagicMock()
        remotels.api.clear_fault.return_value = True
        result = remotels.clear_alarm()
        self.assertTrue(result)
        self.assertFalse(remotels.obj.alarmed)

    def test_clear_alarm_exception(self):
        """Verify clear_alarm_exception returns False on exception."""
        from src import remotels
        remotels.obj = MagicMock()
        remotels.obj.base_eid = 'host=h1'
        remotels.api = MagicMock()
        remotels.api.clear_fault.side_effect = Exception("fail")
        result = remotels.clear_alarm()
        self.assertFalse(result)
        remotels.api.clear_fault.side_effect = None

    def test_config_func(self):
        """Verify config_func returns 0."""
        from src import remotels
        remotels.obj = MagicMock()
        result = remotels.config_func(MagicMock())
        self.assertEqual(result, 0)

    def test_init_func_not_controller(self):
        """Verify init_func_not_controller returns 0."""
        from src import remotels
        remotels.tsc = MagicMock()
        remotels.tsc.nodetype = 'worker'
        result = remotels.init_func()
        self.assertEqual(result, 0)

    def test_init_func_controller(self):
        """Verify init_func_controller returns True."""
        from src import remotels
        remotels.tsc = MagicMock()
        remotels.tsc.nodetype = 'controller'
        remotels.obj = MagicMock()
        remotels.obj.config_complete.return_value = True
        remotels.obj.gethostname.return_value = 'ctrl-0'
        result = remotels.init_func()
        self.assertTrue(result)

    def test_read_func_not_controller(self):
        """Verify read_func_not_controller returns 0."""
        from src import remotels
        remotels.tsc = MagicMock()
        remotels.tsc.nodetype = 'worker'
        result = remotels.read_func()
        self.assertEqual(result, 0)

    def test_read_func_not_initialized(self):
        """Verify read_func_not_initialized returns 0 when not."""
        from src import remotels
        remotels.tsc = MagicMock()
        remotels.tsc.nodetype = 'controller'
        remotels.obj = MagicMock()
        remotels.obj.init_complete = False
        remotels.obj.config_complete.return_value = False
        result = remotels.read_func()
        self.assertEqual(result, 0)


class TestServiceResClearAlarm(unittest.TestCase):
    """Cover clear_alarm and raise_alarm in service_res.py."""

    def setUp(self):
        """Set up test fixtures."""
        from src import service_res
        self.mod = service_res
        self.mod.obj = MagicMock()
        self.mod.obj.hostname = 'testhost'

    def test_clear_alarm_success(self):
        """Verify clear_alarm_success self.mod.clear_alarm() is True."""
        self.mod.api = MagicMock()
        self.mod.api.clear_fault.return_value = True
        alarm = {"id": "100.150", "entity_id": "res=test"}
        self.assertTrue(self.mod.clear_alarm(alarm))

    def test_clear_alarm_already_cleared(self):
        """Verify clear_alarm_already_cleared self.mod.clear_alarm()."""
        self.mod.api = MagicMock()
        self.mod.api.clear_fault.return_value = False
        alarm = {"id": "100.150", "entity_id": "res=test"}
        self.assertTrue(self.mod.clear_alarm(alarm))

    def test_clear_alarm_exception(self):
        """Verify clear_alarm_exception self.mod.clear_alarm() is."""
        self.mod.api = MagicMock()
        self.mod.api.clear_fault.side_effect = Exception("fail")
        alarm = {"id": "100.150", "entity_id": "res=test"}
        self.assertFalse(self.mod.clear_alarm(alarm))

    def test_raise_alarm_success(self):
        """Verify raise_alarm_success self.mod.raise_alarm() is True."""
        self.mod.api = MagicMock()
        self.mod.api.set_fault.return_value = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        mock_pc = sys.modules['plugin_common']
        mock_pc.is_uuid_like.return_value = True
        alarm = {"id": "100.150", "entity_id": "res=test",
                 "severity": "major", "reason": "test", "repair": "fix"}
        self.assertTrue(self.mod.raise_alarm("svc", alarm))

    def test_raise_alarm_exception(self):
        """Verify raise_alarm_exception self.mod.raise_alarm() is."""
        self.mod.api = MagicMock()
        self.mod.api.set_fault.side_effect = Exception("fail")
        alarm = {"id": "100.150", "entity_id": "res=test",
                 "severity": "major", "reason": "test", "repair": "fix"}
        self.assertFalse(self.mod.raise_alarm("svc", alarm))

    def test_raise_alarm_bad_uuid(self):
        """Verify raise_alarm_bad_uuid self.mod.raise_alarm() is."""
        self.mod.api = MagicMock()
        self.mod.api.set_fault.return_value = 'bad'
        mock_pc = sys.modules['plugin_common']
        mock_pc.is_uuid_like.return_value = False
        alarm = {"id": "100.150", "entity_id": "res=test",
                 "severity": "major", "reason": "test", "repair": "fix"}
        self.assertFalse(self.mod.raise_alarm("svc", alarm))


class TestServiceResCheckAndProcess(unittest.TestCase):
    """Cover check_service_status and process_service_alarm."""

    def setUp(self):
        """Set up test fixtures."""
        from src import service_res
        self.mod = service_res
        self.mod.obj = MagicMock()
        self.mod.obj.hostname = 'testhost'

    @patch('subprocess.Popen')
    def test_check_service_status_changed(self, mock_popen):
        """Verify check_service_status_changed returns '100.150'."""
        proc = MagicMock()
        proc.communicate.return_value = ("160", "")
        mock_popen.return_value = proc
        svc = {
            "service_plugin_cmdline": "cmd", "service_plugin_env": {},
            "current_status": "0", "alarm_raised": None,
            "alarms_to_clear": [], "alarm_to_raise": None,
            "service_status": [
                {"status": "0", "alarm": None},
                {"status": "160",
                 "alarm": {"id": "100.150", "entity_id": "e"}},
            ],
        }
        self.mod.check_service_status(svc)
        self.assertEqual(svc["alarm_to_raise"]["id"], "100.150")

    def test_process_service_alarm_clear_and_raise(self):
        """Verify process_service_alarm_clear returns None."""
        self.mod.api = MagicMock()
        self.mod.api.clear_fault.return_value = True
        self.mod.api.set_fault.return_value = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        mock_pc = sys.modules['plugin_common']
        mock_pc.is_uuid_like.return_value = True
        svc = {"alarms_to_clear": [{"id": "100.150", "entity_id": "e"}],
               "alarm_to_raise": {"id": "100.150", "entity_id": "e",
                                  "severity": "major", "reason": "r", "repair": "f"},
               "alarm_raised": None, "service_name": "test"}
        self.mod.process_service_alarm(svc)
        self.assertIsNone(svc["alarm_to_raise"])

    def test_read_func_not_init(self):
        """Verify read_func_not_init returns 0 when not initialized."""
        self.mod.obj.init_complete = False
        self.mod.obj.config_complete.return_value = False
        result = self.mod.read_func()
        self.assertEqual(result, 0)

    def test_read_func_not_ready(self):
        """Verify read_func_not_ready returns 0 when not ready."""
        self.mod.obj.init_complete = True
        self.mod.obj._node_ready = False
        result = self.mod.read_func()
        self.assertEqual(result, 0)

    @patch('subprocess.Popen')
    def test_read_func_running(self, mock_popen):
        """Verify read_func_running returns None."""
        proc = MagicMock()
        proc.communicate.return_value = ("0", "")
        mock_popen.return_value = proc
        self.mod.obj.init_complete = True
        self.mod.obj._node_ready = True
        self.mod.api = MagicMock()
        self.mod.api.clear_fault.return_value = True
        self.mod.services = [{"service_plugin_cmdline": "cmd",
                              "service_plugin_env": {},
                              "current_status": "0",
                              "alarm_raised": None,
                              "alarms_to_clear": [],
                              "alarm_to_raise": None,
                              "service_status": [{"status": "0", "alarm": None}],
                              "service_name": "test"}]
        result = self.mod.read_func()
        self.assertEqual(result, None)


class TestExampleExtended2(unittest.TestCase):
    """Cover example.py config_func, init_func, read_func."""

    def test_config_func_with_data(self):
        """Verify config_func_with_data returns 0."""
        from src import example
        node = MagicMock()
        node.key = 'data'
        node.values = ['1 100']
        config = MagicMock()
        config.children = [node]
        example.obj = MagicMock()
        result = example.config_func(config)
        self.assertEqual(result, 0)

    def test_config_func_no_match(self):
        """Verify config_func_no_match returns 0."""
        from src import example
        config = MagicMock()
        config.children = []
        result = example.config_func(config)
        self.assertEqual(result, 0)

    def test_init_func_complete(self):
        """Verify init_func_complete is called once."""
        from src import example
        example.obj = MagicMock()
        example.obj.config_complete.return_value = True
        result = example.init_func()
        self.assertEqual(result, 0)
        example.obj.init_completed.assert_called_once()

    def test_init_func_not_complete(self):
        """Verify init_func_not_complete returns False when not."""
        from src import example
        example.obj = MagicMock()
        example.obj.config_complete.return_value = False
        result = example.init_func()
        self.assertFalse(result)

    def test_read_func_not_init(self):
        """Verify read_func_not_init returns 0 when not initialized."""
        from src import example
        example.obj = MagicMock()
        example.obj.init_complete = False
        example.obj.config_complete.return_value = False
        result = example.read_func()
        self.assertEqual(result, 0)

    def test_read_func_not_ready(self):
        """Verify read_func_not_ready returns 0 when not ready."""
        from src import example
        example.obj = MagicMock()
        example.obj.init_complete = True
        example.obj._node_ready = False
        result = example.read_func()
        self.assertEqual(result, 0)

    def test_read_func_dispatch(self):
        """Verify read_func_dispatch returns 0."""
        from src import example
        example.obj = MagicMock()
        example.obj.init_complete = True
        example.obj._node_ready = True
        example.obj.plugin_data = ['1', '100']
        example.obj.hostname = 'testhost'
        result = example.read_func()
        self.assertEqual(result, 0)


class TestCguHandlerExtended2(unittest.TestCase):
    """Cover cgu_handler.py init and read_cgu."""

    def test_init_netlink_dpll_success(self):
        """Verify init_netlink_dpll_success returns non-None value on."""
        from src.cgu_handler import CguHandler
        handler = CguHandler.__new__(CguHandler)
        handler._dpll = None
        with patch.object(sys.modules['pynetlink'], 'NetlinkDPLL',
                          return_value=MagicMock()):
            handler._initialize_netlink_dpll()
        self.assertIsNotNone(handler._dpll)

    def test_read_cgu_with_dpll(self):
        """Verify read_cgu_with_dpll returns []."""
        from src.cgu_handler import CguHandler
        handler = CguHandler.__new__(CguHandler)
        handler._dpll = MagicMock()
        handler._dpll.get_all_devices.return_value = [{'id': 1}]
        handler._dpll.get_all_pins.return_value = [{'id': 2}]
        handler._devices = None
        handler._pins = None
        handler.read_cgu()
        self.assertEqual(handler._devices, [{'id': 1}])


if __name__ == '__main__':
    unittest.main()
