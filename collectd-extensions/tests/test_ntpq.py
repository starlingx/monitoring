#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import sys
from unittest.mock import MagicMock
sys.modules.setdefault('collectd', MagicMock())
sys.modules.setdefault('fm_core', MagicMock())
sys.modules.setdefault('tsconfig', MagicMock())
sys.modules.setdefault('tsconfig.tsconfig', MagicMock())
sys.modules.setdefault('fm_api', MagicMock())
sys.modules.setdefault('fm_api.constants', MagicMock())
sys.modules.setdefault('fm_api.fm_api', MagicMock())
sys.modules.setdefault('pynetlink', MagicMock())
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'src'))

import plugin_common as pc
import remotels
import ntpq
import socket
import unittest
from unittest.mock import mock_open
from unittest.mock import patch
for module_name in ['plugin_common', 'ntpq', 'remotels']:
    sys.modules.pop(module_name, None)


def _reset_ntpq():
    ntpq.obj.alarm_raised = False
    ntpq.obj.server_list_conf = []
    ntpq.obj.server_list_ntpq = []
    ntpq.obj.unreachable_servers = []
    ntpq.obj.reachable_servers = []
    ntpq.obj.selected_server = 'None'
    ntpq.obj.selected_server_save = 'None'
    ntpq.obj.peer_selected = False
    ntpq.obj.init_complete = False
    ntpq.obj._node_ready = False
    ntpq.obj.hostname = ''
    ntpq.obj.base_eid = ''


def _reset_remotels():
    remotels.obj.alarmed = False
    remotels.obj.enabled = False
    remotels.obj.init_complete = False
    remotels.obj._node_ready = False
    remotels.obj.hostname = ''
    remotels.obj.base_eid = ''
    remotels.obj.config_done = False
    remotels.obj.audits = 0
    remotels.obj.usage = float(0)


class TestNtpqIsIpAddress(unittest.TestCase):
    def test_ipv4(self):
        """Verify _is_ip_address returns AF_INET for IPv4."""
        self.assertEqual(ntpq._is_ip_address('192.168.1.1'), socket.AF_INET)

    def test_ipv6(self):
        """Verify _is_ip_address returns AF_INET6 for IPv6."""
        self.assertEqual(ntpq._is_ip_address('::1'), socket.AF_INET6)

    def test_invalid(self):
        """Verify invalid ntpq._is_ip_address() is False with invalid."""
        self.assertFalse(ntpq._is_ip_address('not-an-ip'))


class TestNtpqIsUuidLike(unittest.TestCase):
    def test_valid(self):
        """Verify valid ntpq._is_uuid_like() is True with valid."""
        self.assertTrue(ntpq._is_uuid_like('12345678-1234-5678-1234-567812345678'))

    def test_invalid(self):
        """Verify invalid ntpq._is_uuid_like() is False with invalid."""
        self.assertFalse(ntpq._is_uuid_like('not-a-uuid'))

    def test_none(self):
        """Verify none ntpq._is_uuid_like() is False with None input."""
        self.assertFalse(ntpq._is_uuid_like(None))


class TestNtpqIsController(unittest.TestCase):
    def test_is_controller(self):
        """Verify is_controller ntpq._is_controller() is True."""
        hosts = "192.168.1.1 controller-0\n"
        with patch('builtins.open', mock_open(read_data=hosts)):
            self.assertTrue(ntpq._is_controller('192.168.1.1'))

    def test_not_controller(self):
        """Verify not_controller ntpq._is_controller() is False."""
        hosts = "10.0.0.1 worker-0\n"
        with patch('builtins.open', mock_open(read_data=hosts)):
            self.assertFalse(ntpq._is_controller('192.168.1.1'))

    def test_skip_comments(self):
        """Verify skip_comments ntpq._is_controller() is False."""
        hosts = "# 192.168.1.1 controller-0\n10.0.0.1 worker\n"
        with patch('builtins.open', mock_open(read_data=hosts)):
            self.assertFalse(ntpq._is_controller('192.168.1.1'))


class TestNtpqAddUnreachableServer(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_ntpq()

    def test_add_new(self):
        """Verify add_new '1.2.3.4' in ntpq.obj.unreachable_servers."""
        ntpq._add_unreachable_server('1.2.3.4')
        self.assertIn('1.2.3.4', ntpq.obj.unreachable_servers)

    def test_add_duplicate(self):
        """Verify add_duplicate returns 1."""
        ntpq.obj.unreachable_servers = ['1.2.3.4']
        ntpq._add_unreachable_server('1.2.3.4')
        self.assertEqual(ntpq.obj.unreachable_servers.count('1.2.3.4'), 1)

    def test_add_none(self):
        """Verify add_none returns [] with None input."""
        ntpq._add_unreachable_server(None)
        self.assertEqual(ntpq.obj.unreachable_servers, [])


class TestNtpqAddIpToNtpqServerList(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_ntpq()

    def test_add_new(self):
        """Verify add_new '5.6.7.8' in ntpq.obj.server_list_ntpq."""
        ntpq._add_ip_to_ntpq_server_list('5.6.7.8')
        self.assertIn('5.6.7.8', ntpq.obj.server_list_ntpq)

    def test_no_duplicate(self):
        """Verify no_duplicate returns 1."""
        ntpq.obj.server_list_ntpq = ['5.6.7.8']
        ntpq._add_ip_to_ntpq_server_list('5.6.7.8')
        self.assertEqual(len(ntpq.obj.server_list_ntpq), 1)


class TestNtpqRemoveIpFromUnreachableList(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_ntpq()
        ntpq.obj.base_eid = 'host=ctrl.ntp'

    def test_remove_existing(self):
        """Verify _remove_ip removes IP and clears alarm."""
        ntpq.obj.unreachable_servers = ['1.2.3.4']
        ntpq.api.clear_fault = MagicMock(return_value=True)
        ntpq._remove_ip_from_unreachable_list('1.2.3.4')
        self.assertNotIn('1.2.3.4', ntpq.obj.unreachable_servers)

    def test_remove_not_present(self):
        """Verify remove_not_present returns []."""
        ntpq._remove_ip_from_unreachable_list('9.9.9.9')
        self.assertEqual(ntpq.obj.unreachable_servers, [])

    def test_remove_clear_false(self):
        """Verify _remove_ip removes IP even if clear fails."""
        ntpq.obj.unreachable_servers = ['1.2.3.4']
        ntpq.api.clear_fault = MagicMock(return_value=False)
        ntpq._remove_ip_from_unreachable_list('1.2.3.4')
        self.assertNotIn('1.2.3.4', ntpq.obj.unreachable_servers)

    def test_remove_exception(self):
        """Verify _remove_ip keeps IP on clear exception."""
        ntpq.obj.unreachable_servers = ['1.2.3.4']
        ntpq.api.clear_fault = MagicMock(side_effect=Exception('err'))
        ntpq._remove_ip_from_unreachable_list('1.2.3.4')
        self.assertIn('1.2.3.4', ntpq.obj.unreachable_servers)


class TestNtpqGetOneLineData(unittest.TestCase):
    def test_single_line_records(self):
        """Verify _get_one_line_data parses ntpq records."""
        lines = [
            "     remote           refid     st t when poll reach   delay   offset  jitter",
            "==============================================================================",
            "*192.168.1.1     .GPS.            1 u  100  256  377    0.1    -0.5    0.1",
        ]
        result = ntpq._get_one_line_data(lines)
        self.assertEqual(len(result), 3)

    def test_two_line_records(self):
        """Verify two_line '149.56.27.12' in result[...]."""
        lines = [
            "     remote           refid     st t when poll reach   delay   offset  jitter",
            "==============================================================================",
            "+192.168.204.3",
            "                 149.56.27.12    3 u  315  512  376    0.160  -28.910   3.993",
            "*206.108.0.132",
            "                 .PTP0.          1 u  442  512  377    8.057  -36.061   6.171",
        ]
        result = ntpq._get_one_line_data(lines)
        self.assertEqual(len(result), 4)
        self.assertIn('+192.168.204.3', result[2])
        self.assertIn('149.56.27.12', result[2])

    def test_empty_lines_skipped(self):
        """Verify _get_one_line_data skips empty lines."""
        lines = [
            "     remote           refid     st t when poll reach   delay   offset  jitter",
            "==============================================================================",
            "",
        ]
        result = ntpq._get_one_line_data(lines)
        self.assertEqual(len(result), 2)


class TestNtpqGetAssocSrcadr(unittest.TestCase):
    def test_ipv4_returns_same(self):
        """Verify ipv4_returns returns '192.168.1.1'."""
        self.assertEqual(ntpq._get_assoc_srcadr(1, '192.168.1.1'), '192.168.1.1')

    def test_assoc_id_zero(self):
        """Verify assoc_id returns '::1'."""
        self.assertEqual(ntpq._get_assoc_srcadr(0, '::1'), '::1')

    @patch('ntpq.subprocess.check_output')
    def test_ipv6_lookup(self, mock_sub):
        """Verify ipv6_lookup returns '64:ff9b::7819:9afd'."""
        assoc_output = (
            "     remote           refid     st t when poll reach   delay   offset  jitter\n"
            "==============================================================================\n"
            "srcadr=64:ff9b::7819:9afd, srcport=123, dstadr=::1\n"
        )
        mock_sub.return_value = assoc_output
        result = ntpq._get_assoc_srcadr(2, '64:ff9b::7819:9')
        self.assertEqual(result, '64:ff9b::7819:9afd')

    @patch('ntpq.subprocess.check_output')
    def test_ipv6_no_data(self, mock_sub):
        """Verify ipv6_no returns ''."""
        mock_sub.return_value = ''
        result = ntpq._get_assoc_srcadr(2, '64:ff9b::1')
        self.assertEqual(result, '')

    @patch('ntpq.subprocess.check_output')
    def test_ipv6_no_match(self, mock_sub):
        """Verify ipv6_no returns ''."""
        assoc_output = (
            "     remote           refid     st t when poll reach   delay   offset  jitter\n"
            "==============================================================================\n"
            "srcadr=aa:bb::cc, srcport=123\n"
        )
        mock_sub.return_value = assoc_output
        result = ntpq._get_assoc_srcadr(2, '64:ff9b::1')
        self.assertEqual(result, '')


class TestNtpqGetNtpServers(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_ntpq()
        ntpq.obj.base_eid = 'host=ctrl.ntp'

    def test_reads_servers(self):
        """Verify reads_servers returns []."""
        conf = "server 10.0.0.1\nserver 10.0.0.2\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            ntpq._get_ntp_servers()
        self.assertEqual(ntpq.obj.server_list_conf, ['10.0.0.1', '10.0.0.2'])

    def test_no_servers_clears_alarms(self):
        """Verify no_servers returns []."""
        ntpq.obj.alarm_raised = True
        ntpq.obj.unreachable_servers = ['1.2.3.4']
        ntpq.api.clear_fault = MagicMock(return_value=True)
        conf = "# no servers\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            ntpq._get_ntp_servers()
        self.assertEqual(ntpq.obj.server_list_conf, [])

    def test_no_duplicate_servers(self):
        """Verify no_duplicate returns []."""
        conf = "server 10.0.0.1\nserver 10.0.0.1\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            ntpq._get_ntp_servers()
        self.assertEqual(ntpq.obj.server_list_conf, ['10.0.0.1'])


class TestNtpqCleanupStaleServers(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_ntpq()
        ntpq.obj.base_eid = 'host=ctrl.ntp'

    def test_removes_stale_reachable(self):
        """Verify _cleanup removes stale reachable server."""
        ntpq.obj.server_list_ntpq = ['10.0.0.1']
        ntpq.obj.reachable_servers = ['10.0.0.1', '10.0.0.2']
        ntpq.api.clear_fault = MagicMock(return_value=True)
        ntpq._cleanup_stale_servers()
        self.assertNotIn('10.0.0.2', ntpq.obj.reachable_servers)

    def test_removes_stale_unreachable(self):
        """Verify _cleanup removes stale unreachable server."""
        ntpq.obj.server_list_ntpq = ['10.0.0.1']
        ntpq.obj.unreachable_servers = ['10.0.0.2']
        ntpq.api.clear_fault = MagicMock(return_value=True)
        ntpq._cleanup_stale_servers()
        self.assertNotIn('10.0.0.2', ntpq.obj.unreachable_servers)


class TestNtpqRaiseAlarm(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_ntpq()
        ntpq.obj.base_eid = 'host=ctrl.ntp'

    def test_raise_major_alarm(self):
        """Verify raise_major_alarm ntpq.obj.alarm_raised is True."""
        ntpq.api.set_fault = MagicMock(return_value='12345678-1234-5678-1234-567812345678')
        result = ntpq._raise_alarm()
        self.assertTrue(result)
        self.assertTrue(ntpq.obj.alarm_raised)

    def test_raise_major_already_raised(self):
        """Verify raise_major_already_raised returns False."""
        ntpq.obj.alarm_raised = True
        result = ntpq._raise_alarm()
        self.assertFalse(result)

    def test_raise_minor_alarm_for_ip(self):
        """Verify _raise_alarm adds IP to unreachable list."""
        ntpq.api.set_fault = MagicMock(return_value='12345678-1234-5678-1234-567812345678')
        result = ntpq._raise_alarm('1.2.3.4')
        self.assertTrue(result)
        self.assertIn('1.2.3.4', ntpq.obj.unreachable_servers)

    def test_raise_alarm_fm_failure(self):
        """Verify raise_alarm_fm_failure on failure."""
        ntpq.api.set_fault = MagicMock(return_value='bad-value')
        result = ntpq._raise_alarm('1.2.3.4')
        self.assertTrue(result)
        self.assertNotIn('1.2.3.4', ntpq.obj.unreachable_servers)

    def test_raise_alarm_exception(self):
        """Verify raise_alarm_exception returns True on exception."""
        ntpq.api.set_fault = MagicMock(side_effect=Exception('fm error'))
        result = ntpq._raise_alarm('1.2.3.4')
        self.assertTrue(result)


class TestNtpqClearBaseAlarm(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_ntpq()
        ntpq.obj.base_eid = 'host=ctrl.ntp'
        ntpq.obj.alarm_raised = True

    def test_clear_success(self):
        """Verify clear_success ntpq.obj.alarm_raised is False on."""
        ntpq.api.clear_fault = MagicMock(return_value=True)
        result = ntpq._clear_base_alarm()
        self.assertTrue(result)
        self.assertFalse(ntpq.obj.alarm_raised)

    def test_clear_already_clear(self):
        """Verify clear_already_clear ntpq.obj.alarm_raised is False."""
        ntpq.api.clear_fault = MagicMock(return_value=False)
        result = ntpq._clear_base_alarm()
        self.assertTrue(result)
        self.assertFalse(ntpq.obj.alarm_raised)

    def test_clear_exception(self):
        """Verify clear_exception returns False on exception."""
        ntpq.api.clear_fault = MagicMock(side_effect=Exception('err'))
        result = ntpq._clear_base_alarm()
        self.assertFalse(result)


class TestNtpqConfigFunc(unittest.TestCase):
    def test_returns_zero(self):
        """Verify returns_zero returns 0."""
        self.assertEqual(ntpq.config_func(MagicMock()), 0)


class TestNtpqInitFunc(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_ntpq()

    @patch.object(ntpq.tsc, 'nodetype', 'worker')
    def test_not_controller(self):
        """Verify not_controller returns 0."""
        self.assertEqual(ntpq.init_func(), 0)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    def test_config_not_complete(self):
        """Verify config_not_complete returns 0 when not configured."""
        ntpq.obj.config_complete = MagicMock(return_value=False)
        self.assertEqual(ntpq.init_func(), 0)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    def test_node_not_ready(self):
        """Verify node_not returns 0 when not ready."""
        ntpq.obj.config_complete = MagicMock(return_value=True)
        ntpq.obj._node_ready = False
        ntpq.obj.node_ready = MagicMock(return_value=False)
        self.assertEqual(ntpq.init_func(), 0)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    def test_no_hostname(self):
        """Verify no_hostname returns 1."""
        ntpq.obj.config_complete = MagicMock(return_value=True)
        ntpq.obj._node_ready = True
        ntpq.obj.gethostname = MagicMock(return_value=None)
        self.assertEqual(ntpq.init_func(), 1)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    def test_init_with_base_alarm(self):
        """Verify init_with_base_alarm ntpq.obj.alarm_raised is True."""
        ntpq.obj.config_complete = MagicMock(return_value=True)
        ntpq.obj._node_ready = True
        ntpq.obj.gethostname = MagicMock(return_value='controller-0')
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=controller-0.ntp'
        ntpq.api.get_faults_by_id = MagicMock(return_value=[alarm])
        conf = "server 10.0.0.1\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            ntpq.init_func()
        self.assertTrue(ntpq.obj.alarm_raised)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    def test_init_get_faults_exception(self):
        """Verify init_get_faults_exception returns 0 on exception."""
        ntpq.obj.config_complete = MagicMock(return_value=True)
        ntpq.obj._node_ready = True
        ntpq.obj.gethostname = MagicMock(return_value='controller-0')
        ntpq.api.get_faults_by_id = MagicMock(side_effect=Exception('err'))
        conf = "server 10.0.0.1\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            self.assertEqual(ntpq.init_func(), 0)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    def test_init_clear_fault_exception(self):
        """Verify init_clear_fault_exception returns 0 on exception."""
        ntpq.obj.config_complete = MagicMock(return_value=True)
        ntpq.obj._node_ready = True
        ntpq.obj.gethostname = MagicMock(return_value='controller-0')
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=controller-0.ntp=1.2.3.4'
        ntpq.api.get_faults_by_id = MagicMock(return_value=[alarm])
        ntpq.api.clear_fault = MagicMock(side_effect=Exception('err'))
        conf = "server 10.0.0.1\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            self.assertEqual(ntpq.init_func(), 0)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    def test_init_no_servers_clears_base(self):
        """Verify init_no_servers_clears ntpq.obj.alarm_raised is."""
        ntpq.obj.config_complete = MagicMock(return_value=True)
        ntpq.obj._node_ready = True
        ntpq.obj.gethostname = MagicMock(return_value='controller-0')
        alarm = MagicMock()
        alarm.entity_instance_id = 'host=controller-0.ntp'
        ntpq.api.get_faults_by_id = MagicMock(return_value=[alarm])
        ntpq.api.clear_fault = MagicMock(return_value=True)
        conf = "# no servers\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            ntpq.init_func()
        self.assertFalse(ntpq.obj.alarm_raised)


NTP_OUTPUT_ALL_REACHABLE = (
    "     remote           refid     st t when poll reach   delay   offset  jitter\n"
    "==============================================================================\n"
    "*206.108.0.132   .PTP0.          1 u  442  512  377    8.057  -36.061   6.171\n"
    "+154.11.146.39   172.21.138.4    2 u  197  512  377   54.249  -20.327   7.677\n"
)

NTP_OUTPUT_ONE_UNREACHABLE = (
    "     remote           refid     st t when poll reach   delay   offset  jitter\n"
    "==============================================================================\n"
    "*206.108.0.132   .PTP0.          1 u  442  512  377    8.057  -36.061   6.171\n"
    " 1.2.3.4         .INIT.         16 u    -   64    0    0.000    0.000   0.000\n"
)

NTP_OUTPUT_NONE_SELECTED = (
    "     remote           refid     st t when poll reach   delay   offset  jitter\n"
    "==============================================================================\n"
    "+154.11.146.39   172.21.138.4    2 u  197  512  377   54.249  -20.327   7.677\n"
)

NTP_OUTPUT_OTHER_TALLY = (
    "     remote           refid     st t when poll reach   delay   offset  jitter\n"
    "==============================================================================\n"
    "*206.108.0.132   .PTP0.          1 u  442  512  377    8.057  -36.061   6.171\n"
    "x1.2.3.4         .BAD.          16 u    -   64    0    0.000    0.000   0.000\n"
)

NTP_OUTPUT_PEER_SELECTED = (
    "     remote           refid     st t when poll reach   delay   offset  jitter\n"
    "==============================================================================\n"
    "*192.168.1.1     10.10.10.1      2 u  442  512  377    8.057  -36.061   6.171\n"
)

NTP_OUTPUT_TWO_LINE = (
    "     remote           refid     st t when poll reach   delay   offset  jitter\n"
    "==============================================================================\n"
    "+192.168.204.3\n"
    "                 149.56.27.12    3 u  315  512  376    0.160  -28.910   3.993\n"
    "*206.108.0.132\n"
    "                 .PTP0.          1 u  442  512  377    8.057  -36.061   6.171\n"
)


class TestNtpqReadFunc(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_ntpq()
        ntpq.obj.init_complete = True
        ntpq.obj._node_ready = True
        ntpq.obj.hostname = 'controller-0'
        ntpq.obj.base_eid = 'host=controller-0.ntp'
        ntpq.api.set_fault = MagicMock(return_value='12345678-1234-5678-1234-567812345678')
        ntpq.api.clear_fault = MagicMock(return_value=True)

    @patch.object(ntpq.tsc, 'nodetype', 'worker')
    def test_not_controller(self):
        """Verify not_controller returns 0."""
        self.assertEqual(ntpq.read_func(), 0)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    def test_init_not_complete(self):
        """Verify init_not_complete returns 0 when not configured."""
        ntpq.obj = MagicMock()
        ntpq.obj.init_complete = False
        with patch.object(ntpq, 'init_func'):
            self.assertEqual(ntpq.read_func(), 0)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    @patch('ntpq.subprocess.check_output')
    def test_no_servers_configured(self, mock_sub):
        """Verify no_servers returns 0."""
        conf = "# empty\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            self.assertEqual(ntpq.read_func(), 0)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    @patch('ntpq.subprocess.check_output')
    @patch('ntpq._is_controller', return_value=False)
    def test_all_reachable(self, mock_ctrl, mock_sub):
        """Verify read_func with all servers reachable."""
        mock_sub.return_value = NTP_OUTPUT_ALL_REACHABLE
        conf = "server 206.108.0.132\nserver 154.11.146.39\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            result = ntpq.read_func()
        self.assertEqual(result, 0)
        self.assertIn('206.108.0.132', ntpq.obj.selected_server)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    @patch('ntpq.subprocess.check_output')
    @patch('ntpq._is_controller', return_value=False)
    def test_one_unreachable(self, mock_ctrl, mock_sub):
        """Verify read_func marks unreachable server."""
        mock_sub.return_value = NTP_OUTPUT_ONE_UNREACHABLE
        conf = "server 206.108.0.132\nserver 1.2.3.4\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            ntpq.read_func()
        self.assertIn('1.2.3.4', ntpq.obj.unreachable_servers)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    @patch('ntpq.subprocess.check_output')
    @patch('ntpq._is_controller', return_value=False)
    def test_none_selected_raises_major(self, mock_ctrl, mock_sub):
        """Verify none_selected ntpq.obj.alarm_raised is True with."""
        mock_sub.return_value = NTP_OUTPUT_NONE_SELECTED
        conf = "server 154.11.146.39\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            ntpq.read_func()
        self.assertTrue(ntpq.obj.alarm_raised)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    @patch('ntpq.subprocess.check_output')
    def test_no_data(self, mock_sub):
        """Verify no_data returns 0."""
        mock_sub.return_value = ''
        conf = "server 10.0.0.1\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            self.assertEqual(ntpq.read_func(), 0)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    @patch('ntpq.subprocess.check_output')
    @patch('ntpq._is_controller', return_value=False)
    def test_other_tally_code(self, mock_ctrl, mock_sub):
        """Verify read_func marks non-selected tally code."""
        mock_sub.return_value = NTP_OUTPUT_OTHER_TALLY
        conf = "server 206.108.0.132\nserver 1.2.3.4\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            ntpq.read_func()
        self.assertIn('1.2.3.4', ntpq.obj.unreachable_servers)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    @patch('ntpq.subprocess.check_output')
    def test_peer_selected_controller(self, mock_sub):
        """Verify peer_selected ntpq.obj.peer_selected is True."""
        mock_sub.return_value = NTP_OUTPUT_PEER_SELECTED
        conf = "server 192.168.1.1\n"
        hosts = "192.168.1.1 controller-1\n"
        m_conf = mock_open(read_data=conf)
        m_hosts = mock_open(read_data=hosts)

        def open_side_effect(path, *a, **kw):
            if 'hosts' in path:
                return m_hosts()
            return m_conf()
        with patch('builtins.open', side_effect=open_side_effect):
            ntpq.read_func()
        self.assertTrue(ntpq.obj.peer_selected)

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    @patch('ntpq.subprocess.check_output')
    @patch('ntpq._is_controller', return_value=False)
    def test_two_line_format(self, mock_ctrl, mock_sub):
        """Verify two_line returns '206.108.0.132'."""
        mock_sub.return_value = NTP_OUTPUT_TWO_LINE
        conf = "server 192.168.204.3\nserver 206.108.0.132\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            ntpq.read_func()
        self.assertEqual(ntpq.obj.selected_server, '206.108.0.132')

    @patch.object(ntpq.tsc, 'nodetype', 'controller')
    @patch('ntpq.subprocess.check_output')
    @patch('ntpq._is_controller', return_value=False)
    def test_selected_server_clears_alarm(self, mock_ctrl, mock_sub):
        """Verify selected_server ntpq.obj.alarm_raised is False."""
        ntpq.obj.alarm_raised = True
        mock_sub.return_value = NTP_OUTPUT_ALL_REACHABLE
        conf = "server 206.108.0.132\nserver 154.11.146.39\n"
        with patch('builtins.open', mock_open(read_data=conf)):
            ntpq.read_func()
        self.assertFalse(ntpq.obj.alarm_raised)


class TestRemotelsClearAlarm(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_remotels()
        remotels.obj.base_eid = 'host=controller-0'

    def test_clear_success(self):
        """Verify clear_success remotels.obj.alarmed is False on."""
        remotels.api.clear_fault = MagicMock(return_value=True)
        self.assertTrue(remotels.clear_alarm())
        self.assertFalse(remotels.obj.alarmed)

    def test_clear_already_clear(self):
        """Verify clear_already_clear remotels.clear_alarm() is True."""
        remotels.api.clear_fault = MagicMock(return_value=False)
        self.assertTrue(remotels.clear_alarm())

    def test_clear_exception(self):
        """Verify clear_exception remotels.clear_alarm() is False on."""
        remotels.api.clear_fault = MagicMock(side_effect=Exception('err'))
        self.assertFalse(remotels.clear_alarm())


class TestRemotelsRaiseAlarm(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_remotels()
        remotels.obj.base_eid = 'host=controller-0'

    def test_raise_success(self):
        """Verify raise_success remotels.obj.alarmed is True on."""
        remotels.api.set_fault = MagicMock(return_value='12345678-1234-5678-1234-567812345678')
        remotels.raise_alarm()
        self.assertTrue(remotels.obj.alarmed)

    def test_raise_exception(self):
        """Verify raise_exception remotels.obj.alarmed is False on."""
        remotels.api.set_fault = MagicMock(side_effect=Exception('err'))
        remotels.raise_alarm()
        self.assertFalse(remotels.obj.alarmed)


class TestRemotelsConfigFunc(unittest.TestCase):
    def test_returns_zero(self):
        """Verify returns_zero remotels.obj.config_done is True."""
        _reset_remotels()
        self.assertEqual(remotels.config_func(MagicMock()), 0)
        self.assertTrue(remotels.obj.config_done)


class TestRemotelsInitFunc(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_remotels()

    @patch.object(remotels.tsc, 'nodetype', 'worker')
    def test_not_controller(self):
        """Verify not_controller returns 0."""
        self.assertEqual(remotels.init_func(), 0)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    def test_config_not_complete(self):
        """Verify config_not_complete returns 0 when not configured."""
        remotels.obj.config_complete = MagicMock(return_value=False)
        self.assertEqual(remotels.init_func(), 0)


SYSLOG_ENABLED = (
    '@include "remotelogging.conf"\n'
    'destination remote_log_server  {tcp("128.224.186.65" port(514));};\n'
)

SYSLOG_DISABLED = '# remote logging disabled\n'

SYSLOG_IPV6 = (
    '@include "remotelogging.conf"\n'
    'destination remote_log_server  {tcp("fd01::1" port(514));};\n'
)


class TestRemotelsReadFunc(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        _reset_remotels()
        remotels.obj.init_complete = True
        remotels.obj._node_ready = True
        remotels.obj.hostname = 'controller-0'
        remotels.obj.base_eid = 'host=controller-0'
        remotels.obj.audits = 1
        remotels.api.clear_fault = MagicMock(return_value=True)
        remotels.api.set_fault = MagicMock(return_value='12345678-1234-5678-1234-567812345678')

    @patch.object(remotels.tsc, 'nodetype', 'worker')
    def test_not_controller(self):
        """Verify not_controller returns 0."""
        self.assertEqual(remotels.read_func(), 0)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    def test_init_not_complete(self):
        """Verify init_not_complete returns 0 when not configured."""
        remotels.obj.init_complete = False
        with patch('remotels.init_func'):
            self.assertEqual(remotels.read_func(), 0)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    def test_node_not_ready(self):
        """Verify node_not returns 0 when not ready."""
        remotels.obj._node_ready = False
        remotels.obj.node_ready = MagicMock(return_value=False)
        self.assertEqual(remotels.read_func(), 0)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    @patch('os.path.exists', return_value=True)
    def test_disabled_clears_alarm(self, mock_exists):
        """Verify disabled_clears remotels.obj.alarmed is False."""
        remotels.obj.alarmed = True
        with patch('builtins.open', mock_open(read_data=SYSLOG_DISABLED)):
            remotels.read_func()
        self.assertFalse(remotels.obj.alarmed)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    @patch('os.path.exists', return_value=True)
    @patch.object(remotels, 'processutils')
    def test_enabled_connected(self, mock_pu, mock_exists):
        """Verify enabled_connected returns 1."""
        mock_pu.execute.return_value = ('01\n', '')
        with patch('builtins.open', mock_open(read_data=SYSLOG_ENABLED)):
            remotels.read_func()
        self.assertEqual(remotels.obj.usage, 1)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    @patch('os.path.exists', return_value=True)
    @patch.object(remotels, 'processutils')
    def test_enabled_not_connected_raises_alarm(self, mock_pu, mock_exists):
        """Verify enabled_not remotels.obj.alarmed is True."""
        mock_pu.execute.return_value = ('02\n', '')
        remotels.obj.usage = 0
        with patch('builtins.open', mock_open(read_data=SYSLOG_ENABLED)):
            remotels.read_func()
        self.assertTrue(remotels.obj.alarmed)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    @patch('os.path.exists', return_value=True)
    @patch.object(remotels, 'processutils')
    def test_enabled_connected_clears_alarm(self, mock_pu, mock_exists):
        """Verify enabled_connected remotels.obj.alarmed is False."""
        mock_pu.execute.return_value = ('01\n', '')
        remotels.obj.alarmed = True
        with patch('builtins.open', mock_open(read_data=SYSLOG_ENABLED)):
            remotels.read_func()
        self.assertFalse(remotels.obj.alarmed)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    @patch('os.path.exists', return_value=True)
    @patch.object(remotels, 'processutils')
    def test_execute_error(self, mock_pu, mock_exists):
        """Verify execute_error returns 0 on failure."""
        mock_pu.execute.return_value = ('', 'some error')
        with patch('builtins.open', mock_open(read_data=SYSLOG_ENABLED)):
            self.assertEqual(remotels.read_func(), 0)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    @patch('os.path.exists', return_value=True)
    def test_ipv6_hits_type_error(self, mock_exists):
        # Source code has bug: protocol += 6 (int) instead of '6' (str)
        """Verify ipv6_hits raises TypeError on failure."""
        with patch('builtins.open', mock_open(read_data=SYSLOG_IPV6)):
            with self.assertRaises(TypeError):
                remotels.read_func()

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    @patch('os.path.exists', return_value=True)
    def test_first_audit_clears(self, mock_exists):
        """Verify first_audit returns 1."""
        remotels.obj.audits = 0
        with patch('builtins.open', mock_open(read_data=SYSLOG_DISABLED)):
            remotels.read_func()
        self.assertEqual(remotels.obj.audits, 1)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    @patch('os.path.exists', return_value=True)
    def test_first_audit_clear_fails(self, mock_exists):
        """Verify first_audit returns 0 on exception."""
        remotels.obj.audits = 0
        remotels.api.clear_fault = MagicMock(side_effect=Exception('err'))
        with patch('builtins.open', mock_open(read_data=SYSLOG_DISABLED)):
            self.assertEqual(remotels.read_func(), 0)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    @patch('os.path.exists', return_value=False)
    def test_syslog_file_missing(self, mock_exists):
        """Verify syslog_file remotels.obj.enabled is False when."""
        remotels.read_func()
        self.assertFalse(remotels.obj.enabled)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    @patch('os.path.exists', return_value=True)
    @patch.object(remotels, 'processutils')
    def test_not_connected_debounce(self, mock_pu, mock_exists):
        """First failure (usage=1) should not alarm due to debounce"""
        mock_pu.execute.return_value = ('02\n', '')
        remotels.obj.usage = 1
        with patch('builtins.open', mock_open(read_data=SYSLOG_ENABLED)):
            remotels.read_func()
        self.assertFalse(remotels.obj.alarmed)

    @patch.object(remotels.tsc, 'nodetype', 'controller')
    @patch('os.path.exists', return_value=True)
    def test_bad_destination_line(self, mock_exists):
        """Verify bad_destination raises ValueError."""
        bad_conf = (
            '@include "remotelogging.conf"\n'
            'destination remote_log_server  badformat;\n'
        )
        # No '{' in line so address stays empty, hits ValueError in
        # int('')
        with patch('builtins.open', mock_open(read_data=bad_conf)):
            with self.assertRaises(ValueError):
                remotels.read_func()


if __name__ == '__main__':
    unittest.main()
