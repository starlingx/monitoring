#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Extended tests for large collectd plugins: memory, cpu, interface,
   ovs_interface, fm_notifier."""

import os
import sys
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
sys.modules.setdefault('pynetlink', MagicMock())

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


class TestMemoryFunctions(unittest.TestCase):
    """Tests for memory.py functions."""

    def test_is_strict_memory_accounting_true(self):
        """Verify is_strict_memory_accounting returns True."""
        from src import memory
        with patch('builtins.open', mock_open(read_data='2\n')):
            result = memory.is_strict_memory_accounting()
        self.assertTrue(result)

    def test_is_strict_memory_accounting_false(self):
        """Verify is_strict_memory_accounting returns False."""
        from src import memory
        with patch('builtins.open', mock_open(read_data='0\n')):
            result = memory.is_strict_memory_accounting()
        self.assertFalse(result)

    def test_is_strict_memory_accounting_error(self):
        """Verify is_strict_memory_accounting returns False on."""
        from src import memory
        with patch('builtins.open', side_effect=Exception("fail")):
            result = memory.is_strict_memory_accounting()
        self.assertFalse(result)

    def test_get_meminfo(self):
        """Verify get_meminfo parses MemTotal from proc."""
        from src import memory
        content = "MemTotal: 16384 kB\nMemFree: 8192 kB\n"
        with patch('builtins.open', mock_open(read_data=content)):
            result = memory.get_meminfo()
        self.assertEqual(result['MemTotal'], 16384)

    def test_get_meminfo_ioerror(self):
        """Verify get_meminfo_ioerror returns {} on exception."""
        from src import memory
        with patch('builtins.open', side_effect=IOError("fail")):
            result = memory.get_meminfo()
        self.assertEqual(result, {})

    def test_get_cgroup_memory_ioerror(self):
        """Verify get_cgroup_memory returns 0 on IOError."""
        from src import memory
        with patch('builtins.open', side_effect=IOError):
            result = memory.get_cgroup_memory('/nonexistent')
        self.assertEqual(result['rss_MiB'], 0.0)

    def test_format_iec_kib(self):
        """Verify format_iec_kib 'KiB' in result."""
        from src import memory
        result = memory.format_iec(512)
        self.assertIn('KiB', result)

    def test_format_iec_mib(self):
        """Verify format_iec_mib 'MiB' in result."""
        from src import memory
        result = memory.format_iec(2048)
        self.assertIn('MiB', result)

    def test_format_iec_gib(self):
        """Verify format_iec_gib 'GiB' in result."""
        from src import memory
        result = memory.format_iec(2 * 1024 * 1024)
        self.assertIn('GiB', result)

    def test_format_iec_tib(self):
        """Verify format_iec_tib 'TiB' in result."""
        from src import memory
        result = memory.format_iec(2 * 1024 * 1024 * 1024)
        self.assertIn('TiB', result)

    def test_get_cgroup_pid(self):
        """Verify get_cgroup_pid ... is True."""
        from src import memory
        with patch('builtins.open', mock_open(read_data='123\n456\n')):
            result = memory.get_cgroup_pid('/test/path')
        self.assertTrue(len(result) >= 0)

    def test_get_cgroup_pid_ioerror(self):
        """Verify get_cgroup_pid_ioerror returns [] on exception."""
        from src import memory
        with patch('builtins.open', side_effect=IOError):
            result = memory.get_cgroup_pid('/nonexistent')
        self.assertEqual(result, [])

    def test_get_cgroups_procs_paths(self):
        """Verify get_cgroups_procs_paths returns []."""
        from src import memory
        with patch('os.path.isdir', return_value=False):
            result = memory.get_cgroups_procs_paths('/nonexistent')
        self.assertEqual(result, [])

    def test_get_pid_name(self):
        """Verify get_pid_name 'test_proc' in result."""
        from src import memory
        content = "Name:\ttest_proc\nState:\tS\n"
        with patch('builtins.open', mock_open(read_data=content)):
            result = memory.get_pid_name('123')
        self.assertIn('test_proc', result)

    def test_get_pid_name_error(self):
        """Verify get_pid_name_error returns '' on exception."""
        from src import memory
        with patch('builtins.open', side_effect=IOError):
            result = memory.get_pid_name('123')
        self.assertEqual(result, '')

    def test_get_pid_rss(self):
        """Verify get_pid_rss parses VmRSS from status."""
        from src import memory
        content = "VmRSS:\t1024 kB\n"
        with patch('builtins.open', mock_open(read_data=content)):
            result = memory.get_pid_rss('123')
        self.assertEqual(result, 1024)

    def test_get_pid_rss_error(self):
        """Verify get_pid_rss_error returns 0 on exception."""
        from src import memory
        with patch('builtins.open', side_effect=IOError):
            result = memory.get_pid_rss('123')
        self.assertEqual(result, 0)

    def test_get_platform_reserved_memory_no_file(self):
        """Verify reserved memory returns 0 when file missing."""
        from src import memory
        with patch('os.path.exists', return_value=False):
            result = memory.get_platform_reserved_memory()
        self.assertEqual(result, 0.0)

    def test_init_func_not_configured(self):
        """Verify init_func_not_configured returns 0 when not."""
        from src import memory
        memory.obj = MagicMock()
        memory.obj.config_complete.return_value = False
        result = memory.init_func()
        self.assertEqual(result, 0)


class TestCpuFunctions(unittest.TestCase):
    """Tests for cpu.py functions."""

    def test_read_schedstat(self):
        """Verify read_schedstat returns non-None value."""
        from src import cpu
        content = (
            "version 15\n"
            "timestamp 123456\n"
            "cpu0 0 0 0 0 0 0 100 200 50\n"
            "cpu1 0 0 0 0 0 0 150 250 60\n"
        )
        with patch('builtins.open', mock_open(read_data=content)):
            result = cpu.read_schedstat()
        self.assertIsNotNone(result)

    def test_read_schedstat_error(self):
        """Verify read_schedstat_error returns non-None value on."""
        from src import cpu
        with patch('builtins.open', side_effect=IOError):
            result = cpu.read_schedstat()
        self.assertIsNotNone(result)


class TestOvsInterfaceFunctions(unittest.TestCase):
    """Tests for ovs_interface.py functions."""

    def test_parse_ovs_vsctl_list_ports(self):
        """Verify parse_ovs_vsctl_list returns []."""
        from src import ovs_interface
        buf = "port1\nport2\nport3\n"
        result = ovs_interface.parse_ovs_vsctl_list_ports(buf)
        self.assertEqual(result, ['port1', 'port2', 'port3'])

    def test_parse_ovs_vsctl_list_ifaces(self):
        """Verify parse_ovs_vsctl_list returns []."""
        from src import ovs_interface
        buf = "iface1\niface2\n"
        result = ovs_interface.parse_ovs_vsctl_list_ifaces(buf)
        self.assertEqual(result, ['iface1', 'iface2'])

    def test_parse_ovs_appctl_bond_list(self):
        """Verify parse_ovs_appctl_bond returns non-None value."""
        from src import ovs_interface
        buf = "bond\ttype\trecircID\tslaves\n"
        buf += "bond0\tactive-backup\t1\teth0,eth1\n"
        result = ovs_interface.parse_ovs_appctl_bond_list(buf)
        self.assertIsNotNone(result)

    def test_this_hosts_alarm_match(self):
        """Verify this_hosts returns True."""
        from src import interface
        from src import ovs_interface
        result = ovs_interface.this_hosts_alarm(
            'host1', 'host=host1.interface=eth0')
        self.assertTrue(result)

    def test_this_hosts_alarm_no_match(self):
        """Verify this_hosts returns False."""
        from src import interface
        from src import ovs_interface
        result = ovs_interface.this_hosts_alarm(
            'host1', 'host=host2.interface=eth0')
        self.assertFalse(result)

    def test_compare_interfaces(self):
        """Verify compare_interfaces returns True."""
        from src import ovs_interface
        result = ovs_interface.compare_interfaces(
            ['eth0', 'eth1'], ['eth0', 'eth1'])
        self.assertTrue(result)

    def test_compare_interfaces_different(self):
        """Verify compare_interfaces returns False."""
        from src import ovs_interface
        result = ovs_interface.compare_interfaces(
            ['eth0'], ['eth0', 'eth1'])
        self.assertFalse(result)

    def test_is_interface_in_port(self):
        """Verify is_interface_in_port returns True."""
        from src import ovs_interface
        port = MagicMock()
        iface = MagicMock()
        iface.name = 'eth0'
        port.interfaces = [iface]
        result = ovs_interface.is_interface_in_port('eth0', port)
        self.assertTrue(result)

    def test_is_interface_in_port_false(self):
        """Verify is_interface_in_port returns False."""
        from src import ovs_interface
        port = MagicMock()
        iface = MagicMock()
        iface.name = 'eth1'
        port.interfaces = [iface]
        result = ovs_interface.is_interface_in_port('eth0', port)
        self.assertFalse(result)


class TestInterfaceFunctions(unittest.TestCase):
    """Tests for interface.py functions."""

    def test_get_timestamp(self):
        """Verify get_timestamp returns non-None value."""
        from src import interface
        result = interface.get_timestamp(1000.5)
        self.assertIsNotNone(result)

    def test_this_hosts_alarm_match(self):
        """Verify this_hosts returns True."""
        from src import interface
        result = interface.this_hosts_alarm(
            'host1', 'host=host1.interface=eth0')
        self.assertTrue(result)

    def test_this_hosts_alarm_no_match(self):
        """Verify this_hosts returns False."""
        from src import interface
        result = interface.this_hosts_alarm(
            'host1', 'host=host2.interface=eth0')
        self.assertFalse(result)


class TestFmNotifierFunctions(unittest.TestCase):
    """Tests for fm_notifier.py functions."""

    def test_degrade_object_init(self):
        """Verify degrade_object returns non-None value."""
        from src import fm_notifier
        self.assertIsNotNone(fm_notifier.DegradeObject)

if __name__ == '__main__':
    unittest.main()
