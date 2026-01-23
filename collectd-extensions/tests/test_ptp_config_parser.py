#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Unit tests for PTP4L configuration parser with duplicate option support
"""

import unittest
import tempfile
import os
import sys
from unittest.mock import MagicMock

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

# Add the src directory to Python path before importing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import the module under test
from ptp import TimingInstance


class TestPtp4lConfigParser(unittest.TestCase):

    def create_temp_ptp4l_config(self, content):
        """Create a temporary ptp4l config file with proper naming"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='-ptp4l-test.conf', delete=False) as f:
            f.write(content)
            return f.name

    def test_sample_config_file(self):
        """Test parsing with the real sample config file"""
        sample_file = os.path.join(os.path.dirname(
            __file__), 'test_input_files', 'ptp4l_unicast_client.conf')
        with open(sample_file, encoding='utf-8') as f:
            content = f.read()
        temp_file = self.create_temp_ptp4l_config(content)

        try:
            instance = TimingInstance(temp_file)
            config = instance.config

            # Test multiple unicast master tables
            tables = config.get_unicast_master_tables()
            self.assertEqual(len(tables), 2)

            # Test table 1 (IPv4)
            table1 = tables['1']
            self.assertEqual(table1['UDPv4'], [
                             '1.1.1.1', '2.2.2.2', '3.3.3.3'])

            # Test table 2 (IPv6)
            table2 = tables['2']
            self.assertEqual(table2['UDPv6'], ['::1', '::2', '::3'])

            # Test interface extraction
            self.assertIn('eno4', instance.interfaces)
            self.assertIn('eno8', instance.interfaces)

        finally:
            os.unlink(temp_file)

    def test_duplicate_options(self):
        """Test duplicate option handling"""
        content = """[global]
boundary_clock_jbod 1

[unicast_master_table]
table_id 1
UDPv4 1.1.1.1
UDPv4 2.2.2.2

[eno4]
unicast_master_table 1
"""
        temp_file = self.create_temp_ptp4l_config(content)

        try:
            instance = TimingInstance(temp_file)
            config = instance.config

            # Test duplicate values stored as list
            udpv4_values = config['unicast_master_table_0']['UDPv4']
            self.assertEqual(udpv4_values, ['1.1.1.1', '2.2.2.2'])

            # Test single values remain strings
            self.assertEqual(config['unicast_master_table_0']['table_id'], '1')

        finally:
            os.unlink(temp_file)

    def test_config_compatibility(self):
        """Test ConfigParser compatibility"""
        content = """[global]
clock_servo linreg

[eno4]
unicast_master_table 1
"""
        temp_file = self.create_temp_ptp4l_config(content)

        try:
            instance = TimingInstance(temp_file)
            config = instance.config

            # Test sections() method
            sections = config.sections()
            self.assertIn('global', sections)
            self.assertIn('eno4', sections)

            # Test has_section() method
            self.assertTrue(config.has_section('global'))
            self.assertTrue(config.has_section('eno4'))
            self.assertFalse(config.has_section('nonexistent'))

            # Test dictionary access
            self.assertEqual(config['global']['clock_servo'], 'linreg')
            self.assertEqual(config['eno4']['unicast_master_table'], '1')

        finally:
            os.unlink(temp_file)

    def test_error_handling(self):
        """Test error handling in ConfigDict"""
        content = """[global]
clock_servo linreg
"""
        temp_file = self.create_temp_ptp4l_config(content)

        try:
            instance = TimingInstance(temp_file)
            config = instance.config

            # Test KeyError for missing section
            with self.assertRaises(KeyError):
                _ = config['nonexistent']

            # Test TypeError for non-string section name in has_section
            with self.assertRaises(TypeError):
                config.has_section(123)

            # Test TypeError for non-string section name in __getitem__
            with self.assertRaises(TypeError):
                _ = config[123]

        finally:
            os.unlink(temp_file)
