#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Unit tests for dpll-mgr managed instance detection and GM write guard.
"""

import json
import os
import sys
import unittest
from collections import OrderedDict
from unittest.mock import MagicMock
from unittest.mock import mock_open
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
from ptp import PTP_ctrl_object
from ptp import read_dpll_mgr_config
from ptp import write_ptp4l_gm_fields
from ptp import PTP_INSTANCE_TYPE_PTP4L


class MockConfigDict:
    """Minimal ConfigDict mock with has_section and get."""

    def __init__(self, data):
        self._data = data

    def has_section(self, section):
        return section in self._data

    def __getitem__(self, section):
        return self._data[section]


class TestDetectDpllMgrManagedInstances(unittest.TestCase):
    """Test read_dpll_mgr_config detection logic."""

    def setUp(self):
        ptp.dpll_mgr_managed_instances = set()
        self.ctrl = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl.interface = 'ens1f0'
        self.ctrl.timing_instance = MagicMock()
        self.ctrl.timing_instance.config = MockConfigDict({
            'global': {'uds_address': '/var/run/ptp4l-ptpfr0', 'free_running': '1'}
        })
        ptp.ptpinstances = {'ptpfr0': self.ctrl}

    @patch('ptp.glob')
    def test_dpll_mgr_config_exists_instance_matched(self, mock_glob):
        """Instance in dpll-mgr channels gets added to managed set."""
        mock_glob.return_value = ['/etc/linuxptp/ptpinstance/dpll-mgr-dpll-mgr1.json']
        dpll_config = {
            "global": {"operation_mode": "SW_BASED"},
            "channels": {
                "ptp_fr": {"call_channel": "uds:/var/run/ptp4l-ptpfr0"},
                "ptp_bh": {"call_channel": "uds:/var/run/ptp4l-ptp11bh"}
            }
        }
        with patch('builtins.open', mock_open(read_data=json.dumps(dpll_config))):
            read_dpll_mgr_config()

        self.assertTrue(self.ctrl.is_managed_by_dpll_mgr)

    @patch('ptp.glob')
    def test_dpll_mgr_config_exists_instance_not_matched(self, mock_glob):
        """Instance NOT in dpll-mgr channels stays out of managed set."""
        mock_glob.return_value = ['/etc/linuxptp/ptpinstance/dpll-mgr-dpll-mgr1.json']
        dpll_config = {
            "global": {"operation_mode": "SW_BASED"},
            "channels": {
                "ptp_bh": {"call_channel": "uds:/var/run/ptp4l-ptp11bh"}
            }
        }
        with patch('builtins.open', mock_open(read_data=json.dumps(dpll_config))):
            read_dpll_mgr_config()

        self.assertFalse(self.ctrl.is_managed_by_dpll_mgr)

    @patch('ptp.glob')
    def test_no_dpll_mgr_config(self, mock_glob):
        """No dpll-mgr config files — managed set stays empty."""
        mock_glob.return_value = []
        read_dpll_mgr_config()

        self.assertFalse(self.ctrl.is_managed_by_dpll_mgr)

    @patch('ptp.glob')
    def test_invalid_json(self, mock_glob):
        """Invalid JSON in dpll-mgr config — logs warning, no crash."""
        mock_glob.return_value = ['/etc/linuxptp/ptpinstance/dpll-mgr-bad.json']
        with patch('builtins.open', mock_open(read_data='not valid json {')):
            read_dpll_mgr_config()

        self.assertFalse(self.ctrl.is_managed_by_dpll_mgr)


class TestWritePtp4lGmFieldsGuard(unittest.TestCase):
    """Test GM write guard in write_ptp4l_gm_fields."""

    def setUp(self):
        ptp.dpll_mgr_managed_instances = set()
        self.ctrl = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl.interface = 'ens1f0'
        self.ctrl.timing_instance = MagicMock()
        self.ctrl.timing_instance.config = MockConfigDict({
            'global': {'uds_address': '/var/run/ptp4l-ptpfr0', 'free_running': '1'}
        })
        ptp.ptpinstances = {'ptpfr0': self.ctrl}

    @patch('ptp.subprocess.check_output')
    def test_managed_free_running_skips(self, mock_subprocess):
        """dpll-mgr managed + free_running=1 → skip GM write."""
        self.ctrl.is_managed_by_dpll_mgr = True

        write_ptp4l_gm_fields('ptpfr0', OrderedDict({'clockClass': '6'}))

        mock_subprocess.assert_not_called()

    @patch('ptp.subprocess.check_output')
    def test_managed_no_free_running_proceeds(self, mock_subprocess):
        """dpll-mgr managed but free_running NOT set → GM write proceeds."""
        self.ctrl.is_managed_by_dpll_mgr = False
        mock_subprocess.return_value = b''

        write_ptp4l_gm_fields('ptpfr0', OrderedDict({'clockClass': '6'}))

        mock_subprocess.assert_called_once()

    @patch('ptp.subprocess.check_output')
    def test_not_managed_free_running_proceeds(self, mock_subprocess):
        """NOT in dpll-mgr + free_running=1 → GM write proceeds."""
        self.ctrl.is_managed_by_dpll_mgr = False
        mock_subprocess.return_value = b''

        write_ptp4l_gm_fields('ptpfr0', OrderedDict({'clockClass': '6'}))

        mock_subprocess.assert_called_once()

    @patch('ptp.subprocess.check_output')
    def test_no_dpll_mgr_proceeds(self, mock_subprocess):
        """No dpll-mgr at all → GM write proceeds."""
        self.ctrl.is_managed_by_dpll_mgr = False
        mock_subprocess.return_value = b''

        write_ptp4l_gm_fields('ptpfr0', OrderedDict({'clockClass': '6'}))

        mock_subprocess.assert_called_once()


if __name__ == '__main__':
    unittest.main()
