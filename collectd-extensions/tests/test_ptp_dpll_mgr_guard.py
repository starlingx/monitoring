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
sys.modules.setdefault('oslo_utils', MagicMock())
sys.modules.setdefault('oslo_utils.timeutils', MagicMock())

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
            'global': {'uds_address': '/var/run/ptp4l-ptp01bh', 'free_running': '0'}
        })
        ptp.ptpinstances = {'ptp01bh': self.ctrl}

    @patch('ptp.glob')
    def test_dpll_mgr_backhaul_instance_matched(self, mock_glob):
        """The ptp4l instance matching the dpll-mgr ptp_bh channel is managed."""
        mock_glob.return_value = ['/etc/linuxptp/ptpinstance/dpll-mgr-dpll-mgr1.json']
        dpll_config = {
            "global": {"operation_mode": "SW_BASED"},
            "channels": {
                "ptp_bh": {"call_channel": "uds:/var/run/ptp4l-ptp01bh"},
                "ts2_0": {"call_channel": "uds:/var/run/ts2phc0"}
            }
        }
        with patch('builtins.open', mock_open(read_data=json.dumps(dpll_config))):
            read_dpll_mgr_config()

        self.assertTrue(self.ctrl.is_managed_by_dpll_mgr)

    @patch('ptp.glob')
    def test_dpll_mgr_only_ptp_bh_channel_managed(self, mock_glob):
        """Only the ptp_bh channel's instance is managed.

        A fronthaul ptp4l that is also a dpll-mgr channel (e.g. ptp_0) is
        NOT marked managed, so collectd keeps managing its GM fields and
        lock judgement.
        """
        fronthaul = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        fronthaul.interface = 'ens2f0'
        fronthaul.timing_instance = MagicMock()
        fronthaul.timing_instance.config = MockConfigDict({
            'global': {'uds_address': '/var/run/ptp4l-ptp0'}
        })
        ptp.ptpinstances = {'ptp01bh': self.ctrl, 'ptp0': fronthaul}

        mock_glob.return_value = ['/etc/linuxptp/ptpinstance/dpll-mgr-dpll-mgr1.json']
        dpll_config = {
            "global": {"operation_mode": "SW_BASED"},
            "channels": {
                "ptp_bh": {"call_channel": "uds:/var/run/ptp4l-ptp01bh"},
                "ptp_0": {"call_channel": "uds:/var/run/ptp4l-ptp0"}
            }
        }
        with patch('builtins.open', mock_open(read_data=json.dumps(dpll_config))):
            read_dpll_mgr_config()

        self.assertTrue(self.ctrl.is_managed_by_dpll_mgr)
        self.assertFalse(fronthaul.is_managed_by_dpll_mgr)

    @patch('ptp.glob')
    def test_dpll_mgr_managed_servoing_backhaul(self, mock_glob):
        """Managed ptp_bh instance is detected regardless of free_running.

        A servoing backhaul (free_running 0) must be detected, not just a
        free-running one.
        """
        self.ctrl.timing_instance.config = MockConfigDict({
            'global': {'uds_address': '/var/run/ptp4l-ptp01bh',
                       'free_running': '0'}
        })
        mock_glob.return_value = ['/etc/linuxptp/ptpinstance/dpll-mgr-dpll-mgr1.json']
        dpll_config = {
            "global": {"operation_mode": "SW_BASED"},
            "channels": {
                "ptp_bh": {"call_channel": "uds:/var/run/ptp4l-ptp01bh"}
            }
        }
        with patch('builtins.open', mock_open(read_data=json.dumps(dpll_config))):
            read_dpll_mgr_config()

        self.assertTrue(self.ctrl.is_managed_by_dpll_mgr)

    @patch('ptp.glob')
    def test_dpll_mgr_managed_no_free_running_key(self, mock_glob):
        """Managed ptp_bh instance with no free_running key is detected.

        Detection is by UDS match, so the absence of a free_running key does
        not affect it.
        """
        self.ctrl.timing_instance.config = MockConfigDict({
            'global': {'uds_address': '/var/run/ptp4l-ptp01bh'}
        })
        mock_glob.return_value = ['/etc/linuxptp/ptpinstance/dpll-mgr-dpll-mgr1.json']
        dpll_config = {
            "global": {"operation_mode": "SW_BASED"},
            "channels": {
                "ptp_bh": {"call_channel": "uds:/var/run/ptp4l-ptp01bh"}
            }
        }
        with patch('builtins.open', mock_open(read_data=json.dumps(dpll_config))):
            read_dpll_mgr_config()

        self.assertTrue(self.ctrl.is_managed_by_dpll_mgr)

    @patch('ptp.glob')
    def test_dpll_mgr_config_exists_instance_not_matched(self, mock_glob):
        """Instance whose UDS is not the ptp_bh channel stays unmanaged."""
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
    def test_dpll_mgr_no_ptp_bh_channel(self, mock_glob):
        """A dpll-mgr config without a ptp_bh channel marks nothing managed."""
        mock_glob.return_value = ['/etc/linuxptp/ptpinstance/dpll-mgr-dpll-mgr1.json']
        dpll_config = {
            "global": {"operation_mode": "SW_BASED"},
            "channels": {
                "ts2_0": {"call_channel": "uds:/var/run/ts2phc0"}
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
            'global': {'uds_address': '/var/run/ptp4l-ptpfr0'}
        })
        ptp.ptpinstances = {'ptpfr0': self.ctrl}

    @patch('ptp.subprocess.check_output')
    def test_managed_skips(self, mock_subprocess):
        """dpll-mgr managed instance → skip GM write."""
        self.ctrl.is_managed_by_dpll_mgr = True

        write_ptp4l_gm_fields('ptpfr0', OrderedDict({'clockClass': '6'}))

        mock_subprocess.assert_not_called()

    @patch('ptp.subprocess.check_output')
    def test_not_managed_proceeds(self, mock_subprocess):
        """Instance not managed by dpll-mgr → GM write proceeds."""
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
