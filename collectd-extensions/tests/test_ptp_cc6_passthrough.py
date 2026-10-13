#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Unit tests for GNR-D State-2 clockClass passthrough.

Covers the per-leader passthrough decision (toggle + backhaul-really-locked +
DRIVE custody) and the override applied in check_clock_class(). Maps to the
spec test cases:
  TC1 - E825 leader, backhaul cc6, ts2_0 DRIVE          -> forwards cc6
  TC2 - E830 leader on ts2_1, backhaul cc6, ts2_1 DRIVE -> forwards cc6
  TC3 - E830 leader, ts2_1 absent (unknown custody)     -> no forward
  TC4 - backhaul GM gone                                -> no forward
  TC5 - clockclass_passthrough=disabled                 -> no forward
  TC6 - non-dpll-mgr host                               -> no forward (no-op)
  TC7 - custody not DRIVE                               -> no forward
"""

import unittest
import sys
import os
from unittest.mock import MagicMock
from unittest.mock import patch
from unittest.mock import Mock

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

import ptp  # noqa: E402


def _mk_ts2phc_ctrl(uds_address):
    """Build a mock ts2phc ctrl whose config exposes a uds_address."""
    ctrl = Mock()
    config = MagicMock()
    config.has_section.return_value = True
    config.__getitem__.return_value = {'uds_address': uds_address}
    ctrl.timing_instance = Mock()
    ctrl.timing_instance.config = config
    return ctrl


class TestCc6PassthroughDecision(unittest.TestCase):
    """Unit tests for the passthrough decision helpers."""

    def setUp(self):
        # Snapshot module globals so we can restore them (shared-import hygiene)
        self._saved = {
            'name': ptp._dpll_mgr_instance_name,
            'chan': dict(ptp._dpll_mgr_ts2phc_channel_by_uds),
            'instances': dict(getattr(ptp, 'ptpinstances', {})),
            'ts2map': dict(getattr(ptp, 'ts2phc_instance_map', {})),
        }
        # Deterministic module state
        ptp._dpll_mgr_instance_name = 'ptp01bh'
        ptp._dpll_mgr_ts2phc_channel_by_uds = {
            '/var/run/ts2phc0': 'ts2_0',
            '/var/run/ts2phc1': 'ts2_1',
        }
        ptp.CLOCKCLASS_PASSTHROUGH_PARAM = 'clockclass_passthrough'
        ptp.CLOCKCLASS_LOCKED_FORWARDABLE = frozenset(
            str(c) for c in range(6, 128))
        ptp.GEARSHIFT_DRIVE = 'DRIVE'

        # dpll-mgr instance ctrl with default (enabled) toggle
        self.dpll_ctrl = Mock()
        self.dpll_ctrl.monitoring_parameters = {}

        # ts2phc instances for E825 (ts2_0) and E830 (ts2_1)
        self.ts2phc0 = _mk_ts2phc_ctrl('/var/run/ts2phc0')
        self.ts2phc1 = _mk_ts2phc_ctrl('/var/run/ts2phc1')

        ptp.ptpinstances = {
            'ptp01bh': self.dpll_ctrl,
            'ts2phc-0': self.ts2phc0,
            'ts2phc-1': self.ts2phc1,
        }
        ptp.ts2phc_instance_map = {
            'ens1f0': 'ts2phc-0',   # E825 leader base port
            'ens2f0': 'ts2phc-1',   # E830 leader base port
        }

    def tearDown(self):
        # Restore module globals to avoid polluting other test modules that
        # share the imported ptp module under stestr's parallel scheduler.
        ptp._dpll_mgr_instance_name = self._saved['name']
        ptp._dpll_mgr_ts2phc_channel_by_uds = self._saved['chan']
        ptp.ptpinstances = self._saved['instances']
        ptp.ts2phc_instance_map = self._saved['ts2map']

    def test_toggle_default_enabled(self):
        self.assertTrue(ptp._cc6_passthrough_enabled())

    def test_toggle_disabled(self):
        self.dpll_ctrl.monitoring_parameters = {
            'clockclass_passthrough': 'disabled'}
        self.assertFalse(ptp._cc6_passthrough_enabled())

    def test_toggle_enabled_explicit(self):
        self.dpll_ctrl.monitoring_parameters = {
            'clockclass_passthrough': 'enabled'}
        self.assertTrue(ptp._cc6_passthrough_enabled())

    # ---- backhaul forwardable class ------------------------------------

    def test_backhaul_forwardable_cc6_locked(self):
        with patch('ptp.query_pmc', return_value={'gm.ClockClass': '6'}), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}):
            self.assertEqual(ptp._backhaul_forwardable_clock_class(), '6')

    def test_backhaul_not_forwardable_holdover_class(self):
        # clockClass 135 (holdover) is not forwardable
        with patch('ptp.query_pmc', return_value={'gm.ClockClass': '135'}), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}):
            self.assertIsNone(ptp._backhaul_forwardable_clock_class())

    def test_backhaul_not_forwardable_port_down(self):
        # cc6 upstream but port LISTENING (no GM) -> not forwardable (TC4)
        with patch('ptp.query_pmc', return_value={'gm.ClockClass': '6'}), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'LISTENING'}}):
            self.assertIsNone(ptp._backhaul_forwardable_clock_class())

    def test_backhaul_no_parent_data(self):
        with patch('ptp.query_pmc', return_value={}), \
             patch('ptp.query_pmc_indexed', return_value={}):
            self.assertIsNone(ptp._backhaul_forwardable_clock_class())

    # ---- leader custody ------------------------------------------------

    def test_custody_confirmed_ts2_0_drive(self):
        status = {'gearshift': {'ts2_0': 'DRIVE', 'ts2_1': 'DRIVE'}}
        with patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            self.assertTrue(ptp._leader_custody_confirmed('ens1f0'))

    def test_custody_confirmed_ts2_1_drive(self):
        status = {'gearshift': {'ts2_0': 'DRIVE', 'ts2_1': 'DRIVE'}}
        with patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            self.assertTrue(ptp._leader_custody_confirmed('ens2f0'))

    def test_custody_not_drive(self):
        status = {'gearshift': {'ts2_0': 'NEUTRAL', 'ts2_1': 'DRIVE'}}
        with patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            self.assertFalse(ptp._leader_custody_confirmed('ens1f0'))

    def test_custody_ts2_1_absent_failsafe(self):
        # WI-1 not present: ts2_1 missing from gearshift -> unknown -> False (TC3)
        status = {'gearshift': {'ts2_0': 'DRIVE'}}
        with patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            self.assertFalse(ptp._leader_custody_confirmed('ens2f0'))

    def test_custody_channel_unmapped(self):
        # ts2phc instance uds not in the dpll-mgr channel map -> False
        ptp._dpll_mgr_ts2phc_channel_by_uds = {'/var/run/ts2phc0': 'ts2_0'}
        status = {'gearshift': {'ts2_0': 'DRIVE'}}
        with patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            self.assertFalse(ptp._leader_custody_confirmed('ens2f0'))

    def test_custody_no_status(self):
        with patch.object(ptp._dpll_mgr_status, 'read', return_value=None):
            self.assertFalse(ptp._leader_custody_confirmed('ens1f0'))

    # ---- full per-leader decision --------------------------------------

    def _patch_full(self, gm_class, port_state, status):
        return (
            patch('ptp.query_pmc', return_value={'gm.ClockClass': gm_class}),
            patch('ptp.query_pmc_indexed',
                  return_value={'0': {'portState': port_state}}),
            patch.object(ptp._dpll_mgr_status, 'read', return_value=status),
        )

    def test_tc1_e825_backhaul_cc6_ts2_0_drive_forwards(self):
        p1, p2, p3 = self._patch_full(
            '6', 'SLAVE', {'gearshift': {'ts2_0': 'DRIVE', 'ts2_1': 'DRIVE'}})
        with p1, p2, p3:
            self.assertEqual(
                ptp._cc6_passthrough_class(Mock(), 'ens1f0'), '6')

    def test_tc2_e830_backhaul_cc6_ts2_1_drive_forwards(self):
        p1, p2, p3 = self._patch_full(
            '6', 'SLAVE', {'gearshift': {'ts2_0': 'DRIVE', 'ts2_1': 'DRIVE'}})
        with p1, p2, p3:
            self.assertEqual(
                ptp._cc6_passthrough_class(Mock(), 'ens2f0'), '6')

    def test_tc3_e830_ts2_1_absent_no_forward(self):
        p1, p2, p3 = self._patch_full(
            '6', 'SLAVE', {'gearshift': {'ts2_0': 'DRIVE'}})
        with p1, p2, p3:
            self.assertIsNone(
                ptp._cc6_passthrough_class(Mock(), 'ens2f0'))

    def test_tc4_backhaul_gm_gone_no_forward(self):
        p1, p2, p3 = self._patch_full(
            '6', 'LISTENING', {'gearshift': {'ts2_0': 'DRIVE'}})
        with p1, p2, p3:
            self.assertIsNone(
                ptp._cc6_passthrough_class(Mock(), 'ens1f0'))

    def test_tc5_toggle_disabled_no_forward(self):
        self.dpll_ctrl.monitoring_parameters = {
            'clockclass_passthrough': 'disabled'}
        p1, p2, p3 = self._patch_full(
            '6', 'SLAVE', {'gearshift': {'ts2_0': 'DRIVE'}})
        with p1, p2, p3:
            self.assertIsNone(
                ptp._cc6_passthrough_class(Mock(), 'ens1f0'))

    def test_tc6_non_dpll_mgr_host_no_forward(self):
        ptp._dpll_mgr_instance_name = None
        self.assertIsNone(ptp._cc6_passthrough_class(Mock(), 'ens1f0'))
        # enabled() also defaults safely True when no dpll-mgr instance
        self.assertTrue(ptp._cc6_passthrough_enabled())

    def test_tc7_custody_not_drive_no_forward(self):
        p1, p2, p3 = self._patch_full(
            '6', 'SLAVE', {'gearshift': {'ts2_0': 'NEUTRAL'}})
        with p1, p2, p3:
            self.assertIsNone(
                ptp._cc6_passthrough_class(Mock(), 'ens1f0'))


class TestReadDpllMgrConfigTs2phcMap(unittest.TestCase):
    """The ts2phc channel UDS->key map is built from the dpll-mgr JSON."""

    def test_map_built_from_both_channels(self):
        cfg = {
            'channels': {
                'ptp_bh': {'call_channel': 'uds:/var/run/ptp4l-bh'},
                'ts2_0': {'call_channel': 'uds:/var/run/ts2phc0'},
                'ts2_1': {'call_channel': 'uds:/var/run/ts2phc1'},
            }
        }
        import json
        ptp.ptpinstances = {}
        ptp._dpll_mgr_instance_name = None
        ptp._dpll_mgr_ts2phc_channel_by_uds = {}
        with patch('ptp.glob', return_value=['/etc/.../dpll-mgr-ptp01bh.json']), \
             patch('builtins.open',
                   unittest.mock.mock_open(read_data=json.dumps(cfg))):
            ptp.read_dpll_mgr_config()
        self.assertEqual(
            ptp._dpll_mgr_ts2phc_channel_by_uds,
            {'/var/run/ts2phc0': 'ts2_0', '/var/run/ts2phc1': 'ts2_1'})

    def test_map_handles_single_ts2phc(self):
        cfg = {
            'channels': {
                'ptp_bh': {'call_channel': 'uds:/var/run/ptp4l-bh'},
                'ts2_0': {'call_channel': 'uds:/var/run/ts2phc0'},
            }
        }
        import json
        ptp.ptpinstances = {}
        ptp._dpll_mgr_instance_name = None
        ptp._dpll_mgr_ts2phc_channel_by_uds = {}
        with patch('ptp.glob', return_value=['/etc/.../dpll-mgr-ptp01bh.json']), \
             patch('builtins.open',
                   unittest.mock.mock_open(read_data=json.dumps(cfg))):
            ptp.read_dpll_mgr_config()
        self.assertEqual(
            ptp._dpll_mgr_ts2phc_channel_by_uds,
            {'/var/run/ts2phc0': 'ts2_0'})


if __name__ == '__main__':
    unittest.main()
