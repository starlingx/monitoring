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
            'bh_base': getattr(ptp, '_dpll_mgr_backhaul_base_port', None),
            'bh_inst': getattr(ptp, '_dpll_mgr_backhaul_instance', None),
        }
        # Deterministic module state
        ptp._dpll_mgr_instance_name = 'ptp01bh'
        ptp._dpll_mgr_ts2phc_channel_by_uds = {
            '/var/run/ts2phc0': 'ts2_0',
            '/var/run/ts2phc1': 'ts2_1',
        }
        ptp.CLOCKCLASS_PASSTHROUGH_PARAM = 'clockclass_passthrough'
        ptp.CLOCKCLASS_EXTENDED_RELAY_PARAM = 'clockclass_extended_relay'
        ptp.CLOCKCLASS_LOCKED_FORWARDABLE = frozenset(
            str(c) for c in range(6, 128))
        ptp.CLOCKCLASS_EXTENDED_FORWARDABLE = frozenset(
            ('140', '150', '160', '165'))
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
        # Default: backhaul base_port unknown (path inert unless a test
        # sets it). ens1f0 is the E825/backhaul PHC base port when set.
        ptp._dpll_mgr_backhaul_base_port = None
        # the backhaul PTP4L instance name the forwardable query uses.
        ptp._dpll_mgr_backhaul_instance = 'ptp01bh'

    def tearDown(self):
        # Restore module globals to avoid polluting other test modules that
        # share the imported ptp module under stestr's parallel scheduler.
        ptp._dpll_mgr_instance_name = self._saved['name']
        ptp._dpll_mgr_ts2phc_channel_by_uds = self._saved['chan']
        ptp.ptpinstances = self._saved['instances']
        ptp.ts2phc_instance_map = self._saved['ts2map']
        ptp._dpll_mgr_backhaul_base_port = self._saved['bh_base']
        ptp._dpll_mgr_backhaul_instance = self._saved['bh_inst']

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
        pds = {'gm.ClockClass': '6', 'gm.ClockAccuracy': '0x20',
               'gm.OffsetScaledLogVariance': '0x4e5d'}
        with patch('ptp.query_pmc', return_value=pds), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}):
            self.assertEqual(
                ptp._backhaul_forwardable_clock_class(),
                {'clockClass': '6', 'clockAccuracy': '0x20',
                 'offsetScaledLogVariance': '0x4e5d'})

    def test_backhaul_forwardable_none_when_backhaul_instance_unset(self):
        # regression: if the backhaul ptp4l instance was never identified
        # (_dpll_mgr_backhaul_instance is None), forwardable must be None -- never
        # query the wrong (dpll-mgr clock) instance. This was the real-box bug:
        # querying _dpll_mgr_instance_name (dpll-mgr1, no ptp4l UDS) -> empty pmc
        # -> forwardable always None -> cc6 passthrough never fired.
        ptp._dpll_mgr_backhaul_instance = None
        with patch('ptp.query_pmc', return_value={'gm.ClockClass': '6'}), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}):
            self.assertIsNone(ptp._backhaul_forwardable_clock_class())

    def test_backhaul_forwardable_queries_backhaul_instance_not_dpll_mgr(self):
        # the forwardable query must target the backhaul ptp4l instance
        # (_dpll_mgr_backhaul_instance), not the dpll-mgr clock instance. Assert
        # query_pmc is called with the backhaul instance name.
        ptp._dpll_mgr_backhaul_instance = 'ptp01bh'
        ptp._dpll_mgr_instance_name = 'dpll-mgr1'  # the wrong target (clock inst)
        with patch('ptp.query_pmc', return_value={'gm.ClockClass': '6'}) as qp, \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}):
            result = ptp._backhaul_forwardable_clock_class()
            self.assertEqual(result['clockClass'], '6')
            # first positional arg of query_pmc must be the backhaul instance
            self.assertEqual(qp.call_args[0][0], 'ptp01bh')

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

    def test_backhaul_no_parent_clock_class_first_gate(self):
        # No gm.ClockClass in PARENT_DATA_SET -> returns None at the FIRST gate,
        # before the port-health check is ever reached. query_pmc_indexed is
        # deliberately NOT patched here: if the function regressed to reach the
        # port query with no parent class, the unpatched real query_pmc_indexed
        # would surface it rather than a mock masking the gate order.
        with patch('ptp.query_pmc', return_value={}):
            self.assertIsNone(ptp._backhaul_forwardable_clock_class())

    def test_backhaul_forwardable_uncalibrated_accepted(self):
        # port UNCALIBRATED (gmPresent, syncing) is a healthy engaged port and
        # must be accepted exactly like SLAVE (regression guard: dropping
        # UNCALIBRATED from the accepted set would fail here).
        pds = {'gm.ClockClass': '6', 'gm.ClockAccuracy': '0x20',
               'gm.OffsetScaledLogVariance': '0x4e5d'}
        with patch('ptp.query_pmc', return_value=pds), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'UNCALIBRATED'}}):
            self.assertEqual(
                ptp._backhaul_forwardable_clock_class(),
                {'clockClass': '6', 'clockAccuracy': '0x20',
                 'offsetScaledLogVariance': '0x4e5d'})

    def test_backhaul_forwardable_any_port_slave_multi_port(self):
        # Multi-port backhaul: one port LISTENING, another SLAVE. port_healthy is
        # an any() over all indexed ports, so this must forward (regression
        # guard: any()->all() would fail here).
        pds = {'gm.ClockClass': '6', 'gm.ClockAccuracy': '0x20',
               'gm.OffsetScaledLogVariance': '0x4e5d'}
        with patch('ptp.query_pmc', return_value=pds), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'LISTENING'},
                                 '1': {'portState': 'SLAVE'}}):
            self.assertEqual(
                ptp._backhaul_forwardable_clock_class()['clockClass'], '6')

    def test_backhaul_not_forwardable_port_data_empty(self):
        # cc6 is forwardable, but PORT_DATA_SET is empty (no ports reported) ->
        # port_healthy any() over {} is False -> None. This is the TRUE
        # port-empty path (distinct from the first-gate no-parent-class case).
        with patch('ptp.query_pmc', return_value={'gm.ClockClass': '6'}), \
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

    # ---- State-2 ptp_bh custody --------------------
    # In State-2 (GNSS lost) the E825 fronthaul leader's ts2phc (ts2_0) PARKs
    # and the backhaul ptp4l disciplines its PHC via ptp_bh=DRIVE. Custody must
    # be confirmed by ptp_bh for a leader on the backhaul base_port, even though
    # its ts2phc channel is parked.

    def test_custody_state2_ptp_bh_drive_on_backhaul_base_port(self):
        # E825 leader (ens1f0) == backhaul base_port; ts2_0 PARK, ptp_bh DRIVE.
        ptp._dpll_mgr_backhaul_base_port = 'ens1f0'
        status = {'gearshift': {'ptp_bh': 'DRIVE', 'ts2_0': 'PARK',
                                'ts2_1': 'DRIVE'}}
        with patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            self.assertTrue(ptp._leader_custody_confirmed('ens1f0'))

    def test_custody_state2_ptp_bh_not_applied_to_non_backhaul_leader(self):
        # E830 leader (ens2f0) is NOT on the backhaul base_port; ptp_bh DRIVE
        # must NOT confirm its custody. Its own ts2_1 governs (here PARK->False).
        ptp._dpll_mgr_backhaul_base_port = 'ens1f0'
        status = {'gearshift': {'ptp_bh': 'DRIVE', 'ts2_0': 'PARK',
                                'ts2_1': 'PARK'}}
        with patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            self.assertFalse(ptp._leader_custody_confirmed('ens2f0'))

    def test_custody_state2_ptp_bh_park_no_confirm(self):
        # Backhaul base_port leader but ptp_bh not DRIVE -> fall through to
        # ts2phc path (ts2_0 PARK) -> False.
        ptp._dpll_mgr_backhaul_base_port = 'ens1f0'
        status = {'gearshift': {'ptp_bh': 'PARK', 'ts2_0': 'PARK',
                                'ts2_1': 'DRIVE'}}
        with patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            self.assertFalse(ptp._leader_custody_confirmed('ens1f0'))

    def test_custody_state2_backhaul_base_port_unset_inert(self):
        # Before the backhaul instance is identified (None), the ptp_bh path is
        # inert; State-1 ts2_0 DRIVE still confirms as before (no regression).
        ptp._dpll_mgr_backhaul_base_port = None
        # the backhaul PTP4L instance name the forwardable query uses.
        ptp._dpll_mgr_backhaul_instance = 'ptp01bh'
        status = {'gearshift': {'ptp_bh': 'DRIVE', 'ts2_0': 'DRIVE',
                                'ts2_1': 'DRIVE'}}
        with patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            self.assertTrue(ptp._leader_custody_confirmed('ens1f0'))

    def test_custody_state1_e825_ts2_0_drive_still_confirms(self):
        # State-1 (GNSS present): ptp_bh PARK, ts2_0 DRIVE -> ts2phc path
        # confirms even though base_port == backhaul base_port.
        ptp._dpll_mgr_backhaul_base_port = 'ens1f0'
        status = {'gearshift': {'ptp_bh': 'PARK', 'ts2_0': 'DRIVE',
                                'ts2_1': 'DRIVE'}}
        with patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            self.assertTrue(ptp._leader_custody_confirmed('ens1f0'))

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
            result = ptp._cc6_passthrough_class(Mock(), 'ens1f0')
            # full triple: cc6 with the composed PRTC defaults (never 0xfe/0xffff)
            self.assertEqual(result, {
                'clockClass': '6',
                'clockAccuracy': ptp.G8275_CLOCK_ACCURACY_PRTC,
                'offsetScaledLogVariance':
                    ptp.G8275_OFFSET_SCALED_LOG_VARIANCE_PRTC})

    def test_tc2_e830_backhaul_cc6_ts2_1_drive_forwards(self):
        p1, p2, p3 = self._patch_full(
            '6', 'SLAVE', {'gearshift': {'ts2_0': 'DRIVE', 'ts2_1': 'DRIVE'}})
        with p1, p2, p3:
            result = ptp._cc6_passthrough_class(Mock(), 'ens2f0')
            self.assertEqual(result['clockClass'], '6')

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

    def setUp(self):
        # read_dpll_mgr_config() mutates several module globals as a side
        # effect (the dpll-mgr instance name, the ts2phc channel map, and the
        # ptpinstances/ptpinterfaces/alarm registries). Snapshot them so they
        # are restored in tearDown and do not leak into other test modules
        # that share the imported ptp module under stestr's parallel scheduler.
        self._saved = {
            'name': ptp._dpll_mgr_instance_name,
            'chan': dict(ptp._dpll_mgr_ts2phc_channel_by_uds),
            'instances': dict(ptp.ptpinstances),
            'interfaces': dict(ptp.ptpinterfaces),
            'alarms': list(ptp.ALARM_OBJ_LIST),
        }

    def tearDown(self):
        ptp._dpll_mgr_instance_name = self._saved['name']
        ptp._dpll_mgr_ts2phc_channel_by_uds = self._saved['chan']
        ptp.ptpinstances = self._saved['instances']
        ptp.ptpinterfaces = self._saved['interfaces']
        ptp.ALARM_OBJ_LIST[:] = self._saved['alarms']

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

    def test_stale_backhaul_globals_cleared_on_removal(self):
        """Reconfig that removes the dpll-mgr instance must clear stale globals.

        read_dpll_mgr_config() runs on every config read. If a prior read set
        the backhaul identity and a later read has no dpll-mgr-*.json (instance
        deleted), the backhaul base_port/instance globals must reset to None so
        _backhaul_forwardable_clock_class and the State-2 custody check do not
        keep trusting a backhaul that no longer exists (stale-global bug-class).
        """
        # Simulate a previous read having populated the backhaul identity.
        ptp._dpll_mgr_instance_name = 'ptp01bh'
        ptp._dpll_mgr_backhaul_base_port = 'ens1f0'
        ptp._dpll_mgr_backhaul_instance = 'ptp01bh'
        # Now the dpll-mgr config is gone (no matching files).
        with patch('ptp.glob', return_value=[]):
            ptp.read_dpll_mgr_config()
        self.assertIsNone(ptp._dpll_mgr_instance_name)
        self.assertIsNone(ptp._dpll_mgr_backhaul_base_port)
        self.assertIsNone(ptp._dpll_mgr_backhaul_instance)


class TestTs2phcSourceByBasePort(unittest.TestCase):
    """Part A: per-base_port ts2phc source resolution.

    Covers spec test IDs A-1 (per-instance source), A-2 (order independence)
    and A-3 (collision guard, nmea wins). Exercises register_ts2phc_source /
    get_ts2phc_source directly -- the resolver is what every read site now
    consults instead of the former plugin-global obj.capabilities value.
    """

    def setUp(self):
        self._saved = dict(ptp.ts2phc_source_by_base_port)
        ptp.ts2phc_source_by_base_port.clear()

    def tearDown(self):
        ptp.ts2phc_source_by_base_port.clear()
        ptp.ts2phc_source_by_base_port.update(self._saved)

    def test_a1_per_instance_source(self):
        """A-1: distinct base_ports keep distinct sources (no singleton)."""
        ptp.register_ts2phc_source('eno8703', 'nmea')      # E825
        ptp.register_ts2phc_source('enp108s0f0', 'generic')  # E830
        self.assertEqual(ptp.get_ts2phc_source('eno8703'), 'nmea')
        self.assertEqual(ptp.get_ts2phc_source('enp108s0f0'), 'generic')

    def test_a1_unknown_base_port_is_none(self):
        """A-1: a base_port with no ts2phc resolves to None (fail-safe)."""
        self.assertIsNone(ptp.get_ts2phc_source('eno9999'))

    def test_a2_order_independence(self):
        """A-2: registration order does not change the result."""
        ptp.register_ts2phc_source('enp108s0f0', 'generic')
        ptp.register_ts2phc_source('eno8703', 'nmea')
        self.assertEqual(ptp.get_ts2phc_source('eno8703'), 'nmea')
        self.assertEqual(ptp.get_ts2phc_source('enp108s0f0'), 'generic')

    def test_a3_collision_guard_nmea_wins_generic_first(self):
        """A-3: same base_port, generic then nmea -> nmea wins + WARNING."""
        ptp.register_ts2phc_source('eno8703', 'generic')
        warn = MagicMock()
        with patch.object(ptp.collectd, 'warning', warn):
            ptp.register_ts2phc_source('eno8703', 'nmea')
        self.assertTrue(warn.called)
        self.assertEqual(ptp.get_ts2phc_source('eno8703'), 'nmea')

    def test_a3_collision_guard_nmea_wins_nmea_first(self):
        """A-3: same base_port, nmea then generic -> still nmea (order-indep)."""
        ptp.register_ts2phc_source('eno8703', 'nmea')
        warn = MagicMock()
        with patch.object(ptp.collectd, 'warning', warn):
            ptp.register_ts2phc_source('eno8703', 'generic')
        self.assertTrue(warn.called)
        self.assertEqual(ptp.get_ts2phc_source('eno8703'), 'nmea')

    def test_a3_same_source_no_warning(self):
        """A-3: re-registering the same source is not a conflict."""
        ptp.register_ts2phc_source('eno8703', 'nmea')
        warn = MagicMock()
        with patch.object(ptp.collectd, 'warning', warn):
            ptp.register_ts2phc_source('eno8703', 'nmea')
        self.assertFalse(warn.called)
        self.assertEqual(ptp.get_ts2phc_source('eno8703'), 'nmea')

    def test_register_ignores_none(self):
        """A-1: None base_port or empty source is a no-op (never crashes)."""
        ptp.register_ts2phc_source(None, 'nmea')
        ptp.register_ts2phc_source('eno8703', None)
        self.assertEqual(ptp.ts2phc_source_by_base_port, {})


class TestIsPrtcTraceableLeader(unittest.TestCase):
    """Part B: PRTC-traceable role predicate (spec B-1).

    A leader is a T-GM (-> check_clock_class) when disciplined by an NMEA
    ts2phc, OR by a '-s generic' ts2phc that is a dpll-mgr gearshift channel
    (the GNR-D E830 hybrid case). Off a dpll-mgr host the generic clause is
    always False, so the predicate reduces to source == 'nmea'.
    """

    def setUp(self):
        self._saved = {
            'src': dict(ptp.ts2phc_source_by_base_port),
            'chan': dict(ptp._dpll_mgr_ts2phc_channel_by_uds),
            'instances': dict(getattr(ptp, 'ptpinstances', {})),
            'ts2map': dict(getattr(ptp, 'ts2phc_instance_map', {})),
        }
        ptp.ts2phc_source_by_base_port.clear()
        # E825 NMEA leader on eno8703; E830 generic leader on enp108s0f0.
        ptp.ts2phc_source_by_base_port.update(
            {'eno8703': 'nmea', 'enp108s0f0': 'generic'})
        ptp._dpll_mgr_ts2phc_channel_by_uds = {
            '/var/run/ts2phc-ts1': 'ts2_0',
            '/var/run/ts2phc-ts2': 'ts2_1',
        }
        ptp.ptpinstances = {
            'ts1': _mk_ts2phc_ctrl('/var/run/ts2phc-ts1'),
            'ts2': _mk_ts2phc_ctrl('/var/run/ts2phc-ts2'),
            'ts_bad': _mk_ts2phc_ctrl('/var/run/ts2phc-nochan'),
        }
        ptp.ts2phc_instance_map = {
            'eno8703': 'ts1',
            'enp108s0f0': 'ts2',
            'enp108s0f1': 'ts_bad',   # generic ts2phc, NOT a gearshift channel
        }

    def tearDown(self):
        ptp.ts2phc_source_by_base_port.clear()
        ptp.ts2phc_source_by_base_port.update(self._saved['src'])
        ptp._dpll_mgr_ts2phc_channel_by_uds = self._saved['chan']
        ptp.ptpinstances = self._saved['instances']
        ptp.ts2phc_instance_map = self._saved['ts2map']

    def test_b1_nmea_is_true(self):
        self.assertTrue(ptp.is_prtc_traceable_leader('eno8703'))

    def test_b1_generic_with_gearshift_channel_is_true(self):
        """The E830 hybrid case: generic ts2phc that IS a dpll-mgr channel."""
        self.assertTrue(ptp.is_prtc_traceable_leader('enp108s0f0'))

    def test_b1_generic_without_channel_is_false(self):
        """A plain generic ts2phc (no gearshift channel) is a BC relay."""
        ptp.ts2phc_source_by_base_port['enp108s0f1'] = 'generic'
        self.assertFalse(ptp.is_prtc_traceable_leader('enp108s0f1'))

    def test_b1_no_ts2phc_is_false(self):
        self.assertFalse(ptp.is_prtc_traceable_leader('eno9999'))

    def test_b1_off_dpll_mgr_generic_is_false(self):
        """Off a dpll-mgr host (no channel map) generic reduces to not-PRTC."""
        ptp._dpll_mgr_ts2phc_channel_by_uds = {}
        self.assertFalse(ptp.is_prtc_traceable_leader('enp108s0f0'))
        # NMEA stays True regardless -- legacy behaviour preserved.
        self.assertTrue(ptp.is_prtc_traceable_leader('eno8703'))


class TestExtendedClockClassRelay(unittest.TestCase):
    """Full GM-dataset triple relay + extended out-of-spec classes.

    Covers Issue 3 (forward clockAccuracy/OSLV together with clockClass so the
    advertised dataset is never malformed) and Issue 5 (relay the extended
    out-of-spec classes 140/150/160/165 while SLAVE+gmPresent, behind the
    default-on clockclass_extended_relay toggle; never relay 248/255; a locally
    GNSS-locked leader yields to its local class).
    """

    def setUp(self):
        self._saved = {
            'name': ptp._dpll_mgr_instance_name,
            'bh_inst': getattr(ptp, '_dpll_mgr_backhaul_instance', None),
            'instances': dict(getattr(ptp, 'ptpinstances', {})),
            'locked': ptp.CLOCKCLASS_LOCKED_FORWARDABLE,
            'ext': getattr(ptp, 'CLOCKCLASS_EXTENDED_FORWARDABLE', None),
        }
        ptp._dpll_mgr_instance_name = 'ptp01bh'
        ptp._dpll_mgr_backhaul_instance = 'ptp01bh'
        ptp.CLOCKCLASS_LOCKED_FORWARDABLE = frozenset(
            str(c) for c in range(6, 128))
        ptp.CLOCKCLASS_EXTENDED_FORWARDABLE = frozenset(
            ('140', '150', '160', '165'))
        self.dpll_ctrl = Mock()
        self.dpll_ctrl.monitoring_parameters = {}
        ptp.ptpinstances = {'ptp01bh': self.dpll_ctrl}

    def tearDown(self):
        ptp._dpll_mgr_instance_name = self._saved['name']
        ptp._dpll_mgr_backhaul_instance = self._saved['bh_inst']
        ptp.ptpinstances = self._saved['instances']
        ptp.CLOCKCLASS_LOCKED_FORWARDABLE = self._saved['locked']
        ptp.CLOCKCLASS_EXTENDED_FORWARDABLE = self._saved['ext']

    def _parent(self, cc, acc='0x20', oslv='0x4e5d'):
        return {'gm.ClockClass': cc, 'gm.ClockAccuracy': acc,
                'gm.OffsetScaledLogVariance': oslv}

    # ---- Issue 3: full triple forwarded, never malformed ----------------

    def test_issue3_triple_forwarded_from_parent(self):
        """cc6 forwards the backhaul's OWN accuracy/OSLV, not local defaults."""
        with patch('ptp.query_pmc',
                   return_value=self._parent('6', '0x21', '0x4b32')), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}):
            result = ptp._backhaul_forwardable_clock_class()
        self.assertEqual(result, {'clockClass': '6', 'clockAccuracy': '0x21',
                                  'offsetScaledLogVariance': '0x4b32'})

    def test_issue3_triple_never_malformed_defaults_when_absent(self):
        """Parent-omitted accuracy/OSLV falls back to PRTC defaults, never 0xfe/0xffff."""
        with patch('ptp.query_pmc', return_value={'gm.ClockClass': '6'}), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}):
            result = ptp._backhaul_forwardable_clock_class()
        self.assertEqual(result['clockAccuracy'],
                         ptp.G8275_CLOCK_ACCURACY_PRTC)
        self.assertEqual(result['offsetScaledLogVariance'],
                         ptp.G8275_OFFSET_SCALED_LOG_VARIANCE_PRTC)
        self.assertNotEqual(result['clockAccuracy'], '0xfe')

    # ---- Issue 5: extended relay (toggle default-on) --------------------

    def test_issue5_relay_140_when_enabled(self):
        for cc in ('140', '150', '160', '165'):
            with patch('ptp.query_pmc',
                       return_value=self._parent(cc, '0x29')), \
                 patch('ptp.query_pmc_indexed',
                       return_value={'0': {'portState': 'SLAVE'}}):
                result = ptp._backhaul_forwardable_clock_class()
            self.assertIsNotNone(result, "cc%s should relay when enabled" % cc)
            self.assertEqual(result['clockClass'], cc)

    def test_issue5_extended_default_on(self):
        """Absence of the toggle key means extended relay is ON by default."""
        self.assertTrue(ptp._clockclass_extended_relay_enabled())

    def test_issue5_extended_toggle_off_opts_out(self):
        """clockclass_extended_relay=disabled blocks 140 but still relays cc6."""
        self.dpll_ctrl.monitoring_parameters = {
            'clockclass_extended_relay': 'disabled'}
        self.assertFalse(ptp._clockclass_extended_relay_enabled())
        with patch('ptp.query_pmc', return_value=self._parent('140', '0x29')), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}):
            self.assertIsNone(ptp._backhaul_forwardable_clock_class())
        with patch('ptp.query_pmc', return_value=self._parent('6')), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}):
            self.assertEqual(
                ptp._backhaul_forwardable_clock_class()['clockClass'], '6')

    def test_issue5_freerun_248_never_relayed(self):
        for cc in ('248', '255'):
            with patch('ptp.query_pmc', return_value=self._parent(cc, '0xfe')), \
                 patch('ptp.query_pmc_indexed',
                       return_value={'0': {'portState': 'SLAVE'}}):
                self.assertIsNone(
                    ptp._backhaul_forwardable_clock_class(),
                    "cc%s must never be relayed" % cc)

    def test_issue5_extended_not_relayed_if_port_lost(self):
        """Even with extended-on, cc140 is not relayed if the backhaul port is lost."""
        with patch('ptp.query_pmc', return_value=self._parent('140', '0x29')), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'LISTENING'}}):
            self.assertIsNone(ptp._backhaul_forwardable_clock_class())

    # ---- yield-to-local-GNSS precedence (latch fix) ---------------------

    def test_yield_to_local_gnss_declines_forward(self):
        """A locally GNSS/PRTC-locked leader must not relay (latch fix)."""
        with patch('ptp._backhaul_forwardable_clock_class',
                   return_value={'clockClass': '140', 'clockAccuracy': '0x29',
                                 'offsetScaledLogVariance': '0x4e5d'}), \
             patch('ptp._leader_custody_confirmed', return_value=True):
            # locked locally -> decline
            self.assertIsNone(
                ptp._cc6_passthrough_class(Mock(), 'ens1f0',
                                           local_gnss_locked=True))
            # not locked locally -> relay
            result = ptp._cc6_passthrough_class(Mock(), 'ens1f0',
                                                local_gnss_locked=False)
            self.assertEqual(result['clockClass'], '140')


class TestGnssPrimaryBackhaulDegradeNoLeak(unittest.TestCase):
    """A degrading backhaul secondary must not leak into the fronthaul dataset.

    When this leader has its own PRTC lock as the active source (GNSS primary),
    the PARKed/standby backhaul's received class -- whatever it has walked to
    (6, 7, or an extended 140) -- must NOT propagate into the fronthaul GM
    dataset. The fronthaul advertises the leader's own local class. This is the
    inverse of the backhaul-sourced relay: relay fires ONLY while the DUT is
    actually backhaul-sourced. (dpll-mgr Oct-21 known-issue, Vz-2.)
    """

    def setUp(self):
        self._saved_name = ptp._dpll_mgr_instance_name
        ptp._dpll_mgr_instance_name = 'ptp01bh'

    def tearDown(self):
        ptp._dpll_mgr_instance_name = self._saved_name

    def test_local_prtc_lock_declines_relay_whatever_backhaul_carries(self):
        # Across the whole walk a degraded backhaul can show, a locally-locked
        # leader must decline the relay every time (no leak of 6/7/140).
        for backhaul_cc in ('6', '7', '140'):
            forwardable = {'clockClass': backhaul_cc, 'clockAccuracy': '0x29',
                           'offsetScaledLogVariance': '0x4e5d'}
            with patch('ptp._backhaul_forwardable_clock_class',
                       return_value=forwardable), \
                 patch('ptp._leader_custody_confirmed', return_value=True):
                self.assertIsNone(
                    ptp._cc6_passthrough_class(Mock(), 'ens1f0',
                                               local_gnss_locked=True),
                    "locally-locked leader leaked backhaul cc%s" % backhaul_cc)

    def test_no_leak_is_independent_of_custody_and_toggle(self):
        # The local-lock gate precedes custody and backhaul evaluation, so even
        # with custody confirmed and a forwardable backhaul the answer is None.
        with patch('ptp._backhaul_forwardable_clock_class') as fwd, \
             patch('ptp._leader_custody_confirmed', return_value=True):
            fwd.return_value = {'clockClass': '140', 'clockAccuracy': '0x29',
                                'offsetScaledLogVariance': '0x4e5d'}
            self.assertIsNone(
                ptp._cc6_passthrough_class(Mock(), 'ens1f0',
                                           local_gnss_locked=True))

    def test_both_fronthaul_leaders_decline_identically_under_local_lock(self):
        # Vz-2 has two fronthaul leaders; under a local PRTC lock BOTH must
        # decline, so neither can leak and they cannot disagree.
        forwardable = {'clockClass': '7', 'clockAccuracy': '0x29',
                       'offsetScaledLogVariance': '0x4e5d'}
        with patch('ptp._backhaul_forwardable_clock_class',
                   return_value=forwardable), \
             patch('ptp._leader_custody_confirmed', return_value=True):
            r1 = ptp._cc6_passthrough_class(Mock(), 'ens1f0',
                                            local_gnss_locked=True)
            r2 = ptp._cc6_passthrough_class(Mock(), 'ens2f0',
                                            local_gnss_locked=True)
        self.assertIsNone(r1)
        self.assertIsNone(r2)
        self.assertEqual(r1, r2)


class TestFronthaulInstancesDeriveConsistently(unittest.TestCase):
    """Both fronthaul leaders derive from the SAME backhaul source.

    The observed divergence defect was two fronthaul ptp4ls advertising
    different classes from one backhaul source (E825->140, E830->248). Both
    leaders route through the same _backhaul_forwardable_clock_class() result,
    so for identical gating inputs they cannot diverge, and when the backhaul
    is not forwardable they BOTH fall back identically (None -> local ladder).
    The advertised dataset is never a malformed locked-class + 0xfe/0xffff pair.
    (dpll-mgr Oct-21 known-issue, backhaul-only upstream loss.)
    """

    def setUp(self):
        self._saved = {
            'name': ptp._dpll_mgr_instance_name,
            'bh_inst': getattr(ptp, '_dpll_mgr_backhaul_instance', None),
            'instances': dict(getattr(ptp, 'ptpinstances', {})),
            'locked': ptp.CLOCKCLASS_LOCKED_FORWARDABLE,
            'ext': getattr(ptp, 'CLOCKCLASS_EXTENDED_FORWARDABLE', None),
        }
        ptp._dpll_mgr_instance_name = 'ptp01bh'
        ptp._dpll_mgr_backhaul_instance = 'ptp01bh'
        ptp.CLOCKCLASS_LOCKED_FORWARDABLE = frozenset(
            str(c) for c in range(6, 128))
        ptp.CLOCKCLASS_EXTENDED_FORWARDABLE = frozenset(
            ('140', '150', '160', '165'))
        dpll_ctrl = Mock()
        dpll_ctrl.monitoring_parameters = {}
        ptp.ptpinstances = {'ptp01bh': dpll_ctrl}

    def tearDown(self):
        ptp._dpll_mgr_instance_name = self._saved['name']
        ptp._dpll_mgr_backhaul_instance = self._saved['bh_inst']
        ptp.ptpinstances = self._saved['instances']
        ptp.CLOCKCLASS_LOCKED_FORWARDABLE = self._saved['locked']
        ptp.CLOCKCLASS_EXTENDED_FORWARDABLE = self._saved['ext']

    def test_identical_source_yields_identical_result_both_leaders(self):
        forwardable = {'clockClass': '140', 'clockAccuracy': '0x29',
                       'offsetScaledLogVariance': '0x4e5d'}
        with patch('ptp._backhaul_forwardable_clock_class',
                   return_value=forwardable), \
             patch('ptp._leader_custody_confirmed', return_value=True):
            r1 = ptp._cc6_passthrough_class(Mock(), 'ens1f0',
                                            local_gnss_locked=False)
            r2 = ptp._cc6_passthrough_class(Mock(), 'ens2f0',
                                            local_gnss_locked=False)
        self.assertEqual(r1, r2)
        self.assertEqual(r1['clockClass'], '140')

    def test_backhaul_not_forwardable_both_leaders_fall_back_identically(self):
        # Upstream gone -> forwardable None -> both leaders decline the relay
        # identically (no E825->140 / E830->248 split; both -> local ladder).
        with patch('ptp._backhaul_forwardable_clock_class',
                   return_value=None), \
             patch('ptp._leader_custody_confirmed', return_value=True):
            r1 = ptp._cc6_passthrough_class(Mock(), 'ens1f0',
                                            local_gnss_locked=False)
            r2 = ptp._cc6_passthrough_class(Mock(), 'ens2f0',
                                            local_gnss_locked=False)
        self.assertIsNone(r1)
        self.assertIsNone(r2)
        self.assertEqual(r1, r2)

    def test_relayed_triple_is_never_malformed_pair(self):
        # Whatever class is relayed, it carries the backhaul's real accuracy/OSLV
        # (not the 0xfe/0xffff local-bucket defaults) -- the malformed-pair
        # signature must never appear on a forwarded locked/extended class.
        for cc in ('6', '7', '140', '165'):
            with patch('ptp.query_pmc',
                       return_value={'gm.ClockClass': cc,
                                     'gm.ClockAccuracy': '0x29',
                                     'gm.OffsetScaledLogVariance': '0x4e5d'}), \
                 patch('ptp.query_pmc_indexed',
                       return_value={'0': {'portState': 'SLAVE'}}):
                result = ptp._backhaul_forwardable_clock_class()
            self.assertIsNotNone(result)
            self.assertNotEqual(result['clockAccuracy'], '0xfe')
            self.assertNotEqual(result['offsetScaledLogVariance'], '0xffff')


class TestG8275ApplySiteHonoursRelayedTriple(unittest.TestCase):
    """handle_ptp4l_g8275_fields composes with the relayed GM triple.

    When check_clock_class() relayed a backhaul GM dataset this poll it set
    ctrl.ptp4l_relayed_triple. The subsequent g8275 writer must emit that
    triple's clockAccuracy/offsetScaledLogVariance and must NOT fall through to
    the local prc_state bucket (0xfe/0xffff) -- the two-writer composition that
    the malformed-pair defect violated. Oracle is the dict actually handed to
    write_ptp4l_gm_fields (the real emit), not an intermediate.
    (apply-site; the branch where the shipped bug lived.)
    """

    def setUp(self):
        self._saved_instances = dict(getattr(ptp, 'ptpinstances', {}))

    def tearDown(self):
        ptp.ptpinstances = self._saved_instances

    def _mk_g8275_ctrl(self, relayed_triple, prc_state,
                       local_accuracy='0x20', local_oslv='0x4e5d'):
        """A ctrl that reaches the relayed-triple branch then exits cleanly.

        disciplined_by_ts2phc=True skips the T-BC override block; prtc_present
        =False skips the leap-second block; so execution runs the accuracy/OSLV
        composition and falls through to the final emit.
        """
        ctrl = Mock()
        ctrl.ptp4l_relayed_triple = relayed_triple
        ctrl.ptp4l_prc_state = prc_state
        ctrl.ptp4l_prtc_type = 'prtc_a'
        ctrl.ptp4l_announce_settings = {}
        ctrl.ptp4l_clock_accuracy = local_accuracy
        ctrl.ptp4l_offset_scaled_log_variance = local_oslv
        ctrl.ptp4l_time_source = '0x20'
        ctrl.ptp4l_clock_identity = 'aaaa.bbbb.cccc'
        ctrl.ptp4l_grandmaster_identity = 'aaaa.bbbb.cccc'  # == clk id: no GM-change log
        ctrl.ptp4l_clock_class = '6'
        ctrl.disciplined_by_ts2phc = True   # skip the T-BC override block
        ctrl.prtc_present = False            # skip the leap-second block
        config = MagicMock()
        config.has_section.return_value = True
        config.__getitem__.return_value = {'dataset_comparison': 'G.8275.x'}
        config.__contains__.return_value = True
        ctrl.timing_instance = Mock()
        ctrl.timing_instance.config = config
        return ctrl

    def _pmc_side_effect(self, parent_class='6'):
        """Return a query_pmc side_effect keyed by dataset name."""
        def _se(instance, dataset, query_action='GET'):
            if dataset == 'GRANDMASTER_SETTINGS_NP':
                return {'clockClass': '6', 'clockAccuracy': '0x20',
                        'offsetScaledLogVariance': '0x4e5d'}
            if dataset == 'TIME_PROPERTIES_DATA_SET':
                return {'timeTraceable': 1, 'frequencyTraceable': 1}
            if dataset == 'PARENT_DATA_SET':
                return {'grandmasterIdentity': 'aaaa.bbbb.cccc',
                        'gm.ClockClass': parent_class}
            if dataset == 'DEFAULT_DATA_SET':
                return {'numberPorts': '1', 'clockIdentity': 'aaaa.bbbb.cccc'}
            return {}
        return _se

    def _run_and_capture_emit(self, ctrl, parent_class='6'):
        """Run the writer; return the dict handed to write_ptp4l_gm_fields."""
        ptp.ptpinstances = {'ptp01fh': ctrl}
        captured = {}

        def _capture(instance, gm_fields_dict):
            captured.update(gm_fields_dict)
        with patch('ptp.query_pmc',
                   side_effect=self._pmc_side_effect(parent_class)), \
             patch('ptp.write_ptp4l_gm_fields', side_effect=_capture):
            ptp.handle_ptp4l_g8275_fields('ptp01fh')
        return captured

    def test_relayed_triple_sets_accuracy_oslv(self):
        triple = {'clockClass': '140', 'clockAccuracy': '0x29',
                  'offsetScaledLogVariance': '0x4b32'}
        ctrl = self._mk_g8275_ctrl(triple, ptp.CLOCK_STATE_LOCKED)
        emit = self._run_and_capture_emit(ctrl, parent_class='140')
        self.assertEqual(emit['clockAccuracy'], '0x29')
        self.assertEqual(emit['offsetScaledLogVariance'], '0x4b32')

    def test_relayed_triple_overrides_locked_bucket(self):
        # prc_state LOCKED AND triple set: the relayed values win the if/elif,
        # NOT the local ctrl.ptp4l_clock_accuracy bucket.
        triple = {'clockClass': '140', 'clockAccuracy': '0x29',
                  'offsetScaledLogVariance': '0x4b32'}
        ctrl = self._mk_g8275_ctrl(triple, ptp.CLOCK_STATE_LOCKED,
                                   local_accuracy='0x20', local_oslv='0x4e5d')
        emit = self._run_and_capture_emit(ctrl, parent_class='140')
        self.assertNotEqual(emit['clockAccuracy'], '0x20')  # not the local bucket
        self.assertEqual(emit['clockAccuracy'], '0x29')

    def test_no_relayed_triple_uses_local_bucket(self):
        # No triple + prc LOCKED: falls through to the local bucket (no regression
        # to the legacy non-passthrough path).
        ctrl = self._mk_g8275_ctrl(None, ptp.CLOCK_STATE_LOCKED,
                                   local_accuracy='0x20', local_oslv='0x4e5d')
        emit = self._run_and_capture_emit(ctrl, parent_class='6')
        self.assertEqual(emit['clockAccuracy'], '0x20')
        self.assertEqual(emit['offsetScaledLogVariance'], '0x4e5d')

    def test_relayed_triple_never_emits_malformed_pair(self):
        # A relayed locked/extended class must never be emitted beside the
        # 0xfe/0xffff local-freerun bucket (the malformed-pair signature).
        triple = {'clockClass': '140', 'clockAccuracy': '0x29',
                  'offsetScaledLogVariance': '0x4b32'}
        ctrl = self._mk_g8275_ctrl(triple, ptp.CLOCK_STATE_LOCKED)
        emit = self._run_and_capture_emit(ctrl, parent_class='140')
        self.assertNotEqual(emit['clockAccuracy'], '0xfe')
        self.assertNotEqual(emit['offsetScaledLogVariance'], '0xffff')


class TestPassthroughComposesEndToEnd(unittest.TestCase):
    """_cc6_passthrough_class composed with its REAL collaborators.

    Every other decision test mocks _backhaul_forwardable_clock_class and
    _leader_custody_confirmed, so none proves the real wiring: a field-name
    drift between what the forwardable helper returns and what the decision
    passes through would pass those tests but break in the field. Here ONLY the
    I/O boundary (query_pmc / query_pmc_indexed / _dpll_mgr_status.read) is
    mocked; the three helpers run for real. (integration guard.)
    """

    def setUp(self):
        self._saved = {
            'name': ptp._dpll_mgr_instance_name,
            'chan': dict(ptp._dpll_mgr_ts2phc_channel_by_uds),
            'instances': dict(getattr(ptp, 'ptpinstances', {})),
            'ts2map': dict(getattr(ptp, 'ts2phc_instance_map', {})),
            'bh_base': getattr(ptp, '_dpll_mgr_backhaul_base_port', None),
            'bh_inst': getattr(ptp, '_dpll_mgr_backhaul_instance', None),
            'locked': ptp.CLOCKCLASS_LOCKED_FORWARDABLE,
            'ext': getattr(ptp, 'CLOCKCLASS_EXTENDED_FORWARDABLE', None),
        }
        ptp._dpll_mgr_instance_name = 'ptp01bh'
        ptp._dpll_mgr_backhaul_instance = 'ptp01bh'
        ptp._dpll_mgr_backhaul_base_port = None
        ptp._dpll_mgr_ts2phc_channel_by_uds = {
            '/var/run/ts2phc0': 'ts2_0',
            '/var/run/ts2phc1': 'ts2_1',
        }
        ptp.CLOCKCLASS_LOCKED_FORWARDABLE = frozenset(
            str(c) for c in range(6, 128))
        ptp.CLOCKCLASS_EXTENDED_FORWARDABLE = frozenset(
            ('140', '150', '160', '165'))
        dpll_ctrl = Mock()
        dpll_ctrl.monitoring_parameters = {}
        ptp.ptpinstances = {
            'ptp01bh': dpll_ctrl,
            'ts2phc-0': _mk_ts2phc_ctrl('/var/run/ts2phc0'),
            'ts2phc-1': _mk_ts2phc_ctrl('/var/run/ts2phc1'),
        }
        ptp.ts2phc_instance_map = {'ens1f0': 'ts2phc-0', 'ens2f0': 'ts2phc-1'}

    def tearDown(self):
        ptp._dpll_mgr_instance_name = self._saved['name']
        ptp._dpll_mgr_ts2phc_channel_by_uds = self._saved['chan']
        ptp.ptpinstances = self._saved['instances']
        ptp.ts2phc_instance_map = self._saved['ts2map']
        ptp._dpll_mgr_backhaul_base_port = self._saved['bh_base']
        ptp._dpll_mgr_backhaul_instance = self._saved['bh_inst']
        ptp.CLOCKCLASS_LOCKED_FORWARDABLE = self._saved['locked']
        ptp.CLOCKCLASS_EXTENDED_FORWARDABLE = self._saved['ext']

    def test_backhaul_sourced_leader_passes_full_triple_through(self):
        # Real stack: forwardable reads parentDS triple, custody confirms DRIVE,
        # decision passes the SAME triple through. Asserts the FULL dict, so a
        # key-name drift in the forwardable return would fail here (the isolated
        # tests, which mock the helper, would not).
        parent = {'gm.ClockClass': '140', 'gm.ClockAccuracy': '0x29',
                  'gm.OffsetScaledLogVariance': '0x4b32'}
        status = {'gearshift': {'ts2_0': 'DRIVE', 'ts2_1': 'DRIVE'}}
        with patch('ptp.query_pmc', return_value=parent), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}), \
             patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            result = ptp._cc6_passthrough_class(Mock(), 'ens1f0',
                                                local_gnss_locked=False)
        self.assertEqual(result, {'clockClass': '140', 'clockAccuracy': '0x29',
                                  'offsetScaledLogVariance': '0x4b32'})

    def test_local_gnss_lock_declines_through_real_stack(self):
        # Same real stack, but the leader is locally PRTC-locked -> decline,
        # even though forwardable+custody would both succeed.
        parent = {'gm.ClockClass': '140', 'gm.ClockAccuracy': '0x29',
                  'gm.OffsetScaledLogVariance': '0x4b32'}
        status = {'gearshift': {'ts2_0': 'DRIVE', 'ts2_1': 'DRIVE'}}
        with patch('ptp.query_pmc', return_value=parent), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}), \
             patch.object(ptp._dpll_mgr_status, 'read', return_value=status):
            self.assertIsNone(
                ptp._cc6_passthrough_class(Mock(), 'ens1f0',
                                           local_gnss_locked=True))


class TestForwardableSetBoundaries(unittest.TestCase):
    """Boundaries of the PRODUCTION forwardable sets (off-by-one guards).

    Deliberately does NOT override CLOCKCLASS_LOCKED_FORWARDABLE /
    CLOCKCLASS_EXTENDED_FORWARDABLE in setUp -- it exercises whatever ptp.py
    defines, so an off-by-one in range(6, 128) or a widening of the extended
    set is detectable here. (A fixture that re-pins the sets would mask exactly
    the production bug these tests exist to catch.)
    """

    def setUp(self):
        self._saved = {
            'name': ptp._dpll_mgr_instance_name,
            'bh_inst': getattr(ptp, '_dpll_mgr_backhaul_instance', None),
            'instances': dict(getattr(ptp, 'ptpinstances', {})),
        }
        ptp._dpll_mgr_instance_name = 'ptp01bh'
        ptp._dpll_mgr_backhaul_instance = 'ptp01bh'
        dpll_ctrl = Mock()
        dpll_ctrl.monitoring_parameters = {}   # extended relay default-on
        ptp.ptpinstances = {'ptp01bh': dpll_ctrl}
        # NOTE: CLOCKCLASS_*_FORWARDABLE intentionally left at production values.

    def tearDown(self):
        ptp._dpll_mgr_instance_name = self._saved['name']
        ptp._dpll_mgr_backhaul_instance = self._saved['bh_inst']
        ptp.ptpinstances = self._saved['instances']

    def _check(self, cases):
        for cc, expected in cases.items():
            pds = {'gm.ClockClass': cc, 'gm.ClockAccuracy': '0x20',
                   'gm.OffsetScaledLogVariance': '0x4e5d'}
            with patch('ptp.query_pmc', return_value=pds), \
                 patch('ptp.query_pmc_indexed',
                       return_value={'0': {'portState': 'SLAVE'}}):
                result = ptp._backhaul_forwardable_clock_class()
            if expected is None:
                self.assertIsNone(result, "cc%s must not forward" % cc)
            else:
                self.assertEqual(result['clockClass'], expected,
                                 "cc%s should forward" % cc)

    def test_locked_range_boundaries(self):
        # 6..127 inclusive; 5 and 128 are outside (and 128 is not extended).
        self._check({'5': None, '6': '6', '127': '127', '128': None})

    def test_extended_set_exact_membership(self):
        # Extended relay is EXACTLY {140,150,160,165}, not a range.
        self._check({'139': None, '140': '140', '165': '165', '166': None})


class TestForwardedTraceabilityFlags(unittest.TestCase):
    """Forwarded clockClass carries G.8275.1 Table 2 traceability flags.

    Table 2 fixes the (timeTraceable, frequencyTraceable) pair per clockClass.
    A forwarded extended class must advertise timeTraceable=FALSE (PRTC time
    traceability is lost -- what makes it out-of-spec), with frequencyTraceable
    140=TRUE, 150/160/165=FALSE. Guards against regressing to a blanket
    TRUE/TRUE, which would advertise a self-contradictory cc140+timeTraceable.
    """

    def test_table2_extended_class_flags_exact(self):
        # (clockClass, timeTraceable, frequencyTraceable) straight from Table 2.
        expected = {
            '140': (False, True),
            '150': (False, False),
            '160': (False, False),
            '165': (False, False),
        }
        for cc, (tt, ft) in expected.items():
            entry = ptp.CLOCKCLASS_EXTENDED_TRACEABILITY[cc]
            self.assertEqual(entry['timeTraceable'], tt,
                             "cc%s timeTraceable" % cc)
            self.assertEqual(entry['frequencyTraceable'], ft,
                             "cc%s frequencyTraceable" % cc)

    def test_extended_classes_are_never_time_traceable(self):
        # The defining property of the out-of-spec extended range.
        for cc in ('140', '150', '160', '165'):
            self.assertFalse(
                ptp.CLOCKCLASS_EXTENDED_TRACEABILITY[cc]['timeTraceable'],
                "cc%s must advertise timeTraceable=FALSE" % cc)

    def test_mapping_keys_match_forwardable_extended_set(self):
        # Every relayable extended class has a Table 2 flag entry (no class can
        # be forwarded without defined traceability flags).
        self.assertEqual(
            set(ptp.CLOCKCLASS_EXTENDED_TRACEABILITY),
            set(ptp.CLOCKCLASS_EXTENDED_FORWARDABLE))


if __name__ == '__main__':
    unittest.main()
