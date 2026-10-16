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
        with patch('ptp.query_pmc', return_value={'gm.ClockClass': '6'}), \
             patch('ptp.query_pmc_indexed',
                   return_value={'0': {'portState': 'SLAVE'}}):
            self.assertEqual(ptp._backhaul_forwardable_clock_class(), '6')

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
            self.assertEqual(ptp._backhaul_forwardable_clock_class(), '6')
            # first positional arg of query_pmc must be the backhaul instance
            assert qp.call_args[0][0] == 'ptp01bh', qp.call_args

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


if __name__ == '__main__':
    unittest.main()
