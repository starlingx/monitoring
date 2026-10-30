#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Unit tests for the backhaul-loss T-BC holdover clockClass ladder
(_backhaul_holdover_clock_class).

This is the fail-over companion to the cc6/cc140 passthrough. When a
backhaul-sourced fronthaul leader loses its backhaul parent while the DPLL is
holding over, G.8275.1 Appendix VII requires the local T-BC holdover ladder
(135 within spec -> 165 out of spec), NOT free-run clockClass 248.

The helper gates on DPLL state (in_holdover + ever_locked) and custody, but
times the within-spec 135 -> 165 transition with collectd's own
holdover_timestamp against holdover_seconds -- the clockClass control plane
stays in collectd; dpll-mgr's holdover_duration_s (a gearshift-tier timer) is
deliberately not used for the budget.
"""

import os
import ptp
import sys
import unittest

from unittest.mock import MagicMock
from unittest.mock import patch
from unittest.mock import Mock
from datetime import datetime
from datetime import timedelta

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


def _setup_constants():
    ptp.CLOCK_CLASS_135 = '135'
    ptp.CLOCK_CLASS_140 = '140'
    ptp.CLOCK_CLASS_150 = '150'
    ptp.CLOCK_CLASS_160 = '160'
    ptp.CLOCK_CLASS_165 = '165'
    ptp.CLOCK_CLASS_248 = '248'


_setup_constants()


class TestBackhaulHoldoverClockClass(unittest.TestCase):
    """_backhaul_holdover_clock_class gate + 135/165 ladder."""

    BASE_PORT = 'eno8703'
    HO_IFACE = 'eno8703'

    def setUp(self):
        _setup_constants()
        # A backhaul-sourced leader ctrl: last relayed a healthy cc6 parent.
        self.ctrl = Mock()
        self.ctrl.instance_name = 'ptp01fh'
        self.ctrl.ptp4l_clock_class = '6'
        self.ctrl.holdover_timestamp = {}
        self.ctrl.monitoring_parameters = {'holdover_seconds': 14400}

        # Default: a dpll-mgr host, custody confirmed, backhaul lost, DPLL
        # holding over having been locked -- i.e. the Item-10 condition.
        self._p = []
        self._set(ptp, '_dpll_mgr_instance_name', 'dpll-mgr1')
        self._patch('ptp._leader_custody_confirmed', return_value=True)
        self._patch('ptp._backhaul_forwardable_clock_class', return_value=None)
        self._patch('ptp._is_synce_only_frequency_holdover', return_value=False)
        self._status = {'in_holdover': True, 'ever_locked': True}
        status_reader = Mock()
        status_reader.read.return_value = self._status
        self._set(ptp, '_dpll_mgr_status', status_reader)
        # timeutils: utcnow fixed; delta computed from seeded timestamp arg.
        self._now = datetime(2024, 1, 1, 10, 0, 0)
        tu = patch('ptp.timeutils')
        self.mock_tu = tu.start()
        self._p.append(tu)
        self.mock_tu.utcnow.return_value = self._now
        # delta_seconds(seed, now): default 0 (just seeded), overridden per test
        self.mock_tu.delta_seconds.return_value = 0

    def tearDown(self):
        for p in self._p:
            p.stop()

    def _patch(self, target, **kw):
        p = patch(target, **kw)
        p.start()
        self._p.append(p)

    def _set(self, mod, name, value):
        old = getattr(mod, name, None)
        setattr(mod, name, value)
        self._p.append(_Restore(mod, name, old))

    def _call(self):
        return ptp._backhaul_holdover_clock_class(
            self.ctrl, self.BASE_PORT, self.HO_IFACE)

    # ---- the ladder (positive cases) ----------------------------------

    def test_within_spec_yields_135(self):
        """Backhaul lost, DPLL holdover, within holdover_seconds -> 135 tT=1."""
        self.mock_tu.delta_seconds.return_value = 60  # << 14400
        result = self._call()
        self.assertEqual(result, ('135', True, False))
        # collectd seeded its own timestamp (control plane)
        self.assertIsNotNone(self.ctrl.holdover_timestamp.get(self.HO_IFACE))

    def test_seed_backdated_by_dpll_holdover_duration(self):
        """Seed t0 at actual DPLL holdover entry: utcnow - holdover_duration_s.

        dpll-mgr reports 600 s already elapsed in holdover, so the within-spec
        timer must start 600 s before now, not at first-poll detection.
        """
        self._status['holdover_duration_s'] = 600
        self.mock_tu.delta_seconds.return_value = 60
        self._call()
        self.assertEqual(
            self.ctrl.holdover_timestamp[self.HO_IFACE],
            self._now - timedelta(seconds=600),
        )

    def test_seed_not_backdated_when_duration_absent(self):
        """Older dpll-mgr (no holdover_duration_s): seed at now, unchanged."""
        # _status has no 'holdover_duration_s'
        self.mock_tu.delta_seconds.return_value = 60
        self._call()
        self.assertEqual(
            self.ctrl.holdover_timestamp[self.HO_IFACE], self._now)

    def test_within_spec_synce_keeps_freq_traceable(self):
        """SyncE-backed holdover: 135 with frequencyTraceable TRUE."""
        with patch('ptp._is_synce_only_frequency_holdover', return_value=True):
            self.mock_tu.delta_seconds.return_value = 60
            result = self._call()
        self.assertEqual(result, ('135', True, True))

    def test_past_spec_yields_165(self):
        """Backhaul lost, DPLL holdover, past holdover_seconds -> 165 tT=0."""
        self.ctrl.holdover_timestamp = {self.HO_IFACE: self._now}
        self.mock_tu.delta_seconds.return_value = 20000  # > 14400
        result = self._call()
        self.assertEqual(result, ('165', False, False))

    def test_parent_already_out_of_spec_goes_straight_to_165(self):
        """Pre-loss parent was 140 -> straight to 165 even within window."""
        self.ctrl.ptp4l_clock_class = '140'
        self.mock_tu.delta_seconds.return_value = 60  # within window
        result = self._call()
        self.assertEqual(result, ('165', False, False))

    def test_parent_out_of_spec_150_160_go_straight_to_165(self):
        """Pre-loss parent 150 or 160 (Cat2/Cat3) -> straight to 165."""
        self.mock_tu.delta_seconds.return_value = 60  # within window
        for cls in ('150', '160'):
            self.ctrl.ptp4l_clock_class = cls
            self.ctrl.holdover_timestamp = {}
            self.assertEqual(
                self._call(), ('165', False, False),
                msg="parent %s must go straight to 165" % cls)

    def test_relock_reset_restarts_ladder_at_135(self):
        """After backhaul re-lock clears the timestamp, a fresh loss starts 135.

        check_clock_class clears ctrl.holdover_timestamp[iface] on passthrough
        success (backhaul re-locked). This models the subsequent loss: with a
        cleared timestamp the helper re-seeds now and returns within-spec 135,
        rather than inheriting a stale elapsed time that would jump to 165.
        """
        # Simulate a prior loss left a stale (old) timestamp, then re-lock
        # cleared it (None), then a new loss occurs.
        self.ctrl.holdover_timestamp = {self.HO_IFACE: None}
        self.mock_tu.delta_seconds.return_value = 0  # freshly re-seeded
        result = self._call()
        self.assertEqual(result, ('135', True, False))
        self.assertEqual(
            self.ctrl.holdover_timestamp[self.HO_IFACE], self._now)

    # ---- gate (negative / boundary cases) -----------------------------

    def test_not_in_holdover_returns_none_freerun(self):
        """DPLL genuinely free-run (not in holdover) -> None (caller -> 248)."""
        self._status['in_holdover'] = False
        self.assertIsNone(self._call())

    def test_never_locked_returns_none(self):
        """Cold start (ever_locked False) -> None (no false holdover claim)."""
        self._status['ever_locked'] = False
        self.assertIsNone(self._call())

    def test_no_custody_returns_none(self):
        """Not a backhaul-sourced leader (no DRIVE custody) -> None.

        This is the boundary that keeps GNSS-sourced T-GM leaders on their
        existing free-run -> 248 path.
        """
        with patch('ptp._leader_custody_confirmed', return_value=False):
            self.assertIsNone(self._call())

    def test_backhaul_still_locked_returns_none(self):
        """Backhaul still really locked (forwardable not None) -> None.

        Not a loss; the passthrough handles it. The helper must defer.
        """
        with patch('ptp._backhaul_forwardable_clock_class', return_value='6'):
            self.assertIsNone(self._call())

    def test_not_dpll_mgr_host_returns_none(self):
        """Not a dpll-mgr host -> None (no backhaul holdover concept)."""
        self._set(ptp, '_dpll_mgr_instance_name', None)
        self.assertIsNone(self._call())

    def test_no_status_file_returns_none(self):
        """status.json missing -> None (fail-safe to caller's decision)."""
        self.ctrl_status_none = Mock()
        self.ctrl_status_none.read.return_value = None
        with patch('ptp._dpll_mgr_status', self.ctrl_status_none):
            self.assertIsNone(self._call())


class _Restore:
    """Context-free restorer used with the setUp/tearDown patch list."""

    def __init__(self, mod, name, old):
        self._mod = mod
        self._name = name
        self._old = old

    def stop(self):
        setattr(self._mod, self._name, self._old)


if __name__ == '__main__':
    unittest.main()
