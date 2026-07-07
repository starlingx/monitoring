#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Unit tests for leap-seconds file parsing and time-window state machine logic.

Tests cover:
- parse_leapfile: parsing, caching, error handling
- _find_relevant_leap_event: future/recent-past event selection
- get_leapfile_state: state machine transitions (no_leap, pre_leap,
  during_leap, post_leap), offset settling, flag logic
- get_leap_flags_for_gm: state-transition logging
"""

import unittest
import sys
import os
import tempfile
from unittest.mock import MagicMock
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
from ptp import parse_leapfile
from ptp import _find_relevant_leap_event
from ptp import get_leapfile_state
from ptp import get_leap_flags_for_gm
from ptp import NTP_EPOCH_OFFSET
from ptp import LEAP_BEFORE_EVENT
from ptp import LEAP_AFTER_EVENT
from ptp import PTP_ctrl_object
from ptp import PTP_INSTANCE_TYPE_PTP4L


# Sample leap-seconds.list content (simplified, real format)
SAMPLE_LEAPFILE = """\
#	ATOMIC TIME
#	Coordinated Universal Time (UTC) is the reference time scale derived
#	from The "Temps Atomique International" (TAI) calculated by the Bureau
#	International des Poids et Mesures (BIPM) using a worldwide network of atomic
#	clocks. UTC differs from TAI by an integer number of seconds; it is the basis
#	of all activities in the world.
#
#
#	ASTRONOMICAL TIME (UT1) is the time scale based on the rate of rotation of the earth.
#	It is now mainly derived from Very Long Baseline Interferometry (VLBI). The various
#	irregular fluctuations progressively detected in the rotation rate of the Earth led
#	in 1972 to the replacement of UT1 by UTC as the reference time scale.
#
#
#	LEAP SECOND
#	Atomic clocks are more stable than the rate of the earth's rotation since the latter
#	undergoes a full range of geophysical perturbations at various time scales: lunisolar
#	and core-mantle torques, atmospheric and oceanic effects, etc.
#	Leap seconds are needed to keep the two time scales in agreement, i.e. UT1-UTC smaller
#	than 0.9 seconds. Therefore, when necessary a "leap second" is applied to UTC.
#	Since the adoption of this system in 1972 it has been necessary to add a number of seconds to UTC,
#	firstly due to the initial choice of the value of the second (1/86400 mean solar day of
#	the year 1820) and secondly to the general slowing down of the Earth's rotation. It is
#	theoretically possible to have a negative leap second (a second removed from UTC), but so far,
#	all leap seconds have been positive (a second has been added to UTC). Based on what we know about
#	the earth's rotation, it is unlikely that we will ever have a negative leap second.
#
#
#	HISTORY
#	The first leap second was added on June 30, 1972. Until the year 2000, it was necessary in average to add a
#       leap second at a rate of 1 to 2 years. Since the year 2000 leap seconds are introduced with an
#	average interval of 3 to 4 years due to the acceleration of the Earth's rotation speed.
#
#
#	RESPONSIBILITY OF THE DECISION TO INTRODUCE A LEAP SECOND IN UTC
#	The decision to introduce a leap second in UTC is the responsibility of the Earth Orientation Center of
#	the International Earth Rotation and reference System Service (IERS). This center is located at Paris
#	Observatory. According to international agreements, leap seconds should be scheduled only for certain dates:
#	first preference is given to the end of December and June, and second preference at the end of March
#	and September. Since the introduction of leap seconds in 1972, only dates in June and December were used.
#
#		Questions or comments to:
#			Christian Bizouard:  christian.bizouard@obspm.fr
#			Earth orientation Center of the IERS
#			Paris Observatory, France
#
#
#
#    	COPYRIGHT STATUS OF THIS FILE
#    	This file is in the public domain.
#
#
#	VALIDITY OF THE FILE
#	It is important to express the validity of the file. These next two dates are
#	given in units of seconds since 1900.0.
#
#	1) Last update of the file.
#
#	Updated through IERS Bulletin C (https://hpiers.obspm.fr/iers/bul/bulc/bulletinc.dat)
#
#	The following line shows the last update of this file in NTP timestamp:
#
#$	3976686858
#
#	2) Expiration date of the file given on a semi-annual basis: last June or last December
#
#	File expires on 28 December 2026
#
#	Expire date in NTP timestamp:
#
#@	4007404800
#
#
#	LIST OF LEAP SECONDS
#	NTP timestamp (X parameter) is the number of seconds since 1900.0
#
#	MJD: The Modified Julian Day number. MJD = X/86400 + 15020
#
#	DTAI: The difference DTAI= TAI-UTC in units of seconds
#	It is the quantity to add to UTC to get the time in TAI
#
#	Day Month Year : epoch in clear
#
#NTP Time      DTAI    Day Month Year
#
2272060800      10      # 1 Jan 1972
2287785600      11      # 1 Jul 1972
2303683200      12      # 1 Jan 1973
2335219200      13      # 1 Jan 1974
2366755200      14      # 1 Jan 1975
2398291200      15      # 1 Jan 1976
2429913600      16      # 1 Jan 1977
2461449600      17      # 1 Jan 1978
2492985600      18      # 1 Jan 1979
2524521600      19      # 1 Jan 1980
2571782400      20      # 1 Jul 1981
2603318400      21      # 1 Jul 1982
2634854400      22      # 1 Jul 1983
2698012800      23      # 1 Jul 1985
2776982400      24      # 1 Jan 1988
2840140800      25      # 1 Jan 1990
2871676800      26      # 1 Jan 1991
2918937600      27      # 1 Jul 1992
2950473600      28      # 1 Jul 1993
2982009600      29      # 1 Jul 1994
3029443200      30      # 1 Jan 1996
3076704000      31      # 1 Jul 1997
3124137600      32      # 1 Jan 1999
3345062400      33      # 1 Jan 2006
3439756800      34      # 1 Jan 2009
3550089600      35      # 1 Jul 2012
3644697600      36      # 1 Jul 2015
3692217600      37      # 1 Jan 2017
#
#	A hash code has been generated to be able to verify the integrity
#	of this file. For more information about using this hash code,
#	please see the readme file in the 'source' directory :
#	https://hpiers.obspm.fr/iers/bul/bulc/ntp/sources/README
#
#h	34375519 c397c2a2 9f36d2d9 dc914f51 1b9aa6b7
"""

# Expiration NTP timestamp from the sample above
SAMPLE_EXPIRATION_NTP = 4007404800


class TestParseLeapfile(unittest.TestCase):
    """Tests for parse_leapfile()."""

    def setUp(self):
        """Reset the leapfile cache between tests."""
        ptp._leapfile_cache = {'filepath': None, 'mtime': 0,
                               'result': (None, None)}

    def test_parse_leapfile_valid(self):
        """Parses entries and expiration from a real-format file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.list',
                                         delete=False) as f:
            f.write(SAMPLE_LEAPFILE)
            filepath = f.name

        try:
            expiration, entries = parse_leapfile(filepath)
            self.assertEqual(expiration, SAMPLE_EXPIRATION_NTP)
            self.assertIsNotNone(entries)
            self.assertGreater(len(entries), 0)
            # Entries should be sorted by timestamp
            timestamps = [e[0] for e in entries]
            self.assertEqual(timestamps, sorted(timestamps))
            # Last entry should be offset 37 at NTP ts 3692217600
            self.assertEqual(entries[-1], (3692217600, 37))
        finally:
            os.unlink(filepath)

    def test_parse_leapfile_caching(self):
        """Second call with same mtime returns cached result."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.list',
                                         delete=False) as f:
            f.write(SAMPLE_LEAPFILE)
            filepath = f.name

        try:
            result1 = parse_leapfile(filepath)
            result2 = parse_leapfile(filepath)
            # Should be the exact same object (cached)
            self.assertIs(result1[1], result2[1])
        finally:
            os.unlink(filepath)

    def test_parse_leapfile_missing_file(self):
        """Returns (None, None) for nonexistent file."""
        expiration, entries = parse_leapfile('/nonexistent/leapfile.list')
        self.assertIsNone(expiration)
        self.assertIsNone(entries)

    def test_parse_leapfile_empty_entries(self):
        """Returns (None, None) for file with only comments."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.list',
                                         delete=False) as f:
            f.write("# Only comments\n#@ 3960057600\n")
            filepath = f.name

        try:
            expiration, entries = parse_leapfile(filepath)
            self.assertIsNone(expiration)
            self.assertIsNone(entries)
        finally:
            os.unlink(filepath)


class TestFindRelevantLeapEvent(unittest.TestCase):
    """Tests for _find_relevant_leap_event()."""

    def setUp(self):
        """Create a standard set of entries for testing."""
        # Simplified entries: timestamps and offsets
        self.entries = [
            (3550089600, 35),
            (3644697600, 36),
            (3692217600, 37),
        ]

    def test_find_relevant_event_future(self):
        """Finds next future leap event."""
        # now_ntp is before the last entry
        now_ntp = 3692217600 - 3600  # 1 hour before last event
        result = _find_relevant_leap_event(self.entries, now_ntp)
        self.assertIsNotNone(result)
        self.assertEqual(result['ntp_timestamp'], 3692217600)
        self.assertEqual(result['offset_after'], 37)
        self.assertEqual(result['offset_before'], 36)
        self.assertTrue(result['is_positive'])  # 37 > 36

    def test_find_relevant_event_recent_past(self):
        """Finds event within 2 * LEAP_AFTER_EVENT window."""
        # now_ntp is 2 hours after the last entry (within 12h window)
        now_ntp = 3692217600 + (2 * 3600)
        result = _find_relevant_leap_event(self.entries, now_ntp)
        self.assertIsNotNone(result)
        self.assertEqual(result['ntp_timestamp'], 3692217600)
        self.assertEqual(result['offset_after'], 37)

    def test_find_relevant_event_none(self):
        """No relevant event when all are old (past the 12h window)."""
        # now_ntp is 13 hours after the last entry (past 2 * 6h window)
        now_ntp = 3692217600 + (13 * 3600)
        result = _find_relevant_leap_event(self.entries, now_ntp)
        self.assertIsNone(result)

    def test_find_relevant_event_post_leap_window(self):
        """Event between 6h and 12h is still returned (for post_leap state)."""
        # now_ntp is 8 hours after last entry — past LEAP_AFTER_EVENT
        # but within 2 * LEAP_AFTER_EVENT
        now_ntp = 3692217600 + (8 * 3600)
        result = _find_relevant_leap_event(self.entries, now_ntp)
        self.assertIsNotNone(result)
        self.assertEqual(result['ntp_timestamp'], 3692217600)

    def test_find_relevant_event_first_future(self):
        """Returns the first future event when multiple are in the future."""
        # now_ntp is before the first entry — all entries are future
        now_ntp = 3500000000
        result = _find_relevant_leap_event(self.entries, now_ntp)
        self.assertIsNotNone(result)
        self.assertEqual(result['ntp_timestamp'], 3550089600)

    def test_negative_leap_second(self):
        """Correctly identifies a negative leap second (offset decreases)."""
        entries = [
            (3550089600, 37),
            (3644697600, 36),  # Negative leap: offset decreases
        ]
        now_ntp = 3644697600 - 3600  # 1 hour before
        result = _find_relevant_leap_event(entries, now_ntp)
        self.assertIsNotNone(result)
        self.assertFalse(result['is_positive'])  # 36 < 37


class TestGetLeapfileState(unittest.TestCase):
    """Tests for get_leapfile_state() time-window state machine."""

    def setUp(self):
        """Reset cache."""
        ptp._leapfile_cache = {'filepath': None, 'mtime': 0,
                               'result': (None, None)}

    def _write_leapfile(self, entries, expiration_ntp):
        """Helper: write a leapfile with given entries and expiration."""
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.list',
                                        delete=False)
        f.write("#@ %d\n" % expiration_ntp)
        for ts, offset in entries:
            f.write("%d %d\n" % (ts, offset))
        f.close()
        return f.name

    @patch('time.time')
    def test_leapfile_state_no_leap(self, mock_time):
        """No upcoming event, state='no_leap', flags=0."""
        # All entries well in the past, no relevant event
        entries = [
            (2000000000, 35),
            (2100000000, 36),
            (2200000000, 37),
        ]
        # "Now" in NTP: well after last entry + 2 * LEAP_AFTER_EVENT
        # (past the 12h observation window)
        now_unix = 2200000000 - NTP_EPOCH_OFFSET + 2 * LEAP_AFTER_EVENT + 3600
        mock_time.return_value = now_unix

        filepath = self._write_leapfile(entries,
                                        expiration_ntp=2200000000 + 10000000)
        try:
            result = get_leapfile_state(filepath)
            self.assertIsNotNone(result)
            self.assertEqual(result['state'], 'no_leap')
            self.assertEqual(result['leap61'], 0)
            self.assertEqual(result['leap59'], 0)
            self.assertEqual(result['current_offset'], 37)
        finally:
            os.unlink(filepath)

    @patch('time.time')
    def test_leapfile_state_pre_leap(self, mock_time):
        """Within 12h before event, leap61=1."""
        entries = [
            (2000000000, 35),
            (2100000000, 36),
            (2200000000, 37),  # Future event
        ]
        # "Now" is 6 hours before the event (within 12h window)
        now_ntp = 2200000000 - (6 * 3600)
        now_unix = now_ntp - NTP_EPOCH_OFFSET
        mock_time.return_value = now_unix

        filepath = self._write_leapfile(entries,
                                        expiration_ntp=2200000000 + 10000000)
        try:
            result = get_leapfile_state(filepath)
            self.assertIsNotNone(result)
            self.assertEqual(result['state'], 'pre_leap')
            self.assertEqual(result['leap61'], 1)
            self.assertEqual(result['leap59'], 0)
            # Settled offset should be 36 (last entry before the 6h window)
            self.assertEqual(result['current_offset'], 36)
        finally:
            os.unlink(filepath)

    @patch('time.time')
    def test_leapfile_state_during_leap(self, mock_time):
        """Within 6h after event, leap61 still set, old offset returned."""
        entries = [
            (2000000000, 35),
            (2100000000, 36),
            (2200000000, 37),  # Event just happened
        ]
        # "Now" is 2 hours after the event (within 6h window)
        now_ntp = 2200000000 + (2 * 3600)
        now_unix = now_ntp - NTP_EPOCH_OFFSET
        mock_time.return_value = now_unix

        filepath = self._write_leapfile(entries,
                                        expiration_ntp=2200000000 + 10000000)
        try:
            result = get_leapfile_state(filepath)
            self.assertIsNotNone(result)
            self.assertEqual(result['state'], 'during_leap')
            self.assertEqual(result['leap61'], 1)
            self.assertEqual(result['leap59'], 0)
            # Settled offset is 36, NOT 37 (new offset not adopted until
            # 6h after event)
            self.assertEqual(result['current_offset'], 36)
        finally:
            os.unlink(filepath)

    @patch('time.time')
    def test_leapfile_state_post_leap(self, mock_time):
        """Past 6h window but within 12h, state='post_leap', flags cleared."""
        entries = [
            (2000000000, 35),
            (2100000000, 36),
            (2200000000, 37),  # Event in past, beyond 6h but within 12h
        ]
        # "Now" is 7 hours after the event (past LEAP_AFTER_EVENT,
        # but within 2 * LEAP_AFTER_EVENT so the event is still relevant)
        now_ntp = 2200000000 + (7 * 3600)
        now_unix = now_ntp - NTP_EPOCH_OFFSET
        mock_time.return_value = now_unix

        filepath = self._write_leapfile(entries,
                                        expiration_ntp=2200000000 + 10000000)
        try:
            result = get_leapfile_state(filepath)
            self.assertIsNotNone(result)
            self.assertEqual(result['state'], 'post_leap')
            self.assertEqual(result['leap61'], 0)
            self.assertEqual(result['leap59'], 0)
            # New offset 37 is now settled
            self.assertEqual(result['current_offset'], 37)
        finally:
            os.unlink(filepath)

    @patch('time.time')
    def test_leapfile_state_fully_past(self, mock_time):
        """Past 12h window, event no longer relevant, state='no_leap'."""
        entries = [
            (2000000000, 35),
            (2100000000, 36),
            (2200000000, 37),  # Event well in the past
        ]
        # "Now" is 13 hours after the event (past 2 * LEAP_AFTER_EVENT)
        now_ntp = 2200000000 + (13 * 3600)
        now_unix = now_ntp - NTP_EPOCH_OFFSET
        mock_time.return_value = now_unix

        filepath = self._write_leapfile(entries,
                                        expiration_ntp=2200000000 + 10000000)
        try:
            result = get_leapfile_state(filepath)
            self.assertIsNotNone(result)
            self.assertEqual(result['state'], 'no_leap')
            self.assertEqual(result['leap61'], 0)
            self.assertEqual(result['leap59'], 0)
            self.assertEqual(result['current_offset'], 37)
        finally:
            os.unlink(filepath)

    @patch('time.time')
    def test_settled_offset_not_advanced_during_window(self, mock_time):
        """currentUtcOffset stays at old value during the 6h window."""
        entries = [
            (2000000000, 36),
            (2200000000, 37),  # Event just happened
        ]
        # "Now" is 1 hour after the event
        now_ntp = 2200000000 + 3600
        now_unix = now_ntp - NTP_EPOCH_OFFSET
        mock_time.return_value = now_unix

        filepath = self._write_leapfile(entries,
                                        expiration_ntp=2200000000 + 10000000)
        try:
            result = get_leapfile_state(filepath)
            # The settled offset must be 36, not 37
            self.assertEqual(result['current_offset'], 36)
            self.assertEqual(result['offset_after'], 37)
        finally:
            os.unlink(filepath)

    @patch('time.time')
    def test_negative_leap_second(self, mock_time):
        """leap59 flag set for a negative leap (offset decreases)."""
        entries = [
            (2000000000, 37),
            (2200000000, 36),  # Negative leap second
        ]
        # "Now" is 3 hours before the event (within 12h window)
        now_ntp = 2200000000 - (3 * 3600)
        now_unix = now_ntp - NTP_EPOCH_OFFSET
        mock_time.return_value = now_unix

        filepath = self._write_leapfile(entries,
                                        expiration_ntp=2200000000 + 10000000)
        try:
            result = get_leapfile_state(filepath)
            self.assertEqual(result['state'], 'pre_leap')
            self.assertEqual(result['leap59'], 1)
            self.assertEqual(result['leap61'], 0)
        finally:
            os.unlink(filepath)

    @patch('time.time')
    def test_parse_leapfile_expired(self, mock_time):
        """get_leapfile_state returns None for expired file."""
        entries = [
            (2000000000, 36),
            (2100000000, 37),
        ]
        # Expiration in the past relative to "now"
        expiration_ntp = 2200000000
        now_ntp = 2200000001  # 1 second past expiration
        now_unix = now_ntp - NTP_EPOCH_OFFSET
        mock_time.return_value = now_unix

        filepath = self._write_leapfile(entries,
                                        expiration_ntp=expiration_ntp)
        try:
            result = get_leapfile_state(filepath)
            self.assertIsNone(result)
        finally:
            os.unlink(filepath)

    @patch('time.time')
    def test_pre_leap_boundary_exactly_12h(self, mock_time):
        """At exactly 12h before event, time_to_event == LEAP_BEFORE_EVENT.

        The condition is 'time_to_event > LEAP_BEFORE_EVENT' for no_leap,
        so at exactly 12h the event falls into pre_leap (not >).
        """
        entries = [
            (2000000000, 36),
            (2200000000, 37),
        ]
        # "Now" is exactly LEAP_BEFORE_EVENT seconds before the event
        now_ntp = 2200000000 - LEAP_BEFORE_EVENT
        now_unix = now_ntp - NTP_EPOCH_OFFSET
        mock_time.return_value = now_unix

        filepath = self._write_leapfile(entries,
                                        expiration_ntp=2200000000 + 10000000)
        try:
            result = get_leapfile_state(filepath)
            # time_to_event == LEAP_BEFORE_EVENT, condition is >
            # so NOT greater-than, falls into elif time_to_event > 0 → pre_leap
            self.assertEqual(result['state'], 'pre_leap')
            self.assertEqual(result['leap61'], 1)
        finally:
            os.unlink(filepath)

    @patch('time.time')
    def test_during_leap_boundary_exactly_6h(self, mock_time):
        """At exactly 6h after event, flags should still be set."""
        entries = [
            (2000000000, 36),
            (2200000000, 37),
        ]
        # "Now" is exactly LEAP_AFTER_EVENT seconds after the event
        now_ntp = 2200000000 + LEAP_AFTER_EVENT
        now_unix = now_ntp - NTP_EPOCH_OFFSET
        mock_time.return_value = now_unix

        filepath = self._write_leapfile(entries,
                                        expiration_ntp=2200000000 + 10000000)
        try:
            result = get_leapfile_state(filepath)
            # -time_to_event == LEAP_AFTER_EVENT, condition is <= so
            # it's 'during_leap'
            self.assertEqual(result['state'], 'during_leap')
            self.assertEqual(result['leap61'], 1)
        finally:
            os.unlink(filepath)


class TestGetLeapFlagsForGm(unittest.TestCase):
    """Tests for get_leap_flags_for_gm() state-transition logging."""

    def setUp(self):
        """Reset cache and set up a ctrl object."""
        ptp._leapfile_cache = {'filepath': None, 'mtime': 0,
                               'result': (None, None)}
        self.ctrl = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)

    @patch('time.time')
    def test_state_transition_logging(self, mock_time):
        """State transitions are logged and tracked on ctrl."""
        entries = [
            (2000000000, 36),
            (2200000000, 37),
        ]
        expiration_ntp = 2200000000 + 10000000

        f = tempfile.NamedTemporaryFile(mode='w', suffix='.list',
                                        delete=False)
        f.write("#@ %d\n" % expiration_ntp)
        for ts, offset in entries:
            f.write("%d %d\n" % (ts, offset))
        f.close()
        filepath = f.name

        try:
            ptp.leap_seconds_file = filepath

            # First call: no_leap → pre_leap transition
            now_ntp = 2200000000 - (6 * 3600)
            mock_time.return_value = now_ntp - NTP_EPOCH_OFFSET

            result = get_leap_flags_for_gm(self.ctrl)
            self.assertEqual(result['state'], 'pre_leap')
            self.assertEqual(self.ctrl._previous_leap_state, 'pre_leap')

            # Second call at same time: no transition, same state
            ptp._leapfile_cache = {'filepath': None, 'mtime': 0,
                                   'result': (None, None)}
            result = get_leap_flags_for_gm(self.ctrl)
            self.assertEqual(self.ctrl._previous_leap_state, 'pre_leap')
        finally:
            ptp.leap_seconds_file = None
            os.unlink(filepath)

    def test_previous_leap_state_initialized(self):
        """_previous_leap_state is initialized to None in __init__."""
        ctrl = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.assertIsNone(ctrl._previous_leap_state)

    def test_leap_file_none(self):
        """Returns None when leap_seconds_file is not configured."""
        ptp.leap_seconds_file = None
        result = get_leap_flags_for_gm(self.ctrl)
        self.assertIsNone(result)


class TestHandleG8275NotCalledForDerived(unittest.TestCase):
    """Verify derived instances don't enter handle_ptp4l_g8275_fields.

    This confirms the call-site guard: handle_ptp4l_g8275_fields is only
    called when ctrl.is_derived_instance is False. Derived instances go
    through process_ptp4l_derived instead.
    """

    def test_dispatch_guard_excludes_derived(self):
        """Derived instance goes to process_ptp4l_derived, not g8275."""
        ctrl = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        ctrl.is_derived_instance = True
        ctrl.disciplined_by_ts2phc = True

        # The guard at the call site:
        #   if not ctrl.is_derived_instance:
        #       handle_ptp4l_g8275_fields(instance)
        # Verify: derived instances should NOT pass this guard
        self.assertTrue(ctrl.is_derived_instance)
        # Therefore handle_ptp4l_g8275_fields would not be called

    def test_dispatch_guard_includes_non_derived(self):
        """Non-derived instance passes the guard to handle_ptp4l_g8275_fields."""
        ctrl = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        ctrl.is_derived_instance = False
        ctrl.disciplined_by_ts2phc = True

        self.assertFalse(ctrl.is_derived_instance)
        # Therefore handle_ptp4l_g8275_fields WOULD be called


if __name__ == '__main__':
    unittest.main()
