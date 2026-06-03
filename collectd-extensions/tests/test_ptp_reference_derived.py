#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Unit tests for reference/derived ptp4l instance locking and clock quality forwarding.
"""

import unittest
import sys
import os
from unittest.mock import MagicMock
from unittest.mock import patch
from collections import OrderedDict

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
from ptp import _try_lock_reference_derived
from ptp import _lock_derived_instance
from ptp import _resolve_reference_derived_roles
from ptp import process_ptp4l_derived
from ptp import PTP_INSTANCE_TYPE_PTP4L


class TestTryLockReferenceDerived(unittest.TestCase):
    """Test _try_lock_reference_derived role locking logic."""

    def setUp(self):
        """Set up two ptp4l instances sharing the same base_port."""
        self.ctrl_a = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_a.interface = 'ens1f0'
        self.ctrl_b = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_b.interface = 'ens1f0'

        ptp.ptpinstances = {
            'ptp4l-pts': self.ctrl_a,
            'ptp4l-fts': self.ctrl_b,
        }
        ptp.base_port_to_ptp4l_instances = {
            'ens1f0': ['ptp4l-pts', 'ptp4l-fts'],
        }
        ptp.ptp4l_instance_map = {}

    def tearDown(self):
        ptp.ptpinstances = {}
        ptp.base_port_to_ptp4l_instances = {}
        ptp.ptp4l_instance_map = {}
        ptp.ts2phc_instance_map = {}

    @patch('ptp.query_pmc_indexed')
    def test_i_have_slave_port_locks_as_reference(self, mock_query):
        """Instance with slave port locks as reference, sibling as derived."""
        mock_query.return_value = OrderedDict({
            'port1': {'portState': 'SLAVE', **{f'k{i}': 'v' for i in range(10)}}
        })

        result = _try_lock_reference_derived('ptp4l-pts', self.ctrl_a, 'ens1f0')

        self.assertFalse(result)
        self.assertFalse(self.ctrl_a.is_derived_instance)
        self.assertTrue(self.ctrl_b.is_derived_instance)
        self.assertEqual(self.ctrl_b.reference_ptp4l_instance, 'ptp4l-pts')
        self.assertEqual(ptp.ptp4l_instance_map['ens1f0'], 'ptp4l-pts')

    @patch('ptp.query_pmc_indexed')
    def test_sibling_has_slave_port_locks_me_as_derived(self, mock_query):
        """If my ports aren't slave but sibling's is, I'm derived."""
        def side_effect(instance, *args, **kwargs):
            if instance == 'ptp4l-fts':
                return OrderedDict({
                    'port1': {'portState': 'MASTER', **{f'k{i}': 'v' for i in range(10)}}
                })
            if instance == 'ptp4l-pts':
                return OrderedDict({
                    'port1': {'portState': 'SLAVE', **{f'k{i}': 'v' for i in range(10)}}
                })
            return OrderedDict()

        mock_query.side_effect = side_effect

        result = _try_lock_reference_derived('ptp4l-fts', self.ctrl_b, 'ens1f0')

        self.assertTrue(result)
        self.assertTrue(self.ctrl_b.is_derived_instance)
        self.assertFalse(self.ctrl_a.is_derived_instance)
        self.assertEqual(self.ctrl_b.reference_ptp4l_instance, 'ptp4l-pts')
        self.assertEqual(ptp.ptp4l_instance_map['ens1f0'], 'ptp4l-pts')

    @patch('ptp.query_pmc_indexed')
    def test_sibling_owns_ts2phc_port_nmea_locks_me_as_derived(self, mock_query):
        """If sibling owns ts2phc port (nmea), I'm derived."""
        # Use distinct interfaces: ptp4l-pts uses ens1f0, ptp4l-fts uses ens1f1
        self.ctrl_a.interface = 'ens1f0'
        self.ctrl_b.interface = 'ens1f1'
        # Set up ts2phc instance that disciplines ens1f0
        ctrl_ts2phc = PTP_ctrl_object(ptp.PTP_INSTANCE_TYPE_TS2PHC)
        ctrl_ts2phc.timing_instance = MagicMock()
        ctrl_ts2phc.timing_instance.interfaces = {'ens1f0'}
        ptp.ptpinstances['ts2phc-nmea'] = ctrl_ts2phc
        ptp.ts2phc_instance_map = {'ens1f0': 'ts2phc-nmea'}
        # ptp4l instances have their own timing_instance.interfaces
        self.ctrl_a.timing_instance = MagicMock()
        self.ctrl_a.timing_instance.interfaces = {'ens1f0'}
        self.ctrl_b.timing_instance = MagicMock()
        self.ctrl_b.timing_instance.interfaces = {'ens1f1'}
        self.ctrl_a.prtc_present = True
        self.ctrl_a.disciplined_by_ts2phc = True
        # My PMC query returns no slave
        mock_query.return_value = OrderedDict({
            'port1': {'portState': 'MASTER', **{f'k{i}': 'v' for i in range(10)}}
        })

        result = _try_lock_reference_derived('ptp4l-fts', self.ctrl_b, 'ens1f0')

        self.assertTrue(result)
        self.assertTrue(self.ctrl_b.is_derived_instance)
        self.assertFalse(self.ctrl_a.is_derived_instance)
        self.assertEqual(ptp.ptp4l_instance_map['ens1f0'], 'ptp4l-pts')

    @patch('ptp.query_pmc_indexed')
    def test_sibling_owns_ts2phc_port_generic_locks_me_as_derived(self, mock_query):
        """If sibling owns ts2phc port (generic), I'm derived."""
        # Use distinct interfaces: ptp4l-pts uses ens1f0, ptp4l-fts uses ens1f1
        self.ctrl_a.interface = 'ens1f0'
        self.ctrl_b.interface = 'ens1f1'
        # Set up ts2phc instance that disciplines ens1f0
        ctrl_ts2phc = PTP_ctrl_object(ptp.PTP_INSTANCE_TYPE_TS2PHC)
        ctrl_ts2phc.timing_instance = MagicMock()
        ctrl_ts2phc.timing_instance.interfaces = {'ens1f0'}
        ptp.ptpinstances['ts2phc-generic'] = ctrl_ts2phc
        ptp.ts2phc_instance_map = {'ens1f0': 'ts2phc-generic'}
        # ptp4l instances have their own timing_instance.interfaces
        self.ctrl_a.timing_instance = MagicMock()
        self.ctrl_a.timing_instance.interfaces = {'ens1f0'}
        self.ctrl_b.timing_instance = MagicMock()
        self.ctrl_b.timing_instance.interfaces = {'ens1f1'}
        self.ctrl_a.prtc_present = False
        self.ctrl_a.disciplined_by_ts2phc = True
        # My PMC query returns no slave
        mock_query.return_value = OrderedDict({
            'port1': {'portState': 'MASTER', **{f'k{i}': 'v' for i in range(10)}}
        })

        result = _try_lock_reference_derived('ptp4l-fts', self.ctrl_b, 'ens1f0')

        self.assertTrue(result)
        self.assertTrue(self.ctrl_b.is_derived_instance)
        self.assertFalse(self.ctrl_a.is_derived_instance)
        self.assertEqual(ptp.ptp4l_instance_map['ens1f0'], 'ptp4l-pts')

    @patch('ptp.query_pmc_indexed')
    def test_no_slave_port_defers(self, mock_query):
        """If no instance has slave port or prtc_present, defer (return False)."""
        mock_query.return_value = OrderedDict({
            'port1': {'portState': 'LISTENING', **{f'k{i}': 'v' for i in range(10)}}
        })

        result = _try_lock_reference_derived('ptp4l-pts', self.ctrl_a, 'ens1f0')

        self.assertFalse(result)
        self.assertIsNone(self.ctrl_a.is_derived_instance)
        self.assertIsNone(self.ctrl_b.is_derived_instance)

    @patch('ptp.query_pmc_indexed')
    def test_already_locked_derived_returns_true(self, mock_query):
        """Once locked as derived, returns True immediately without PMC query."""
        self.ctrl_b.is_derived_instance = True

        result = _try_lock_reference_derived('ptp4l-fts', self.ctrl_b, 'ens1f0')

        self.assertTrue(result)
        mock_query.assert_not_called()

    @patch('ptp.query_pmc_indexed')
    def test_already_locked_reference_returns_false(self, mock_query):
        """Once locked as reference, returns False immediately without PMC query."""
        self.ctrl_a.is_derived_instance = False

        result = _try_lock_reference_derived('ptp4l-pts', self.ctrl_a, 'ens1f0')

        self.assertFalse(result)
        mock_query.assert_not_called()

    def test_single_instance_on_base_port_locks_as_reference(self):
        """Single instance on base_port: not derived, no PMC queries needed."""
        ptp.base_port_to_ptp4l_instances = {'ens1f0': ['ptp4l-pts']}

        result = _try_lock_reference_derived('ptp4l-pts', self.ctrl_a, 'ens1f0')

        self.assertFalse(result)
        self.assertFalse(self.ctrl_a.is_derived_instance)


class TestTryLockThreeSiblings(unittest.TestCase):
    """Test _try_lock_reference_derived with 3 instances sharing base_port."""

    def setUp(self):
        self.ctrl_a = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_a.interface = 'ens1f0'
        self.ctrl_b = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_b.interface = 'ens1f0'
        self.ctrl_c = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_c.interface = 'ens1f0'

        ptp.ptpinstances = {
            'ptp4l-a': self.ctrl_a,
            'ptp4l-b': self.ctrl_b,
            'ptp4l-c': self.ctrl_c,
        }
        ptp.base_port_to_ptp4l_instances = {
            'ens1f0': ['ptp4l-a', 'ptp4l-b', 'ptp4l-c'],
        }
        ptp.ptp4l_instance_map = {}

    def tearDown(self):
        ptp.ptpinstances = {}
        ptp.base_port_to_ptp4l_instances = {}
        ptp.ptp4l_instance_map = {}
        ptp.ts2phc_instance_map = {}

    @patch('ptp.query_pmc_indexed')
    def test_i_have_slave_locks_all_siblings(self, mock_query):
        """Reference with slave port locks ALL siblings as derived in one call."""
        mock_query.return_value = OrderedDict({
            'port1': {'portState': 'SLAVE', **{f'k{i}': 'v' for i in range(10)}}
        })

        result = _try_lock_reference_derived('ptp4l-a', self.ctrl_a, 'ens1f0')

        self.assertFalse(result)
        self.assertFalse(self.ctrl_a.is_derived_instance)
        self.assertTrue(self.ctrl_b.is_derived_instance)
        self.assertTrue(self.ctrl_c.is_derived_instance)
        self.assertEqual(self.ctrl_b.reference_ptp4l_instance, 'ptp4l-a')
        self.assertEqual(self.ctrl_c.reference_ptp4l_instance, 'ptp4l-a')

    @patch('ptp.query_pmc_indexed')
    def test_sibling_slave_locks_all_others(self, mock_query):
        """When sibling has slave port, lock ALL other siblings as derived."""
        def side_effect(instance, *args, **kwargs):
            if instance == 'ptp4l-c':
                # caller: no slave
                return OrderedDict({
                    'port1': {'portState': 'MASTER', **{f'k{i}': 'v' for i in range(10)}}
                })
            if instance == 'ptp4l-a':
                # first sibling checked: has slave
                return OrderedDict({
                    'port1': {'portState': 'SLAVE', **{f'k{i}': 'v' for i in range(10)}}
                })
            return OrderedDict()

        mock_query.side_effect = side_effect

        result = _try_lock_reference_derived('ptp4l-c', self.ctrl_c, 'ens1f0')

        self.assertTrue(result)
        # A is reference
        self.assertFalse(self.ctrl_a.is_derived_instance)
        self.assertEqual(ptp.ptp4l_instance_map['ens1f0'], 'ptp4l-a')
        # B and C both derived
        self.assertTrue(self.ctrl_b.is_derived_instance)
        self.assertTrue(self.ctrl_c.is_derived_instance)
        self.assertEqual(self.ctrl_b.reference_ptp4l_instance, 'ptp4l-a')
        self.assertEqual(self.ctrl_c.reference_ptp4l_instance, 'ptp4l-a')

    @patch('ptp.query_pmc_indexed')
    def test_sibling_owns_ts2phc_port_locks_all_others(self, mock_query):
        """When sibling owns ts2phc port, lock ALL other siblings as derived."""
        # Use distinct interfaces: a=ens1f0, b=ens1f1, c=ens1f2
        self.ctrl_a.interface = 'ens1f0'
        self.ctrl_b.interface = 'ens1f1'
        self.ctrl_c.interface = 'ens1f2'
        # Set up ts2phc instance that disciplines ens1f0 (owned by ptp4l-a)
        ctrl_ts2phc = PTP_ctrl_object(ptp.PTP_INSTANCE_TYPE_TS2PHC)
        ctrl_ts2phc.timing_instance = MagicMock()
        ctrl_ts2phc.timing_instance.interfaces = {'ens1f0'}
        ptp.ptpinstances['ts2phc-nmea'] = ctrl_ts2phc
        ptp.ts2phc_instance_map = {'ens1f0': 'ts2phc-nmea'}
        # ptp4l instances have their own timing_instance.interfaces
        self.ctrl_a.timing_instance = MagicMock()
        self.ctrl_a.timing_instance.interfaces = {'ens1f0'}
        self.ctrl_b.timing_instance = MagicMock()
        self.ctrl_b.timing_instance.interfaces = {'ens1f1'}
        self.ctrl_c.timing_instance = MagicMock()
        self.ctrl_c.timing_instance.interfaces = {'ens1f2'}
        self.ctrl_a.disciplined_by_ts2phc = True
        mock_query.return_value = OrderedDict({
            'port1': {'portState': 'MASTER', **{f'k{i}': 'v' for i in range(10)}}
        })

        result = _try_lock_reference_derived('ptp4l-c', self.ctrl_c, 'ens1f0')

        self.assertTrue(result)
        self.assertFalse(self.ctrl_a.is_derived_instance)
        self.assertTrue(self.ctrl_b.is_derived_instance)
        self.assertTrue(self.ctrl_c.is_derived_instance)

    @patch('ptp.query_pmc_indexed')
    def test_no_extra_pmc_after_all_locked(self, mock_query):
        """After all siblings locked, subsequent calls issue no PMC queries."""
        self.ctrl_b.is_derived_instance = True
        self.ctrl_b.reference_ptp4l_instance = 'ptp4l-a'
        self.ctrl_c.is_derived_instance = True
        self.ctrl_c.reference_ptp4l_instance = 'ptp4l-a'

        result_b = _try_lock_reference_derived('ptp4l-b', self.ctrl_b, 'ens1f0')
        result_c = _try_lock_reference_derived('ptp4l-c', self.ctrl_c, 'ens1f0')

        self.assertTrue(result_b)
        self.assertTrue(result_c)
        mock_query.assert_not_called()


class TestTryLockInitialConfigOrder(unittest.TestCase):
    """Test that runtime locking correctly overwrites initial config registration order.

    Scenario: read_ptp4l_config() sets ptp4l_instance_map[base_port] to the
    first instance registered (B). At runtime, A acquires slave port and
    overwrites the mapping.
    """

    def setUp(self):
        self.ctrl_a = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_a.interface = 'ens1f0'
        self.ctrl_b = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_b.interface = 'ens1f0'

        ptp.ptpinstances = {
            'ptp4l-a': self.ctrl_a,
            'ptp4l-b': self.ctrl_b,
        }
        ptp.base_port_to_ptp4l_instances = {
            'ens1f0': ['ptp4l-a', 'ptp4l-b'],
        }
        # Simulate B registering first in read_ptp4l_config
        ptp.ptp4l_instance_map = {'ens1f0': 'ptp4l-b'}

    def tearDown(self):
        ptp.ptpinstances = {}
        ptp.base_port_to_ptp4l_instances = {}
        ptp.ptp4l_instance_map = {}

    @patch('ptp.query_pmc_indexed')
    def test_overwrite_initial_map_when_reference_found(self, mock_query):
        """ptp4l_instance_map overwritten from B to A when A has slave port."""
        mock_query.return_value = OrderedDict({
            'port1': {'portState': 'SLAVE', **{f'k{i}': 'v' for i in range(10)}}
        })

        # A discovers it has slave port
        _try_lock_reference_derived('ptp4l-a', self.ctrl_a, 'ens1f0')

        self.assertEqual(ptp.ptp4l_instance_map['ens1f0'], 'ptp4l-a')
        self.assertFalse(self.ctrl_a.is_derived_instance)
        self.assertTrue(self.ctrl_b.is_derived_instance)

    @patch('ptp.query_pmc_indexed')
    def test_overwrite_via_sibling_slave_discovery(self, mock_query):
        """ptp4l_instance_map overwritten when B discovers A has slave port."""
        def side_effect(instance, *args, **kwargs):
            if instance == 'ptp4l-b':
                return OrderedDict({
                    'port1': {'portState': 'MASTER', **{f'k{i}': 'v' for i in range(10)}}
                })
            if instance == 'ptp4l-a':
                return OrderedDict({
                    'port1': {'portState': 'SLAVE', **{f'k{i}': 'v' for i in range(10)}}
                })
            return OrderedDict()

        mock_query.side_effect = side_effect

        _try_lock_reference_derived('ptp4l-b', self.ctrl_b, 'ens1f0')

        # Map corrected from B to A
        self.assertEqual(ptp.ptp4l_instance_map['ens1f0'], 'ptp4l-a')
        self.assertTrue(self.ctrl_b.is_derived_instance)
        self.assertFalse(self.ctrl_a.is_derived_instance)


class TestProcessPtp4lDerived(unittest.TestCase):
    """Test clock quality forwarding from reference to derived instance."""

    def setUp(self):
        self.ctrl_ref = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_ref.interface = 'ens1f0'
        self.ctrl_derived = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_derived.interface = 'ens1f0'
        self.ctrl_derived.is_derived_instance = True
        self.ctrl_derived.reference_ptp4l_instance = 'ptp4l-ref'

        ptp.ptpinstances = {
            'ptp4l-ref': self.ctrl_ref,
            'ptp4l-derived': self.ctrl_derived,
        }

    def tearDown(self):
        ptp.ptpinstances = {}

    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.query_pmc')
    def test_forwards_clock_quality_from_reference(self, mock_pmc, mock_write):
        """Derived instance receives clockClass and traceability from reference."""
        def pmc_side_effect(instance, query_string, **kwargs):
            if instance == 'ptp4l-ref' and query_string == 'PARENT_DATA_SET':
                return OrderedDict({
                    'gm.ClockClass': '6',
                    'gm.ClockAccuracy': '0x21',
                    'gm.OffsetScaledLogVariance': '0x4e5d',
                    **{f'k{i}': 'v' for i in range(10)},
                })
            if instance == 'ptp4l-ref' and query_string == 'TIME_PROPERTIES_DATA_SET':
                return OrderedDict({
                    'currentUtcOffset': '37',
                    'currentUtcOffsetValid': '1',
                    'ptpTimescale': '1',
                    'timeTraceable': '1',
                    'frequencyTraceable': '1',
                    'timeSource': '0x20',
                    **{f'k{i}': 'v' for i in range(10)},
                })
            if instance == 'ptp4l-derived' and query_string == 'GRANDMASTER_SETTINGS_NP':
                return OrderedDict({
                    'clockClass': '248',
                    'clockAccuracy': '0xfe',
                    'offsetScaledLogVariance': '0xffff',
                    'currentUtcOffset': '37',
                    'leap61': '0',
                    'leap59': '0',
                    'currentUtcOffsetValid': '0',
                    'ptpTimescale': '1',
                    'timeTraceable': '0',
                    'frequencyTraceable': '0',
                    'timeSource': '0xa0',
                })
            return OrderedDict()

        mock_pmc.side_effect = pmc_side_effect

        process_ptp4l_derived('ptp4l-derived')

        mock_write.assert_called_once()
        call_args = mock_write.call_args[0]
        self.assertEqual(call_args[0], 'ptp4l-derived')
        gm_fields = call_args[1]
        self.assertEqual(gm_fields['clockClass'], '6')
        self.assertEqual(gm_fields['timeTraceable'], '1')
        self.assertEqual(gm_fields['frequencyTraceable'], '1')
        self.assertEqual(gm_fields['clockAccuracy'], '0x21')

    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.query_pmc')
    def test_no_write_when_reference_not_found(self, mock_pmc, mock_write):
        """No GM write when reference instance is missing from ptpinstances."""
        self.ctrl_derived.reference_ptp4l_instance = 'ptp4l-nonexistent'

        process_ptp4l_derived('ptp4l-derived')

        mock_write.assert_not_called()

    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.query_pmc')
    def test_no_write_when_reference_pmc_fails(self, mock_pmc, mock_write):
        """No GM write when PMC query to reference returns insufficient data."""
        mock_pmc.return_value = OrderedDict({'error': 'timeout'})

        process_ptp4l_derived('ptp4l-derived')

        mock_write.assert_not_called()

    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.query_pmc')
    def test_no_write_when_no_reference_set(self, mock_pmc, mock_write):
        """No GM write when reference_ptp4l_instance is None."""
        self.ctrl_derived.reference_ptp4l_instance = None

        process_ptp4l_derived('ptp4l-derived')

        mock_write.assert_not_called()
        mock_pmc.assert_not_called()

    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.query_pmc')
    def test_holdover_forwarded_from_reference(self, mock_pmc, mock_write):
        """Derived mirrors reference holdover state (clock class 7 -> 7)."""
        def pmc_side_effect(instance, query_string, **kwargs):
            if instance == 'ptp4l-ref' and query_string == 'PARENT_DATA_SET':
                return OrderedDict({
                    'gm.ClockClass': '7',
                    'gm.ClockAccuracy': '0x21',
                    'gm.OffsetScaledLogVariance': '0x4e5d',
                    **{f'k{i}': 'v' for i in range(10)},
                })
            if instance == 'ptp4l-ref' and query_string == 'TIME_PROPERTIES_DATA_SET':
                return OrderedDict({
                    'currentUtcOffset': '37',
                    'currentUtcOffsetValid': '1',
                    'ptpTimescale': '1',
                    'timeTraceable': '1',
                    'frequencyTraceable': '1',
                    'timeSource': '0x20',
                    **{f'k{i}': 'v' for i in range(10)},
                })
            if instance == 'ptp4l-derived' and query_string == 'GRANDMASTER_SETTINGS_NP':
                return OrderedDict({
                    'clockClass': '6',
                    'clockAccuracy': '0x21',
                    'offsetScaledLogVariance': '0x4e5d',
                    'currentUtcOffset': '37',
                    'leap61': '0',
                    'leap59': '0',
                    'currentUtcOffsetValid': '1',
                    'ptpTimescale': '1',
                    'timeTraceable': '1',
                    'frequencyTraceable': '1',
                    'timeSource': '0x20',
                })
            return OrderedDict()

        mock_pmc.side_effect = pmc_side_effect

        process_ptp4l_derived('ptp4l-derived')

        mock_write.assert_called_once()
        gm_fields = mock_write.call_args[0][1]
        self.assertEqual(gm_fields['clockClass'], '7')


class TestPhc2sysResolvesAfterLock(unittest.TestCase):
    """Test that phc2sys upstream resolution works correctly after locking.

    Verifies ptp4l_instance_map[base_port] points to the reference instance,
    ensuring process_ptp_bc and phc2sys HA resolve correctly.
    """

    def setUp(self):
        self.ctrl_a = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_a.interface = 'ens1f0'
        self.ctrl_b = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_b.interface = 'ens1f0'

        ptp.ptpinstances = {
            'ptp4l-a': self.ctrl_a,
            'ptp4l-b': self.ctrl_b,
        }
        ptp.base_port_to_ptp4l_instances = {
            'ens1f0': ['ptp4l-a', 'ptp4l-b'],
        }
        # B registered first (simulating read_ptp4l_config order)
        ptp.ptp4l_instance_map = {'ens1f0': 'ptp4l-b'}

    def tearDown(self):
        ptp.ptpinstances = {}
        ptp.base_port_to_ptp4l_instances = {}
        ptp.ptp4l_instance_map = {}

    @patch('ptp.query_pmc_indexed')
    def test_phc2sys_base_port_resolves_to_reference(self, mock_query):
        """After locking, ptp4l_instance_map[base_port] resolves to reference."""
        mock_query.return_value = OrderedDict({
            'port1': {'portState': 'SLAVE', **{f'k{i}': 'v' for i in range(10)}}
        })

        _try_lock_reference_derived('ptp4l-a', self.ctrl_a, 'ens1f0')

        # phc2sys would do: ptp4l_instance_map.get(get_base_port(source))
        upstream = ptp.ptp4l_instance_map.get('ens1f0')
        self.assertEqual(upstream, 'ptp4l-a')


class TestRolePermanence(unittest.TestCase):
    """Test that roles never change once locked."""

    def setUp(self):
        self.ctrl_a = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_a.interface = 'ens1f0'
        self.ctrl_a.is_derived_instance = False  # locked as reference

        self.ctrl_b = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_b.interface = 'ens1f0'
        self.ctrl_b.is_derived_instance = True  # locked as derived
        self.ctrl_b.reference_ptp4l_instance = 'ptp4l-a'

        ptp.ptpinstances = {
            'ptp4l-a': self.ctrl_a,
            'ptp4l-b': self.ctrl_b,
        }
        ptp.base_port_to_ptp4l_instances = {
            'ens1f0': ['ptp4l-a', 'ptp4l-b'],
        }
        ptp.ptp4l_instance_map = {'ens1f0': 'ptp4l-a'}

    def tearDown(self):
        ptp.ptpinstances = {}
        ptp.base_port_to_ptp4l_instances = {}
        ptp.ptp4l_instance_map = {}

    @patch('ptp.query_pmc_indexed')
    def test_locked_roles_never_change(self, mock_query):
        """Even if port states change, locked roles remain permanent."""
        # Call multiple times - should short-circuit
        for _ in range(10):
            r_a = _try_lock_reference_derived('ptp4l-a', self.ctrl_a, 'ens1f0')
            r_b = _try_lock_reference_derived('ptp4l-b', self.ctrl_b, 'ens1f0')

        self.assertFalse(r_a)
        self.assertTrue(r_b)
        self.assertFalse(self.ctrl_a.is_derived_instance)
        self.assertTrue(self.ctrl_b.is_derived_instance)
        self.assertEqual(self.ctrl_b.reference_ptp4l_instance, 'ptp4l-a')
        mock_query.assert_not_called()


class TestResolveReferenceDerivedRoles(unittest.TestCase):
    """Test _resolve_reference_derived_roles pre-loop orchestration."""

    def setUp(self):
        self.ctrl_ts2phc = PTP_ctrl_object(ptp.PTP_INSTANCE_TYPE_TS2PHC)
        self.ctrl_ts2phc.interface = 'ens1f0'
        self.ctrl_ts2phc.timing_instance = MagicMock()
        self.ctrl_ts2phc.timing_instance.interfaces = {'ens1f0'}

        self.ctrl_ref = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_ref.interface = 'ens1f0'
        self.ctrl_ref.disciplined_by_ts2phc = True
        self.ctrl_ref.timing_instance = MagicMock()
        self.ctrl_ref.timing_instance.interfaces = {'ens1f0'}

        self.ctrl_derived = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_derived.interface = 'ens1f1'
        self.ctrl_derived.disciplined_by_ts2phc = True
        self.ctrl_derived.timing_instance = MagicMock()
        self.ctrl_derived.timing_instance.interfaces = {'ens1f1'}

        ptp.ptpinstances = {
            'ts2phc-nmea': self.ctrl_ts2phc,
            'ptp4l-ref': self.ctrl_ref,
            'ptp4l-derived': self.ctrl_derived,
        }
        ptp.base_port_to_ptp4l_instances = {
            'ens1f0': ['ptp4l-ref', 'ptp4l-derived'],
        }
        ptp.ptp4l_instance_map = {'ens1f0': 'ptp4l-ref'}
        ptp.ts2phc_instance_map = {'ens1f0': 'ts2phc-nmea'}
        # Derived comes before reference in initial order
        ptp.ordered_instances = OrderedDict([
            ('ts2phc-nmea', self.ctrl_ts2phc),
            ('ptp4l-derived', self.ctrl_derived),
            ('ptp4l-ref', self.ctrl_ref),
        ])

    def tearDown(self):
        ptp.ptpinstances = {}
        ptp.base_port_to_ptp4l_instances = {}
        ptp.ptp4l_instance_map = {}
        ptp.ts2phc_instance_map = {}
        ptp.ordered_instances = OrderedDict()

    @patch('ptp.get_base_port', return_value='ens1f0')
    @patch('ptp.query_pmc_indexed')
    def test_locks_roles_and_reorders(self, mock_query, mock_base_port):
        """Roles locked and ordered_instances reordered: derived after reference."""
        # ptp4l-derived has no slave, ptp4l-ref has disciplined_by_ts2phc
        mock_query.return_value = OrderedDict({
            'port1': {'portState': 'MASTER', **{f'k{i}': 'v' for i in range(10)}}
        })

        ptp._resolve_reference_derived_roles()

        self.assertFalse(self.ctrl_ref.is_derived_instance)
        self.assertTrue(self.ctrl_derived.is_derived_instance)
        self.assertEqual(self.ctrl_derived.reference_ptp4l_instance, 'ptp4l-ref')
        # Verify ordering: derived is after reference
        keys = list(ptp.ordered_instances.keys())
        self.assertLess(keys.index('ptp4l-ref'), keys.index('ptp4l-derived'))

    @patch('ptp.get_base_port', return_value='ens1f0')
    @patch('ptp.query_pmc_indexed')
    def test_noop_after_roles_locked(self, mock_query, mock_base_port):
        """After roles locked, no PMC queries issued on subsequent calls."""
        self.ctrl_ref.is_derived_instance = False
        self.ctrl_derived.is_derived_instance = True
        self.ctrl_derived.reference_ptp4l_instance = 'ptp4l-ref'

        ptp._resolve_reference_derived_roles()

        mock_query.assert_not_called()

    @patch('ptp.get_base_port', return_value='ens1f0')
    @patch('ptp.query_pmc_indexed')
    def test_defers_when_no_slave_or_ts2phc(self, mock_query, mock_base_port):
        """When no slave port and no ts2phc on this base_port, roles stay None."""
        self.ctrl_ref.disciplined_by_ts2phc = False
        self.ctrl_derived.disciplined_by_ts2phc = False
        ptp.ts2phc_instance_map = {}
        mock_query.return_value = OrderedDict({
            'port1': {'portState': 'LISTENING', **{f'k{i}': 'v' for i in range(10)}}
        })

        ptp._resolve_reference_derived_roles()

        self.assertIsNone(self.ctrl_ref.is_derived_instance)
        self.assertIsNone(self.ctrl_derived.is_derived_instance)
        # No reorder since no roles locked
        keys = list(ptp.ordered_instances.keys())
        self.assertEqual(keys, ['ts2phc-nmea', 'ptp4l-derived', 'ptp4l-ref'])

    @patch('ptp.get_base_port', return_value='ens1f0')
    @patch('ptp.query_pmc_indexed')
    def test_single_instance_skipped(self, mock_query, mock_base_port):
        """Single ptp4l instance on base_port is skipped (no sibling)."""
        ptp.base_port_to_ptp4l_instances = {'ens1f0': ['ptp4l-ref']}
        ptp.ordered_instances = OrderedDict([
            ('ptp4l-ref', self.ctrl_ref),
        ])

        ptp._resolve_reference_derived_roles()

        mock_query.assert_not_called()
        # is_derived_instance stays None (not locked via this path)
        self.assertIsNone(self.ctrl_ref.is_derived_instance)


class TestResolveWithSlavePort(unittest.TestCase):
    """Test _resolve_reference_derived_roles with slave port detection."""

    def setUp(self):
        self.ctrl_a = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_a.interface = 'ens2f0'
        self.ctrl_b = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.ctrl_b.interface = 'ens2f0'

        ptp.ptpinstances = {
            'ptp4l-a': self.ctrl_a,
            'ptp4l-b': self.ctrl_b,
        }
        ptp.base_port_to_ptp4l_instances = {
            'ens2f0': ['ptp4l-a', 'ptp4l-b'],
        }
        ptp.ptp4l_instance_map = {}
        # B before A in initial order
        ptp.ordered_instances = OrderedDict([
            ('ptp4l-b', self.ctrl_b),
            ('ptp4l-a', self.ctrl_a),
        ])

    def tearDown(self):
        ptp.ptpinstances = {}
        ptp.base_port_to_ptp4l_instances = {}
        ptp.ptp4l_instance_map = {}
        ptp.ordered_instances = OrderedDict()

    @patch('ptp.get_base_port', return_value='ens2f0')
    @patch('ptp.query_pmc_indexed')
    def test_slave_port_locks_and_reorders(self, mock_query, mock_base_port):
        """Instance with slave port becomes reference, reordered before derived."""
        def side_effect(instance, *args, **kwargs):
            if instance == 'ptp4l-b':
                return OrderedDict({
                    'port1': {'portState': 'MASTER', **{f'k{i}': 'v' for i in range(10)}}
                })
            if instance == 'ptp4l-a':
                return OrderedDict({
                    'port1': {'portState': 'SLAVE', **{f'k{i}': 'v' for i in range(10)}}
                })
            return OrderedDict()

        mock_query.side_effect = side_effect

        ptp._resolve_reference_derived_roles()

        self.assertFalse(self.ctrl_a.is_derived_instance)
        self.assertTrue(self.ctrl_b.is_derived_instance)
        self.assertEqual(self.ctrl_b.reference_ptp4l_instance, 'ptp4l-a')
        # Verify ordering: reference (A) before derived (B)
        keys = list(ptp.ordered_instances.keys())
        self.assertLess(keys.index('ptp4l-a'), keys.index('ptp4l-b'))


if __name__ == '__main__':
    unittest.main()
