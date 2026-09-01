#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Unit tests for process_ptp_bc downstream degradation when the upstream
ptp4l service (the instance connected to the GM) is stopped.

When the upstream ptp4l service is down, its pmc UDS socket is gone so it
cannot be polled and the last clock class polled from it is stale. The
downstream ptp4l (T-BC) instances must not keep advertising a healthy
clock class (e.g. clockClass 6); they must degrade through holdover
(clockClass 135) and then holdover-expired (clockClass 165).

Note on test isolation: the ptp module derives its CLOCK_STATE_* constants
from pynetlink.LockStatus, which is mocked across this suite. To avoid being
the module that imports ptp first at collection time (which would rebind those
shared constants and perturb sibling test modules), this module performs all
sys.modules mocking and the ptp import lazily inside setUp, and reads the
CLOCK_STATE_* values from the ptp module at run time.
"""

import unittest
import sys
import os
from unittest.mock import MagicMock
from unittest.mock import patch


class TestProcessPtpBcUpstreamDown(unittest.TestCase):
    """process_ptp_bc downstream degradation on upstream ptp4l down."""

    _MOCK_MODULES = [
        'collectd', 'tsconfig', 'tsconfig.tsconfig', 'plugin_common',
        'fm_api', 'fm_api.constants', 'fm_api.fm_api', 'ptp_interface',
        'ptp_gnss_monitor', 'cgu_handler', 'pynetlink', 'oslo_utils',
        'oslo_utils.timeutils',
    ]

    @staticmethod
    def _gm_settings(clock_class):
        """A GRANDMASTER_SETTINGS_NP reply with the fields the code reads."""
        return {
            'clockClass': clock_class,
            'clockAccuracy': '0x21',
            'offsetScaledLogVariance': '0x4e5d',
            'currentUtcOffset': '37',
            'currentUtcOffsetValid': '1',
            'ptpTimescale': '1',
            'timeTraceable': '1',
            'frequencyTraceable': '1',
            'timeSource': '0x20',
            'leap61': '0',
            'leap59': '0',
        }

    def setUp(self):
        # Mock external dependencies only if not already present, so this
        # module does not replace a pynetlink mock another module relies on.
        self._added_modules = []
        for mod in self._MOCK_MODULES:
            if mod not in sys.modules:
                sys.modules[mod] = MagicMock()
                self._added_modules.append(mod)

        src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
        self._added_syspath = src_path not in sys.path
        if self._added_syspath:
            sys.path.insert(0, src_path)

        import ptp
        self.ptp = ptp
        from ptp import PTP_ctrl_object
        from ptp import PTP_INSTANCE_TYPE_PTP4L

        # Downstream T-BC instance under test
        self.downstream = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.downstream.interface = 'ens2f0'
        self.downstream.timing_instance = MagicMock()
        self.downstream.timing_instance.config = {
            'global': {'domainNumber': 24}}
        self.downstream.monitoring_parameters = {'holdover_seconds': 60}
        self.downstream.ptp4l_ptp_source_state = ptp.CLOCK_STATE_LOCKED

        # Upstream instance connected to the GM
        self.upstream = PTP_ctrl_object(PTP_INSTANCE_TYPE_PTP4L)
        self.upstream.interface = 'ens1f0'
        self.upstream.timing_instance = MagicMock()
        self.upstream.timing_instance.config = {
            'global': {'domainNumber': 24}}

        # Save and set the module globals process_ptp_bc reads
        self._saved_globals = {
            'ptpinstances': ptp.ptpinstances,
            'phc2sys_source': ptp.phc2sys_source,
            'phc2sys_sink': ptp.phc2sys_sink,
            'ptp4l_instance_map': ptp.ptp4l_instance_map,
            'ts2phc_instance_map': ptp.ts2phc_instance_map,
        }
        ptp.ptpinstances = {
            'ptp4l-down': self.downstream,
            'ptp4l-up': self.upstream,
        }
        ptp.phc2sys_source = 'ens1f0'
        ptp.phc2sys_sink = 'CLOCK_REALTIME'
        ptp.ptp4l_instance_map = {'ens1f0': 'ptp4l-up'}
        # downstream base_port has no ts2phc mapping (isolate upstream path)
        ptp.ts2phc_instance_map = {}

    def tearDown(self):
        # Restore module globals and any sys.modules/sys.path we added.
        for name, value in self._saved_globals.items():
            setattr(self.ptp, name, value)
        for mod in self._added_modules:
            sys.modules.pop(mod, None)

    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.query_pmc')
    @patch('ptp.get_base_port')
    @patch('ptp.is_service_running')
    def test_upstream_down_locked_degrades_to_holdover_135(
            self, mock_service, mock_base_port, mock_query, mock_write):
        """Upstream ptp4l down, downstream previously Locked -> 135."""
        ptp = self.ptp
        # upstream ptp4l service is down
        mock_service.return_value = False
        mock_base_port.return_value = 'ens2f0'
        # downstream GM settings currently advertise clockClass 6
        mock_query.return_value = self._gm_settings(ptp.CLOCK_CLASS_6)

        with patch('ptp.timeutils') as mock_tu:
            mock_tu.utcnow.return_value = 1000.0
            mock_tu.delta_seconds.return_value = 10  # within holdover

            ptp.process_ptp_bc('ptp4l-down')

        self.assertEqual(
            self.downstream.ptp4l_ptp_source_state, ptp.CLOCK_STATE_HOLDOVER)
        mock_write.assert_called_once()
        written = mock_write.call_args[0][1]
        self.assertEqual(written['clockClass'], ptp.CLOCK_CLASS_135)

    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.query_pmc')
    @patch('ptp.get_base_port')
    @patch('ptp.is_service_running')
    def test_upstream_down_holdover_expired_degrades_to_165(
            self, mock_service, mock_base_port, mock_query, mock_write):
        """Upstream down, downstream in holdover past timer -> 165."""
        ptp = self.ptp
        mock_service.return_value = False
        mock_base_port.return_value = 'ens2f0'
        mock_query.return_value = self._gm_settings(ptp.CLOCK_CLASS_135)
        self.downstream.ptp4l_ptp_source_state = ptp.CLOCK_STATE_HOLDOVER
        # holdover timestamp already set (in holdover)
        self.downstream.holdover_timestamp = {'ens2f0': 500.0}

        with patch('ptp.timeutils') as mock_tu:
            mock_tu.utcnow.return_value = 1000.0
            # elapsed beyond holdover_seconds (60)
            mock_tu.delta_seconds.return_value = 120

            ptp.process_ptp_bc('ptp4l-down')

        self.assertEqual(
            self.downstream.ptp4l_ptp_source_state,
            ptp.CLOCK_STATE_HOLDOVER_EXPIRED)
        mock_write.assert_called_once()
        written = mock_write.call_args[0][1]
        self.assertEqual(written['clockClass'], ptp.CLOCK_CLASS_165)

    @patch('ptp.write_ptp4l_gm_fields')
    @patch('ptp.query_pmc')
    @patch('ptp.get_base_port')
    @patch('ptp.is_service_running')
    def test_upstream_running_does_not_use_service_down_path(
            self, mock_service, mock_base_port, mock_query, mock_write):
        """Upstream ptp4l running: service-down degrade path is skipped.

        With the upstream service up and its pmc queries failing (empty
        reply), the function keeps previous status via early return and
        does not write degraded GM fields through the down path.
        """
        ptp = self.ptp
        # both ts2phc (n/a) and upstream ptp4l report running
        mock_service.return_value = True
        mock_base_port.return_value = 'ens2f0'
        # upstream PARENT_DATA_SET query returns too few keys -> early return
        mock_query.return_value = {}

        ptp.process_ptp_bc('ptp4l-down')

        # No GM field write happened via the service-down degradation path
        mock_write.assert_not_called()
        # state left unchanged
        self.assertEqual(
            self.downstream.ptp4l_ptp_source_state, ptp.CLOCK_STATE_LOCKED)


if __name__ == '__main__':
    unittest.main()
