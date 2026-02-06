#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import unittest
import tempfile
import os
import sys
import unittest.mock
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


class TestReadFilesForTimingInstances(unittest.TestCase):

    def setUp(self):
        ptp.ptpinstances = {}
        ptp.phc2sys_source = None
        ptp.phc2sys_sink = None
        ptp.obj.INIT_LOG_THROTTLE = 10
        ptp.obj.hostname = 'testhost'
        self.mock_collectd = sys.modules['collectd']
        self.mock_collectd.reset_mock()

    def _create_config_file(self, content, instance_name):
        with tempfile.NamedTemporaryFile(
            mode='w', suffix=f'-phc2sys-{instance_name}.conf', delete=False
        ) as f:
            f.write(content)
            return f.name

    def _mock_create_ctrl(self, interface, instance_name, instance_type=ptp.PTP_INSTANCE_TYPE_PTP4L):
        if instance_name and not ptp.ptpinstances.get(instance_name, None):
            ctrl = ptp.PTP_ctrl_object(instance_type)
            ctrl.interface = interface
            ctrl.oot_alarm_object = ptp.PTP_alarm_object(instance_name)
            ctrl.oot_alarm_object.raised = False
            ctrl.oot_alarm_object.severity = sys.modules['fm_api'].constants.FM_ALARM_SEVERITY_CLEAR
            ptp.ptpinstances[instance_name] = ctrl

    def _setup_time_drift_test(
        self, ctrl, instance_name, temp_file, mock_subprocess,
        mock_raise_alarm, mock_read_time_status, mock_check_offset
    ):
        ctrl.monitoring_parameters = {
            'offset_threshold_minor_nsec': 1000,
            'offset_threshold_major_nsec': 1000000
        }
        ctrl.ptp4l_utc_offset_nanoseconds = 0
        ctrl.log_throttle_count = 0

        mock_read_time_status.return_value = ('clock1', True, 'gm1', True, 0)
        mock_check_offset.return_value = None
        mock_result = MagicMock()
        mock_result.decode.return_value = 'offset from CLOCK_REALTIME is 2000000ns\n'
        mock_subprocess.return_value = mock_result
        mock_raise_alarm.return_value = True

        ptp.check_phc2sys_time_drift(instance_name, ctrl, temp_file)
        mock_raise_alarm.assert_called_with(ptp.ALARM_CAUSE__OOT, instance_name, unittest.mock.ANY)

    @patch('ptp.read_time_status_np')
    @patch('ptp.raise_alarm')
    @patch('ptp.check_phc2sys_offset')
    @patch('ptp.set_utc_offset')
    @patch('ptp.subprocess.check_output')
    @patch('ptp.glob')
    @patch('ptp.read_ptp_service_options')
    def test_non_ha_with_source_option(
        self, mock_service_opts, mock_glob, mock_subprocess,
        mock_set_utc, mock_check_offset, mock_raise_alarm,
        mock_read_time_status
    ):
        config = """[global]\nmessage_tag phcinst0"""
        temp_file = self._create_config_file(config, 'phcinst0')

        try:
            mock_glob.return_value = [temp_file]
            mock_service_opts.return_value = '-s eth0 -O -37 -m'

            with patch('ptp.create_interface_alarm_objects', side_effect=self._mock_create_ctrl):
                ptp.read_files_for_timing_instances()

            ctrl = ptp.ptpinstances['phcinst0']
            self.assertFalse(ctrl.phc2sys_ha_enabled)
            self.assertEqual(ctrl.interface, 'eth0')

            self._setup_time_drift_test(
                ctrl, 'phcinst0', temp_file, mock_subprocess,
                mock_raise_alarm, mock_read_time_status, mock_check_offset
            )
        finally:
            os.unlink(temp_file)

    @patch('ptp.read_time_status_np')
    @patch('ptp.raise_alarm')
    @patch('ptp.check_phc2sys_offset')
    @patch('ptp.set_utc_offset')
    @patch('ptp.subprocess.check_output')
    @patch('ptp.glob')
    @patch('ptp.read_ptp_service_options')
    def test_non_ha_without_source_option(
        self, mock_service_opts, mock_glob, mock_subprocess,
        mock_set_utc, mock_check_offset, mock_raise_alarm,
        mock_read_time_status
    ):
        config = """[global]\nha_enabled 0\n\n[eth0]\nha_priority 100\n\n"""
        temp_file = self._create_config_file(config, 'test2')

        try:
            mock_glob.return_value = [temp_file]
            mock_service_opts.return_value = '-a -r -R 2 -u 600'

            with patch('ptp.create_interface_alarm_objects', side_effect=self._mock_create_ctrl):
                ptp.read_files_for_timing_instances()

            ctrl = ptp.ptpinstances['test2']
            self.assertFalse(ctrl.phc2sys_ha_enabled)
            self.assertEqual(ctrl.interface, 'eth0')

            self._setup_time_drift_test(ctrl, 'test2', temp_file, mock_subprocess,
                                        mock_raise_alarm, mock_read_time_status, mock_check_offset)
        finally:
            os.unlink(temp_file)

    @patch('ptp.glob')
    @patch('ptp.read_ptp_service_options')
    def test_ha_enabled(self, mock_service_opts, mock_glob):
        config = """
[global]
ha_enabled 1
ha_phc2sys_com_socket /var/run/phc2sys-test

[enp1s0f0]
ha_priority 100
ha_uds_address /var/run/ptp4l-enp1s0f0
ha_domainNumber 0

[enp1s0f1]
ha_priority 90
ha_uds_address /var/run/ptp4l-enp1s0f1
ha_domainNumber 0
"""
        temp_file = self._create_config_file(config, 'test-ha')

        try:
            mock_glob.return_value = [temp_file]
            mock_service_opts.return_value = '-a -r -R 2 -u 600'

            with patch('ptp.create_interface_alarm_objects', side_effect=self._mock_create_ctrl):
                ptp.read_files_for_timing_instances()

            ctrl = ptp.ptpinstances['test-ha']
            self.assertTrue(ctrl.phc2sys_ha_enabled)
            self.assertIn(ctrl.interface, ['enp1s0f0', 'enp1s0f1'])

        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main()
